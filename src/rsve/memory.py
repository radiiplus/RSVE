"""Concrete, explicit-identity memory semantics for aggregate state."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .logic import Constraint, Every, Literal, Rel, Sort, Variable


class MemoryFaultKind(str, Enum):
    NIL_POINTER = "nil_pointer_dereference"
    INDEX = "index_out_of_range"
    NIL_MAP_WRITE = "assignment_to_nil_map"
    SLICE_BOUNDS = "slice_bounds"
    CAPACITY = "invalid_capacity"
    CLOSED_TRANSACTION = "closed_transaction"
    TRANSACTION_CONFLICT = "transaction_conflict"


class MemoryFault(RuntimeError):
    """A concrete Go-like memory operation that panics or violates its model."""

    def __init__(self, kind: MemoryFaultKind, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


@dataclass(frozen=True)
class Pointer:
    object_id: int
    path: tuple[str, ...] = ()


@dataclass(frozen=True)
class SliceRef:
    object_id: int
    offset: int
    length: int
    capacity: int


@dataclass(frozen=True)
class MapRef:
    object_id: int


@dataclass(frozen=True)
class StructValue:
    type_name: str
    fields: tuple[tuple[str, Any], ...]

    @classmethod
    def create(cls, type_name: str, fields: Mapping[str, Any]) -> "StructValue":
        if not type_name:
            raise ValueError("struct type name is required")
        return cls(type_name, tuple(sorted((name, _copy_value(value)) for name, value in fields.items())))

    def get(self, name: str) -> Any:
        try:
            return dict(self.fields)[name]
        except KeyError:
            raise KeyError(f"struct {self.type_name} has no field {name!r}") from None

    def set(self, name: str, value: Any) -> "StructValue":
        fields = dict(self.fields)
        if name not in fields:
            raise KeyError(f"struct {self.type_name} has no field {name!r}")
        fields[name] = _copy_value(value)
        return StructValue.create(self.type_name, fields)


@dataclass(frozen=True)
class ArrayValue:
    type_name: str
    elements: tuple[Any, ...]

    @classmethod
    def create(cls, type_name: str, elements: tuple[Any, ...] | list[Any]) -> "ArrayValue":
        if not type_name:
            raise ValueError("array type name is required")
        return cls(type_name, tuple(_copy_value(value) for value in elements))

    def get(self, index: int) -> Any:
        if index < 0 or index >= len(self.elements):
            raise MemoryFault(MemoryFaultKind.INDEX, f"array index {index} outside length {len(self.elements)}")
        return self.elements[index]

    def set(self, index: int, value: Any) -> "ArrayValue":
        if index < 0 or index >= len(self.elements):
            raise MemoryFault(MemoryFaultKind.INDEX, f"array index {index} outside length {len(self.elements)}")
        elements = list(self.elements)
        elements[index] = _copy_value(value)
        return ArrayValue(self.type_name, tuple(elements))


@dataclass(frozen=True)
class _HeapObject:
    kind: str
    value: Any


@dataclass(frozen=True)
class Memory:
    """Persistent heap snapshot. Layout offsets are intentionally not inferred."""

    objects: tuple[_HeapObject, ...] = ()
    next_id: int = 1
    revision: int = 0

    def transaction(self) -> "MemoryTransaction":
        return MemoryTransaction(self)


@dataclass
class MemoryTransaction:
    """Isolated write overlay over one memory snapshot."""

    base: Memory
    _overlay: dict[int, _HeapObject] = field(default_factory=dict)
    _next_id: int = 0
    _closed: bool = False

    def __post_init__(self) -> None:
        self._next_id = self.base.next_id

    def _ensure_open(self) -> None:
        if self._closed:
            raise MemoryFault(MemoryFaultKind.CLOSED_TRANSACTION, "memory transaction is closed")

    def _allocate(self, kind: str, value: Any) -> int:
        self._ensure_open()
        object_id = self._next_id
        self._next_id += 1
        self._overlay[object_id] = _HeapObject(kind, value)
        return object_id

    def _object(self, object_id: int, kind: str | None = None) -> _HeapObject:
        self._ensure_open()
        if object_id in self._overlay:
            value = self._overlay[object_id]
        elif 0 < object_id <= len(self.base.objects):
            value = self.base.objects[object_id - 1]
        else:
            raise MemoryFault(MemoryFaultKind.NIL_POINTER, f"invalid heap object {object_id}")
        if kind is not None and value.kind != kind:
            raise TypeError(f"heap object {object_id} is {value.kind}, expected {kind}")
        return value

    def _write_object(self, object_id: int, value: _HeapObject) -> None:
        self._ensure_open()
        self._object(object_id)
        self._overlay[object_id] = value

    def new_pointer(self, value: Any) -> Pointer:
        return Pointer(self._allocate("cell", _copy_value(value)))

    def new_struct(self, value: StructValue) -> Pointer:
        return Pointer(self._allocate("cell", _copy_value(value)))

    def new_slice(self, elements: tuple[Any, ...] | list[Any], *, capacity: int | None = None) -> SliceRef:
        values = tuple(_copy_value(value) for value in elements)
        cap = len(values) if capacity is None else capacity
        if cap < len(values) or cap < 0:
            raise MemoryFault(MemoryFaultKind.CAPACITY, "slice capacity must be at least its length")
        backing = values + (None,) * (cap - len(values))
        object_id = self._allocate("slice", backing)
        return SliceRef(object_id, 0, len(values), cap)

    def new_map(self, values: Mapping[Any, Any] | None = None) -> MapRef:
        entries = tuple((key, _copy_value(value)) for key, value in (values or {}).items())
        return MapRef(self._allocate("map", entries))

    def load(self, pointer: Pointer | None) -> Any:
        if pointer is None:
            raise MemoryFault(MemoryFaultKind.NIL_POINTER, "dereference of nil pointer")
        value = self._object(pointer.object_id, "cell").value
        for field_name in pointer.path:
            if not isinstance(value, StructValue):
                raise TypeError(f"pointer path {pointer.path!r} crosses a non-struct value")
            value = value.get(field_name)
        return _copy_value(value)

    def store(self, pointer: Pointer | None, value: Any) -> None:
        if pointer is None:
            raise MemoryFault(MemoryFaultKind.NIL_POINTER, "assignment through nil pointer")
        obj = self._object(pointer.object_id, "cell")
        if not pointer.path:
            self._write_object(pointer.object_id, _HeapObject("cell", _copy_value(value)))
            return
        root = obj.value
        if not isinstance(root, StructValue):
            raise TypeError("field pointer target is not a struct")
        replacement = _store_struct_path(root, pointer.path, value)
        self._write_object(pointer.object_id, _HeapObject("cell", replacement))

    def field_pointer(self, pointer: Pointer, field_name: str) -> Pointer:
        value = self.load(pointer)
        if not isinstance(value, StructValue):
            raise TypeError("field pointer requires a struct")
        value.get(field_name)
        return Pointer(pointer.object_id, pointer.path + (field_name,))

    def slice_get(self, ref: SliceRef, index: int) -> Any:
        self._check_index(index, ref.length, "slice")
        backing = self._object(ref.object_id, "slice").value
        return _copy_value(backing[ref.offset + index])

    def slice_set(self, ref: SliceRef, index: int, value: Any) -> None:
        self._check_index(index, ref.length, "slice")
        backing = list(self._object(ref.object_id, "slice").value)
        backing[ref.offset + index] = _copy_value(value)
        self._write_object(ref.object_id, _HeapObject("slice", tuple(backing)))

    def slice_view(
        self, ref: SliceRef, low: int = 0, high: int | None = None, maximum: int | None = None,
    ) -> SliceRef:
        three_index = maximum is not None
        high = ref.length if high is None else high
        maximum = ref.capacity if maximum is None else maximum
        if low < 0 or high < low or maximum < high or maximum > ref.capacity:
            raise MemoryFault(MemoryFaultKind.SLICE_BOUNDS, "slice bounds outside capacity")
        if high > ref.length and not three_index:
            raise MemoryFault(MemoryFaultKind.SLICE_BOUNDS, "two-index slice high bound exceeds length")
        return SliceRef(ref.object_id, ref.offset + low, high - low, maximum - low)

    def append_slice(self, ref: SliceRef, value: Any, *, new_capacity: int | None = None) -> SliceRef:
        if ref.length < ref.capacity:
            result = SliceRef(ref.object_id, ref.offset, ref.length + 1, ref.capacity)
            self.slice_set(SliceRef(ref.object_id, ref.offset, ref.capacity, ref.capacity), ref.length, value)
            return result
        if new_capacity is None:
            raise MemoryFault(MemoryFaultKind.CAPACITY, "slice reallocation requires explicit capacity")
        if new_capacity <= ref.length:
            raise MemoryFault(MemoryFaultKind.CAPACITY, "new slice capacity must exceed its length")
        contents = tuple(self.slice_get(ref, index) for index in range(ref.length)) + (_copy_value(value),)
        return self.new_slice(contents, capacity=new_capacity)

    def map_get(self, ref: MapRef | None, key: Any, *, zero: Any = None) -> Any:
        if ref is None:
            return _copy_value(zero)
        entries = dict(self._object(ref.object_id, "map").value)
        return _copy_value(entries.get(key, zero))

    def map_set(self, ref: MapRef | None, key: Any, value: Any) -> None:
        if ref is None:
            raise MemoryFault(MemoryFaultKind.NIL_MAP_WRITE, "assignment to entry in nil map")
        entries = dict(self._object(ref.object_id, "map").value)
        entries[key] = _copy_value(value)
        self._write_object(ref.object_id, _HeapObject("map", tuple(entries.items())))

    def map_delete(self, ref: MapRef | None, key: Any) -> None:
        if ref is None:
            return
        entries = dict(self._object(ref.object_id, "map").value)
        entries.pop(key, None)
        self._write_object(ref.object_id, _HeapObject("map", tuple(entries.items())))

    def commit(self, current: Memory | None = None) -> Memory:
        self._ensure_open()
        current = self.base if current is None else current
        if current is not self.base:
            raise MemoryFault(MemoryFaultKind.TRANSACTION_CONFLICT, "memory changed since transaction began")
        objects = list(current.objects)
        for object_id, item in sorted(self._overlay.items()):
            if object_id <= len(objects):
                objects[object_id - 1] = item
            elif object_id == len(objects) + 1:
                objects.append(item)
            else:
                raise MemoryFault(MemoryFaultKind.TRANSACTION_CONFLICT, "transaction allocated a noncontiguous object id")
        self._closed = True
        return Memory(tuple(objects), max(current.next_id, self._next_id), current.revision + 1)

    def rollback(self) -> Memory:
        self._ensure_open()
        self._closed = True
        return self.base

    @staticmethod
    def _check_index(index: int, length: int, kind: str) -> None:
        if index < 0 or index >= length:
            raise MemoryFault(MemoryFaultKind.INDEX, f"{kind} index {index} outside length {length}")


def index_constraint(index: Constraint, length: int | Constraint) -> Constraint:
    """Exact guard for a valid Go index, assuming integer index/length values."""
    upper = Literal(length, Sort.INT) if isinstance(length, int) else length
    return Every((Rel(index, ">=", Literal(0, Sort.INT)), Rel(index, "<", upper)))


def _copy_value(value: Any) -> Any:
    if isinstance(value, StructValue):
        return StructValue.create(value.type_name, dict(value.fields))
    if isinstance(value, ArrayValue):
        return ArrayValue.create(value.type_name, value.elements)
    return value


def _store_struct_path(root: StructValue, path: tuple[str, ...], value: Any) -> StructValue:
    if len(path) == 1:
        return root.set(path[0], value)
    child = root.get(path[0])
    if not isinstance(child, StructValue):
        raise TypeError(f"field path {path!r} crosses a non-struct value")
    return root.set(path[0], _store_struct_path(child, path[1:], value))
