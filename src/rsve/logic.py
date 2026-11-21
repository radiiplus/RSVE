"""Solver-neutral, typed constraint subset used by RSVE objectives."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar

from .schema import Version, encode


class Sort(str, Enum):
    BOOL = "bool"
    INT = "int"
    BITVECTOR = "bitvector"
    STRING = "string"
    BYTES = "bytes"
    ENUM = "enum"
    STATE = "state"


class Constraint:
    type_name: ClassVar[str]

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    def to_record(self) -> dict[str, Any]:
        return {"schema_version": Version, "type": self.type_name, "payload": self.to_dict()}

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "Constraint":
        if record.get("schema_version") != Version:
            raise ValueError(f"unsupported schema version: {record.get('schema_version')!r}")
        try:
            node_type = _TYPES[record["type"]]
            payload = record["payload"]
        except (KeyError, TypeError):
            raise ValueError("invalid constraint record") from None
        if not isinstance(payload, dict):
            raise ValueError("constraint payload must be an object")
        return node_type.from_dict(payload)


def _node(value: Constraint) -> dict[str, Any]:
    return {"type": value.type_name, "payload": value.to_dict()}


def _load(value: Any) -> Constraint:
    if not isinstance(value, dict) or "type" not in value or "payload" not in value:
        raise ValueError("invalid nested constraint")
    node_type = _TYPES.get(value["type"])
    if node_type is None:
        raise ValueError(f"unsupported constraint type: {value['type']!r}")
    return node_type.from_dict(value["payload"])


@dataclass(frozen=True)
class Literal(Constraint):
    type_name: ClassVar[str] = "literal"
    value: Any
    sort: Sort

    def to_dict(self) -> dict[str, Any]:
        return {"value": encode(self.value), "sort": self.sort.value}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Literal":
        value = data["value"]
        if isinstance(value, dict) and "__bytes__" in value:
            value = bytes.fromhex(value["__bytes__"])
        return cls(value, Sort(data["sort"]))


@dataclass(frozen=True)
class Variable(Constraint):
    type_name: ClassVar[str] = "variable"
    name: str
    sort: Sort
    width: int | None = None
    signed: bool | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("constraint variable name is required")
        if self.sort is Sort.BITVECTOR and (self.width is None or self.width <= 0):
            raise ValueError("bitvector variables require a positive width")
        if self.sort is not Sort.BITVECTOR and self.signed is not None:
            raise ValueError("signedness is only valid for bitvector variables")

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "sort": self.sort.value, "width": self.width, "signed": self.signed}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Variable":
        return cls(data["name"], Sort(data["sort"]), data.get("width"), data.get("signed"))


@dataclass(frozen=True)
class Equal(Constraint):
    type_name: ClassVar[str] = "equal"
    left: Constraint
    right: Constraint

    def to_dict(self) -> dict[str, Any]:
        return {"left": _node(self.left), "right": _node(self.right)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Equal":
        return cls(_load(data["left"]), _load(data["right"]))


@dataclass(frozen=True)
class Arithmetic(Constraint):
    """Supported side-effect-free integer/bit-vector expression."""

    type_name: ClassVar[str] = "arithmetic"
    operator: str
    left: Constraint
    right: Constraint

    def __post_init__(self) -> None:
        if self.operator not in {
            "+", "-", "*", "/", "%", "&", "|", "^", "&^", "<<", "s>>", "u>>",
            "s/", "u/", "s%", "u%",
        }:
            raise ValueError("unsupported arithmetic operator")

    def to_dict(self) -> dict[str, Any]:
        return {"operator": self.operator, "left": _node(self.left), "right": _node(self.right)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Arithmetic":
        return cls(data["operator"], _load(data["left"]), _load(data["right"]))


def Add(left: Constraint, right: Constraint) -> Arithmetic:
    return Arithmetic("+", left, right)


def Subtract(left: Constraint, right: Constraint) -> Arithmetic:
    return Arithmetic("-", left, right)


def Multiply(left: Constraint, right: Constraint) -> Arithmetic:
    return Arithmetic("*", left, right)


@dataclass(frozen=True)
class Range(Constraint):
    type_name: ClassVar[str] = "int_range"
    value: Constraint
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if self.minimum > self.maximum:
            raise ValueError("range minimum cannot exceed maximum")

    def to_dict(self) -> dict[str, Any]:
        return {"value": _node(self.value), "minimum": self.minimum, "maximum": self.maximum}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Range":
        return cls(_load(data["value"]), int(data["minimum"]), int(data["maximum"]))


@dataclass(frozen=True)
class Set(Constraint):
    type_name: ClassVar[str] = "finite_enum"
    value: Constraint
    values: tuple[Any, ...]

    def __post_init__(self) -> None:
        if not self.values:
            raise ValueError("finite enum requires at least one value")

    def to_dict(self) -> dict[str, Any]:
        return {"value": _node(self.value), "values": [encode(item) for item in self.values]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Set":
        return cls(_load(data["value"]), tuple(data["values"]))


@dataclass(frozen=True)
class Every(Constraint):
    type_name: ClassVar[str] = "all_of"
    terms: tuple[Constraint, ...]

    def __post_init__(self) -> None:
        if not self.terms:
            raise ValueError("all_of requires at least one term")

    def to_dict(self) -> dict[str, Any]:
        return {"terms": [_node(term) for term in self.terms]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Every":
        return cls(tuple(_load(term) for term in data["terms"]))


@dataclass(frozen=True)
class Either(Constraint):
    type_name: ClassVar[str] = "any_of"
    terms: tuple[Constraint, ...]

    def __post_init__(self) -> None:
        if not self.terms:
            raise ValueError("any_of requires at least one term")

    def to_dict(self) -> dict[str, Any]:
        return {"terms": [_node(term) for term in self.terms]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Either":
        return cls(tuple(_load(term) for term in data["terms"]))


@dataclass(frozen=True)
class Negate(Constraint):
    type_name: ClassVar[str] = "negate"
    term: Constraint

    def to_dict(self) -> dict[str, Any]:
        return {"term": _node(self.term)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Negate":
        return cls(_load(data["term"]))


@dataclass(frozen=True)
class Rel(Constraint):
    type_name: ClassVar[str] = "state_relation"
    left: Constraint
    relation: str
    right: Constraint

    def __post_init__(self) -> None:
        if not self.relation:
            raise ValueError("state relation operator is required")

    def to_dict(self) -> dict[str, Any]:
        return {"left": _node(self.left), "relation": self.relation, "right": _node(self.right)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rel":
        return cls(_load(data["left"]), data["relation"], _load(data["right"]))


@dataclass(frozen=True)
class Axiom(Constraint):
    type_name: ClassVar[str] = "named_assumption"
    name: str
    term: Constraint

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("named assumption requires a name")

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "term": _node(self.term)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Axiom":
        return cls(data["name"], _load(data["term"]))


_TYPES = {
    node.type_name: node
    for node in (Literal, Variable, Equal, Arithmetic, Range, Set, Every, Either, Negate, Rel, Axiom)
}


def named_assertions(term: Constraint) -> tuple[tuple[str, Constraint], ...]:
    """Collect named assertions in canonical traversal order."""
    found: list[tuple[str, Constraint]] = []

    def visit(node: Constraint) -> None:
        if isinstance(node, Axiom):
            found.append((node.name, node.term))
            visit(node.term)
        elif isinstance(node, (Every, Either)):
            for child in node.terms:
                visit(child)
        elif isinstance(node, (Equal, Rel)):
            visit(node.left)
            visit(node.right)
        elif isinstance(node, Arithmetic):
            visit(node.left)
            visit(node.right)
        elif isinstance(node, (Range, Set, Negate)):
            visit(node.value if isinstance(node, (Range, Set)) else node.term)

    visit(term)
    return tuple(found)
