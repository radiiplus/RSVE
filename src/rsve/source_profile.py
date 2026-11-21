"""Explicit source-to-profile bindings used by executable source models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .logic import Sort
from .model import State
from .source import SourceFunction


class BindingSpace(str, Enum):
    REQUEST = "request"
    STATE = "state"


@dataclass(frozen=True)
class SourceSymbolBinding:
    """Bind one normalized source symbol to an explicit runtime value."""

    space: BindingSpace
    field: str
    sort: Sort
    width: int | None = None
    signed: bool | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.space, BindingSpace):
            raise TypeError("source binding space must be REQUEST or STATE")
        if not self.field or self.field.startswith(("request.", "state.")):
            raise ValueError("source binding field must be a non-empty unqualified path")
        if not isinstance(self.sort, Sort):
            raise TypeError("source binding sort must use rsve.logic.Sort")
        if self.sort is Sort.BITVECTOR:
            if self.width is None or self.width <= 0 or not isinstance(self.signed, bool):
                raise ValueError("bitvector bindings require positive width and explicit signedness")
        elif self.width is not None or self.signed is not None:
            raise ValueError("width and signedness apply only to bitvector bindings")

    @property
    def qualified_name(self) -> str:
        return f"{self.space.value}.{self.field}"

    def canonical(self) -> dict[str, Any]:
        return {
            "space": self.space.value,
            "field": self.field,
            "sort": self.sort.value,
            "width": self.width,
            "signed": self.signed,
        }


@dataclass(frozen=True)
class SourceFunctionProfile:
    """Profile-specific entry, symbol, and assignment bindings for a function."""

    function_identity: str
    entry_point: str
    symbols: Mapping[str, SourceSymbolBinding]
    assignment_targets: Mapping[str, str]
    guard_lines: tuple[int, ...] = ()
    guard_senses: Mapping[int, bool] = field(default_factory=dict)
    assignment_lines: tuple[int, ...] = ()
    operation_name: str = ""
    component: str = ""
    complete: bool = True
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.function_identity or not self.entry_point:
            raise ValueError("source function identity and entry point are required")
        if any(not name for name in self.symbols):
            raise ValueError("source symbol names cannot be empty")
        if any(not isinstance(binding, SourceSymbolBinding) for binding in self.symbols.values()):
            raise TypeError("source symbols must map to SourceSymbolBinding records")
        if any(not name or not target for name, target in self.assignment_targets.items()):
            raise ValueError("assignment target names and state keys must be non-empty")
        selected_lines = (*self.guard_lines, *self.assignment_lines)
        if any(line <= 0 for line in selected_lines):
            raise ValueError("selected source guard and assignment lines must be positive")
        if (
            len(set(self.guard_lines)) != len(self.guard_lines)
            or len(set(self.assignment_lines)) != len(self.assignment_lines)
        ):
            raise ValueError("selected source guard and assignment lines cannot repeat")
        if set(self.guard_senses) != set(self.guard_lines):
            raise ValueError("every selected source guard line requires exactly one explicit branch sense")
        if any(not isinstance(sense, bool) for sense in self.guard_senses.values()):
            raise TypeError("source guard senses must be boolean")
        if not isinstance(self.complete, bool):
            raise TypeError("source function completeness must be boolean")
        if any(not isinstance(item, str) or not item for item in self.limitations):
            raise ValueError("source profile limitations must be non-empty strings")
        object.__setattr__(self, "symbols", MappingProxyType(dict(self.symbols)))
        object.__setattr__(self, "assignment_targets", MappingProxyType(dict(self.assignment_targets)))
        object.__setattr__(self, "guard_senses", MappingProxyType(dict(self.guard_senses)))
        object.__setattr__(self, "limitations", tuple(dict.fromkeys(self.limitations)))

    def compiler_bindings(self) -> Mapping[str, tuple[Any, ...]]:
        """Return the binding shape accepted by `FormulaCompiler`."""
        result = {}
        for source_name, binding in self.symbols.items():
            value = (binding.qualified_name, binding.sort)
            if binding.sort is Sort.BITVECTOR:
                value += (binding.width, binding.signed)
            result[source_name] = value
        return MappingProxyType(result)

    def source_values(self, state: Mapping[str, Any], request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Resolve each explicitly bound symbol from current state or request."""
        result = {}
        for source_name, binding in self.symbols.items():
            values = request if binding.space is BindingSpace.REQUEST else state
            value = _resolve(values, binding.field)
            _validate_value(source_name, binding, value)
            result[source_name] = value
        return MappingProxyType(result)

    def validate(self, function: SourceFunction, *, require_all_assignments: bool = False) -> None:
        if function.identity != self.function_identity:
            raise ValueError(
                f"source profile identity {self.function_identity!r} does not match {function.identity!r}"
            )
        referenced = _referenced_symbols(
            function,
            guard_lines=frozenset(self.guard_lines),
            assignment_lines=frozenset(self.assignment_lines),
        )
        missing = sorted(referenced - self.symbols.keys())
        if missing:
            raise ValueError(f"source profile has no bindings for symbols: {', '.join(missing)}")
        source_targets = {str(item.get("target", "")) for item in function.assignments if item.get("target")}
        condition_lines = {int(item.get("line", 0)) for item in function.conditions if int(item.get("line", 0)) > 0}
        assignment_lines = {int(item.get("line", 0)) for item in function.assignments if int(item.get("line", 0)) > 0}
        missing_guards = sorted(set(self.guard_lines) - condition_lines)
        missing_assignments = sorted(set(self.assignment_lines) - assignment_lines)
        if missing_guards:
            raise ValueError(f"source profile selects undeclared guard lines: {', '.join(map(str, missing_guards))}")
        if missing_assignments:
            raise ValueError(f"source profile selects undeclared assignment lines: {', '.join(map(str, missing_assignments))}")
        unexpected = sorted(self.assignment_targets.keys() - source_targets)
        if unexpected:
            raise ValueError(f"source profile maps undeclared assignment targets: {', '.join(unexpected)}")
        if require_all_assignments:
            selected_targets = {
                str(item.get("target", ""))
                for item in function.assignments
                if int(item.get("line", 0)) in self.assignment_lines and item.get("target")
            }
            unmapped = sorted(selected_targets - self.assignment_targets.keys())
            if unmapped:
                raise ValueError(f"source profile has no state targets for assignments: {', '.join(unmapped)}")

    def canonical(self) -> dict[str, Any]:
        return {
            "function_identity": self.function_identity,
            "entry_point": self.entry_point,
            "operation_name": self.operation_name,
            "component": self.component,
            "symbols": {key: value.canonical() for key, value in sorted(self.symbols.items())},
            "assignment_targets": dict(sorted(self.assignment_targets.items())),
            "guard_lines": self.guard_lines,
            "guard_senses": dict(sorted(self.guard_senses.items())),
            "assignment_lines": self.assignment_lines,
            "complete": self.complete,
            "limitations": self.limitations,
        }


@dataclass(frozen=True)
class SourceProfile:
    """Named profile binding a set of source functions to a target model."""

    target_id: str
    profile_id: str
    functions: Mapping[str, SourceFunctionProfile] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.target_id or not self.profile_id:
            raise ValueError("source profile target and profile identities are required")
        for identity, function in self.functions.items():
            if identity != function.function_identity:
                raise ValueError(f"source profile key {identity!r} does not match its function binding")
        object.__setattr__(self, "functions", MappingProxyType(dict(self.functions)))

    def function(self, identity: str) -> SourceFunctionProfile:
        try:
            return self.functions[identity]
        except KeyError as exc:
            raise KeyError(f"no source profile binding for function {identity!r}") from exc

    def validate(self, source_index: Any, *, require_all_assignments: bool = False) -> None:
        for identity, binding in self.functions.items():
            function = source_index.function(identity)
            if function is None:
                raise ValueError(f"source profile function is absent from index: {identity}")
            binding.validate(function, require_all_assignments=require_all_assignments)

    def canonical(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "profile_id": self.profile_id,
            "functions": {key: value.canonical() for key, value in sorted(self.functions.items())},
        }


def _resolve(values: Mapping[str, Any], field_name: str) -> Any:
    if field_name in values:
        return values[field_name]
    current: Any = values
    for part in field_name.split("."):
        if not isinstance(current, Mapping) or part not in current:
            raise KeyError(f"profile field not present: {field_name}")
        current = current[part]
    return current


def _validate_value(source_name: str, binding: SourceSymbolBinding, value: Any) -> None:
    valid = False
    if binding.sort is Sort.BOOL:
        valid = type(value) is bool
    elif binding.sort is Sort.INT:
        valid = type(value) is int
    elif binding.sort is Sort.BITVECTOR:
        if type(value) is int:
            magnitude_bits = abs(value).bit_length()
            if binding.signed:
                valid = (
                    magnitude_bits < binding.width
                    or (value >= 0 and magnitude_bits <= binding.width - 1)
                    or (value < 0 and magnitude_bits == binding.width and abs(value).bit_count() == 1)
                )
            else:
                valid = value >= 0 and magnitude_bits <= binding.width
    elif binding.sort in {Sort.STRING, Sort.ENUM}:
        valid = isinstance(value, str)
    elif binding.sort is Sort.BYTES:
        valid = isinstance(value, bytes)
    elif binding.sort is Sort.STATE:
        valid = isinstance(value, (Mapping, State))
    if not valid:
        suffix = ""
        if binding.sort is Sort.BITVECTOR:
            if binding.signed:
                suffix = f" in signed {binding.width}-bit range"
            else:
                suffix = f" in unsigned {binding.width}-bit range"
        raise TypeError(
            f"profile value for source symbol {source_name!r} bound to {binding.qualified_name!r} "
            f"does not match {binding.sort.value}{suffix}"
        )


def _referenced_symbols(
    function: SourceFunction,
    *,
    guard_lines: frozenset[int],
    assignment_lines: frozenset[int],
) -> set[str]:
    found: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, Mapping):
            kind = node.get("kind")
            if kind == "variable":
                name = str(node.get("name", ""))
                if name and name not in {"true", "false"}:
                    found.add(name)
            elif kind == "selector":
                name = _source_symbol(node)
                if name:
                    found.add(name)
            else:
                for value in node.values():
                    visit(value)
        elif isinstance(node, (tuple, list)):
            for item in node:
                visit(item)

    for condition in function.conditions:
        if int(condition.get("line", 0)) in guard_lines:
            visit(condition.get("expr"))
    for assignment in function.assignments:
        if int(assignment.get("line", 0)) in assignment_lines:
            visit(assignment.get("value"))
    return found


def _source_symbol(node: Mapping[str, Any]) -> str:
    if node.get("kind") == "variable":
        return str(node.get("name", ""))
    if node.get("kind") == "selector":
        base = _source_symbol(node.get("base", {}))
        return f"{base}.{node.get('field', '')}" if base else ""
    return ""
