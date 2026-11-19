"""Exact weakest-precondition rules for the deliberately small symbolic subset."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from .logic import (
    AllOf,
    AnyOf,
    Arithmetic,
    Constraint,
    Equal,
    FiniteEnum,
    IntRange,
    Literal,
    NamedAssumption,
    Negate,
    StateRelation,
    Variable,
)
from .schema import SCHEMA_VERSION, SchemaMixin


class WeakestPreconditionStatus(str, Enum):
    EXACT = "EXACT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class SymbolicTransition(SchemaMixin):
    """A platform-neutral deterministic transition relation.

    Variables name pre-state values. ``assignments`` maps state variables to
    post-state expressions; variables absent from the map are unchanged.
    """

    transition_id: str
    entry_point: str
    guard: Constraint
    assignments: Mapping[str, Constraint] = field(default_factory=dict)
    relation: str = "function"
    deterministic: bool = True
    semantics_ref: str = "rsve.symbolic/1"
    assumptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.transition_id or not self.entry_point:
            raise ValueError("symbolic transition identity and entry point are required")
        if self.relation not in {"function", "relation", "unknown"}:
            raise ValueError("unsupported symbolic transition relation")

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "type": "SymbolicTransition",
            "payload": {
                "transition_id": self.transition_id,
                "entry_point": self.entry_point,
                "guard": self.guard.to_record(),
                "assignments": {key: value.to_record() for key, value in sorted(self.assignments.items())},
                "relation": self.relation,
                "deterministic": self.deterministic,
                "semantics_ref": self.semantics_ref,
                "assumptions": list(self.assumptions),
            },
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "SymbolicTransition":
        if record.get("schema_version") != SCHEMA_VERSION or record.get("type") != "SymbolicTransition":
            raise ValueError("unsupported symbolic transition schema version or type")
        payload = record.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("symbolic transition payload must be an object")
        return cls(
            transition_id=payload["transition_id"],
            entry_point=payload["entry_point"],
            guard=Constraint.from_record(payload["guard"]),
            assignments={key: Constraint.from_record(value) for key, value in payload.get("assignments", {}).items()},
            relation=payload.get("relation", "function"),
            deterministic=bool(payload.get("deterministic", True)),
            semantics_ref=payload.get("semantics_ref", "rsve.symbolic/1"),
            assumptions=tuple(payload.get("assumptions", ())),
        )


@dataclass(frozen=True)
class WeakestPreconditionResult:
    status: WeakestPreconditionStatus
    postcondition: Constraint
    precondition: Constraint | None
    transitions: tuple[str, ...]
    query: str
    reason: str | None = None
    assumptions: tuple[str, ...] = ()

    @property
    def exact(self) -> bool:
        return self.status is WeakestPreconditionStatus.EXACT

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "type": "WeakestPreconditionResult",
            "payload": {
                "status": self.status.value,
                "postcondition": self.postcondition.to_record(),
                "precondition": self.precondition.to_record() if self.precondition else None,
                "transitions": list(self.transitions),
                "query": self.query,
                "reason": self.reason,
                "assumptions": list(self.assumptions),
            },
        }


class WeakestPreconditionEngine:
    """Compose substitutions backwards for exact supported transitions."""

    def derive(
        self,
        postcondition: Constraint,
        transitions: Sequence[SymbolicTransition],
    ) -> WeakestPreconditionResult:
        current = postcondition
        assumptions: list[str] = []
        for transition in reversed(tuple(transitions)):
            if not transition.deterministic or transition.relation != "function":
                return WeakestPreconditionResult(
                    WeakestPreconditionStatus.UNKNOWN,
                    postcondition,
                    None,
                    tuple(item.transition_id for item in transitions),
                    self._query(postcondition, transitions),
                    "nondeterministic or relational transitions require an explicit relational preimage",
                    tuple(assumptions) + transition.assumptions,
                )
            try:
                current = AllOf((transition.guard, _substitute(current, transition.assignments)))
                assumptions.extend(transition.assumptions)
            except UnsupportedSymbolicConstraint as exc:
                return WeakestPreconditionResult(
                    WeakestPreconditionStatus.UNKNOWN,
                    postcondition,
                    None,
                    tuple(item.transition_id for item in transitions),
                    self._query(postcondition, transitions),
                    str(exc),
                    tuple(assumptions) + transition.assumptions,
                )
        return WeakestPreconditionResult(
            WeakestPreconditionStatus.EXACT,
            postcondition,
            current,
            tuple(item.transition_id for item in transitions),
            self._query(postcondition, transitions),
            assumptions=tuple(assumptions),
        )

    def _query(self, postcondition: Constraint, transitions: Sequence[SymbolicTransition]) -> str:
        return json.dumps({
            "postcondition": postcondition.to_record(),
            "transitions": [item.to_record() for item in transitions],
        }, sort_keys=True, separators=(",", ":"))


class UnsupportedSymbolicConstraint(ValueError):
    pass


def _substitute(node: Constraint, assignments: Mapping[str, Constraint]) -> Constraint:
    if isinstance(node, Variable):
        return assignments.get(node.name, node)
    if isinstance(node, Literal):
        return node
    if isinstance(node, Equal):
        return Equal(_substitute(node.left, assignments), _substitute(node.right, assignments))
    if isinstance(node, Arithmetic):
        return Arithmetic(node.operator, _substitute(node.left, assignments), _substitute(node.right, assignments))
    if isinstance(node, IntRange):
        return IntRange(_substitute(node.value, assignments), node.minimum, node.maximum)
    if isinstance(node, FiniteEnum):
        return FiniteEnum(_substitute(node.value, assignments), node.values)
    if isinstance(node, AllOf):
        return AllOf(tuple(_substitute(item, assignments) for item in node.terms))
    if isinstance(node, AnyOf):
        return AnyOf(tuple(_substitute(item, assignments) for item in node.terms))
    if isinstance(node, Negate):
        return Negate(_substitute(node.term, assignments))
    if isinstance(node, StateRelation):
        return StateRelation(_substitute(node.left, assignments), node.relation, _substitute(node.right, assignments))
    if isinstance(node, NamedAssumption):
        return NamedAssumption(node.name, _substitute(node.term, assignments))
    raise UnsupportedSymbolicConstraint(f"unsupported constraint node: {type(node).__name__}")
