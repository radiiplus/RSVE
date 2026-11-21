"""Exact weakest-precondition rules for the deliberately small symbolic subset."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from .logic import (
    Every,
    Either,
    Arithmetic,
    Constraint,
    Equal,
    Set,
    Range,
    Literal,
    Axiom,
    Negate,
    Rel,
    Variable,
)
from .schema import Version, Schema


class Truth(str, Enum):
    EXACT = "EXACT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Symbolic(Schema):
    """A platform-neutral transition relation.

    Variables name pre-state values. ``assignments`` maps state variables to
    post-state expressions; variables absent from the map are unchanged.
    ``alternatives`` gives an explicit finite relational successor set.
    """

    transition_id: str
    entry_point: str
    guard: Constraint
    assignments: Mapping[str, Constraint] = field(default_factory=dict)
    relation: str = "function"
    deterministic: bool = True
    semantics_ref: str = "rsve.symbolic/1"
    semantics_version: str = "1"
    assumptions: tuple[str, ...] = ()
    alternatives: tuple[Mapping[str, Constraint], ...] = ()

    def __post_init__(self) -> None:
        if not self.transition_id or not self.entry_point:
            raise ValueError("symbolic transition identity and entry point are required")
        if self.relation not in {"function", "relation", "unknown"}:
            raise ValueError("unsupported symbolic transition relation")

    def scoped(self, input_prefix: str, output_prefix: str) -> "Symbolic":
        """Rename representation variables for one composed route stage."""
        rename = lambda name: _scope_name(name, input_prefix, output_prefix)
        return Symbolic(
            transition_id=self.transition_id,
            entry_point=self.entry_point,
            guard=_rename(self.guard, rename),
            assignments={rename(key): _rename(value, rename) for key, value in self.assignments.items()},
            relation=self.relation,
            deterministic=self.deterministic,
            semantics_ref=self.semantics_ref,
            semantics_version=self.semantics_version,
            assumptions=self.assumptions,
            alternatives=tuple(
                {rename(key): _rename(value, rename) for key, value in branch.items()}
                for branch in self.alternatives
            ),
        )

    def variants(self) -> tuple[Mapping[str, Constraint], ...]:
        """Return explicit successor assignments for relational regression."""
        return self.alternatives or (self.assignments,)

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": Version,
            "type": "Symbolic",
            "payload": {
                "transition_id": self.transition_id,
                "entry_point": self.entry_point,
                "guard": self.guard.to_record(),
                "assignments": {key: value.to_record() for key, value in sorted(self.assignments.items())},
                "relation": self.relation,
                "deterministic": self.deterministic,
                "semantics_ref": self.semantics_ref,
                "semantics_version": self.semantics_version,
                "assumptions": list(self.assumptions),
                "alternatives": [
                    {key: value.to_record() for key, value in sorted(branch.items())}
                    for branch in self.alternatives
                ],
            },
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "Symbolic":
        if record.get("schema_version") != Version or record.get("type") != "Symbolic":
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
            semantics_version=payload.get("semantics_version", "1"),
            assumptions=tuple(payload.get("assumptions", ())),
            alternatives=tuple(
                {
                    key: Constraint.from_record(value)
                    for key, value in branch.items()
                }
                for branch in payload.get("alternatives", ())
            ),
        )


@dataclass(frozen=True)
class Preimage:
    status: Truth
    postcondition: Constraint
    precondition: Constraint | None
    transitions: tuple[str, ...]
    query: str
    reason: str | None = None
    assumptions: tuple[str, ...] = ()

    @property
    def exact(self) -> bool:
        return self.status is Truth.EXACT

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": Version,
            "type": "Preimage",
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


class WP:
    """Compose substitutions backwards for exact supported transitions."""

    def derive(
        self,
        postcondition: Constraint,
        transitions: Sequence[Symbolic],
    ) -> Preimage:
        current = postcondition
        assumptions: list[str] = []
        for transition in reversed(tuple(transitions)):
            if not transition.deterministic or transition.relation != "function":
                if transition.relation == "relation" and transition.alternatives:
                    variants = transition.variants()
                else:
                    return Preimage(
                        Truth.UNKNOWN,
                        postcondition,
                        None,
                        tuple(item.transition_id for item in transitions),
                        self._query(postcondition, transitions),
                        "nondeterministic or relational transitions require explicit finite alternatives",
                        tuple(assumptions) + transition.assumptions,
                    )
            else:
                variants = transition.variants()
            if not variants:
                return Preimage(
                    Truth.UNKNOWN,
                    postcondition,
                    None,
                    tuple(item.transition_id for item in transitions),
                    self._query(postcondition, transitions),
                    "transition has no successor assignment",
                    tuple(assumptions) + transition.assumptions,
                )
            try:
                options = tuple(
                    Every((transition.guard, _substitute(current, assignments)))
                    for assignments in variants
                )
                current = options[0] if len(options) == 1 else Either(options)
                assumptions.extend(transition.assumptions)
            except Opaque as exc:
                return Preimage(
                    Truth.UNKNOWN,
                    postcondition,
                    None,
                    tuple(item.transition_id for item in transitions),
                    self._query(postcondition, transitions),
                    str(exc),
                    tuple(assumptions) + transition.assumptions,
                )
        return Preimage(
            Truth.EXACT,
            postcondition,
            current,
            tuple(item.transition_id for item in transitions),
            self._query(postcondition, transitions),
            assumptions=tuple(assumptions),
        )

    def _query(self, postcondition: Constraint, transitions: Sequence[Symbolic]) -> str:
        return json.dumps({
            "postcondition": postcondition.to_record(),
            "transitions": [item.to_record() for item in transitions],
        }, sort_keys=True, separators=(",", ":"))


class Opaque(ValueError):
    pass


def _scope_name(name: str, input_prefix: str, output_prefix: str) -> str:
    if name.startswith("input."):
        return input_prefix + name[len("input."):]
    if name.startswith("output."):
        return output_prefix + name[len("output."):]
    return name


def rename(node: Constraint, mapper: Any) -> Constraint:
    """Rename variables in a supported constraint tree."""
    return _rename(node, mapper)


def _rename(node: Constraint, rename: Any) -> Constraint:
    if isinstance(node, Variable):
        return Variable(rename(node.name), node.sort, node.width, node.signed)
    if isinstance(node, Literal):
        return node
    if isinstance(node, Equal):
        return Equal(_rename(node.left, rename), _rename(node.right, rename))
    if isinstance(node, Arithmetic):
        return Arithmetic(node.operator, _rename(node.left, rename), _rename(node.right, rename))
    if isinstance(node, Range):
        return Range(_rename(node.value, rename), node.minimum, node.maximum)
    if isinstance(node, Set):
        return Set(_rename(node.value, rename), node.values)
    if isinstance(node, Every):
        return Every(tuple(_rename(item, rename) for item in node.terms))
    if isinstance(node, Either):
        return Either(tuple(_rename(item, rename) for item in node.terms))
    if isinstance(node, Negate):
        return Negate(_rename(node.term, rename))
    if isinstance(node, Rel):
        return Rel(_rename(node.left, rename), node.relation, _rename(node.right, rename))
    if isinstance(node, Axiom):
        return Axiom(node.name, _rename(node.term, rename))
    raise Opaque(f"unsupported constraint node: {type(node).__name__}")


def _substitute(node: Constraint, assignments: Mapping[str, Constraint]) -> Constraint:
    if isinstance(node, Variable):
        return assignments.get(node.name, node)
    if isinstance(node, Literal):
        return node
    if isinstance(node, Equal):
        return Equal(_substitute(node.left, assignments), _substitute(node.right, assignments))
    if isinstance(node, Arithmetic):
        return Arithmetic(node.operator, _substitute(node.left, assignments), _substitute(node.right, assignments))
    if isinstance(node, Range):
        return Range(_substitute(node.value, assignments), node.minimum, node.maximum)
    if isinstance(node, Set):
        return Set(_substitute(node.value, assignments), node.values)
    if isinstance(node, Every):
        return Every(tuple(_substitute(item, assignments) for item in node.terms))
    if isinstance(node, Either):
        return Either(tuple(_substitute(item, assignments) for item in node.terms))
    if isinstance(node, Negate):
        return Negate(_substitute(node.term, assignments))
    if isinstance(node, Rel):
        return Rel(_substitute(node.left, assignments), node.relation, _substitute(node.right, assignments))
    if isinstance(node, Axiom):
        return Axiom(node.name, _substitute(node.term, assignments))
    raise Opaque(f"unsupported constraint node: {type(node).__name__}")
