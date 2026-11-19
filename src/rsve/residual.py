"""Bounded residual queries and candidate-region accounting."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable

from .logic import Every, Constraint
from .ir import Scope
from .result import Verdict
from .solver import Query, Answer, Zed


class Type(str, Enum):
    TRANSFORM_DOMAIN = "gap"
    OVER_ACCEPTANCE = "over_acceptance"
    UNDER_ACCEPTANCE = "under_acceptance"
    PATH_GUARD = "bounded_path_guard"
    UNMODELED = "actual_transition_unmodeled"
    UNOBSERVED = "modeled_transition_unobserved"
    DIVERGENCE = "transition_state_divergence"
    REJECTION = "unexpected_rejection_effect"
    ACCEPTANCE = "unexpected_acceptance_effect"
    MISSING = "missing_intended_transition"
    CONTROL = "unexpected_control_transition"
    ENVIRONMENT = "environmental_transition_divergence"
    CAUSAL = "cross_region_causal_divergence"
    ROUTE = "alternative_objective_route"
    OPAQUE = "unknown_transition_semantics"


class Phase(str, Enum):
    FOUND = "FOUND"
    EMPTY = "EMPTY"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Area:
    region_id: str
    candidates: tuple[Any, ...]
    explored: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        keys = [_key(candidate) for candidate in self.candidates]
        if len(keys) != len(set(keys)):
            raise ValueError("candidate region contains duplicate canonical candidates")

    @property
    def pending(self) -> tuple[Any, ...]:
        return tuple(candidate for candidate in self.candidates if _key(candidate) not in self.explored)

    @property
    def coverage(self) -> float:
        return 1.0 if not self.candidates else (len(self.candidates) - len(self.pending)) / len(self.candidates)

    def mark(self, values: Iterable[Any]) -> "Area":
        known = self.explored | {_key(value) for value in values}
        return Area(self.region_id, self.candidates, frozenset(known))


@dataclass(frozen=True)
class Residual:
    kind: Type
    status: Phase
    residual: tuple[Any, ...]
    region: Area
    detail: str
    solver_result: Answer | None = None
    transition: str | None = None
    expected: Any = None
    observed: Any = None
    evidence: tuple[str, ...] = ()
    fidelity: str = "unknown"
    uncertainty: tuple[str, ...] = ()


def mismatch(
    kind: Type,
    region: Area,
    detail: str,
    *,
    transition: str | None = None,
    expected: Any = None,
    observed: Any = None,
    evidence: Iterable[str] = (),
    fidelity: str = "unknown",
    uncertainty: Iterable[str] = (),
) -> Residual:
    """Record a transition-space residual without implying exploitability."""
    return Residual(
        kind=kind,
        status=Phase.FOUND,
        residual=(),
        region=region,
        detail=detail,
        transition=transition,
        expected=expected,
        observed=observed,
        evidence=tuple(evidence),
        fidelity=fidelity,
        uncertainty=tuple(uncertainty),
    )


def transform(
    transform: Callable[[Any], Any] | None,
    source: Area,
    downstream_domain: Iterable[Any],
) -> Residual:
    if transform is None:
        return Residual(
            Type.TRANSFORM_DOMAIN,
            Phase.UNKNOWN,
            (),
            source,
            "transform relation is opaque; no identity or unconstrained approximation was assumed",
        )
    downstream = {_key(value) for value in downstream_domain}
    outputs: dict[str, Any] = {}
    for candidate in source.pending:
        output = transform(candidate)
        outputs.setdefault(_key(output), output)
    residual = tuple(output for key, output in sorted(outputs.items()) if key not in downstream)
    region = source.mark(source.pending)
    return Residual(
        Type.TRANSFORM_DOMAIN,
        Phase.FOUND if residual else Phase.EMPTY,
        residual,
        region,
        "computed Image(T) minus the declared downstream domain over the finite source region",
    )


def accept(
    actual: Callable[[Any], bool],
    intended: Callable[[Any], bool],
    region: Area,
    *,
    over: bool,
) -> Residual:
    residual = tuple(
        candidate
        for candidate in region.pending
        if ((actual(candidate) and not intended(candidate)) if over else (intended(candidate) and not actual(candidate)))
    )
    checked = region.mark(region.pending)
    kind = Type.OVER_ACCEPTANCE if over else Type.UNDER_ACCEPTANCE
    direction = "actual minus intended" if over else "intended minus actual"
    return Residual(
        kind,
        Phase.FOUND if residual else Phase.EMPTY,
        residual,
        checked,
        f"computed {direction} over the finite candidate region",
    )


def route(
    constraints: tuple[Constraint, ...],
    solver: Zed,
    *,
    query_id: str,
    scope: Scope | None = None,
) -> Residual:
    if not constraints:
        raise ValueError("bounded path query requires at least one guard/constraint")
    formula = constraints[0] if len(constraints) == 1 else Every(constraints)
    result = solver.solve(Query(query_id, formula, scope=scope))
    status = {
        Verdict.SAT: Phase.FOUND,
        Verdict.UNSAT_BOUNDED: Phase.EMPTY,
        Verdict.UNKNOWN: Phase.UNKNOWN,
    }[result.status]
    return Residual(
        Type.PATH_GUARD,
        status,
        (result.model,) if result.status is Verdict.SAT else (),
        Area(query_id, ()),
        "conjunction of the supplied bounded path guards",
        result,
    )


def _key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
