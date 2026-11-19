"""Bounded residual queries and candidate-region accounting."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable

from .logic import AllOf, Constraint
from .ir import ResultScope
from .result import SolverStatus
from .solver import ConstraintQuery, SolverResult, Z3SolverAdapter


class ResidualKind(str, Enum):
    TRANSFORM_DOMAIN = "transform_domain_mismatch"
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


class ResidualStatus(str, Enum):
    FOUND = "FOUND"
    EMPTY = "EMPTY"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CandidateRegion:
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

    def mark_explored(self, values: Iterable[Any]) -> "CandidateRegion":
        known = self.explored | {_key(value) for value in values}
        return CandidateRegion(self.region_id, self.candidates, frozenset(known))


@dataclass(frozen=True)
class ResidualResult:
    kind: ResidualKind
    status: ResidualStatus
    residual: tuple[Any, ...]
    region: CandidateRegion
    detail: str
    solver_result: SolverResult | None = None
    transition: str | None = None
    expected: Any = None
    observed: Any = None
    evidence: tuple[str, ...] = ()
    fidelity: str = "unknown"
    uncertainty: tuple[str, ...] = ()


def mismatch(
    kind: ResidualKind,
    region: CandidateRegion,
    detail: str,
    *,
    transition: str | None = None,
    expected: Any = None,
    observed: Any = None,
    evidence: Iterable[str] = (),
    fidelity: str = "unknown",
    uncertainty: Iterable[str] = (),
) -> ResidualResult:
    """Record a transition-space residual without implying exploitability."""
    return ResidualResult(
        kind=kind,
        status=ResidualStatus.FOUND,
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


def transform_domain_residual(
    transform: Callable[[Any], Any] | None,
    source: CandidateRegion,
    downstream_domain: Iterable[Any],
) -> ResidualResult:
    if transform is None:
        return ResidualResult(
            ResidualKind.TRANSFORM_DOMAIN,
            ResidualStatus.UNKNOWN,
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
    region = source.mark_explored(source.pending)
    return ResidualResult(
        ResidualKind.TRANSFORM_DOMAIN,
        ResidualStatus.FOUND if residual else ResidualStatus.EMPTY,
        residual,
        region,
        "computed Image(T) minus the declared downstream domain over the finite source region",
    )


def acceptance_residual(
    actual: Callable[[Any], bool],
    intended: Callable[[Any], bool],
    region: CandidateRegion,
    *,
    over: bool,
) -> ResidualResult:
    residual = tuple(
        candidate
        for candidate in region.pending
        if ((actual(candidate) and not intended(candidate)) if over else (intended(candidate) and not actual(candidate)))
    )
    checked = region.mark_explored(region.pending)
    kind = ResidualKind.OVER_ACCEPTANCE if over else ResidualKind.UNDER_ACCEPTANCE
    direction = "actual minus intended" if over else "intended minus actual"
    return ResidualResult(
        kind,
        ResidualStatus.FOUND if residual else ResidualStatus.EMPTY,
        residual,
        checked,
        f"computed {direction} over the finite candidate region",
    )


def bounded_path_residual(
    constraints: tuple[Constraint, ...],
    solver: Z3SolverAdapter,
    *,
    query_id: str,
    scope: ResultScope | None = None,
) -> ResidualResult:
    if not constraints:
        raise ValueError("bounded path query requires at least one guard/constraint")
    formula = constraints[0] if len(constraints) == 1 else AllOf(constraints)
    result = solver.solve(ConstraintQuery(query_id, formula, scope=scope))
    status = {
        SolverStatus.SAT: ResidualStatus.FOUND,
        SolverStatus.UNSAT_BOUNDED: ResidualStatus.EMPTY,
        SolverStatus.UNKNOWN: ResidualStatus.UNKNOWN,
    }[result.status]
    return ResidualResult(
        ResidualKind.PATH_GUARD,
        status,
        (result.model,) if result.status is SolverStatus.SAT else (),
        CandidateRegion(query_id, ()),
        "conjunction of the supplied bounded path guards",
        result,
    )


def _key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
