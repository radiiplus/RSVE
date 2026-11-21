"""Bounded, core-directed counterfactual search over named constraints."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from collections import Counter
from itertools import islice
from typing import Any, Callable, Mapping, Sequence

from .logic import Axiom, Constraint, Every, Literal, Sort
from .model import Authorization, Decision, Fidelity
from .objective import Objective
from .result import Verdict
from .solver import Answer, Query, Zed
from .workspace import Frame, Workspace


class AlternativeStatus(str, Enum):
    COUNTERFACTUAL = "COUNTERFACTUAL"
    MODEL_CONFIRMED = "MODEL_CONFIRMED"


@dataclass(frozen=True)
class Alternative:
    """One single-assumption relaxation and its evidence classification."""

    relaxed: str
    answer: Answer
    status: AlternativeStatus = AlternativeStatus.COUNTERFACTUAL
    trace: tuple[Mapping[str, Any], ...] = ()
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelaxationReport:
    baseline: Answer
    core: tuple[str, ...]
    alternatives: tuple[Alternative, ...]
    complete: bool
    limitations: tuple[str, ...] = ()


def _top_level_axioms(formula: Constraint) -> tuple[tuple[str, Constraint], ...]:
    terms = formula.terms if isinstance(formula, Every) else (formula,)
    return tuple((term.name, term.term) for term in terms if isinstance(term, Axiom))


def _without_axiom(formula: Constraint, name: str) -> Constraint:
    if isinstance(formula, Axiom) and formula.name == name:
        return Literal(True, Sort.BOOL)
    if not isinstance(formula, Every):
        return formula
    terms = tuple(
        term for term in formula.terms
        if not (isinstance(term, Axiom) and term.name == name)
    )
    if not terms:
        return Literal(True, Sort.BOOL)
    return terms[0] if len(terms) == 1 else Every(terms)


def _run_trace(
    workspace: Workspace,
    objective: Objective,
    trace: Sequence[Mapping[str, Any]],
    *,
    max_states: int,
) -> tuple[bool, tuple[str, ...]]:
    initial_frame = workspace.start()
    frontier: list[tuple[Frame, tuple[Any, ...], bool]] = [
        (initial_frame, (), not initial_frame.uncertain)
    ]
    for interaction in trace:
        entry = str(interaction["entry_point"])
        request = dict(interaction.get("request", {}))
        operations = workspace.operations(entry)
        if not operations or not workspace.model.allows(entry, request):
            return False, (f"no modeled operation accepts the route entry {entry!r}",)
        successors: list[tuple[Frame, tuple[Any, ...], bool]] = []
        for frame, events, certain in frontier:
            for operation in operations:
                for move in workspace.moves(frame, entry, request, operation=operation):
                    if len(successors) >= max_states:
                        return False, ("workspace route branch bound reached",)
                    event_certain = (
                        not move.event.uncertainty
                        and not move.event.correlation_uncertain
                        and move.outcome.decision is not Decision.UNKNOWN
                        and move.event.fidelity is not Fidelity.ASSUMED
                        and move.outcome.fidelity is not Fidelity.ASSUMED
                    )
                    successors.append((
                        move.after,
                        events + (move.event,),
                        certain and not move.after.uncertain and event_certain,
                    ))
        frontier = successors
        if not frontier:
            return False, (f"route has no modeled successor at {entry!r}",)
    initial = initial_frame.view()
    for frame, events, certain in frontier:
        if not certain or frame.uncertain:
            continue
        if objective.evaluate(frame.view(), events) and objective.satisfy(initial, events):
            return True, ()
    return False, ("workspace execution did not reach the objective on a certain branch",)


def _binding_errors(
    model: Mapping[str, Any],
    trace: Sequence[Mapping[str, Any]],
    bindings: Mapping[str, Sequence[tuple[int, str]]] | None,
) -> tuple[str, ...]:
    if not bindings:
        return ("no declarative model-to-request bindings were supplied",)
    errors: list[str] = []
    missing = set(model) - set(bindings)
    extra = set(bindings) - set(model)
    if missing:
        errors.append("model variables without request bindings: " + ", ".join(sorted(missing)))
    if extra:
        errors.append("bindings for variables absent from the solver model: " + ", ".join(sorted(extra)))
    for variable, locations in bindings.items():
        if variable not in model:
            continue
        if not locations:
            errors.append(f"model variable {variable!r} has no request locations")
            continue
        for step, field in locations:
            if step < 0 or step >= len(trace) or not field:
                errors.append(f"invalid request binding for model variable {variable!r}")
                continue
            request = trace[step].get("request", {})
            if not isinstance(request, Mapping) or field not in request:
                errors.append(f"request field {step}.{field} is absent for model variable {variable!r}")
            elif request[field] != model[variable]:
                errors.append(f"request field {step}.{field} does not match model variable {variable!r}")
    return tuple(errors)


class RelaxationAnalyzer:
    """Explore core-directed alternatives without promoting relaxation to reachability."""

    def __init__(self, solver: Any | None = None) -> None:
        self.solver = solver or Zed()

    def explore(
        self,
        query: Query,
        *,
        baseline: Answer | None = None,
        max_relaxations: int = 8,
        trace_builder: Callable[[Mapping[str, Any]], Sequence[Mapping[str, Any]]] | None = None,
        model_bindings: Mapping[str, Sequence[tuple[int, str]]] | None = None,
        workspace: Workspace | None = None,
        objective: Objective | None = None,
        authorization: Authorization | None = None,
        harness_sinks: set[str] | frozenset[str] = frozenset(),
    ) -> RelaxationReport:
        if max_relaxations <= 0:
            raise ValueError("max_relaxations must be positive")
        if (workspace is None) != (objective is None):
            raise ValueError("workspace and objective must be provided together")
        if objective is not None and workspace is not None and objective.target_id != workspace.model.target_id:
            raise ValueError("workspace and objective target identities must match")
        if workspace is not None and objective is not None:
            if authorization is None:
                raise ValueError("workspace confirmation requires explicit objective authorization")
            objective.validate(
                authorization,
                harness_sinks=harness_sinks,
                environment=workspace.start().environment.as_dict(),
            )

        axiom_names = tuple(name for name, _ in _top_level_axioms(query.formula))
        identifiers = axiom_names + tuple(query.assumptions)
        duplicates = tuple(name for name, count in Counter(identifiers).items() if count > 1)
        if duplicates:
            raise ValueError("duplicate top-level relaxation identifiers: " + ", ".join(sorted(duplicates)))

        supplied_baseline = baseline
        baseline = self.solver.solve(query, timeout_ms=query.limits.timeout_ms)
        baseline_notes = ()
        if supplied_baseline is not None and (
            supplied_baseline.query_id != baseline.query_id
            or supplied_baseline.status is not baseline.status
            or supplied_baseline.unsat_core != baseline.unsat_core
        ):
            baseline_notes = ("caller-supplied baseline was ignored because baseline/core provenance is not trusted",)
        if baseline.status is not Verdict.UNSAT_BOUNDED:
            return RelaxationReport(
                baseline,
                baseline.unsat_core,
                (),
                True,
                ("relaxation requires an UNSAT_BOUNDED baseline query",) + baseline_notes,
            )

        axioms = dict(_top_level_axioms(query.formula))
        eligible = tuple(
            name for name in baseline.unsat_core
            if name in axioms or name in query.assumptions
        )
        selected = eligible[:max_relaxations]
        limitations: list[str] = list(baseline_notes)
        alternatives: list[Alternative] = []
        for name in selected:
            formula = _without_axiom(query.formula, name) if name in axioms else query.formula
            assumptions = tuple(item for item in query.assumptions if item != name)
            relaxed_query = replace(
                query,
                query_id=f"{query.query_id}:relax:{name}",
                formula=formula,
                assumptions=assumptions,
            )
            answer = self.solver.solve(relaxed_query, timeout_ms=relaxed_query.limits.timeout_ms)
            alternative = Alternative(name, answer)
            if answer.status is Verdict.SAT and trace_builder is not None and workspace is not None and objective is not None:
                try:
                    trace_limit = objective.budget.max_trace_length
                    trace = tuple(
                        dict(item)
                        for item in islice(iter(trace_builder(answer.model)), trace_limit + 1)
                    )
                    if len(trace) > trace_limit:
                        alternatives.append(replace(
                            alternative,
                            evidence=(f"trace construction exceeded max_trace_length {trace_limit}",),
                        ))
                        continue
                    binding_errors = _binding_errors(answer.model, trace, model_bindings)
                    confirmed, evidence = _run_trace(
                        workspace,
                        objective,
                        trace,
                        max_states=objective.budget.max_states,
                    )
                    if confirmed and not binding_errors:
                        alternative = replace(
                            alternative,
                            status=AlternativeStatus.MODEL_CONFIRMED,
                            trace=trace,
                            evidence=("all solver model variables matched declared request fields; a certain Workspace route satisfied the objective",),
                        )
                    else:
                        alternative = replace(
                            alternative,
                            trace=trace,
                            evidence=tuple(binding_errors) + evidence,
                        )
                except Exception as exc:
                    alternative = replace(
                        alternative,
                        evidence=(f"trace construction or workspace verification failed: {type(exc).__name__}",),
                    )
            alternatives.append(alternative)

        if not eligible:
            limitations.append("UNSAT core contained no safely relaxable top-level named constraint")
        unhandled = tuple(name for name in baseline.unsat_core if name not in eligible)
        if unhandled:
            limitations.append(
                "some core entries are not top-level named constraints or query assumptions: "
                + ", ".join(unhandled)
            )
        if len(eligible) > len(selected):
            limitations.append("relaxation enumeration was truncated by max_relaxations")
        if any(item.answer.status is Verdict.SAT and item.status is AlternativeStatus.COUNTERFACTUAL for item in alternatives):
            limitations.append("SAT after relaxation is counterfactual without a confirmed workspace route")
        complete = len(eligible) <= len(selected) and not unhandled
        return RelaxationReport(
            baseline,
            tuple(baseline.unsat_core),
            tuple(alternatives),
            complete,
            tuple(limitations),
        )
