"""Deterministic bounded planner and model/reality comparison."""

from __future__ import annotations

from collections import deque
from dataclasses import replace
from typing import Iterable

from .model import Authorization, Budget, Objective, State, TraceEvent, TransitionModel
from .results import (
    AnalysisReport,
    AnalysisStatus,
    Divergence,
    GapKind,
    ProofResult,
    ResidualGap,
    SolverStatus,
    Witness,
)


class AuthorizationError(PermissionError):
    """Raised when an objective is outside the caller's explicit lab scope."""


class Engine:
    """Explore a transition model in a stable breadth-first order.

    Input constraints are used as a small solver boundary in this first slice:
    candidate requests are enumerated in canonical order and rejected before a
    transition executes. A future SMT adapter can replace candidate selection
    without changing witnesses or reports.
    """

    def analyze(
        self,
        model: TransitionModel,
        objective: Objective,
        authorization: Authorization,
        budget: Budget = Budget(),
    ) -> AnalysisReport:
        if not authorization.permits(model.target_id, objective.scope):
            raise AuthorizationError(
                f"subject {authorization.subject!r} is not authorized for "
                f"{model.target_id!r} in scope {objective.scope!r}"
            )

        queue: deque[tuple[int, State, tuple[TraceEvent, ...]]] = deque(
            [(0, model.initial_state, ())]
        )
        visited: set[tuple[int, str, tuple[tuple[str, str], ...]]] = set()
        operations = model.ordered_operations()
        inputs = model.ordered_inputs()
        explored_states = 0
        explored_events = 0
        state_budget_hit = False
        event_budget_hit = False

        def objective_reached(state: State, trace: tuple[TraceEvent, ...]) -> bool:
            if not objective.postcondition(state, trace):
                return False
            if not objective.effect_lemmas:
                return True
            checkpoints = [(model.initial_state, ())]
            checkpoints.extend((event.after, trace[:index]) for index, event in enumerate(trace, 1))
            return all(
                any(lemma.predicate(checkpoint_state, checkpoint_trace) for checkpoint_state, checkpoint_trace in checkpoints)
                for lemma in objective.effect_lemmas
            )

        while queue:
            depth, state, trace = queue.popleft()
            trace_key = tuple((event.operation, repr(event.request)) for event in trace)
            visit_key = (depth, repr(state.canonical()), trace_key)
            if visit_key in visited:
                continue
            visited.add(visit_key)
            explored_states += 1

            if objective_reached(state, trace):
                witness = Witness(
                    objective=objective.name,
                    target_id=model.target_id,
                    events=trace,
                    final_state=state,
                    validated=False,
                )
                proof = ProofResult(
                    status=SolverStatus.SAT,
                    bound=budget.max_depth,
                    explored_states=explored_states,
                    explored_events=explored_events,
                    scope=objective.scope,
                    query=objective.description or objective.name,
                    assumptions=model.assumptions,
                )
                return AnalysisReport(
                    status=AnalysisStatus.MODEL_SAT,
                    target_id=model.target_id,
                    objective=objective.name,
                    witness=witness,
                    proof=proof,
                    explored_states=explored_states,
                    explored_events=explored_events,
                    model_version=model.model_version,
                    build_hash=model.build_hash,
                )

            if depth >= budget.max_depth:
                continue

            for operation in operations:
                for request in inputs:
                    if not objective.accepts_request(request):
                        continue
                    if not model.allows(operation.entry_point.name, request):
                        continue
                    if explored_events >= budget.max_events:
                        event_budget_hit = True
                        break
                    explored_events += 1
                    result = operation.execute(state, request)
                    if result is None:
                        continue
                    next_state, observation = result
                    event = TraceEvent(
                        operation=operation.name,
                        entry_point=operation.entry_point.name,
                        request=dict(request),
                        before=state,
                        after=next_state,
                        observation=dict(observation),
                        fidelity=operation.fidelity,
                        mode=operation.mode,
                        component=operation.component,
                    )
                    if explored_states + len(queue) >= budget.max_states:
                        state_budget_hit = True
                        continue
                    queue.append((depth + 1, next_state, trace + (event,)))
                if event_budget_hit:
                    break
            if event_budget_hit:
                break

        if event_budget_hit or state_budget_hit:
            status = AnalysisStatus.BUDGET_EXHAUSTED
            solver_status = SolverStatus.UNKNOWN
            gaps = []
            if event_budget_hit:
                gaps.append(ResidualGap(GapKind.EVENT_BUDGET, "event exploration budget was exhausted"))
            if state_budget_hit:
                gaps.append(ResidualGap(GapKind.STATE_BUDGET, "state exploration budget was exhausted"))
        else:
            status = AnalysisStatus.UNSAT_BOUNDED
            solver_status = SolverStatus.UNSAT_BOUNDED
            gaps = [ResidualGap(
                GapKind.BOUND,
                "absence of a witness is proved only through the declared depth bound",
                {"max_depth": budget.max_depth},
            )]

        proof = ProofResult(
            status=solver_status,
            bound=budget.max_depth,
            explored_states=explored_states,
            explored_events=explored_events,
            scope=objective.scope,
            query=objective.description or objective.name,
            assumptions=model.assumptions,
        )
        return AnalysisReport(
            status=status,
            target_id=model.target_id,
            objective=objective.name,
            witness=None,
            proof=proof,
            gaps=tuple(gaps),
            explored_states=explored_states,
            explored_events=explored_events,
            model_version=model.model_version,
            build_hash=model.build_hash,
        )

    @staticmethod
    def compare_trace(
        expected: Iterable[TraceEvent], observed: Iterable[TraceEvent]
    ) -> tuple[Divergence, ...]:
        """Return the first model/reality mismatch, preserving later evidence."""
        expected_events = tuple(expected)
        observed_events = tuple(observed)
        divergences: list[Divergence] = []
        for index, (model_event, actual_event) in enumerate(zip(expected_events, observed_events)):
            if model_event.operation != actual_event.operation or model_event.entry_point != actual_event.entry_point:
                divergences.append(Divergence(
                    index=index,
                    kind="entry_point",
                    expected=(model_event.operation, model_event.entry_point),
                    observed=(actual_event.operation, actual_event.entry_point),
                    detail="the first executed operation differs from the model",
                ))
                break
            if model_event.request != actual_event.request:
                divergences.append(Divergence(
                    index=index,
                    kind="request",
                    expected=model_event.request,
                    observed=actual_event.request,
                    detail="the request differs from the synthesized witness",
                ))
                break
            if model_event.observation != actual_event.observation or model_event.after != actual_event.after:
                divergences.append(Divergence(
                    index=index,
                    kind="state_or_observation",
                    expected={"after": model_event.after.canonical(), "observation": model_event.observation},
                    observed={"after": actual_event.after.canonical(), "observation": actual_event.observation},
                    detail="runtime evidence differs after a matching operation",
                ))
                break
        if not divergences and len(expected_events) != len(observed_events):
            index = min(len(expected_events), len(observed_events))
            divergences.append(Divergence(
                index=index,
                kind="length",
                expected="end of trace" if index >= len(expected_events) else expected_events[index].canonical(),
                observed="end of trace" if index >= len(observed_events) else observed_events[index].canonical(),
                detail="model and runtime traces have different lengths",
            ))
        return tuple(divergences)

    def reconcile(self, report: AnalysisReport, observed: Iterable[TraceEvent]) -> AnalysisReport:
        if report.witness is None:
            return report
        divergences = self.compare_trace(report.witness.events, observed)
        if not divergences:
            return report
        return replace(
            report,
            status=AnalysisStatus.MODEL_DIVERGENCE,
            divergences=divergences,
            gaps=report.gaps + (ResidualGap(
                GapKind.ASSUMPTION,
                "observed runtime behavior diverges from the modeled witness",
                {"first_index": divergences[0].index},
            ),),
        )
