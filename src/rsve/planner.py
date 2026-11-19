"""Bounded hybrid objective planning over the platform-neutral transition model."""

from __future__ import annotations

import heapq
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .adapters import TargetAdapter
from .differential import DifferentialAnalyzer
from .model import Authorization, Operation, State, TraceEvent, TransitionModel
from .objectives import ObjectiveDefinition
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


@dataclass(frozen=True)
class BackwardPlan:
    objective_id: str
    required_actions: tuple[tuple[str, Mapping[str, Any]], ...]
    method: str
    complete: bool
    uncertainty: tuple[str, ...] = ()


@dataclass(frozen=True)
class CandidateAttempt:
    interactions: tuple[Mapping[str, Any], ...]
    predicted_events: tuple[TraceEvent, ...]
    replayed: bool
    objective_observed: bool | None
    observed_events: tuple[TraceEvent, ...] = ()
    replay_stable: bool | None = None
    divergences: tuple[Divergence, ...] = ()
    detail: str = ""


class BackwardRegressor:
    """Derive bounded preimages for supported concrete operations.

    This deliberately reports bounded preimage enumeration as incomplete for
    opaque or information-losing operations; it never constructs an inverse.
    """

    def regress(self, model: TransitionModel, objective: ObjectiveDefinition) -> BackwardPlan:
        actions: list[tuple[str, Mapping[str, Any]]] = []
        uncertainty: list[str] = []
        for operation in model.ordered_operations():
            for request in model.ordered_inputs():
                if self.weakest_precondition(operation, request, objective)(model.initial_state):
                    actions.append((operation.entry_point.name, dict(request)))
        if not actions:
            uncertainty.append("no one-step preimage was found; longer paths use forward bounded exploration")
        if any(operation.transforms and any(transform.information_loss.value != "none" for transform in operation.transforms) for operation in model.operations):
            uncertainty.append("information-losing transforms require bounded forward/preimage search")
        return BackwardPlan(
            objective_id=objective.objective_id,
            required_actions=tuple(actions),
            method="bounded_preimage_enumeration",
            complete=False,
            uncertainty=tuple(uncertainty),
        )

    def weakest_precondition(
        self,
        operation: Operation,
        request: Mapping[str, Any],
        objective: ObjectiveDefinition,
    ) -> Callable[[State], bool]:
        """Return the exact concrete preimage predicate for a modeled relation.

        The returned predicate is exact only for the supplied modeled operation
        and request. It is intentionally a concrete relational preimage, not a
        claimed inverse for the underlying runtime transform.
        """
        def precondition(state: State) -> bool:
            result = operation.execute(state, request)
            if result is None:
                return False
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
                guard_result=True,
            )
            return objective.evaluate(next_state, (event,))
        return precondition


class HybridPlanner:
    """Use backward action hints, then deterministic forward concretization."""

    def __init__(self, *, harness_sinks: set[str] | frozenset[str] = frozenset()) -> None:
        self.harness_sinks = frozenset(harness_sinks)

    def plan(
        self,
        model: TransitionModel,
        objective: ObjectiveDefinition,
        authorization: Authorization,
        *,
        adapter: TargetAdapter | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> AnalysisReport:
        adapter_environment = self._environment(adapter)
        execution_profile = self._execution_profile(adapter)
        objective.validate(
            authorization,
            harness_sinks=self.harness_sinks,
            environment=environment or adapter_environment,
            execution_profile=execution_profile,
        )
        backward = BackwardRegressor().regress(model, objective)
        preferred = {(entry, self._request_key(request)) for entry, request in backward.required_actions}
        started = time.monotonic()
        budget = objective.budget
        queue: list[tuple[int, int, int, State, tuple[TraceEvent, ...]]] = []
        serial = 0
        heapq.heappush(queue, (0, serial, 0, model.initial_state, ()))
        visited: set[tuple[int, str, tuple[tuple[str, str], ...]]] = set()
        explored_states = 0
        explored_events = 0
        attempts: list[CandidateAttempt] = []
        budget_hit = False

        while queue:
            if (time.monotonic() - started) * 1000 > budget.max_time_ms:
                budget_hit = True
                break
            _, _, depth, state, trace = heapq.heappop(queue)
            key = (depth, json.dumps(state.canonical(), sort_keys=True), tuple((event.entry_point, repr(event.request)) for event in trace))
            if key in visited:
                continue
            visited.add(key)
            explored_states += 1

            if objective.evaluate(state, trace) and objective.checkpoints_satisfied(model.initial_state, trace):
                attempt = self._replay_candidate(adapter, objective, model, trace, environment or adapter_environment)
                attempts.append(attempt)
                if attempt.replayed and attempt.objective_observed and self._stable(attempt, objective):
                    return self._report(
                        AnalysisStatus.VALIDATED_WITNESS,
                        model,
                        objective,
                        trace,
                        attempt,
                        explored_states,
                        explored_events,
                        backward,
                        environment or adapter_environment,
                    )
                if not attempt.replayed:
                    return self._report(
                        AnalysisStatus.SAT_CANDIDATE,
                        model,
                        objective,
                        trace,
                        attempt,
                        explored_states,
                        explored_events,
                        backward,
                        environment or adapter_environment,
                    )
                if attempt.divergences and attempt.objective_observed is not True:
                    return self._report(
                        AnalysisStatus.MODEL_DIVERGENCE,
                        model,
                        objective,
                        trace,
                        attempt,
                        explored_states,
                        explored_events,
                        backward,
                        environment or adapter_environment,
                    )

            if depth >= budget.max_trace_length:
                continue
            for operation in model.ordered_operations():
                for request in model.ordered_inputs():
                    if explored_events >= budget.max_events:
                        budget_hit = True
                        break
                    if not model.allows(operation.entry_point.name, request):
                        continue
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
                        guard_result=True,
                        ordering=len(trace),
                    )
                    if explored_states + len(queue) >= budget.max_states:
                        budget_hit = True
                        continue
                    next_trace = trace + (event,)
                    preference = 0 if (operation.entry_point.name, self._request_key(request)) in preferred else depth + 1
                    serial += 1
                    heapq.heappush(queue, (preference, serial, depth + 1, next_state, next_trace))
                if budget_hit:
                    break
            if budget_hit:
                break

        status = AnalysisStatus.BUDGET_EXHAUSTED if budget_hit else (AnalysisStatus.UNKNOWN if attempts else AnalysisStatus.UNSAT_BOUNDED)
        gaps = [ResidualGap(
            GapKind.EVENT_BUDGET if budget_hit else (GapKind.ASSUMPTION if attempts else GapKind.BOUND),
            "bounded hybrid search exhausted its event/time/state budget" if budget_hit else ("candidate replay did not satisfy the objective or stability policy" if attempts else "no witness exists in the encoded bounded model/surface"),
            {"max_trace_length": budget.max_trace_length, "attempts": len(attempts)},
        )]
        return self._report(
            status,
            model,
            objective,
            (),
            attempts[-1] if attempts else CandidateAttempt((), (), False, None),
            explored_states,
            explored_events,
            backward,
            environment or adapter_environment,
            gaps=gaps,
        )

    def analyze(self, *args: Any, **kwargs: Any) -> AnalysisReport:
        """Compatibility spelling for callers that use the engine's analyze API."""
        return self.plan(*args, **kwargs)

    def _replay_candidate(
        self,
        adapter: TargetAdapter | None,
        objective: ObjectiveDefinition,
        model: TransitionModel,
        predicted: Sequence[TraceEvent],
        environment: Mapping[str, str],
    ) -> CandidateAttempt:
        interactions = tuple({"entry_point": event.entry_point, "request": dict(event.request)} for event in predicted)
        if adapter is None:
            return CandidateAttempt(interactions, tuple(predicted), False, None, detail="candidate was not replayed by a target adapter")
        adapter.prepare()
        baseline = adapter.snapshot()
        all_runs: list[tuple[TraceEvent, ...]] = []
        outcomes: list[bool] = []
        signatures: list[str] = []
        first_divergences: tuple[Divergence, ...] = ()
        try:
            for _ in range(objective.budget.replay_runs):
                adapter.reset(baseline)
                observed = tuple(adapter.execute_trace(interactions))
                all_runs.append(observed)
                final_state = observed[-1].after if observed else model.initial_state
                outcomes.append(objective.evaluate(final_state, observed) and objective.checkpoints_satisfied(model.initial_state, observed))
                signatures.append(hashlib.sha256(json.dumps({
                    "events": [self._semantic_event(event) for event in observed],
                    "output": self._semantic_output(getattr(adapter, "collect_output", lambda: {})()),
                }, sort_keys=True, default=str).encode()).hexdigest())
                if not first_divergences:
                    first_divergences = DifferentialAnalyzer().compare(predicted, observed)
        finally:
            adapter.teardown()
        stable = len(set(outcomes)) == 1 and len(set(signatures)) == 1 and bool(outcomes)
        detail = "replay objective did not hold" if not all(outcomes) else ("replay was unstable" if not stable else "")
        return CandidateAttempt(
            interactions,
            tuple(predicted),
            True,
            all(outcomes) if outcomes else False,
            all_runs[0] if all_runs else (),
            stable,
            first_divergences,
            detail,
        )

    def _report(
        self,
        status: AnalysisStatus,
        model: TransitionModel,
        objective: ObjectiveDefinition,
        predicted: Sequence[TraceEvent],
        attempt: CandidateAttempt,
        explored_states: int,
        explored_events: int,
        backward: BackwardPlan,
        environment: Mapping[str, str],
        *,
        gaps: Sequence[ResidualGap] = (),
    ) -> AnalysisReport:
        witness = None
        witness_events = attempt.observed_events if status is AnalysisStatus.VALIDATED_WITNESS and attempt.observed_events else tuple(predicted)
        if witness_events or attempt.interactions:
            final_state = witness_events[-1].after if witness_events else model.initial_state
            witness = Witness(
                objective=objective.objective_id,
                target_id=model.target_id,
                events=witness_events,
                final_state=final_state,
                validated=status is AnalysisStatus.VALIDATED_WITNESS,
                predicted_events=tuple(predicted),
                interactions=attempt.interactions,
                input_refs=tuple(ref for event in witness_events for ref in event.evidence_refs),
                state_checkpoints=tuple(event.after.canonical() for event in witness_events),
                environment=dict(environment),
                replay_result={"replayed": attempt.replayed, "objective_observed": attempt.objective_observed, "detail": attempt.detail},
                fidelity_scope={"mode": "concrete+instrumented", "model": "bounded", "backward": backward.method},
            )
        divergences = attempt.divergences
        proof_status = (
            SolverStatus.SAT
            if witness and status in {AnalysisStatus.VALIDATED_WITNESS, AnalysisStatus.SAT_CANDIDATE, AnalysisStatus.MODEL_DIVERGENCE}
            else SolverStatus.UNKNOWN
            if status in {AnalysisStatus.BUDGET_EXHAUSTED, AnalysisStatus.UNKNOWN, AnalysisStatus.MODEL_DIVERGENCE}
            else SolverStatus.UNSAT_BOUNDED
        )
        proof = ProofResult(
            status=proof_status,
            bound=objective.budget.max_trace_length,
            explored_states=explored_states,
            explored_events=explored_events,
            scope=objective.authorization_scope,
            query=json.dumps(objective.to_record(), sort_keys=True, default=str),
            assumptions=objective.assumptions + backward.uncertainty,
            backend="bounded-hybrid-planner",
            options={"max_time_ms": objective.budget.max_time_ms, "max_events": objective.budget.max_events},
            fidelity_limitations=("bounded surface and trace length", "runtime replay depends on adapter capabilities"),
            execution_profile_id=environment.get("execution_profile_id", "unknown"),
        )
        report_gaps = list(gaps)
        if attempt.detail:
            report_gaps.append(ResidualGap(GapKind.ASSUMPTION, attempt.detail, {"interactions": attempt.interactions}))
        return AnalysisReport(
            status=status,
            target_id=model.target_id,
            objective=objective.objective_id,
            witness=witness,
            proof=proof,
            gaps=tuple(report_gaps),
            explored_states=explored_states,
            explored_events=explored_events,
            model_version=model.model_version,
            build_hash=model.build_hash,
            divergences=divergences,
            objective_version=objective.version,
            surface_scope=tuple(sorted({event.entry_point for event in predicted})),
            environment=dict(environment),
            replay_runs=objective.budget.replay_runs if attempt.replayed else 0,
            replay_stable=(attempt.replay_stable if attempt.replayed else None),
            unresolved_uncertainty=backward.uncertainty,
            model_revision=model.model_version,
            execution_profile_id=environment.get("execution_profile_id", "unknown"),
        )

    @staticmethod
    def _request_key(request: Mapping[str, Any]) -> str:
        return json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def _semantic_event(event: TraceEvent) -> dict[str, Any]:
        return {
            "operation": event.operation,
            "entry_point": event.entry_point,
            "request": event.request,
            "before": event.before.canonical(),
            "after": event.after.canonical(),
            "observation": event.observation,
            "guard_result": event.guard_result,
        }

    @staticmethod
    def _semantic_output(output: Mapping[str, Any]) -> Any:
        if isinstance(output, Mapping) and "outcome" in output:
            return output["outcome"]
        return output

    @staticmethod
    def _environment(adapter: TargetAdapter | None) -> Mapping[str, str]:
        observation = getattr(adapter, "environment_observation", None)
        if observation is None:
            return {}
        result = observation()
        facts = dict(getattr(result, "facts", result))
        profile_factory = getattr(adapter, "execution_profile", None)
        if callable(profile_factory):
            facts["execution_profile_id"] = profile_factory().profile_id
        return facts

    @staticmethod
    def _execution_profile(adapter: TargetAdapter | None) -> Any | None:
        profile_factory = getattr(adapter, "execution_profile", None)
        return profile_factory() if callable(profile_factory) else None

    @staticmethod
    def _stable(attempt: CandidateAttempt, objective: ObjectiveDefinition) -> bool:
        return attempt.replayed and attempt.objective_observed is True and attempt.replay_stable is True and objective.budget.replay_runs >= 1
