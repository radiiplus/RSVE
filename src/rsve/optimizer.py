"""Optional bounded optimization over already-supported realizations."""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from statistics import mean
from typing import Any, Mapping, Sequence

from .adapters import TargetAdapter
from .model import Authorization, State, TraceEvent, TransitionModel
from .objectives import ObjectiveDefinition
from .results import Witness
from .planner import BackwardRegressor


class OptimizationStatus(str, Enum):
    OPTIMIZED = "OPTIMIZED"
    UNCHANGED = "UNCHANGED"
    NO_EQUIVALENT = "NO_EQUIVALENT"


@dataclass(frozen=True)
class CostWeights:
    interaction_count: float = 10.0
    trace_length: float = 5.0
    execution_time_ms: float = 0.01
    resource_use: float = 1.0
    dependency_count: float = 2.0
    stability: float = 20.0
    instrumentation_overhead: float = 1.0
    reproducibility: float = 20.0
    unknown_metric_penalty: float = 1.0


@dataclass(frozen=True)
class RealizationCost:
    interaction_count: int
    trace_length: int
    execution_time_ms: float | None
    resource_use: float | None
    dependency_count: int
    stability: float
    instrumentation_overhead: int
    reproducibility: float
    unknown_metrics: tuple[str, ...] = ()

    def score(self, weights: CostWeights = CostWeights()) -> float:
        values = {
            "interaction_count": self.interaction_count,
            "trace_length": self.trace_length,
            "execution_time_ms": self.execution_time_ms,
            "resource_use": self.resource_use,
            "dependency_count": self.dependency_count,
            "stability": 1.0 - self.stability,
            "instrumentation_overhead": self.instrumentation_overhead,
            "reproducibility": 1.0 - self.reproducibility,
        }
        costs = {
            "interaction_count": weights.interaction_count,
            "trace_length": weights.trace_length,
            "execution_time_ms": weights.execution_time_ms,
            "resource_use": weights.resource_use,
            "dependency_count": weights.dependency_count,
            "stability": weights.stability,
            "instrumentation_overhead": weights.instrumentation_overhead,
            "reproducibility": weights.reproducibility,
        }
        return sum(
            costs[key] * (weights.unknown_metric_penalty if value is None else value)
            for key, value in values.items()
        )


@dataclass(frozen=True)
class OptimizationResult:
    status: OptimizationStatus
    original: Witness
    selected: Witness
    original_cost: RealizationCost
    selected_cost: RealizationCost
    equivalence_evidence: tuple[str, ...] = ()
    rejected_candidates: tuple[str, ...] = ()

    @property
    def improvement(self) -> float:
        return self.original_cost.score() - self.selected_cost.score()


@dataclass(frozen=True)
class _ReplayCandidate:
    interactions: tuple[Mapping[str, Any], ...]
    events: tuple[TraceEvent, ...]
    cost: RealizationCost
    outcome: Mapping[str, Any]
    signatures: tuple[str, ...]


class RealizationOptimizer:
    """Compare finite caller-supplied realizations after clean replay.

    The optimizer does not invent commands or alter objectives. Candidates must
    already be supported by the model/adapter boundary supplied by the caller.
    """

    def optimize(
        self,
        original: Witness,
        alternatives: Sequence[Sequence[Mapping[str, Any]]],
        objective: ObjectiveDefinition,
        authorization: Authorization,
        *,
        adapter: TargetAdapter,
        weights: CostWeights = CostWeights(),
        replay_runs: int | None = None,
    ) -> OptimizationResult:
        if not original.validated:
            raise ValueError("realization optimization requires a validated original witness")
        if not authorization.permits(original.target_id, objective.authorization_scope):
            raise PermissionError("authorization does not permit realization optimization")
        objective.validate(
            authorization,
            environment=dict(getattr(adapter.environment_observation(), "facts", {})),
            execution_profile=getattr(adapter, "analysis_profile", lambda: None)(),
        )
        runs = replay_runs or objective.budget.replay_runs
        if runs <= 0:
            raise ValueError("replay_runs must be positive")
        adapter.prepare()
        baseline = adapter.snapshot()
        candidates = [tuple(original.interactions), *(tuple(item) for item in alternatives)]
        replayed: list[_ReplayCandidate] = []
        rejected: list[str] = []
        original_candidate: _ReplayCandidate | None = None
        try:
            for interactions in candidates:
                try:
                    candidate = self._replay(adapter, baseline, interactions, objective, authorization, runs)
                except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
                    rejected.append(f"{self._candidate_id(interactions)}: {exc}")
                    continue
                if candidate is None:
                    rejected.append(f"{self._candidate_id(interactions)}: objective or stability policy failed")
                    continue
                replayed.append(candidate)
                if interactions == tuple(original.interactions) and original_candidate is None:
                    original_candidate = candidate
        finally:
            adapter.teardown()
        if not replayed or original_candidate is None:
            raise ValueError("no equivalent authorized realization replayed successfully")
        selected = min(replayed, key=lambda item: item.cost.score(weights))
        selected_witness = self._witness(original, selected, objective)
        original_witness = self._witness(original, original_candidate, objective)
        selected_is_different = selected.interactions != original_candidate.interactions
        status = OptimizationStatus.OPTIMIZED if selected_is_different and selected.cost.score(weights) < original_candidate.cost.score(weights) else OptimizationStatus.UNCHANGED
        return OptimizationResult(
            status=status,
            original=original_witness,
            selected=selected_witness,
            original_cost=original_candidate.cost,
            selected_cost=selected.cost,
            equivalence_evidence=(
                "both original and selected realizations replayed from the same clean snapshot",
                "both realizations satisfied every objective postcondition and checkpoint",
                "both realizations satisfied the replay stability policy",
            ),
            rejected_candidates=tuple(rejected),
        )

    def synthesize_alternatives(
        self,
        model: TransitionModel,
        objective: ObjectiveDefinition,
        authorization: Authorization,
        *,
        max_candidates: int = 64,
    ) -> tuple[tuple[Mapping[str, Any], ...], ...]:
        """Generate bounded model realizations for later replay comparison."""
        objective.validate(authorization)
        if max_candidates <= 0:
            raise ValueError("max_candidates must be positive")
        backward = BackwardRegressor().regress(
            model,
            objective,
            solver_timeout_ms=objective.budget.solver_timeout_ms,
        )
        inputs = list(model.ordered_inputs())
        known_inputs = {self._key(item) for item in inputs}
        for _entry, request in backward.required_actions:
            if self._key(request) not in known_inputs:
                inputs.append(dict(request))
                known_inputs.add(self._key(request))
        queue: deque[tuple[State, tuple[Mapping[str, Any], ...]]] = deque()
        queue.append((model.initial_state, ()))
        candidates: list[tuple[Mapping[str, Any], ...]] = []
        seen: set[str] = set()
        while queue and len(candidates) < max_candidates and len(seen) < objective.budget.max_states:
            state, interactions = queue.popleft()
            key = self._key(interactions) + ":" + self._key(state.canonical())
            if key in seen:
                continue
            seen.add(key)
            if interactions and objective.evaluate(state, self._events_for(model, interactions)) and objective.checkpoints_satisfied(model.initial_state, self._events_for(model, interactions)):
                candidates.append(interactions)
            if len(interactions) >= objective.budget.max_trace_length:
                continue
            for operation in model.ordered_operations():
                for request in inputs:
                    if not model.allows(operation.entry_point.name, request):
                        continue
                    result = operation.execute(state, request)
                    if result is None:
                        continue
                    next_state, _observation = result
                    queue.append((next_state, interactions + ({"entry_point": operation.entry_point.name, "request": dict(request)},)))
        return tuple(candidates)

    def optimize_synthesized(
        self,
        original: Witness,
        model: TransitionModel,
        objective: ObjectiveDefinition,
        authorization: Authorization,
        *,
        adapter: TargetAdapter,
        weights: CostWeights = CostWeights(),
        replay_runs: int | None = None,
        max_candidates: int = 64,
    ) -> OptimizationResult:
        alternatives = self.synthesize_alternatives(
            model,
            objective,
            authorization,
            max_candidates=max_candidates,
        )
        return self.optimize(
            original,
            alternatives,
            objective,
            authorization,
            adapter=adapter,
            weights=weights,
            replay_runs=replay_runs,
        )

    @staticmethod
    def _events_for(model: TransitionModel, interactions: Sequence[Mapping[str, Any]]) -> tuple[TraceEvent, ...]:
        state = model.initial_state
        operations = {operation.entry_point.name: operation for operation in model.ordered_operations()}
        events: list[TraceEvent] = []
        for interaction in interactions:
            operation = operations.get(str(interaction["entry_point"]))
            request = dict(interaction.get("request", {}))
            if operation is None:
                return ()
            result = operation.execute(state, request)
            if result is None:
                return ()
            after, observation = result
            events.append(TraceEvent(
                operation=operation.name,
                entry_point=operation.entry_point.name,
                request=request,
                before=state,
                after=after,
                observation=dict(observation),
                fidelity=operation.fidelity,
                mode=operation.mode,
                component=operation.component,
                guard_result=True,
                ordering=len(events),
            ))
            state = after
        return tuple(events)

    @staticmethod
    def _key(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)

    def _replay(
        self,
        adapter: TargetAdapter,
        baseline: Any,
        interactions: tuple[Mapping[str, Any], ...],
        objective: ObjectiveDefinition,
        authorization: Authorization,
        runs: int,
    ) -> _ReplayCandidate | None:
        runs_events: list[tuple[TraceEvent, ...]] = []
        signatures: list[str] = []
        durations: list[float] = []
        output: Mapping[str, Any] = {}
        for _ in range(runs):
            adapter.reset(baseline)
            started = time.perf_counter()
            events = tuple(adapter.execute_trace(interactions, authorization))
            durations.append((time.perf_counter() - started) * 1000)
            output = dict(getattr(adapter, "collect_output", lambda: {})())
            final_state = events[-1].after if events else State()
            initial_state = events[0].before if events else State()
            if not objective.evaluate(final_state, events) or not objective.checkpoints_satisfied(initial_state, events):
                return None
            runs_events.append(events)
            signatures.append(self._signature(events, output))
        stable = len(set(signatures)) == 1
        if not stable:
            return None
        events = runs_events[0]
        resource = output.get("resource_use")
        resource_use = float(resource) if isinstance(resource, (int, float)) else None
        dependencies = {event.component or event.operation or event.entry_point for event in events}
        cost = RealizationCost(
            interaction_count=len(interactions),
            trace_length=len(events),
            execution_time_ms=mean(durations),
            resource_use=resource_use,
            dependency_count=len(dependencies),
            stability=1.0,
            instrumentation_overhead=max(0, len(events) - len(interactions)),
            reproducibility=1.0,
            unknown_metrics=("resource_use",) if resource_use is None else (),
        )
        return _ReplayCandidate(interactions, events, cost, output, tuple(signatures))

    @staticmethod
    def _witness(original: Witness, candidate: _ReplayCandidate, objective: ObjectiveDefinition) -> Witness:
        final_state = candidate.events[-1].after if candidate.events else original.final_state
        return Witness(
            objective=objective.objective_id,
            target_id=original.target_id,
            events=candidate.events,
            final_state=final_state,
            validated=True,
            predicted_events=original.predicted_events,
            interactions=candidate.interactions,
            input_refs=tuple(ref for event in candidate.events for ref in event.evidence_refs),
            state_checkpoints=tuple(event.after.canonical() for event in candidate.events),
            environment=original.environment,
            replay_result={"optimized": True, "outcome": dict(candidate.outcome)},
            fidelity_scope={**dict(original.fidelity_scope), "optimization": "replay-validated"},
        )

    @staticmethod
    def _signature(events: Sequence[TraceEvent], output: Mapping[str, Any]) -> str:
        payload = {
            "events": [
                {
                    "operation": event.operation,
                    "entry_point": event.entry_point,
                    "request": event.request,
                    "before": event.before.canonical(),
                    "after": event.after.canonical(),
                    "observation": event.observation,
                    "guard_result": event.guard_result,
                }
                for event in events
            ],
            "output": output.get("outcome", output),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

    @staticmethod
    def _candidate_id(interactions: Sequence[Mapping[str, Any]]) -> str:
        return json.dumps(list(interactions), sort_keys=True, default=str)
