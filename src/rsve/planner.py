"""Bounded hybrid objective planning over the platform-neutral transition model."""

from __future__ import annotations

import heapq
import hashlib
import json
import time
from dataclasses import dataclass
from itertools import product
from typing import Any, Callable, Mapping, Sequence

from .adapter import Target
from .logic import Every, Constraint, Equal, Literal, Sort, Variable
from .diff import Analyzer
from .index import Index
from .model import Authorization, Decision, Operation, State, Event, Model
from .objective import All, Some, Objective, Same
from .result import (
    Report,
    Status,
    Divergence,
    Grade,
    Proof,
    Gap,
    Verdict,
    Witness,
)
from .solver import Query, Zed
from .wp import WP, Truth


@dataclass(frozen=True)
class Plan:
    objective_id: str
    required_actions: tuple[tuple[str, Mapping[str, Any]], ...]
    method: str
    complete: bool
    uncertainty: tuple[str, ...] = ()
    required_traces: tuple[tuple[Mapping[str, Any], ...], ...] = ()


@dataclass(frozen=True)
class Attempt:
    interactions: tuple[Mapping[str, Any], ...]
    predicted_events: tuple[Event, ...]
    replayed: bool
    objective_observed: bool | None
    observed_events: tuple[Event, ...] = ()
    replay_stable: bool | None = None
    divergences: tuple[Divergence, ...] = ()
    detail: str = ""


def _sort_for(value: Any) -> Sort | None:
    if isinstance(value, bool):
        return Sort.BOOL
    if isinstance(value, int):
        return Sort.INT
    if isinstance(value, str):
        return Sort.STRING
    return None


def _transform_is_lossy(transform: Any) -> bool:
    marker = getattr(transform, "information_loss", False)
    return marker.value != "none" if hasattr(marker, "value") else bool(marker)


def _symbolic_postcondition(objective: Objective) -> Constraint | None:
    constraints: list[Constraint] = []
    for predicate in objective.postconditions:
        if not isinstance(predicate, Same):
            return None
        sort = _sort_for(predicate.expected)
        if sort is None:
            return None
        constraints.append(
            Equal(
                Variable(f"state.{predicate.key}", sort),
                Literal(predicate.expected, sort),
            )
        )
    if not constraints:
        return None
    return constraints[0] if len(constraints) == 1 else Every(tuple(constraints))


def _initial_state_constraints(state: State) -> list[Constraint]:
    constraints: list[Constraint] = []
    for key, value in sorted(state.as_dict().items()):
        sort = _sort_for(value)
        if sort is not None:
            constraints.append(Equal(Variable(f"state.{key}", sort), Literal(value, sort)))
    return constraints


def _request_for_step(model: Mapping[str, Any], index: int) -> dict[str, Any]:
    request: dict[str, Any] = {}
    indexed_prefixes = (f"input.{index}.", f"request.{index}.")
    for name, value in model.items():
        for prefix in indexed_prefixes:
            if name.startswith(prefix):
                request[name[len(prefix):]] = value
    if request:
        return request
    for name, value in model.items():
        for prefix in ("input.", "request."):
            if name.startswith(prefix) and "." not in name[len(prefix):]:
                request[name[len(prefix):]] = value
    return request


class Regressor:
    """Derive bounded preimages for supported concrete operations.

    This deliberately reports bounded preimage enumeration as incomplete for
    opaque or information-losing operations; it never constructs an inverse.
    """

    def regress(
        self,
        model: Model,
        objective: Objective,
        *,
        solver: Zed | None = None,
        solver_timeout_ms: int | None = None,
    ) -> Plan:
        actions: list[tuple[str, Mapping[str, Any]]] = []
        uncertainty: list[str] = []
        index = Index.build(model)
        needed = self._keys(objective.postconditions)
        indexed = [item.operation for item in index.predecessors(needed)] if needed else []
        seen = {(item.entry_point.name, item.name) for item in indexed}
        operations = tuple(indexed) + tuple(
            item for item in model.ops()
            if (item.entry_point.name, item.name) not in seen
        )
        if needed and not indexed:
            uncertainty.append("no indexed writer was found for the objective state keys")
        for operation in operations:
            for request in model.args():
                if self.preimage(operation, request, objective)(model.initial_state):
                    actions.append((operation.entry_point.name, dict(request)))
        symbolic_actions, symbolic_uncertainty = self._symbolic_actions(
            model,
            objective,
            solver=solver or Zed(),
            solver_timeout_ms=solver_timeout_ms,
        )
        symbolic_traces, sequence_uncertainty = self._symbolic_traces(
            model,
            objective,
            solver=solver or Zed(),
            solver_timeout_ms=solver_timeout_ms,
        )
        for action in symbolic_actions:
            if (action[0], self._request_key(action[1])) not in {
                (entry, self._request_key(request)) for entry, request in actions
            }:
                actions.append(action)
        uncertainty.extend(symbolic_uncertainty)
        uncertainty.extend(sequence_uncertainty)
        for trace in symbolic_traces:
            for interaction in trace:
                action = (interaction["entry_point"], dict(interaction.get("request", {})))
                if (action[0], self._request_key(action[1])) not in {
                    (entry, self._request_key(request)) for entry, request in actions
                }:
                    actions.append(action)
        if not actions:
            uncertainty.append("no one-step preimage was found; longer paths use forward bounded exploration")
        if any(operation.transforms and any(_transform_is_lossy(transform) for transform in operation.transforms) for operation in model.operations):
            uncertainty.append("information-losing transforms require bounded forward/preimage search")
        return Plan(
            objective_id=objective.objective_id,
            required_actions=tuple(actions),
            method=("preimage+solver+sequence+bounded_preimage"
                    if symbolic_actions or symbolic_traces else "bounded_preimage_enumeration"),
            complete=False,
            uncertainty=tuple(uncertainty),
            required_traces=tuple(symbolic_traces),
        )

    @staticmethod
    def _keys(predicates: Sequence[Any]) -> frozenset[str]:
        found: set[str] = set()
        for predicate in predicates:
            if isinstance(predicate, Same):
                found.add(predicate.key)
            elif isinstance(predicate, (All, Some)):
                found.update(Regressor._keys(predicate.predicates))
        return frozenset(found)

    def _symbolic_traces(
        self,
        model: Model,
        objective: Objective,
        *,
        solver: Zed,
        solver_timeout_ms: int | None,
    ) -> tuple[list[tuple[Mapping[str, Any], ...]], list[str]]:
        symbolic_operations = tuple(
            operation for operation in model.ops()
            if operation.symbolic_transition is not None
        )
        if len(symbolic_operations) < 1 or objective.budget.max_trace_length < 2:
            return [], []
        postcondition = _symbolic_postcondition(objective)
        if postcondition is None:
            return [], ["multi-step symbolic regression supports Same postconditions only"]
        initial_constraints = _initial_state_constraints(model.initial_state)
        traces: list[tuple[Mapping[str, Any], ...]] = []
        uncertainty: list[str] = []
        examined = 0
        for length in range(2, objective.budget.max_trace_length + 1):
            for sequence in product(symbolic_operations, repeat=length):
                examined += 1
                if examined > min(objective.budget.max_states, 256):
                    uncertainty.append("multi-step symbolic sequence bound reached")
                    return traces, uncertainty
                transitions = tuple(operation.symbolic_transition for operation in sequence)
                result = WP().derive(postcondition, transitions)
                if result.status is not Truth.EXACT or result.precondition is None:
                    continue
                formula: Constraint = result.precondition
                if initial_constraints:
                    formula = Every(tuple(initial_constraints) + (formula,))
                solved = solver.solve(
                    Query(
                        f"wp-sequence:{objective.objective_id}:{length}:{examined}",
                        formula,
                    ),
                    timeout_ms=solver_timeout_ms,
                )
                if solved.status is Verdict.UNKNOWN:
                    uncertainty.append(solved.unknown_reason or "multi-step symbolic query returned UNKNOWN")
                    continue
                if solved.status is not Verdict.SAT:
                    continue
                interactions = tuple(
                    {
                        "entry_point": operation.entry_point.name,
                        "request": _request_for_step(solved.model, index),
                    }
                    for index, operation in enumerate(sequence)
                )
                if all(interaction["request"] or operation.symbolic_transition is not None for interaction, operation in zip(interactions, sequence)):
                    traces.append(interactions)
        return traces, uncertainty

    def _symbolic_actions(
        self,
        model: Model,
        objective: Objective,
        *,
        solver: Zed,
        solver_timeout_ms: int | None,
    ) -> tuple[list[tuple[str, Mapping[str, Any]]], list[str]]:
        if not any(operation.symbolic_transition is not None for operation in model.operations):
            return [], []
        postcondition = _symbolic_postcondition(objective)
        if postcondition is None:
            return [], ["symbolic backward planning supports Same postconditions only"]
        actions: list[tuple[str, Mapping[str, Any]]] = []
        uncertainty: list[str] = []
        wp_engine = WP()
        for operation in model.ops():
            transition = operation.symbolic_transition
            if transition is None:
                continue
            result = wp_engine.derive(postcondition, (transition,))
            if result.status is not Truth.EXACT or result.precondition is None:
                uncertainty.append(
                    f"symbolic preimage for {operation.entry_point.name} is unknown: {result.reason or 'unsupported semantics'}"
                )
                continue
            initial_constraints = [
                Equal(Variable(f"state.{key}", _sort_for(value)), Literal(value, _sort_for(value)))
                for key, value in sorted(model.initial_state.as_dict().items())
                if _sort_for(value) is not None
            ]
            formula: Constraint = result.precondition
            if initial_constraints:
                formula = Every(tuple(initial_constraints) + (formula,))
            solved = solver.solve(
                Query(
                    f"wp:{objective.objective_id}:{operation.entry_point.name}",
                    formula,
                ),
                timeout_ms=solver_timeout_ms,
            )
            if solved.status is Verdict.UNKNOWN:
                uncertainty.append(
                    f"solver could not concretize symbolic preimage for {operation.entry_point.name}: {solved.unknown_reason or 'unknown'}"
                )
                continue
            if solved.status is not Verdict.SAT:
                continue
            request = {
                name.removeprefix("input.").removeprefix("request."): value
                for name, value in solved.model.items()
                if name.startswith(("input.", "request."))
            }
            if request:
                actions.append((operation.entry_point.name, request))
        return actions, uncertainty

    @staticmethod
    def _request_key(request: Mapping[str, Any]) -> str:
        return json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)

    def preimage(
        self,
        operation: Operation,
        request: Mapping[str, Any],
        objective: Objective,
    ) -> Callable[[State], bool]:
        """Return the exact concrete preimage predicate for a modeled relation.

        The returned predicate is exact only for the supplied modeled operation
        and request. It is intentionally a concrete relational preimage, not a
        claimed inverse for the underlying runtime transform.
        """
        def precondition(state: State) -> bool:
            return any(
                objective.evaluate(outcome.after, (outcome.event(
                    operation.name,
                    operation.entry_point.name,
                    request,
                    state,
                    component=operation.component,
                ),))
                for outcome in operation.branches(state, request)
                if outcome.decision is not Decision.UNKNOWN
            )
        return precondition


class Planner:
    """Use backward action hints, then deterministic forward concretization."""

    def __init__(self, *, harness_sinks: set[str] | frozenset[str] = frozenset()) -> None:
        self.harness_sinks = frozenset(harness_sinks)

    def plan(
        self,
        model: Model,
        objective: Objective,
        authorization: Authorization,
        *,
        adapter: Target | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> Report:
        adapter_environment = self._environment(adapter)
        execution_profile = self._analysis_profile(adapter)
        objective.validate(
            authorization,
            harness_sinks=self.harness_sinks,
            environment=environment or adapter_environment,
            execution_profile=execution_profile,
        )
        backward = Regressor().regress(
            model,
            objective,
            solver_timeout_ms=objective.budget.solver_timeout_ms,
        )
        phantom_attempt = self._probe_phantom_entries(adapter, objective, authorization)
        if phantom_attempt is not None and phantom_attempt.objective_observed and phantom_attempt.replay_stable:
            return self._report(
                Status.VALIDATED_WITNESS,
                model,
                objective,
                (),
                phantom_attempt,
                0,
                0,
                backward,
                environment or adapter_environment,
            )
        preferred = {(entry, self._request_key(request)) for entry, request in backward.required_actions}
        started = time.monotonic()
        budget = objective.budget
        queue: list[tuple[int, int, int, State, tuple[Event, ...]]] = []
        serial = 0
        heapq.heappush(queue, (0, serial, 0, model.initial_state, ()))
        for interactions in backward.required_traces:
            seeded = self._model_trace(model, interactions)
            if seeded is not None:
                state, trace = seeded
                serial += 1
                heapq.heappush(queue, (-1, serial, len(trace), state, trace))
        input_candidates = list(model.args())
        for _entry, request in backward.required_actions:
            if self._request_key(request) not in {self._request_key(item) for item in input_candidates}:
                input_candidates.append(dict(request))
        input_candidates = sorted(input_candidates, key=self._request_key)
        visited: set[tuple[int, str, tuple[tuple[str, str], ...]]] = set()
        explored_states = 0
        explored_events = 0
        attempts: list[Attempt] = []
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

            if objective.evaluate(state, trace) and objective.satisfy(model.initial_state, trace):
                attempt = self._replay_candidate(
                    adapter,
                    objective,
                    model,
                    trace,
                    environment or adapter_environment,
                    authorization,
                )
                attempts.append(attempt)
                if attempt.replayed and attempt.objective_observed and self._stable(attempt, objective):
                    return self._report(
                        Status.VALIDATED_WITNESS,
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
                        Status.SAT_CANDIDATE,
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
                        Status.MODEL_DIVERGENCE,
                        model,
                        objective,
                        trace,
                        attempt,
                        explored_states,
                        explored_events,
                        backward,
                        environment or adapter_environment,
                    )

            if trace and trace[-1].terminal:
                continue

            if depth >= budget.max_trace_length:
                continue
            for operation in model.ops():
                for request in input_candidates:
                    if explored_events >= budget.max_events:
                        budget_hit = True
                        break
                    if not model.allows(operation.entry_point.name, request):
                        continue
                    explored_events += 1
                    for outcome in operation.branches(state, request):
                        if outcome.decision is Decision.UNKNOWN:
                            continue
                        if explored_states + len(queue) >= budget.max_states:
                            budget_hit = True
                            continue
                        event = outcome.event(
                            operation.name,
                            operation.entry_point.name,
                            request,
                            state,
                            component=operation.component,
                            order=len(trace),
                        )
                        next_trace = trace + (event,)
                        preference = 0 if (operation.entry_point.name, self._request_key(request)) in preferred else depth + 1
                        serial += 1
                        heapq.heappush(queue, (preference, serial, depth + 1, outcome.after, next_trace))
                if budget_hit:
                    break
            if budget_hit:
                break

        status = Status.BUDGET_EXHAUSTED if budget_hit else (Status.UNKNOWN if attempts else Status.UNSAT_BOUNDED)
        gaps = [Gap(
            Grade.EVENT_BUDGET if budget_hit else (Grade.ASSUMPTION if attempts else Grade.BOUND),
            "bounded hybrid search exhausted its event/time/state budget" if budget_hit else ("candidate replay did not satisfy the objective or stability policy" if attempts else "no witness exists in the encoded bounded model/surface"),
            {"max_trace_length": budget.max_trace_length, "attempts": len(attempts)},
        )]
        return self._report(
            status,
            model,
            objective,
            (),
            attempts[-1] if attempts else Attempt((), (), False, None),
            explored_states,
            explored_events,
            backward,
            environment or adapter_environment,
            gaps=gaps,
        )

    def analyze(self, *args: Any, **kwargs: Any) -> Report:
        """Compatibility spelling for callers that use the engine's analyze API."""
        return self.plan(*args, **kwargs)

    def _replay_candidate(
        self,
        adapter: Target | None,
        objective: Objective,
        model: Model,
        predicted: Sequence[Event],
        environment: Mapping[str, str],
        authorization: Authorization,
    ) -> Attempt:
        interactions = tuple({"entry_point": event.entry_point, "request": dict(event.request)} for event in predicted)
        if adapter is None:
            return Attempt(interactions, tuple(predicted), False, None, detail="candidate was not replayed by a target adapter")
        adapter.prepare()
        baseline = adapter.snapshot()
        all_runs: list[tuple[Event, ...]] = []
        outcomes: list[bool] = []
        signatures: list[str] = []
        first_divergences: tuple[Divergence, ...] = ()
        try:
            for _ in range(objective.budget.replay_runs):
                adapter.reset(baseline)
                observed = tuple(adapter.trace(interactions, authorization))
                all_runs.append(observed)
                final_state = observed[-1].after if observed else model.initial_state
                outcomes.append(objective.evaluate(final_state, observed) and objective.satisfy(model.initial_state, observed))
                signatures.append(hashlib.sha256(json.dumps({
                    "events": [self._semantic_event(event) for event in observed],
                    "output": self._semantic_output(getattr(adapter, "output", lambda: {})()),
                }, sort_keys=True, default=str).encode()).hexdigest())
                if not first_divergences:
                    first_divergences = Analyzer().compare(predicted, observed)
        finally:
            adapter.teardown()
        stable = len(set(outcomes)) == 1 and len(set(signatures)) == 1 and bool(outcomes)
        detail = "replay objective did not hold" if not all(outcomes) else ("replay was unstable" if not stable else "")
        return Attempt(
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
        status: Status,
        model: Model,
        objective: Objective,
        predicted: Sequence[Event],
        attempt: Attempt,
        explored_states: int,
        explored_events: int,
        backward: Plan,
        environment: Mapping[str, str],
        *,
        gaps: Sequence[Gap] = (),
    ) -> Report:
        witness = None
        witness_events = attempt.observed_events if status is Status.VALIDATED_WITNESS and attempt.observed_events else tuple(predicted)
        model_aligned = (not bool(attempt.divergences)) if attempt.replayed and attempt.predicted_events else None
        if witness_events or attempt.interactions:
            final_state = witness_events[-1].after if witness_events else model.initial_state
            witness = Witness(
                objective=objective.objective_id,
                target_id=model.target_id,
                events=witness_events,
                final_state=final_state,
                validated=status is Status.VALIDATED_WITNESS,
                model_aligned=model_aligned,
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
            Verdict.SAT
            if witness and status in {Status.VALIDATED_WITNESS, Status.SAT_CANDIDATE, Status.MODEL_DIVERGENCE}
            else Verdict.UNKNOWN
            if status in {Status.BUDGET_EXHAUSTED, Status.UNKNOWN, Status.MODEL_DIVERGENCE}
            else Verdict.UNSAT_BOUNDED
        )
        proof = Proof(
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
            execution_profile_id=environment.get("profile_id", "unknown"),
        )
        report_gaps = list(gaps)
        if attempt.detail:
            report_gaps.append(Gap(Grade.ASSUMPTION, attempt.detail, {"interactions": attempt.interactions}))
        return Report(
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
            surface_scope=tuple(sorted({event.entry_point for event in tuple(predicted) + tuple(attempt.observed_events)})),
            environment=dict(environment),
            replay_runs=objective.budget.replay_runs if attempt.replayed else 0,
            replay_stable=(attempt.replay_stable if attempt.replayed else None),
            model_aligned=model_aligned,
            unresolved_uncertainty=backward.uncertainty,
            model_revision=model.model_version,
            execution_profile_id=environment.get("profile_id", "unknown"),
        )

    @staticmethod
    def _request_key(request: Mapping[str, Any]) -> str:
        return json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def _model_trace(
        model: Model,
        interactions: Sequence[Mapping[str, Any]],
    ) -> tuple[State, tuple[Event, ...]] | None:
        operations = {operation.entry_point.name: operation for operation in model.ops()}
        state = model.initial_state
        events: list[Event] = []
        for index, interaction in enumerate(interactions):
            entry = str(interaction["entry_point"])
            operation = operations.get(entry)
            request = dict(interaction.get("request", {}))
            if operation is None or not model.allows(entry, request):
                return None
            outcome = operation.execute(state, request)
            event = outcome.event(
                operation.name,
                entry,
                request,
                state,
                component=operation.component,
                order=len(events),
            )
            events.append(event)
            state = outcome.after
            if outcome.terminal and index != len(interactions) - 1:
                return None
        return state, tuple(events)

    @staticmethod
    def _probe_phantom_entries(
        adapter: Target | None,
        objective: Objective,
        authorization: Authorization,
    ) -> Attempt | None:
        if adapter is None:
            return None
        registry_factory = getattr(adapter, "surface", None)
        replay = getattr(adapter, "replay", None)
        if not callable(registry_factory) or not callable(replay):
            return None
        registry = registry_factory()
        for observed in registry.phantoms():
            interactions = ({"entry_point": observed.entry_point.name, "request": {}},)
            try:
                report = replay(interactions, runs=objective.budget.replay_runs, authorization=authorization)
            except (OSError, RuntimeError, TimeoutError, ValueError, PermissionError):
                continue
            if not report.runs:
                continue
            run = report.runs[0]
            observed_objective = bool(run.events) and objective.evaluate(run.events[-1].after, run.events)
            observed_objective = observed_objective and objective.satisfy(run.events[0].before, run.events)
            if observed_objective:
                return Attempt(
                    interactions,
                    (),
                    True,
                    True,
                    tuple(run.events),
                    bool(report.stable),
                    detail=f"phantom entry {observed.entry_point.name} was promoted from observed surface evidence",
                )
        return None

    @staticmethod
    def _semantic_event(event: Event) -> dict[str, Any]:
        return {
            "operation": event.operation,
            "entry_point": event.entry_point,
            "request": event.request,
            "before": event.before.canonical(),
            "after": event.after.canonical(),
            "observation": event.observation,
            "guard_result": event.guard_result,
            "decision": event.decision.value,
            "terminal": event.terminal,
            "effects": event.effects,
            "reaction": event.reaction,
        }

    @staticmethod
    def _semantic_output(output: Mapping[str, Any]) -> Any:
        if isinstance(output, Mapping) and "outcome" in output:
            return output["outcome"]
        return output

    @staticmethod
    def _environment(adapter: Target | None) -> Mapping[str, str]:
        observation = getattr(adapter, "observe", None)
        if observation is None:
            return {}
        result = observation()
        facts = dict(getattr(result, "facts", result))
        profile_factory = getattr(adapter, "profile", None)
        if callable(profile_factory):
            facts["profile_id"] = profile_factory().profile_id
        return facts

    @staticmethod
    def _analysis_profile(adapter: Target | None) -> Any | None:
        profile_factory = getattr(adapter, "profile", None)
        return profile_factory() if callable(profile_factory) else None

    @staticmethod
    def _stable(attempt: Attempt, objective: Objective) -> bool:
        return attempt.replayed and attempt.objective_observed is True and attempt.replay_stable is True and objective.budget.replay_runs >= 1
