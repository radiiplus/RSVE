"""Trace alignment and evidence-backed model refinement."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence

from .model import Exclusion, State, Event, Model
from .result import Divergence


class Kind(str, Enum):
    MODEL_TOO_LOOSE = "model_too_loose"
    MODEL_TOO_STRICT = "model_too_strict"
    WRONG_STATE = "wrong_state_or_initial_condition"
    ENVIRONMENT = "environment_or_schedule_difference"
    OPAQUE_SEMANTICS = "opaque_or_non_invertible_gap"
    OBJECTIVE_DEFECT = "objective_or_decomposition_defect"
    INSTRUMENTATION_GAP = "instrumentation_or_correlation_gap"


@dataclass(frozen=True)
class Delta:
    delta_id: str
    parent_revision: str
    revision: str
    kind: Kind
    description: str
    added_constraints: tuple[str, ...] = ()
    demoted_assumptions: tuple[str, ...] = ()
    promoted_evidence: tuple[str, ...] = ()
    observed_entries: tuple[str, ...] = ()
    invalidated_queries: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Experiment:
    experiment_id: str
    target_id: str
    build_hash: str
    objective_version: str
    surface_scope: tuple[str, ...]
    max_trace_length: int
    assumptions: tuple[str, ...]
    model_revision: str
    solver_query: str
    solver_status: str
    replay_count: int
    replay_stable: bool | None
    evidence_refs: tuple[str, ...] = ()
    unresolved_uncertainty: tuple[str, ...] = ()


@dataclass(frozen=True)
class Refinement:
    model: Model
    delta: Delta
    divergences: tuple[Divergence, ...]


class Analyzer:
    """Align semantic events while tolerating adapter-only observation events."""

    def compare(self, expected: Iterable[Event], observed: Iterable[Event]) -> tuple[Divergence, ...]:
        expected_events = tuple(expected)
        observed_events = tuple(observed)
        cursor = 0
        for expected_event in expected_events:
            match_index = self._find_match(expected_event, observed_events, cursor)
            if match_index is None:
                same_entry = [event for event in observed_events[cursor:] if event.entry_point == expected_event.entry_point]
                if any(event.guard_result is False for event in same_entry):
                    event = next(event for event in same_entry if event.guard_result is False)
                    return (Divergence(
                        index=cursor,
                        kind=Kind.MODEL_TOO_LOOSE.value,
                        expected=expected_event.canonical(),
                        observed=event.canonical(),
                        detail="the model permitted an interaction rejected by the runtime guard",
                        observed_index=observed_events.index(event, cursor),
                    ),)
                unexpected = self._first_unexpected(observed_events, cursor)
                if unexpected is not None:
                    index, event = unexpected
                    return (Divergence(
                        index=cursor,
                        kind=Kind.MODEL_TOO_STRICT.value,
                        expected=expected_event.canonical(),
                        observed=event.canonical(),
                        detail="an unexpected semantic runtime event appeared before the predicted event",
                        observed_index=index,
                    ),)
                return (Divergence(
                    index=cursor,
                    kind=Kind.MODEL_TOO_STRICT.value,
                    expected=expected_event.canonical(),
                    observed="no semantically matching runtime event",
                    detail="the predicted semantic operation was not observed",
                ),)
            unexpected = self._first_unexpected(observed_events, cursor, stop=match_index)
            if unexpected is not None:
                index, event = unexpected
                return (Divergence(
                    index=cursor,
                    kind=Kind.MODEL_TOO_STRICT.value,
                    expected=expected_event.canonical(),
                    observed=event.canonical(),
                    detail="an unexpected semantic runtime event appeared before the predicted event",
                    observed_index=index,
                ),)
            actual = observed_events[match_index]
            divergence = self._event_divergence(match_index, expected_event, actual)
            if divergence is not None:
                return (divergence,)
            cursor = match_index + 1
        unexpected = self._first_unexpected(observed_events, cursor)
        if unexpected is not None:
            index, event = unexpected
            return (Divergence(
                index=len(expected_events),
                kind=Kind.MODEL_TOO_STRICT.value,
                expected="end of predicted semantic trace",
                observed=event.canonical(),
                detail="the runtime produced an unexpected semantic event after the predicted trace",
                observed_index=index,
            ),)
        return ()

    def align(self, expected: Iterable[Event], observed: Iterable[Event]) -> tuple[Divergence, ...]:
        return self.compare(expected, observed)

    def refine(
        self,
        model: Model,
        divergences: Sequence[Divergence],
        observed: Iterable[Event],
        *,
        invalidated_queries: Sequence[str] = (),
        probe: Callable[[str, Mapping[str, Any]], bool] | None = None,
        probe_radius: int = 2,
    ) -> Refinement:
        if not divergences:
            raise ValueError("a refinement requires at least one divergence")
        divergence = divergences[0]
        observed_events = tuple(observed)
        observed_index = divergence.observed_index if divergence.observed_index is not None else divergence.index
        event = observed_events[observed_index] if observed_index < len(observed_events) else None
        next_model = model
        added: tuple[str, ...] = ()
        demoted: tuple[str, ...] = ()
        promoted: tuple[str, ...] = ()
        if divergence.kind == Kind.MODEL_TOO_LOOSE.value and event is not None:
            request = dict(event.request)
            description = (
                f"record runtime behavior for {event.entry_point} request "
                f"{json.dumps(request, sort_keys=True, default=str)} at the observed pre-state"
            )
            if probe is not None:
                learned = self._learn_numeric_exclusion(
                    event.entry_point,
                    request,
                    probe,
                    radius=probe_radius,
                    evidence=event.evidence_refs,
                )
                if learned is not None:
                    next_model = next_model.learn(learned)
                    added = added + (learned.describe(),)
                    description += f"; learned only the probed rejection region {learned.describe()}"
        elif divergence.kind == Kind.INSTRUMENTATION_GAP.value and event is not None:
            promoted = (f"observed:{event.operation}:{event.entry_point}",)
            description = "promote observed event only for the evidenced target/build region"
        else:
            demoted = model.assumptions
            if demoted:
                next_model = model.demote(demoted)
            description = f"demote affected assumptions and retain divergence {divergence.kind} as an explicit unresolved model gap"
        gap_payload = json.dumps({
            "kind": divergence.kind,
            "index": divergence.index,
            "expected": divergence.expected,
            "observed": divergence.observed,
        }, sort_keys=True, default=str)
        gap_id = hashlib.sha256(gap_payload.encode()).hexdigest()[:16]
        next_model = next_model.record_refinement_gap(f"{divergence.kind}:{gap_id}")
        prior_observations = len(next_model.observed_transitions)
        next_model = next_model.record_observations(observed_events)
        recorded = len(next_model.observed_transitions) - prior_observations
        if recorded:
            promoted += tuple(
                f"observed:{item.operation}:{item.entry_point}:{item.event_id or item.ordering}"
                for item in next_model.observed_transitions[prior_observations:]
            )
            description += f"; recorded {recorded} exact-context runtime transition(s)"
        revision = next_model.model_version
        delta_id = "delta-" + hashlib.sha256((revision + description).encode()).hexdigest()[:16]
        delta = Delta(
            delta_id=delta_id,
            parent_revision=model.model_version,
            revision=revision,
            kind=Kind(divergence.kind) if divergence.kind in {item.value for item in Kind} else Kind.OPAQUE_SEMANTICS,
            description=description,
            added_constraints=added,
            demoted_assumptions=demoted,
            promoted_evidence=promoted,
            observed_entries=tuple(dict.fromkeys(item.entry_point for item in observed_events)),
            invalidated_queries=tuple(invalidated_queries),
            evidence_refs=tuple(dict.fromkeys(
                reference for item in observed_events for reference in item.evidence_refs
            )),
        )
        return Refinement(next_model, delta, tuple(divergences))

    @staticmethod
    def _learn_numeric_exclusion(
        entry_point: str,
        request: Mapping[str, Any],
        probe: Callable[[str, Mapping[str, Any]], bool],
        *,
        radius: int,
        evidence: Sequence[str],
    ) -> Exclusion | None:
        for key, value in request.items():
            if isinstance(value, bool) or not isinstance(value, int):
                continue
            samples: dict[int, bool] = {}
            for candidate in range(value - radius, value + radius + 1):
                candidate_request = dict(request)
                candidate_request[key] = candidate
                try:
                    samples[candidate] = bool(probe(entry_point, candidate_request))
                except (OSError, RuntimeError, TimeoutError, ValueError):
                    continue
            if samples.get(value, True):
                continue
            rejected = sorted(item for item, accepted in samples.items() if not accepted)
            accepted = sorted(item for item, accepted in samples.items() if accepted)
            if not rejected:
                continue
            lower = min(rejected)
            upper = max(rejected)
            if accepted and min(accepted) < lower and all(not samples.get(item, True) for item in range(lower, upper + 1)):
                return Exclusion(entry_point, key, ">=", lower, min(samples), max(samples), tuple(evidence) + ("bounded-neighbor-probes",))
            if accepted and max(accepted) > upper and all(not samples.get(item, True) for item in range(lower, upper + 1)):
                return Exclusion(entry_point, key, "<=", upper, min(samples), max(samples), tuple(evidence) + ("bounded-neighbor-probes",))
            if all(samples.get(item) is False for item in (value - 1, value, value + 1) if item in samples):
                return Exclusion(entry_point, key, "=", value, min(samples), max(samples), tuple(evidence) + ("bounded-neighbor-probes",))
        return None

    def experiment(
        self,
        *,
        target_id: str,
        build_hash: str,
        objective_version: str,
        surface_scope: Sequence[str],
        max_trace_length: int,
        assumptions: Sequence[str],
        model_revision: str,
        solver_query: str,
        solver_status: str,
        replay_count: int,
        replay_stable: bool | None,
        evidence_refs: Sequence[str] = (),
        unresolved_uncertainty: Sequence[str] = (),
    ) -> Experiment:
        payload = json.dumps({
            "target_id": target_id,
            "build_hash": build_hash,
            "objective_version": objective_version,
            "surface_scope": list(surface_scope),
            "model_revision": model_revision,
            "solver_query": solver_query,
        }, sort_keys=True)
        return Experiment(
            experiment_id="experiment-" + hashlib.sha256(payload.encode()).hexdigest()[:16],
            target_id=target_id,
            build_hash=build_hash,
            objective_version=objective_version,
            surface_scope=tuple(surface_scope),
            max_trace_length=max_trace_length,
            assumptions=tuple(assumptions),
            model_revision=model_revision,
            solver_query=solver_query,
            solver_status=solver_status,
            replay_count=replay_count,
            replay_stable=replay_stable,
            evidence_refs=tuple(evidence_refs),
            unresolved_uncertainty=tuple(unresolved_uncertainty),
        )

    @staticmethod
    def _find_match(expected: Event, observed: Sequence[Event], start: int) -> int | None:
        for index in range(start, len(observed)):
            candidate = observed[index]
            if candidate.operation == expected.operation and candidate.entry_point == expected.entry_point:
                return index
        return None

    @staticmethod
    def _first_unexpected(observed: Sequence[Event], start: int, *, stop: int | None = None) -> tuple[int, Event] | None:
        end = len(observed) if stop is None else stop
        for index in range(start, end):
            event = observed[index]
            if event.operation not in {
                "entry.invocation",
                "guard.decision",
                "entry.outcome",
                "async.correlation",
                "task.schedule",
                "environment.observation",
            }:
                return index, event
        return None

    @staticmethod
    def _event_divergence(index: int, expected: Event, actual: Event) -> Divergence | None:
        if expected.correlation_uncertain or actual.correlation_uncertain:
            return Divergence(index, Kind.INSTRUMENTATION_GAP.value, expected.canonical(), actual.canonical(), "event correlation is explicitly uncertain")
        if expected.environment and actual.environment and expected.environment != actual.environment:
            return Divergence(index, Kind.ENVIRONMENT.value, expected.environment, actual.environment, "environment evidence differs")
        if expected.before != actual.before:
            return Divergence(index, Kind.WRONG_STATE.value, expected.before.canonical(), actual.before.canonical(), "state before the matching operation differs")
        if expected.request != actual.request:
            return Divergence(index, Kind.OBJECTIVE_DEFECT.value, expected.request, actual.request, "the realized request differs from the planned request")
        if expected.guard_result is not None and actual.guard_result != expected.guard_result:
            kind = Kind.MODEL_TOO_LOOSE.value if actual.guard_result is False else Kind.MODEL_TOO_STRICT.value
            return Divergence(index, kind, expected.guard_result, actual.guard_result, "guard result differs")
        if expected.decision != actual.decision:
            kind = Kind.MODEL_TOO_LOOSE.value if actual.decision.value == "REJECT" else Kind.MODEL_TOO_STRICT.value
            return Divergence(index, kind, expected.decision.value, actual.decision.value, "transition decision differs")
        if expected.reaction != actual.reaction:
            return Divergence(index, Kind.ENVIRONMENT.value, expected.reaction, actual.reaction, "environmental reaction differs")
        if expected.after != actual.after or expected.observation != actual.observation:
            return Divergence(index, Kind.OPAQUE_SEMANTICS.value, {"after": expected.after.canonical(), "observation": expected.observation}, {"after": actual.after.canonical(), "observation": actual.observation}, "matching operation has different state or observation semantics")
        return None
