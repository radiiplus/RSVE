"""Deterministic, budgeted expansion for open interaction domains."""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import random
import time
from dataclasses import dataclass, replace
from itertools import islice
from typing import Any, Callable, Iterable, Mapping, Sequence

from .result import (
    DiscoveryEvidence,
    EvidenceLevel,
    Divergence,
    Status,
    discovery_evidence,
)
from .diff import Analyzer, Refinement
from .index import Index
from .signature import Archive, Signature
from .model import Authorization, Event, State
from .objective import Objective
from .workspace import Frame, Workspace


@dataclass(frozen=True)
class Bounds:
    max_candidates: int = 1_000
    max_trace_length: int = 4
    max_time_ms: int = 5_000

    def __post_init__(self) -> None:
        if min(self.max_candidates, self.max_trace_length, self.max_time_ms) <= 0:
            raise ValueError("domain search budgets must be positive")


@dataclass(frozen=True)
class CandidatePriority:
    """Objective-aware ordering signal; it is not evidence of reachability."""

    objective_progress: float = 0.0
    addressed_conditions: int = 0
    exposed_transitions: int = 0
    uncertainty_resolved: int = 0
    route_potential: int = 0
    novelty: float = 0.0
    computation_cost_ms: float = 0.0

    @property
    def score(self) -> float:
        return (
            max(0.0, self.objective_progress) * 1000
            + max(0, self.addressed_conditions) * 25
            + min(max(0, self.exposed_transitions), 8) * 4
            + min(max(0, self.uncertainty_resolved), 8) * 20
            + min(max(0, self.route_potential), 8) * 12
            + max(0.0, self.novelty) * 5
            - min(max(0.0, self.computation_cost_ms), 5000) * 0.02
        )


def _assess_candidate(
    assess: Callable[[tuple[Mapping[str, Any], ...]], "Trial"],
    candidate: tuple[Mapping[str, Any], ...],
) -> "Trial":
    started = time.perf_counter()
    trial = assess(candidate)
    elapsed_ms = (time.perf_counter() - started) * 1000
    return replace(trial, computation_cost_ms=trial.computation_cost_ms + elapsed_ms)


def _accepted(trial: "Trial") -> bool:
    return trial.accepted and trial.status not in {Status.UNKNOWN, Status.MODEL_DIVERGENCE}


def _merge_evidence(*groups: Sequence[DiscoveryEvidence]) -> tuple[DiscoveryEvidence, ...]:
    merged: dict[str, DiscoveryEvidence] = {}
    for group in groups:
        if isinstance(group, DiscoveryEvidence):
            group = (group,)
        for item in group:
            merged.setdefault(item.evidence_id, item)
    return tuple(merged.values())


def _merge_refinements(*groups: Sequence[Refinement]) -> tuple[Refinement, ...]:
    merged: dict[str, Refinement] = {}
    for group in groups:
        for item in group:
            merged.setdefault(item.delta.delta_id, item)
    return tuple(merged.values())


@dataclass(frozen=True)
class Found:
    status: Status
    attempts: int
    generated: int
    candidate: tuple[Mapping[str, Any], ...] = ()
    detail: str = ""
    frontier_digest: str = ""
    archive: Archive = Archive()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    refinements: tuple[Refinement, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence:
            level = {
                Status.VALIDATED_WITNESS: EvidenceLevel.REPLAY_VALIDATED,
                Status.MODEL_SAT: EvidenceLevel.MODEL_SATISFIABLE,
                Status.SAT_CANDIDATE: EvidenceLevel.HYPOTHESIZED,
                Status.UNSAT_BOUNDED: EvidenceLevel.BOUNDED_EXHAUSTION,
            }.get(self.status, EvidenceLevel.HYPOTHESIZED)
            claim = (
                self.detail or "a candidate was returned without a target/runtime evidence record"
                if level is not EvidenceLevel.BOUNDED_EXHAUSTION
                else self.detail or "the generated finite candidate region was exhausted"
            )
            object.__setattr__(self, "evidence", (discovery_evidence(
                level,
                claim,
                "bounded-search",
                artifact_refs=(self.frontier_digest,) if self.frontier_digest else (),
                fidelity_scope={"attempts": self.attempts, "generated": self.generated},
            ),))


@dataclass(frozen=True)
class Trial:
    """One evaluated candidate and its behavior evidence."""

    accepted: bool
    signature: Signature | None
    detail: str = ""
    status: Status = Status.SAT_CANDIDATE
    progress: float = 0.0
    replayed: bool = False
    stable: bool | None = None
    model_events: tuple[Event, ...] = ()
    observed_events: tuple[Event, ...] = ()
    divergences: tuple[Any, ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    addressed_conditions: int = 0
    exposed_transitions: tuple[str, ...] = ()
    uncertainty_resolved: tuple[str, ...] = ()
    route_potential: int = 0
    computation_cost_ms: float = 0.0
    refinements: tuple[Refinement, ...] = ()

    def __post_init__(self) -> None:
        if self.progress < 0:
            raise ValueError("trial progress must be non-negative")
        if min(self.addressed_conditions, self.route_potential) < 0 or self.computation_cost_ms < 0:
            raise ValueError("priority metrics must be non-negative")
        if self.status is Status.VALIDATED_WITNESS and not (self.accepted and self.replayed and self.stable is True):
            raise ValueError("validated trials require accepted stable replay evidence")
        if not self.evidence:
            records: list[DiscoveryEvidence] = []
            profile = self.signature.profile if self.signature is not None else "unknown"
            scope = dict(self.signature.scope) if self.signature is not None else {}
            divergence_refs = tuple(
                f"divergence:{item.index}:{item.kind}" for item in self.divergences
            )
            if self.replayed:
                if self.model_events:
                    records.append(discovery_evidence(
                        EvidenceLevel.MODEL_REACHABLE,
                        "the candidate route reached the objective in the bounded workspace model",
                        "workspace-execution",
                        artifact_refs=tuple(
                            ref for event in self.model_events for ref in event.evidence_refs
                        ),
                        assumptions=tuple(str(value) for value in scope.get("assumptions", ())),
                        fidelity_scope=scope,
                        execution_profile_id=profile,
                    ))
                records.append(discovery_evidence(
                    EvidenceLevel.OBSERVED,
                    "candidate behavior was captured during target replay",
                    "target-adapter-replay",
                    artifact_refs=tuple(
                        ref for event in self.observed_events for ref in event.evidence_refs
                    ),
                    fidelity_scope=scope,
                    execution_profile_id=profile,
                    divergence_refs=divergence_refs,
                ))
            elif self.model_events:
                records.append(discovery_evidence(
                    EvidenceLevel.MODEL_REACHABLE,
                    "the candidate route reached the objective in the bounded workspace model",
                    "workspace-execution",
                    artifact_refs=tuple(
                        ref for event in self.model_events for ref in event.evidence_refs
                    ),
                    fidelity_scope=scope,
                    execution_profile_id=profile,
                ))
            elif self.status is Status.MODEL_SAT:
                records.append(discovery_evidence(
                    EvidenceLevel.MODEL_SATISFIABLE,
                    "candidate satisfies the supplied executable model assessment",
                    "search-assessment",
                    fidelity_scope=scope,
                    execution_profile_id=profile,
                ))
            else:
                records.append(discovery_evidence(
                    EvidenceLevel.HYPOTHESIZED,
                    self.detail or "candidate was generated or assessed without replay validation",
                    "search-assessment",
                    fidelity_scope=scope,
                    execution_profile_id=profile,
                    divergence_refs=divergence_refs,
                ))
            if self.status is Status.VALIDATED_WITNESS and self.stable is True:
                records.append(discovery_evidence(
                    EvidenceLevel.REPLAY_VALIDATED,
                    "candidate satisfied the objective on stable target replay",
                    "target-adapter-replay",
                    artifact_refs=tuple(
                        ref for event in self.observed_events for ref in event.evidence_refs
                    ),
                    fidelity_scope={**scope, "stable": self.stable},
                    execution_profile_id=profile,
                    divergence_refs=divergence_refs,
                ))
            object.__setattr__(self, "evidence", tuple(records))

    def priority(self, novelty: float = 0.0) -> CandidatePriority:
        return CandidatePriority(
            objective_progress=self.progress,
            addressed_conditions=self.addressed_conditions,
            exposed_transitions=len(set(self.exposed_transitions)),
            uncertainty_resolved=len(set(self.uncertainty_resolved)),
            route_potential=self.route_potential,
            novelty=novelty,
            computation_cost_ms=self.computation_cost_ms,
        )


class Guide:
    """Connect novelty search to RSVE regression and workspace execution.

    The guide owns candidate discovery and assessment for a composed workspace.
    Strategies remain responsible only for ordering the candidates they are
    given. Model-only results are reported as ``MODEL_SAT``; adapter replay is
    required before ``VALIDATED_WITNESS`` can be returned.
    """

    def __init__(
        self,
        workspace: Workspace,
        objective: Objective,
        authorization: Authorization,
        *,
        harness_sinks: set[str] | frozenset[str] = frozenset(),
        adapter: Any | None = None,
        source_index: Any | None = None,
        source_profile: Any | None = None,
    ) -> None:
        if (source_index is None) != (source_profile is None):
            raise ValueError("source_index and source_profile must be supplied together")
        source_notes: list[str] = []
        source_incomplete = False
        if source_profile is not None:
            if source_profile.target_id != workspace.model.target_id:
                raise ValueError("source profile and workspace target identities must match")
            source_profile.validate(source_index)
            from .source_semantics import SourceSemanticLowerer

            lowerer = SourceSemanticLowerer()
            existing = {
                (operation.name, operation.entry_point.name)
                for operation in workspace.operations()
            }
            source_operations = []
            for identity, binding in sorted(source_profile.functions.items()):
                result = lowerer.lower(source_index, binding)
                source_notes.extend(
                    f"source lowering for {identity}: {limitation}"
                    for limitation in result.limitations
                )
                if not result.complete:
                    source_incomplete = True
                if result.operation is None:
                    continue
                key = (result.operation.name, result.operation.entry_point.name)
                if key in existing:
                    raise ValueError(
                        f"source profile operation duplicates workspace operation {key[0]} at {key[1]}"
                    )
                existing.add(key)
                source_operations.append(result.operation)
            if source_profile.functions and not source_operations:
                source_incomplete = True
            if source_operations:
                model = replace(
                    workspace.model,
                    operations=workspace.model.operations + tuple(source_operations),
                )
                workspace = replace(workspace, model=model)
        if workspace.model.target_id != objective.target_id:
            raise ValueError("workspace and objective target identities must match")
        objective.validate(
            authorization,
            harness_sinks=harness_sinks,
            environment=workspace.start().environment.as_dict(),
        )
        self.workspace = workspace
        self.objective = objective
        self.authorization = authorization
        self.adapter = adapter
        self.source_index = source_index
        self.source_profile = source_profile
        from .planner import Regressor

        self.capability_index = Index.build(workspace.model)
        self.refinements: list[Refinement] = []
        objective_keys = objective.state_keys or Regressor._keys(objective.postconditions)
        self.objective_operations = {
            (item.entry, item.operation.name)
            for item in self.capability_index.chain(objective_keys)
        }
        self.plan = Regressor().regress(
            workspace.model,
            objective,
            workspace=workspace,
            solver_timeout_ms=objective.budget.solver_timeout_ms,
        )
        self.notes = list(self.plan.uncertainty) + source_notes
        self._requests: dict[str, tuple[Mapping[str, Any], ...]] | None = None
        self._prepared = False
        self._baseline: Any = None
        self._incomplete = source_incomplete

    def close(self) -> None:
        if self._prepared and self.adapter is not None:
            self.adapter.teardown()
            self._prepared = False

    def _prepare(self) -> None:
        if self.adapter is not None and not self._prepared:
            self.adapter.prepare()
            self._baseline = self.adapter.snapshot()
            self._prepared = True

    def _entries(self) -> tuple[str, ...]:
        return tuple(sorted({item.entry_point.name for item in self.workspace.operations()}))

    def _domains(self) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
        if self._requests is not None:
            return self._requests
        values: dict[str, list[Mapping[str, Any]]] = {entry: [] for entry in self._entries()}
        for entry, request in self.plan.required_actions:
            values.setdefault(entry, []).append(dict(request))
        for entry in tuple(values):
            try:
                values[entry].extend(self.workspace.probes_for(entry, self.objective.budget.max_states))
            except Exception as exc:
                self.notes.append(f"probe expansion for {entry} is unknown: {type(exc).__name__}")
        model_requests = self.workspace.model.args()
        remaining = self.objective.budget.max_states
        for entry in values:
            values[entry].extend(model_requests)
            if not values[entry]:
                values[entry].append({})
            unique: dict[str, Mapping[str, Any]] = {}
            for request in values[entry]:
                key = json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)
                unique.setdefault(key, dict(request))
            if len(unique) > remaining:
                self._incomplete = True
                note = f"static request domain exceeded the global state bound {self.objective.budget.max_states}"
                if note not in self.notes:
                    self.notes.append(note)
            values[entry] = list(unique.values())[:remaining]
            remaining -= len(values[entry])
        self._requests = {entry: tuple(requests) for entry, requests in values.items()}
        return self._requests

    def _generated_requests(
        self,
        frame: Frame,
        operations: Sequence[Any] | None = None,
        limit: int | None = None,
    ) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
        """Ask semantic candidate sources for requests at this reached state."""
        generated: dict[str, list[Mapping[str, Any]]] = {}
        bound = self.objective.budget.max_states if limit is None else max(0, limit)
        remaining = bound
        for operation in operations or self.workspace.operations():
            source = operation.request_candidates
            if source is None:
                continue
            entry = operation.entry_point.name
            try:
                candidates = iter(source(self.workspace._local(frame, operation), self.objective))
                for index, request in enumerate(islice(candidates, remaining + 1)):
                    if index >= remaining:
                        self._incomplete = True
                        note = f"request candidates for {entry} exceeded the per-state bound {bound}"
                        if note not in self.notes:
                            self.notes.append(note)
                        break
                    generated.setdefault(entry, []).append(dict(request))
                    remaining -= 1
            except Exception as exc:
                self._incomplete = True
                note = f"request candidates for {entry} are unknown: {type(exc).__name__}"
                if note not in self.notes:
                    self.notes.append(note)
        result: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for entry, requests in generated.items():
            unique: dict[str, Mapping[str, Any]] = {}
            for request in requests:
                key = json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)
                unique.setdefault(key, dict(request))
            result[entry] = tuple(unique.values())
        return result

    def seeds(self) -> tuple[tuple[Mapping[str, Any], ...], ...]:
        found: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for trace in self.plan.required_traces:
            candidate = tuple(dict(item) for item in trace)
            found.setdefault(self._key(candidate), candidate)
        for entry, request in self.plan.required_actions:
            candidate = ({"entry_point": entry, "request": dict(request)},)
            found.setdefault(self._key(candidate), candidate)
        initial = self.workspace.start()
        for entry, requests in self._generated_requests(initial).items():
            for request in requests:
                candidate = ({"entry_point": entry, "request": dict(request)},)
                found.setdefault(self._key(candidate), candidate)
        if not found:
            for entry, requests in self._domains().items():
                for request in requests:
                    candidate = ({"entry_point": entry, "request": dict(request)},)
                    found.setdefault(self._key(candidate), candidate)
        candidates = tuple(found.values())
        if len(candidates) > self.objective.budget.max_states:
            self._incomplete = True
            note = f"seed candidates exceeded the global state bound {self.objective.budget.max_states}"
            if note not in self.notes:
                self.notes.append(note)
        return candidates[: self.objective.budget.max_states]

    def expand(self, candidate: tuple[Mapping[str, Any], ...]) -> tuple[tuple[Mapping[str, Any], ...], ...]:
        if len(candidate) >= self.objective.budget.max_trace_length:
            return ()
        result: list[tuple[Mapping[str, Any], ...]] = []
        seen: set[str] = set()
        domains = {entry: list(requests) for entry, requests in self._domains().items()}
        dynamic_limit = max(0, self.objective.budget.max_states - sum(map(len, domains.values())))
        for frame, _events, _uncertain in self._model(candidate):
            if dynamic_limit <= 0 and self._incomplete:
                break
            generated = self._generated_requests(frame, limit=dynamic_limit)
            generated_count = sum(map(len, generated.values()))
            dynamic_limit -= generated_count
            for entry, requests in generated.items():
                domains.setdefault(entry, []).extend(requests)
        for entry, requests in domains.items():
            for request in requests:
                if not self.workspace.model.allows(entry, request):
                    continue
                expanded = candidate + ({"entry_point": entry, "request": dict(request)},)
                key = self._key(expanded)
                if key in seen:
                    continue
                if len(result) >= self.objective.budget.max_states:
                    self._incomplete = True
                    note = f"expanded candidates exceeded the global state bound {self.objective.budget.max_states}"
                    if note not in self.notes:
                        self.notes.append(note)
                    return tuple(result)
                seen.add(key)
                result.append(expanded)
        return tuple(result)

    def _model(self, candidate: Sequence[Mapping[str, Any]]) -> tuple[tuple[Frame, tuple[Event, ...], bool], ...]:
        frontier: list[tuple[Frame, tuple[Event, ...], bool]] = [(self.workspace.start(), (), False)]
        for index, interaction in enumerate(candidate):
            entry = str(interaction["entry_point"])
            request = dict(interaction.get("request", {}))
            if not self.workspace.model.allows(entry, request):
                return ()
            operations = self.workspace.operations(entry)
            if not operations:
                return ()
            next_frontier: list[tuple[Frame, tuple[Event, ...], bool]] = []
            truncated = False
            for frame, events, uncertain in frontier:
                for operation in operations:
                    for move in self.workspace.moves(frame, entry, request, operation=operation):
                        if len(next_frontier) >= self.objective.budget.max_states:
                            truncated = True
                            break
                        event = replace(move.event, ordering=len(events))
                        next_frontier.append((move.after, events + (event,), uncertain or move.after.uncertain))
                    if truncated:
                        break
                if truncated:
                    break
            if truncated:
                self._incomplete = True
                note = "workspace candidate branches were bounded by max_states"
                if note not in self.notes:
                    self.notes.append(note)
            frontier = next_frontier
            if not frontier:
                return ()
        return tuple(frontier)

    def _signature(self, events: Sequence[Event], frame: Frame) -> Signature:
        profile = "workspace"
        scope: dict[str, Any] = {
            "model_version": self.workspace.model.model_version,
            "build_hash": self.workspace.model.build_hash,
            "objective_version": self.objective.version,
        }
        if self.source_profile is not None:
            profile_record = self.source_profile.canonical()
            profile_payload = json.dumps(profile_record, sort_keys=True, separators=(",", ":"), default=str)
            profile_digest = hashlib.sha256(profile_payload.encode()).hexdigest()
            profile = str(self.source_profile.profile_id)
            scope.update({
                "source_profile_id": profile,
                "source_profile_digest": profile_digest,
            })
        if self.adapter is not None:
            try:
                identity = self.adapter.identity()
                profile = str(identity.get("profile_id", identity.get("version", "adapter")))
                scope.update({str(key): value for key, value in identity.items()})
            except Exception as exc:
                self.notes.append(f"adapter identity is unknown: {type(exc).__name__}")
        return Signature.make(
            tuple(events),
            frame,
            target=self.workspace.model.target_id,
            profile=profile,
            keys=self.objective.state_keys,
            scope=scope,
        )

    def _priority_metrics(
        self,
        frame: Frame,
        events: Sequence[Event],
    ) -> dict[str, Any]:
        initial = self.workspace.start().view()
        current = frame.view()
        satisfied_now = sum(
            predicate.evaluate(current, events)
            for predicate in self.objective.postconditions
        )
        satisfied_initially = sum(
            predicate.evaluate(initial, ())
            for predicate in self.objective.postconditions
        )
        addressed = sum(
            not predicate.evaluate(initial, ()) and predicate.evaluate(current, events)
            for predicate in self.objective.postconditions
        )
        changed: set[str] = set()
        resolved: set[str] = set()
        for event in events:
            before = event.before.as_dict()
            after = event.after.as_dict()
            changed.update(
                key for key in before.keys() | after.keys()
                if before.get(key) != after.get(key)
            )
            changed.update(event.writes)
            declarations = event.observation.get("uncertainty_resolved", ())
            if isinstance(declarations, str):
                resolved.add(declarations)
            elif isinstance(declarations, (tuple, list, set, frozenset)):
                resolved.update(str(item) for item in declarations)
        relevant_readers = {
            (item.entry, item.operation.name)
            for item in self.capability_index.readers(changed)
            if (item.entry, item.operation.name) in self.objective_operations
        }
        return {
            "progress": satisfied_now / max(1, len(self.objective.postconditions)),
            "addressed_conditions": max(0, satisfied_now - satisfied_initially, addressed),
            "exposed_transitions": tuple(sorted({event.operation for event in events})),
            "uncertainty_resolved": tuple(sorted(resolved)),
            "route_potential": len(relevant_readers),
        }

    def _replay(self, candidate: tuple[Mapping[str, Any], ...], predicted: Trial) -> Trial:
        self._prepare()
        outcomes: list[bool] = []
        signatures: list[str] = []
        observed_events: tuple[Event, ...] = ()
        try:
            for _ in range(self.objective.budget.replay_runs):
                self.adapter.reset(self._baseline)
                observed_events = tuple(self.adapter.trace(candidate, self.authorization))
                final = observed_events[-1].after if observed_events else self.workspace.model.initial_state
                result = self.objective.evaluate(final, observed_events)
                result = result and self.objective.satisfy(self.workspace.start().view(), observed_events)
                outcomes.append(result)
                signatures.append(json.dumps([event.canonical() for event in observed_events], sort_keys=True, default=str))
        except Exception as exc:
            return Trial(
                False,
                predicted.signature,
                f"authorized replay failed: {type(exc).__name__}",
                Status.UNKNOWN,
                predicted.progress,
                model_events=predicted.model_events,
                addressed_conditions=predicted.addressed_conditions,
                exposed_transitions=predicted.exposed_transitions,
                uncertainty_resolved=predicted.uncertainty_resolved,
                route_potential=predicted.route_potential,
            )
        accepted = bool(outcomes) and all(outcomes)
        stable = bool(outcomes) and len(set(outcomes)) == 1 and len(set(signatures)) == 1
        divergences = Analyzer().compare(predicted.model_events, observed_events) if predicted.model_events else ()
        if accepted != predicted.accepted and not divergences:
            divergences = (Divergence(
                index=max(0, len(predicted.model_events) - 1),
                kind="objective_or_decomposition_defect",
                expected={"objective_satisfied": predicted.accepted},
                observed={"objective_satisfied": accepted},
                detail="the replay objective result differs despite aligned semantic events",
                observed_index=max(0, len(observed_events) - 1),
            ),)
        refinement_records: tuple[Refinement, ...] = ()
        if divergences:
            from .planner import Regressor

            previous_revision = self.workspace.model.model_version
            affected_entries = tuple(dict.fromkeys(
                event.entry_point for event in tuple(predicted.model_events) + observed_events
            ))
            refinement = Analyzer().refine(
                self.workspace.model,
                divergences,
                observed_events,
                invalidated_queries=(
                    f"guide-plan:{self.objective.objective_id}:{previous_revision}",
                    *(f"guide-route:{entry}:{previous_revision}" for entry in affected_entries),
                ),
            )
            refinement_records = (refinement,)
            self.refinements.append(refinement)
            self.workspace = replace(self.workspace, model=refinement.model)
            self.capability_index = Index.build(self.workspace.model)
            objective_keys = self.objective.state_keys or Regressor._keys(self.objective.postconditions)
            self.objective_operations = {
                (item.entry, item.operation.name)
                for item in self.capability_index.chain(objective_keys)
            }
            self.plan = Regressor().regress(
                self.workspace.model,
                self.objective,
                workspace=self.workspace,
                solver_timeout_ms=self.objective.budget.solver_timeout_ms,
            )
            self._requests = None
            note = f"model refined {previous_revision} -> {refinement.model.model_version}: {refinement.delta.description}"
            if note not in self.notes:
                self.notes.append(note)
            self.notes.extend(item for item in self.plan.uncertainty if item not in self.notes)
        status = (
            Status.MODEL_DIVERGENCE
            if divergences or accepted != predicted.accepted
            else Status.VALIDATED_WITNESS
            if accepted and stable and predicted.accepted
            else Status.SAT_CANDIDATE
        )
        return Trial(
            accepted and not divergences,
            predicted.signature,
            "replay did not match the model" if accepted != predicted.accepted or divergences else "",
            status,
            predicted.progress,
            True,
            stable,
            model_events=predicted.model_events,
            observed_events=observed_events,
            divergences=divergences,
            addressed_conditions=predicted.addressed_conditions,
            exposed_transitions=predicted.exposed_transitions,
            uncertainty_resolved=predicted.uncertainty_resolved,
            route_potential=predicted.route_potential,
            refinements=refinement_records,
        )

    def assess(self, candidate: tuple[Mapping[str, Any], ...]) -> Trial:
        branches = self._model(candidate)
        if not branches:
            return Trial(False, None, "candidate has no modeled successor", Status.UNKNOWN)
        best: tuple[float, Frame, tuple[Event, ...], bool, bool, dict[str, Any]] | None = None
        for frame, events, uncertain in branches:
            metrics = self._priority_metrics(frame, events)
            progress = metrics["progress"]
            accepted = self.objective.evaluate(frame.view(), events) and self.objective.satisfy(self.workspace.start().view(), events)
            item = (progress, frame, events, uncertain, accepted, metrics)
            item_priority = CandidatePriority(
                objective_progress=progress,
                addressed_conditions=metrics["addressed_conditions"],
                exposed_transitions=len(metrics["exposed_transitions"]),
                uncertainty_resolved=len(metrics["uncertainty_resolved"]),
                route_potential=metrics["route_potential"],
            ).score
            best_priority = CandidatePriority(
                objective_progress=best[0],
                addressed_conditions=best[5]["addressed_conditions"],
                exposed_transitions=len(best[5]["exposed_transitions"]),
                uncertainty_resolved=len(best[5]["uncertainty_resolved"]),
                route_potential=best[5]["route_potential"],
            ).score if best is not None else None
            if best is None or item_priority > best_priority:
                best = item
            if accepted and not uncertain:
                signature = self._signature(events, frame)
                trial = Trial(
                    True,
                    signature,
                    status=Status.MODEL_SAT,
                    model_events=events,
                    **metrics,
                )
                return self._replay(candidate, trial) if self.adapter is not None else trial
        assert best is not None
        progress, frame, events, uncertain, accepted, metrics = best
        signature = self._signature(events, frame)
        if accepted and uncertain:
            return Trial(False, signature, "objective reached through an uncertain modeled branch", Status.UNKNOWN, **metrics)
        return Trial(False, signature, "objective not reached in modeled branches", Status.UNKNOWN if uncertain else Status.SAT_CANDIDATE, **metrics)

    @staticmethod
    def _key(candidate: Sequence[Mapping[str, Any]]) -> str:
        return json.dumps(list(candidate), sort_keys=True, separators=(",", ":"), default=str)

    def search(
        self,
        strategy: str | Any = "frontier",
        *,
        budget: Bounds | None = None,
        archive: Archive = Archive(),
        **options: Any,
    ) -> Found:
        strategies = {
            "mcts": Mcts,
            "evolve": Evolve,
            "beam": Beam,
            "frontier": Frontier,
            "anneal": Anneal,
            "portfolio": Portfolio,
        }
        selected = strategies[strategy] if isinstance(strategy, str) else strategy
        runner = selected() if isinstance(selected, type) else selected
        bounds = budget or Bounds(
            max_candidates=self.objective.budget.max_states,
            max_trace_length=max(1, self.objective.budget.max_trace_length),
            max_time_ms=self.objective.budget.max_time_ms,
        )
        try:
            result = runner.search(self.seeds(), self.expand, self.assess, budget=bounds, archive=archive, **options)
            detail = result.detail
            if self.notes:
                detail = "; ".join(filter(None, (detail, "exploration notes: " + " | ".join(dict.fromkeys(self.notes)))))
            status = Status.UNKNOWN if self._incomplete and result.status is Status.UNSAT_BOUNDED else result.status
            if result.refinements and status is Status.UNKNOWN:
                status = Status.MODEL_DIVERGENCE
            return replace(result, status=status, detail=detail, evidence=() if status is not result.status else result.evidence)
        finally:
            self.close()


class Explorer:
    """Explore an expanding interaction domain without claiming completeness."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        evaluate: Callable[[tuple[Mapping[str, Any], ...]], bool],
        *,
        budget: Bounds = Bounds(),
        evidence_level: EvidenceLevel = EvidenceLevel.HYPOTHESIZED,
    ) -> Found:
        queue = [self._normalize(candidate) for candidate in seeds]
        seen: set[str] = set()
        attempts = 0
        generated = len(queue)
        started = time.monotonic()
        budget_hit = False
        while queue:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            candidate = queue.pop(0)
            key = self._key(candidate)
            if key in seen:
                continue
            seen.add(key)
            if len(candidate) > budget.max_trace_length:
                continue
            attempts += 1
            if evaluate(candidate):
                status = {
                    EvidenceLevel.REPLAY_VALIDATED: Status.VALIDATED_WITNESS,
                    EvidenceLevel.MODEL_SATISFIABLE: Status.MODEL_SAT,
                    EvidenceLevel.MODEL_REACHABLE: Status.SAT_CANDIDATE,
                }.get(evidence_level, Status.SAT_CANDIDATE)
                evidence = discovery_evidence(
                    evidence_level,
                    "candidate satisfied the supplied boolean evaluation callback",
                    "explorer-callback",
                    fidelity_scope={"max_trace_length": budget.max_trace_length},
                )
                return Found(
                    status,
                    attempts,
                    generated,
                    candidate,
                    "candidate was accepted by the supplied evaluation callback",
                    self._frontier_digest(queue),
                    evidence=(evidence,),
                )
            for child in expand(candidate):
                normalized = self._normalize(child)
                if len(normalized) <= budget.max_trace_length and self._key(normalized) not in seen:
                    queue.append(normalized)
                    generated += 1
        status = Status.BUDGET_EXHAUSTED if budget_hit else (Status.UNSAT_BOUNDED if generated else Status.UNKNOWN)
        detail = (
            "open interaction domain exhausted its explicit candidate/time budget"
            if budget_hit
            else "no candidate in the generated finite interaction region satisfied the evaluation callback"
            if generated else "no seed candidates were supplied; no search domain was established"
        )
        return Found(status, attempts, generated, detail=detail, frontier_digest=self._frontier_digest(queue))

    @staticmethod
    def _normalize(candidate: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
        return tuple({"entry_point": str(item["entry_point"]), "request": dict(item.get("request", {}))} for item in candidate)

    @staticmethod
    def _key(candidate: Sequence[Mapping[str, Any]]) -> str:
        return json.dumps(list(candidate), sort_keys=True, separators=(",", ":"), default=str)

    @classmethod
    def _frontier_digest(cls, frontier: Sequence[Sequence[Mapping[str, Any]]]) -> str:
        payload = json.dumps([list(item) for item in frontier], sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass
class _Node:
    candidate: tuple[Mapping[str, Any], ...]
    parent: "_Node | None" = None
    children: dict[str, "_Node"] | None = None
    visits: int = 0
    value: float = 0.0
    expanded: bool = False

    def __post_init__(self) -> None:
        if self.children is None:
            self.children = {}


class Mcts:
    """Deterministic, bounded Monte Carlo tree search over behavior novelty.

    ``assess`` must execute or model a candidate and return its objective
    result plus a ``Signature`` derived from that execution. Novelty only
    ranks candidates; ``accepted`` remains the caller's objective decision.
    """

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
        explore: float = 1.41421356237,
    ) -> Found:
        root = _Node(())
        known: set[str] = set()
        generated = 0
        for seed in seeds:
            if generated >= budget.max_candidates:
                break
            candidate = Explorer._normalize(seed)
            key = Explorer._key(candidate)
            if len(candidate) <= budget.max_trace_length and key not in known:
                root.children[key] = _Node(candidate, root)
                known.add(key)
                generated += 1
        if not root.children:
            return Found(Status.UNKNOWN, 0, 0, detail="no seed candidates were supplied; no search domain was established", archive=archive)

        cache: dict[str, Trial] = {}
        attempts = 0
        started = time.monotonic()
        budget_hit = False
        unknown_seen = False
        details: list[str] = []

        while root.children:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            if len(cache) >= len(known):
                break
            node = self._select(root, explore)
            key = Explorer._key(node.candidate)
            trial = cache.get(key)
            if trial is None:
                trial = _assess_candidate(assess, node.candidate)
                cache[key] = trial
                attempts += 1
                unknown_seen = unknown_seen or trial.status in {Status.UNKNOWN, Status.MODEL_DIVERGENCE}
                if trial.signature is None:
                    details.append(f"candidate {key} produced no behavior signature")
                    novelty = 0
                else:
                    archive, observation = archive.offer(trial.signature)
                    novelty = observation.score
                reward = float((10_000 if _accepted(trial) else 0) + trial.priority(novelty).score)
                if _accepted(trial):
                    return Found(
                        trial.status,
                        attempts,
                        generated,
                        node.candidate,
                        "MCTS accepted a candidate after behavior-aware assessment",
                        Explorer._frontier_digest(tuple(item.candidate for item in root.children.values())),
                        archive,
                        evidence=trial.evidence,
                        refinements=trial.refinements,
                    )
                if trial.detail:
                    details.append(trial.detail)
            else:
                reward = float(10_000 if _accepted(trial) else 0) + trial.priority().score
            self._expand(node, expand, known, budget)
            generated = len(known)
            self._back(node, reward)

        status = Status.BUDGET_EXHAUSTED if budget_hit else (Status.UNKNOWN if unknown_seen else Status.UNSAT_BOUNDED)
        detail = (
            "MCTS exhausted its explicit candidate/time budget"
            if budget_hit
            else "MCTS exhausted the generated finite candidate tree"
        )
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(
            status,
            attempts,
            generated,
            detail=detail,
            frontier_digest=Explorer._frontier_digest(tuple(item.candidate for item in root.children.values())),
            archive=archive,
            evidence=_merge_evidence(*(trial.evidence for trial in cache.values())),
            refinements=_merge_refinements(*(trial.refinements for trial in cache.values())),
        )

    @staticmethod
    def _select(root: _Node, explore: float) -> _Node:
        node = root
        while node.children:
            unvisited = [child for child in node.children.values() if child.visits == 0]
            if unvisited:
                return min(unvisited, key=lambda child: Explorer._key(child.candidate))
            parent_visits = max(1, node.visits)
            node = max(
                node.children.values(),
                key=lambda child: (
                    child.value / child.visits
                    + explore * math.sqrt(math.log(parent_visits + 1) / child.visits),
                    Explorer._key(child.candidate),
                ),
            )
        return node

    @staticmethod
    def _expand(
        node: _Node,
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        known: set[str],
        budget: Bounds,
    ) -> None:
        if node.expanded:
            return
        node.expanded = True
        for child in expand(node.candidate):
            if len(known) >= budget.max_candidates:
                break
            candidate = Explorer._normalize(child)
            if len(candidate) > budget.max_trace_length:
                continue
            key = Explorer._key(candidate)
            if key in known:
                continue
            known.add(key)
            node.children[key] = _Node(candidate, node)

    @staticmethod
    def _back(node: _Node, reward: float) -> None:
        current: _Node | None = node
        while current is not None:
            current.visits += 1
            current.value += reward
            current = current.parent


class Evolve:
    """Bounded evolutionary search selected by behavior novelty."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        mutate: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
        size: int = 8,
    ) -> Found:
        if size <= 0:
            raise ValueError("evolution population size must be positive")
        population: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for seed in seeds:
            if len(population) >= budget.max_candidates:
                break
            candidate = Explorer._normalize(seed)
            if len(candidate) <= budget.max_trace_length:
                population.setdefault(Explorer._key(candidate), candidate)
        if not population:
            return Found(Status.UNKNOWN, 0, 0, detail="no seed candidates were supplied; no search domain was established", archive=archive)

        attempts = 0
        generated = len(population)
        started = time.monotonic()
        budget_hit = False
        unknown_seen = False
        details: list[str] = []
        scored_evidence: list[DiscoveryEvidence] = []
        scored_refinements: list[Refinement] = []
        while population:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            scored: list[tuple[float, str, tuple[Mapping[str, Any], ...]]] = []
            for key, candidate in sorted(population.items()):
                if attempts >= budget.max_candidates:
                    budget_hit = True
                    break
                trial = _assess_candidate(assess, candidate)
                attempts += 1
                unknown_seen = unknown_seen or trial.status in {Status.UNKNOWN, Status.MODEL_DIVERGENCE}
                scored_evidence.extend(trial.evidence)
                scored_refinements.extend(trial.refinements)
                novelty = 0.0
                if trial.signature is not None:
                    archive, observation = archive.offer(trial.signature)
                    novelty = float(observation.score)
                else:
                    details.append(f"candidate {key} produced no behavior signature")
                if trial.detail:
                    details.append(trial.detail)
                if _accepted(trial):
                    return Found(
                        trial.status,
                        attempts,
                        generated,
                        candidate,
                        "evolution accepted a candidate after behavior-aware assessment",
                        Explorer._frontier_digest(tuple(population.values())),
                        archive,
                        evidence=trial.evidence,
                        refinements=trial.refinements,
                    )
                scored.append((trial.priority(novelty).score, key, candidate))
            if budget_hit or not scored:
                break
            scored.sort(key=lambda item: (-item[0], item[1]))
            parents = [item[2] for item in scored[:max(1, min(size, len(scored) // 2 or 1))]]
            next_population: dict[str, tuple[Mapping[str, Any], ...]] = {}
            for parent in parents:
                for child in mutate(parent):
                    if generated >= budget.max_candidates:
                        budget_hit = True
                        break
                    candidate = Explorer._normalize(child)
                    if len(candidate) > budget.max_trace_length:
                        continue
                    key = Explorer._key(candidate)
                    if key not in next_population:
                        next_population[key] = candidate
                        generated += 1
                    if len(next_population) >= size:
                        break
                if len(next_population) >= size:
                    break
            population = next_population
            if budget_hit:
                break

        status = Status.BUDGET_EXHAUSTED if budget_hit else (Status.UNKNOWN if unknown_seen else Status.UNSAT_BOUNDED)
        detail = (
            "evolution exhausted its explicit candidate/time budget"
            if budget_hit
            else "evolution exhausted the generated finite candidate population"
        )
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(
            status,
            attempts,
            generated,
            detail=detail,
            frontier_digest=Explorer._frontier_digest(tuple(population.values())),
            archive=archive,
            evidence=_merge_evidence(*scored_evidence),
            refinements=_merge_refinements(*scored_refinements),
        )


class Beam:
    """Layer-wise novelty search that retains a bounded diverse beam."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
        width: int = 8,
    ) -> Found:
        if width <= 0:
            raise ValueError("beam width must be positive")
        population = self._seeds(seeds, budget)
        if not population:
            return Found(Status.UNKNOWN, 0, 0, detail="no seed candidates were supplied; no search domain was established", archive=archive)
        known = {Explorer._key(item) for item in population}
        attempts = 0
        generated = len(population)
        started = time.monotonic()
        details: list[str] = []
        budget_hit = False
        unknown_seen = False
        scored_evidence: list[DiscoveryEvidence] = []
        scored_refinements: list[Refinement] = []
        while population:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            scored: list[tuple[float, str, tuple[Mapping[str, Any], ...]]] = []
            for candidate in sorted(population, key=Explorer._key):
                if attempts >= budget.max_candidates:
                    budget_hit = True
                    break
                trial = _assess_candidate(assess, candidate)
                attempts += 1
                unknown_seen = unknown_seen or trial.status in {Status.UNKNOWN, Status.MODEL_DIVERGENCE}
                scored_evidence.extend(trial.evidence)
                scored_refinements.extend(trial.refinements)
                priority, detail = self._novel(trial, archive)
                if trial.signature is not None:
                    archive, _ = archive.offer(trial.signature)
                if detail:
                    details.append(detail)
                if trial.detail:
                    details.append(trial.detail)
                if _accepted(trial):
                    return Found(
                        trial.status, attempts, generated, candidate,
                        "beam accepted a behavior-assessed candidate", archive=archive,
                        evidence=trial.evidence,
                        refinements=trial.refinements,
                    )
                scored.append((priority, Explorer._key(candidate), candidate))
            if budget_hit or not scored:
                break
            scored.sort(key=lambda item: (-item[0], item[1]))
            children: dict[str, tuple[Mapping[str, Any], ...]] = {}
            for _novelty, _key, parent in scored[:width]:
                for child in expand(parent):
                    if generated >= budget.max_candidates:
                        budget_hit = True
                        break
                    candidate = Explorer._normalize(child)
                    if len(candidate) > budget.max_trace_length:
                        continue
                    key = Explorer._key(candidate)
                    if key not in known and key not in children:
                        children[key] = candidate
                        known.add(key)
                        generated += 1
                    if len(children) >= width:
                        break
                if len(children) >= width:
                    break
            population = tuple(children.values())
            if budget_hit:
                break
        status = Status.BUDGET_EXHAUSTED if budget_hit else (Status.UNKNOWN if unknown_seen else Status.UNSAT_BOUNDED)
        detail = "beam exhausted its explicit candidate/time budget" if budget_hit else "beam exhausted the generated finite layers"
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(
            status,
            attempts,
            generated,
            detail=detail,
            archive=archive,
            evidence=_merge_evidence(tuple(scored_evidence)),
            refinements=_merge_refinements(tuple(scored_refinements)),
        )

    @staticmethod
    def _seeds(seeds: Iterable[Sequence[Mapping[str, Any]]], budget: Bounds) -> tuple[tuple[Mapping[str, Any], ...], ...]:
        found: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for seed in seeds:
            if len(found) >= budget.max_candidates:
                break
            candidate = Explorer._normalize(seed)
            if len(candidate) <= budget.max_trace_length:
                found.setdefault(Explorer._key(candidate), candidate)
        return tuple(found.values())

    @staticmethod
    def _novel(trial: Trial, archive: Archive) -> tuple[float, str | None]:
        if trial.signature is None:
            return trial.priority().score, "candidate produced no behavior signature"
        _, novelty = archive.offer(trial.signature)
        return trial.priority(float(novelty.score)).score, None


class Frontier:
    """Best-first novelty search over an explicitly generated candidate frontier."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
    ) -> Found:
        queue: list[tuple[float, str, tuple[Mapping[str, Any], ...]]] = []
        known: set[str] = set()
        for seed in seeds:
            if len(known) >= budget.max_candidates:
                break
            candidate = Explorer._normalize(seed)
            if len(candidate) <= budget.max_trace_length:
                key = Explorer._key(candidate)
                if key not in known:
                    known.add(key)
                    heapq.heappush(queue, (0, key, candidate))
        if not queue:
            return Found(Status.UNKNOWN, 0, 0, detail="no seed candidates were supplied; no search domain was established", archive=archive)
        attempts = 0
        generated = len(known)
        started = time.monotonic()
        budget_hit = False
        details: list[str] = []
        evidence_records: list[DiscoveryEvidence] = []
        refinement_records: list[Refinement] = []
        unknown_seen = False
        while queue:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            _priority, key, candidate = heapq.heappop(queue)
            trial = _assess_candidate(assess, candidate)
            attempts += 1
            unknown_seen = unknown_seen or trial.status in {Status.UNKNOWN, Status.MODEL_DIVERGENCE}
            evidence_records.extend(trial.evidence)
            refinement_records.extend(trial.refinements)
            novelty, detail = Beam._novel(trial, archive)
            if trial.signature is not None:
                archive, _ = archive.offer(trial.signature)
            if detail:
                details.append(detail)
            if trial.detail:
                details.append(trial.detail)
            if _accepted(trial):
                return Found(
                    trial.status, attempts, generated, candidate,
                    "frontier accepted a behavior-assessed candidate", archive=archive,
                    evidence=trial.evidence,
                    refinements=trial.refinements,
                )
            for child in expand(candidate):
                if generated >= budget.max_candidates:
                    budget_hit = True
                    break
                normalized = Explorer._normalize(child)
                if len(normalized) > budget.max_trace_length:
                    continue
                child_key = Explorer._key(normalized)
                if child_key in known:
                    continue
                known.add(child_key)
                generated += 1
                heapq.heappush(queue, (-novelty, child_key, normalized))
            if budget_hit:
                break
        status = Status.BUDGET_EXHAUSTED if budget_hit else (Status.UNKNOWN if unknown_seen else Status.UNSAT_BOUNDED)
        detail = "frontier exhausted its explicit candidate/time budget" if budget_hit else "frontier exhausted the generated finite candidates"
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(
            status,
            attempts,
            generated,
            detail=detail,
            frontier_digest=Explorer._frontier_digest(tuple(item[2] for item in queue)),
            archive=archive,
            evidence=_merge_evidence(tuple(evidence_records)),
            refinements=_merge_refinements(tuple(refinement_records)),
        )


class Anneal:
    """Deterministic simulated-annealing search over behavior signatures."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        mutate: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
        seed: int = 0,
        start: float = 3.0,
        cool: float = 0.85,
    ) -> Found:
        if start <= 0 or not 0 < cool < 1:
            raise ValueError("annealing requires positive start temperature and cooling in (0, 1)")
        population = Beam._seeds(seeds, budget)
        if not population:
            return Found(Status.UNKNOWN, 0, 0, detail="no seed candidates were supplied; no search domain was established", archive=archive)
        current = min(population, key=Explorer._key)
        known = {Explorer._key(item) for item in population}
        attempts = 0
        generated = len(known)
        started = time.monotonic()
        temperature = start
        rng = random.Random(seed)
        details: list[str] = []
        evidence_records: list[DiscoveryEvidence] = []
        refinement_records: list[Refinement] = []
        unknown_seen = False
        current_score = 0
        budget_hit = False
        while attempts < budget.max_candidates:
            if (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            trial = _assess_candidate(assess, current)
            attempts += 1
            unknown_seen = unknown_seen or trial.status in {Status.UNKNOWN, Status.MODEL_DIVERGENCE}
            evidence_records.extend(trial.evidence)
            refinement_records.extend(trial.refinements)
            score, detail = Beam._novel(trial, archive)
            if trial.signature is not None:
                archive, _ = archive.offer(trial.signature)
            if detail:
                details.append(detail)
            if trial.detail:
                details.append(trial.detail)
            if _accepted(trial):
                return Found(
                    trial.status, attempts, generated, current,
                    "annealing accepted a behavior-assessed candidate", archive=archive,
                    evidence=trial.evidence,
                    refinements=trial.refinements,
                )
            current_score = score
            candidates: list[tuple[float, str, tuple[Mapping[str, Any], ...]]] = []
            for child in mutate(current):
                if attempts >= budget.max_candidates:
                    budget_hit = True
                    break
                candidate = Explorer._normalize(child)
                if len(candidate) > budget.max_trace_length:
                    continue
                key = Explorer._key(candidate)
                if key in known:
                    continue
                known.add(key)
                generated += 1
                child_trial = _assess_candidate(assess, candidate)
                attempts += 1
                unknown_seen = unknown_seen or child_trial.status in {Status.UNKNOWN, Status.MODEL_DIVERGENCE}
                evidence_records.extend(child_trial.evidence)
                refinement_records.extend(child_trial.refinements)
                child_score, child_detail = Beam._novel(child_trial, archive)
                if child_trial.signature is not None:
                    archive, _ = archive.offer(child_trial.signature)
                if child_detail:
                    details.append(child_detail)
                if child_trial.detail:
                    details.append(child_trial.detail)
                if _accepted(child_trial):
                    return Found(
                        child_trial.status, attempts, generated, candidate,
                        "annealing accepted a behavior-assessed candidate", archive=archive,
                        evidence=child_trial.evidence,
                        refinements=child_trial.refinements,
                    )
                candidates.append((child_score, key, candidate))
                if attempts >= budget.max_candidates:
                    budget_hit = True
                    break
            if budget_hit or not candidates:
                break
            candidates.sort(key=lambda item: (-item[0], item[1]))
            score, _key, candidate = candidates[0]
            delta = score - current_score
            probability = 1.0 if delta >= 0 else math.exp(delta / max(temperature, 1e-9))
            if delta >= 0 or rng.random() < probability:
                current = candidate
                current_score = score
            temperature *= cool
        status = (
            Status.BUDGET_EXHAUSTED
            if budget_hit or attempts >= budget.max_candidates
            else Status.UNKNOWN if unknown_seen else Status.UNSAT_BOUNDED
        )
        detail = "annealing exhausted its explicit candidate/time budget" if status is Status.BUDGET_EXHAUSTED else "annealing exhausted the generated mutation neighborhood"
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(
            status,
            attempts,
            generated,
            detail=detail,
            archive=archive,
            evidence=_merge_evidence(tuple(evidence_records)),
            refinements=_merge_refinements(tuple(refinement_records)),
        )


class Portfolio:
    """Run complementary behavior searches over one shared semantic archive."""

    DEFAULT_STRATEGIES = ("mcts", "evolve", "beam", "frontier", "anneal")
    RUNNERS = {
        "mcts": Mcts,
        "evolve": Evolve,
        "beam": Beam,
        "frontier": Frontier,
        "anneal": Anneal,
    }

    def __init__(self, strategies: Sequence[str] = DEFAULT_STRATEGIES) -> None:
        if not strategies or any(name not in self.RUNNERS for name in strategies):
            raise ValueError("portfolio strategies must be a non-empty list of supported search names")
        self.strategies = tuple(dict.fromkeys(strategies))

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
        strategy_options: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> Found:
        seed_pool = tuple(seeds)
        if not seed_pool:
            return Found(Status.UNKNOWN, 0, 0, detail="no seed candidates were supplied; no search domain was established", archive=archive)
        options = strategy_options or {}
        unknown = set(options) - set(self.strategies)
        if unknown:
            raise ValueError(f"options supplied for strategies outside this portfolio: {', '.join(sorted(unknown))}")

        attempts = 0
        generated = 0
        details: list[str] = []
        frontier_digest = ""
        started = time.monotonic()
        strategy_budget_hit = False
        unknown_seen = False
        evidence_records: list[DiscoveryEvidence] = []
        refinement_records: list[Refinement] = []
        for index, name in enumerate(self.strategies):
            remaining_candidates = budget.max_candidates - attempts
            remaining_time = budget.max_time_ms - int((time.monotonic() - started) * 1000)
            if remaining_candidates <= 0 or remaining_time <= 0:
                return Found(
                    Status.BUDGET_EXHAUSTED,
                    attempts,
                    generated,
                    detail="portfolio exhausted its aggregate candidate/time budget",
                    frontier_digest=frontier_digest,
                    archive=archive,
                    evidence=_merge_evidence(tuple(evidence_records)),
                    refinements=_merge_refinements(tuple(refinement_records)),
                )
            remaining_strategies = len(self.strategies) - index
            local_budget = Bounds(
                max_candidates=max(1, remaining_candidates // remaining_strategies),
                max_trace_length=budget.max_trace_length,
                max_time_ms=max(1, remaining_time // remaining_strategies),
            )
            runner = self.RUNNERS[name]()
            result = runner.search(
                seed_pool,
                expand,
                assess,
                budget=local_budget,
                archive=archive,
                **dict(options.get(name, {})),
            )
            attempts += result.attempts
            generated += result.generated
            evidence_records.extend(result.evidence)
            refinement_records.extend(result.refinements)
            archive = result.archive
            frontier_digest = result.frontier_digest
            strategy_budget_hit = strategy_budget_hit or result.status is Status.BUDGET_EXHAUSTED
            unknown_seen = unknown_seen or result.status in {Status.UNKNOWN, Status.MODEL_DIVERGENCE}
            if result.detail:
                details.append(f"{name}: {result.detail}")
            if result.status in {Status.VALIDATED_WITNESS, Status.MODEL_SAT, Status.SAT_CANDIDATE}:
                return Found(
                    result.status,
                    attempts,
                    generated,
                    result.candidate,
                    f"portfolio found a candidate with {name}; " + "; ".join(details),
                    frontier_digest,
                    archive,
                    evidence=result.evidence,
                    refinements=result.refinements,
                )
        exhausted = (
            strategy_budget_hit
            or attempts >= budget.max_candidates
            or (time.monotonic() - started) * 1000 >= budget.max_time_ms
        )
        return Found(
            Status.BUDGET_EXHAUSTED if exhausted else (Status.UNKNOWN if unknown_seen else Status.UNSAT_BOUNDED),
            attempts,
            generated,
            detail=(
                "portfolio exhausted a strategy or aggregate search budget"
                if exhausted
                else "portfolio exhausted each strategy's generated finite region"
            ) + "; " + "; ".join(details),
            frontier_digest=frontier_digest,
            archive=archive,
            evidence=_merge_evidence(tuple(evidence_records)),
            refinements=_merge_refinements(tuple(refinement_records)),
        )
