"""Auditable analysis and divergence result types."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import json
from typing import Any, Mapping

from .model import State, Event, _canonical


class Status(str, Enum):
    VALIDATED_WITNESS = "VALIDATED_WITNESS"
    MODEL_SAT = "MODEL_SAT"
    SAT_CANDIDATE = "SAT_CANDIDATE"
    UNSAT_BOUNDED = "UNSAT_BOUNDED"
    UNKNOWN = "UNKNOWN"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    MODEL_DIVERGENCE = "MODEL_DIVERGENCE"


class Reach(str, Enum):
    """Bounded model reachability, separate from replay/result status."""

    POSSIBLE = "POSSIBLE"
    GUARANTEED = "GUARANTEED"
    UNKNOWN = "UNKNOWN"


class Verdict(str, Enum):
    SAT = "SAT"
    UNSAT_BOUNDED = "UNSAT_BOUNDED"
    UNKNOWN = "UNKNOWN"


class Grade(str, Enum):
    BOUND = "BOUND_EXHAUSTED"
    STATE_BUDGET = "STATE_BUDGET_EXHAUSTED"
    EVENT_BUDGET = "EVENT_BUDGET_EXHAUSTED"
    UNSUPPORTED = "UNSUPPORTED_CAPABILITY"
    ASSUMPTION = "MODEL_ASSUMPTION"
    UNKNOWN = "UNKNOWN_SEMANTICS"


class EvidenceLevel(str, Enum):
    MODEL_RESULT = "MODEL_RESULT"
    IMPORTED_ARTIFACT = "IMPORTED_ARTIFACT"
    RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
    REPRODUCED_RUNTIME_OBSERVATION = "REPRODUCED_RUNTIME_OBSERVATION"
    INDEPENDENTLY_VERIFIED_RESULT = "INDEPENDENTLY_VERIFIED_RESULT"
    HYPOTHESIZED = "HYPOTHESIZED"
    MODEL_SATISFIABLE = "MODEL_SATISFIABLE"
    MODEL_REACHABLE = "MODEL_REACHABLE"
    OBSERVED = "OBSERVED"
    REPLAY_VALIDATED = "REPLAY_VALIDATED"
    BOUNDED_EXHAUSTION = "BOUNDED_EXHAUSTION"


@dataclass(frozen=True)
class DiscoveryEvidence:
    """Auditable support and scope for one analysis claim."""

    evidence_id: str
    level: EvidenceLevel
    claim: str
    source: str
    artifact_refs: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    fidelity_scope: Mapping[str, Any] = field(default_factory=dict)
    execution_profile_id: str = "unknown"
    divergence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence_id or not self.claim or not self.source:
            raise ValueError("discovery evidence identity, claim, and source are required")
        if not isinstance(self.level, EvidenceLevel):
            raise TypeError("discovery evidence level must be an EvidenceLevel")
        object.__setattr__(self, "artifact_refs", tuple(dict.fromkeys(self.artifact_refs)))
        object.__setattr__(self, "assumptions", tuple(dict.fromkeys(self.assumptions)))
        object.__setattr__(self, "divergence_refs", tuple(dict.fromkeys(self.divergence_refs)))
        object.__setattr__(self, "fidelity_scope", dict(self.fidelity_scope))

    def canonical(self) -> dict[str, Any]:
        return _canonical({
            "evidence_id": self.evidence_id,
            "level": self.level.value,
            "claim": self.claim,
            "source": self.source,
            "artifact_refs": self.artifact_refs,
            "assumptions": self.assumptions,
            "fidelity_scope": self.fidelity_scope,
            "execution_profile_id": self.execution_profile_id,
            "divergence_refs": self.divergence_refs,
        })


def discovery_evidence(
    level: EvidenceLevel,
    claim: str,
    source: str,
    *,
    artifact_refs: tuple[str, ...] = (),
    assumptions: tuple[str, ...] = (),
    fidelity_scope: Mapping[str, Any] | None = None,
    execution_profile_id: str = "unknown",
    divergence_refs: tuple[str, ...] = (),
) -> DiscoveryEvidence:
    payload = {
        "level": level.value,
        "claim": claim,
        "source": source,
        "artifact_refs": artifact_refs,
        "assumptions": assumptions,
        "fidelity_scope": fidelity_scope or {},
        "execution_profile_id": execution_profile_id,
        "divergence_refs": divergence_refs,
    }
    identity = hashlib.sha256(
        json.dumps(_canonical(payload), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:20]
    return DiscoveryEvidence(
        f"discovery:{identity}",
        level,
        claim,
        source,
        artifact_refs,
        assumptions,
        fidelity_scope or {},
        execution_profile_id,
        divergence_refs,
    )


@dataclass(frozen=True)
class Witness:
    objective: str
    target_id: str
    events: tuple[Event, ...]
    final_state: State
    validated: bool = True
    model_aligned: bool | None = None
    predicted_events: tuple[Event, ...] = ()
    interactions: tuple[Mapping[str, Any], ...] = ()
    input_refs: tuple[str, ...] = ()
    state_checkpoints: tuple[Mapping[str, Any], ...] = ()
    environment: Mapping[str, str] = field(default_factory=dict)
    replay_result: Mapping[str, Any] = field(default_factory=dict)
    fidelity_scope: Mapping[str, Any] = field(default_factory=dict)
    evidence: tuple[DiscoveryEvidence, ...] = ()

    def canonical(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "target_id": self.target_id,
            "events": [event.canonical() for event in self.events],
            "final_state": self.final_state.canonical(),
            "validated": self.validated,
            "model_aligned": self.model_aligned,
            "predicted_events": [event.canonical() for event in self.predicted_events],
            "interactions": [_canonical(interaction) for interaction in self.interactions],
            "input_refs": list(self.input_refs),
            "state_checkpoints": [_canonical(checkpoint) for checkpoint in self.state_checkpoints],
            "environment": _canonical(self.environment),
            "replay_result": _canonical(self.replay_result),
            "fidelity_scope": _canonical(self.fidelity_scope),
            "evidence": [item.canonical() for item in self.evidence],
        }


@dataclass(frozen=True)
class Proof:
    status: Verdict
    bound: int
    explored_states: int
    explored_events: int
    scope: str
    query: str
    assumptions: tuple[str, ...] = ()
    artifact_ref: str | None = None
    named_core: tuple[str, ...] = ()
    proof_artifact_ref: str | None = None
    backend: str = "bounded-engine"
    backend_version: str = "unknown"
    options: Mapping[str, Any] = field(default_factory=dict)
    fidelity_limitations: tuple[str, ...] = ()
    execution_profile_id: str = "unknown"


@dataclass(frozen=True)
class Gap:
    kind: Grade
    detail: str
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Divergence:
    index: int
    kind: str
    expected: Any
    observed: Any
    detail: str
    observed_index: int | None = None


@dataclass(frozen=True)
class Report:
    status: Status
    target_id: str
    objective: str
    witness: Witness | None
    proof: Proof
    gaps: tuple[Gap, ...] = ()
    explored_states: int = 0
    explored_events: int = 0
    model_version: str = "1"
    build_hash: str = "unknown"
    divergences: tuple[Divergence, ...] = ()
    objective_version: str = "1"
    surface_scope: tuple[str, ...] = ()
    environment: Mapping[str, str] = field(default_factory=dict)
    replay_runs: int = 0
    replay_stable: bool | None = None
    model_aligned: bool | None = None
    evidence_refs: tuple[str, ...] = ()
    unresolved_uncertainty: tuple[str, ...] = ()
    model_revision: str = "unknown"
    execution_profile_id: str = "unknown"
    reachability: Reach = Reach.UNKNOWN
    reachability_scope: str = "bounded workspace model"
    solver_cores: tuple[tuple[str, ...], ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence:
            evidence = _report_evidence(self)
            object.__setattr__(self, "evidence", evidence)
        if self.witness is not None and not self.witness.evidence:
            object.__setattr__(self, "witness", replace(self.witness, evidence=self.evidence))

    def canonical(self) -> dict[str, Any]:
        proof = {
            **self.proof.__dict__,
            "status": self.proof.status.value,
        }
        gaps = [
            {**gap.__dict__, "kind": gap.kind.value}
            for gap in self.gaps
        ]
        return _canonical({
            "status": self.status.value,
            "target_id": self.target_id,
            "objective": self.objective,
            "witness": self.witness.canonical() if self.witness else None,
            "proof": proof,
            "gaps": gaps,
            "explored_states": self.explored_states,
            "explored_events": self.explored_events,
            "model_version": self.model_version,
            "build_hash": self.build_hash,
            "divergences": [divergence.__dict__ for divergence in self.divergences],
            "objective_version": self.objective_version,
            "surface_scope": list(self.surface_scope),
            "environment": _canonical(self.environment),
            "replay_runs": self.replay_runs,
            "replay_stable": self.replay_stable,
            "model_aligned": self.model_aligned,
            "evidence_refs": list(self.evidence_refs),
            "unresolved_uncertainty": list(self.unresolved_uncertainty),
            "model_revision": self.model_revision,
            "execution_profile_id": self.execution_profile_id,
            "reachability": self.reachability.value,
            "reachability_scope": self.reachability_scope,
            "solver_cores": [list(core) for core in self.solver_cores],
            "evidence": [item.canonical() for item in self.evidence],
        })


def _report_evidence(report: Report) -> tuple[DiscoveryEvidence, ...]:
    witness = report.witness
    predicted = (
        witness.predicted_events
        if witness and witness.predicted_events
        else witness.events
        if witness and report.status is not Status.VALIDATED_WITNESS
        else ()
    )
    observed = tuple(
        event for event in (witness.events if witness else ())
        if getattr(event.fidelity, "value", event.fidelity) == "observed"
        or report.replay_runs > 0
    )
    artifact_refs = tuple(dict.fromkeys(
        report.evidence_refs
        + (witness.input_refs if witness else ())
        + tuple(ref for event in (tuple(predicted) + observed) for ref in event.evidence_refs)
    ))
    divergence_refs = tuple(
        f"divergence:{item.index}:{item.kind}" for item in report.divergences
    )
    assumptions = tuple(dict.fromkeys(report.proof.assumptions + report.unresolved_uncertainty))
    scope = {
        "model_version": report.model_version,
        "model_revision": report.model_revision,
        "build_hash": report.build_hash,
        "objective_version": report.objective_version,
        "surface_scope": report.surface_scope,
        "reachability_scope": report.reachability_scope,
        "fidelities": tuple(dict.fromkeys(
            str(getattr(event.fidelity, "value", event.fidelity))
            for event in tuple(predicted) + observed
        )),
    }
    source = report.proof.backend
    records: list[DiscoveryEvidence] = []
    if report.status is Status.UNSAT_BOUNDED and report.proof.status is Verdict.UNSAT_BOUNDED:
        records.append(discovery_evidence(
            EvidenceLevel.BOUNDED_EXHAUSTION,
            "no witness was found within the declared model and bounds",
            source,
            artifact_refs=artifact_refs,
            assumptions=assumptions,
            fidelity_scope=scope,
            execution_profile_id=report.execution_profile_id,
        ))
        return tuple(records)
    if report.status in {Status.BUDGET_EXHAUSTED, Status.UNKNOWN}:
        records.append(discovery_evidence(
            EvidenceLevel.HYPOTHESIZED,
            "analysis ended without an impossibility result; unresolved scope remains",
            source,
            artifact_refs=artifact_refs,
            assumptions=assumptions,
            fidelity_scope=scope,
            execution_profile_id=report.execution_profile_id,
            divergence_refs=divergence_refs,
        ))
    elif predicted:
        records.append(discovery_evidence(
            EvidenceLevel.MODEL_REACHABLE,
            "the recorded route reached the reported state in the bounded model",
            source,
            artifact_refs=artifact_refs,
            assumptions=assumptions,
            fidelity_scope=scope,
            execution_profile_id=report.execution_profile_id,
            divergence_refs=divergence_refs,
        ))
    elif report.proof.status is Verdict.SAT:
        records.append(discovery_evidence(
            EvidenceLevel.MODEL_SATISFIABLE,
            "the reported constraints are satisfiable in the selected model",
            source,
            artifact_refs=artifact_refs,
            assumptions=assumptions,
            fidelity_scope=scope,
            execution_profile_id=report.execution_profile_id,
        ))
    if observed:
        records.append(discovery_evidence(
            EvidenceLevel.OBSERVED,
            "the reported behavior was present in captured execution events",
            "target-adapter",
            artifact_refs=artifact_refs,
            assumptions=assumptions,
            fidelity_scope=scope,
            execution_profile_id=report.execution_profile_id,
            divergence_refs=divergence_refs,
        ))
    if (
        report.status is Status.VALIDATED_WITNESS
        and report.replay_stable is True
        and report.replay_runs > 0
    ):
        records.append(discovery_evidence(
            EvidenceLevel.REPLAY_VALIDATED,
            "the objective reproduced stably against the target under the recorded replay scope",
            "target-adapter-replay",
            artifact_refs=artifact_refs,
            assumptions=assumptions,
            fidelity_scope=scope,
            execution_profile_id=report.execution_profile_id,
            divergence_refs=divergence_refs,
        ))
    if not records:
        records.append(discovery_evidence(
            EvidenceLevel.HYPOTHESIZED,
            "analysis result has no stronger attached evidence classification",
            source,
            artifact_refs=artifact_refs,
            assumptions=assumptions,
            fidelity_scope=scope,
            execution_profile_id=report.execution_profile_id,
            divergence_refs=divergence_refs,
        ))
    return tuple(records)
