"""Auditable analysis and divergence result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .model import State, TraceEvent, _canonical


class AnalysisStatus(str, Enum):
    VALIDATED_WITNESS = "VALIDATED_WITNESS"
    MODEL_SAT = "MODEL_SAT"
    SAT_CANDIDATE = "SAT_CANDIDATE"
    UNSAT_BOUNDED = "UNSAT_BOUNDED"
    UNKNOWN = "UNKNOWN"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    MODEL_DIVERGENCE = "MODEL_DIVERGENCE"


class SolverStatus(str, Enum):
    SAT = "SAT"
    UNSAT_BOUNDED = "UNSAT_BOUNDED"
    UNKNOWN = "UNKNOWN"


class GapKind(str, Enum):
    BOUND = "BOUND_EXHAUSTED"
    STATE_BUDGET = "STATE_BUDGET_EXHAUSTED"
    EVENT_BUDGET = "EVENT_BUDGET_EXHAUSTED"
    UNSUPPORTED = "UNSUPPORTED_CAPABILITY"
    ASSUMPTION = "MODEL_ASSUMPTION"


@dataclass(frozen=True)
class Witness:
    objective: str
    target_id: str
    events: tuple[TraceEvent, ...]
    final_state: State
    validated: bool = True
    model_aligned: bool | None = None
    predicted_events: tuple[TraceEvent, ...] = ()
    interactions: tuple[Mapping[str, Any], ...] = ()
    input_refs: tuple[str, ...] = ()
    state_checkpoints: tuple[Mapping[str, Any], ...] = ()
    environment: Mapping[str, str] = field(default_factory=dict)
    replay_result: Mapping[str, Any] = field(default_factory=dict)
    fidelity_scope: Mapping[str, Any] = field(default_factory=dict)

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
        }


@dataclass(frozen=True)
class ProofResult:
    status: SolverStatus
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
class ResidualGap:
    kind: GapKind
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
class AnalysisReport:
    status: AnalysisStatus
    target_id: str
    objective: str
    witness: Witness | None
    proof: ProofResult
    gaps: tuple[ResidualGap, ...] = ()
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
        })
