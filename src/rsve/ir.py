"""Platform-neutral typed records and the minimal Transform/Transition IR."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .logic import Constraint
from .model import ExecutionMode, Fidelity, Provenance
from .schema import SchemaMixin


class Partiality(str, Enum):
    TOTAL = "total"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class RelationKind(str, Enum):
    FUNCTION = "function"
    RELATION = "relation"
    UNKNOWN = "unknown"


class Invertibility(str, Enum):
    BIJECTIVE = "bijective"
    INJECTIVE = "injective"
    SURJECTIVE = "surjective"
    MANY_TO_ONE = "many_to_one"
    NON_INVERTIBLE = "non_invertible"
    UNKNOWN = "unknown"


class InformationLoss(str, Enum):
    NONE = "none"
    POSSIBLE = "possible"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TargetIdentity(SchemaMixin):
    target_id: str
    runtime: str
    runtime_version: str
    platform: str
    platform_version: str
    build_hash: str
    adapter: str
    adapter_version: str
    capabilities: frozenset[str] = frozenset()
    provenance: Provenance = field(default_factory=lambda: Provenance("identity"))

    def __post_init__(self) -> None:
        if not self.target_id or not self.runtime or not self.platform:
            raise ValueError("target_id, runtime, and platform are required")


@dataclass(frozen=True)
class Representation(SchemaMixin):
    representation_id: str
    type_name: str
    encoding: str = "opaque"
    provenance: Provenance = field(default_factory=lambda: Provenance("model"))

    def __post_init__(self) -> None:
        if not self.representation_id or not self.type_name:
            raise ValueError("representation_id and type_name are required")


@dataclass(frozen=True)
class TypedValue(SchemaMixin):
    value: Any
    representation_id: str
    provenance: Provenance = field(default_factory=lambda: Provenance("model"))


@dataclass(frozen=True)
class Evidence(SchemaMixin):
    evidence_id: str
    tier: Fidelity
    source: str
    reference: str = ""
    conditions: tuple[str, ...] = ()
    redacted: bool = False


@dataclass(frozen=True)
class StateIdentity(SchemaMixin):
    state_id: str
    parent_state_id: str | None = None
    scope: str = "session"


@dataclass(frozen=True)
class StateCheckpoint(SchemaMixin):
    identity: StateIdentity
    values: Mapping[str, Any]
    mode: ExecutionMode
    tier: Fidelity
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Interaction(SchemaMixin):
    ordinal: int
    entry_point: str
    request: Mapping[str, Any]
    state_before: str
    state_after: str | None = None
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if self.ordinal < 0:
            raise ValueError("interaction ordinal must be non-negative")


@dataclass(frozen=True)
class Transform(SchemaMixin):
    transform_id: str
    input_representation: str
    output_representation: str
    semantics_ref: str
    semantics_version: str
    partiality: Partiality
    relation: RelationKind
    invertibility: Invertibility
    information_loss: InformationLoss
    state_effects: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.transform_id or not self.semantics_ref or not self.semantics_version:
            raise ValueError("transform identity and semantics reference/version are required")


@dataclass(frozen=True)
class Recognizer(SchemaMixin):
    recognizer_id: str
    input_representation: str
    actual_predicate_ref: str
    intended_predicate_ref: str | None
    enforcement_point: str
    state_dependencies: tuple[str, ...] = ()
    dominates_effect: bool = False
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Effect(SchemaMixin):
    effect_id: str
    observable: str
    state_effects: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Contract(SchemaMixin):
    contract_id: str
    intended_predicate_ref: str
    observed_enforcement_ref: str
    scope: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Assumption(SchemaMixin):
    assumption_id: str
    statement: str
    tier: Fidelity
    provenance: Provenance
    confidence: str = "unknown"


@dataclass(frozen=True)
class Transition(SchemaMixin):
    transition_id: str
    entry_point: str
    input_representation: str
    output_representation: str
    transform_ids: tuple[str, ...] = ()
    recognizer_ids: tuple[str, ...] = ()
    effect_ids: tuple[str, ...] = ()
    guard_ref: str | None = None
    partiality: Partiality = Partiality.UNKNOWN
    relation: RelationKind = RelationKind.UNKNOWN
    state_effects: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ModelRevision(SchemaMixin):
    revision_id: str
    parent_revision_id: str | None
    target: TargetIdentity
    transitions: tuple[Transition, ...]
    assumptions: tuple[Assumption, ...] = ()
    created_by: str = "rsve"


@dataclass(frozen=True)
class ResultScope(SchemaMixin):
    target_id: str
    build_hash: str
    model_revision_id: str
    max_depth: int
    max_states: int
    environment: Mapping[str, str] = field(default_factory=dict)
    mode: ExecutionMode = ExecutionMode.ABSTRACT
    tier: Fidelity = Fidelity.MODELED
    execution_profile_id: str = "unknown"


@dataclass(frozen=True)
class EnvironmentObservation(SchemaMixin):
    facts: Mapping[str, str]
    unknown: tuple[str, ...] = ()
    redacted_keys: tuple[str, ...] = ()
    profile_id: str = "unknown"
    capabilities: frozenset[str] = frozenset()
    execution_profile_id: str = "unknown"


@dataclass(frozen=True)
class TraceRecord(SchemaMixin):
    trace_id: str
    ordinal: int
    interaction: Interaction
    mode: ExecutionMode
    tier: Fidelity
    state_checkpoint_ids: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ObjectiveCheckpoint(SchemaMixin):
    checkpoint_id: str
    predicate: Constraint
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ObjectiveAst(SchemaMixin):
    objective_id: str
    scope: str
    postcondition: Constraint
    checkpoints: tuple[ObjectiveCheckpoint, ...] = ()
    assumptions: tuple[str, ...] = ()


