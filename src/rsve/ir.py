"""Platform-neutral typed records and the minimal Transform/Transition IR."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .logic import Constraint
from .model import Mode, Fidelity, Provenance
from .schema import Schema


class Partiality(str, Enum):
    TOTAL = "total"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class Relation(str, Enum):
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


class Loss(str, Enum):
    NONE = "none"
    POSSIBLE = "possible"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Identity(Schema):
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
class Representation(Schema):
    representation_id: str
    type_name: str
    encoding: str = "opaque"
    provenance: Provenance = field(default_factory=lambda: Provenance("model"))

    def __post_init__(self) -> None:
        if not self.representation_id or not self.type_name:
            raise ValueError("representation_id and type_name are required")


@dataclass(frozen=True)
class Cell(Schema):
    value: Any
    representation_id: str
    provenance: Provenance = field(default_factory=lambda: Provenance("model"))


@dataclass(frozen=True)
class Evidence(Schema):
    evidence_id: str
    tier: Fidelity
    source: str
    reference: str = ""
    conditions: tuple[str, ...] = ()
    redacted: bool = False


@dataclass(frozen=True)
class Key(Schema):
    state_id: str
    parent_state_id: str | None = None
    scope: str = "session"


@dataclass(frozen=True)
class Checkpoint(Schema):
    identity: Key
    values: Mapping[str, Any]
    mode: Mode
    tier: Fidelity
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Interaction(Schema):
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
class Transform(Schema):
    transform_id: str
    input_representation: str
    output_representation: str
    semantics_ref: str
    semantics_version: str
    partiality: Partiality
    relation: Relation
    invertibility: Invertibility
    information_loss: Loss
    state_effects: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.transform_id or not self.semantics_ref or not self.semantics_version:
            raise ValueError("transform identity and semantics reference/version are required")


@dataclass(frozen=True)
class Semantic(Schema):
    """Executable binding status for one forward/backward semantic relation."""

    semantic_id: str
    semantics_ref: str
    semantics_version: str
    forward: bool = False
    backward: bool = False
    complete: bool = False
    relation: Relation = Relation.UNKNOWN
    partiality: Partiality = Partiality.UNKNOWN
    limitations: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.semantic_id or not self.semantics_ref or not self.semantics_version:
            raise ValueError("semantic identity and reference/version are required")
        if self.complete and not (self.forward and self.backward):
            raise ValueError("complete semantics require forward and backward bindings")


@dataclass(frozen=True)
class Recognizer(Schema):
    recognizer_id: str
    input_representation: str
    actual_predicate_ref: str
    intended_predicate_ref: str | None
    enforcement_point: str
    state_dependencies: tuple[str, ...] = ()
    dominates_effect: bool = False
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Effect(Schema):
    effect_id: str
    observable: str
    state_effects: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Contract(Schema):
    contract_id: str
    intended_predicate_ref: str
    observed_enforcement_ref: str
    scope: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Assumption(Schema):
    assumption_id: str
    statement: str
    tier: Fidelity
    provenance: Provenance
    confidence: str = "unknown"


@dataclass(frozen=True)
class Transition(Schema):
    transition_id: str
    entry_point: str
    input_representation: str
    output_representation: str
    transform_ids: tuple[str, ...] = ()
    recognizer_ids: tuple[str, ...] = ()
    effect_ids: tuple[str, ...] = ()
    guard_ref: str | None = None
    partiality: Partiality = Partiality.UNKNOWN
    relation: Relation = Relation.UNKNOWN
    state_effects: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    region_id: str | None = None


@dataclass(frozen=True)
class Revision(Schema):
    revision_id: str
    parent_revision_id: str | None
    target: Identity
    transitions: tuple[Transition, ...]
    assumptions: tuple[Assumption, ...] = ()
    created_by: str = "rsve"


@dataclass(frozen=True)
class Scope(Schema):
    target_id: str
    build_hash: str
    model_revision_id: str
    max_depth: int
    max_states: int
    environment: Mapping[str, str] = field(default_factory=dict)
    mode: Mode = Mode.ABSTRACT
    tier: Fidelity = Fidelity.MODELED
    execution_profile_id: str = "unknown"


@dataclass(frozen=True)
class Fact(Schema):
    facts: Mapping[str, str]
    unknown: tuple[str, ...] = ()
    redacted_keys: tuple[str, ...] = ()
    profile_id: str = "unknown"
    capabilities: frozenset[str] = frozenset()
    execution_profile_id: str = "unknown"


@dataclass(frozen=True)
class Record(Schema):
    trace_id: str
    ordinal: int
    interaction: Interaction
    mode: Mode
    tier: Fidelity
    state_checkpoint_ids: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Mark(Schema):
    checkpoint_id: str
    predicate: Constraint
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Ast(Schema):
    objective_id: str
    scope: str
    postcondition: Constraint
    checkpoints: tuple[Mark, ...] = ()
    assumptions: tuple[str, ...] = ()


