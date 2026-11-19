"""Typed, runtime-independent model objects used by the analysis engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, TypeAlias

Primitive: TypeAlias = None | bool | int | float | str | bytes
Value: TypeAlias = Primitive | tuple[Primitive, ...]
Request: TypeAlias = Mapping[str, Value]
StatePredicate: TypeAlias = Callable[["State", tuple["TraceEvent", ...]], bool]
Guard: TypeAlias = Callable[["State", Request], bool]
StateUpdate: TypeAlias = Callable[["State", Request], "State"]
Observation: TypeAlias = Callable[["State", Request, "State"], Mapping[str, Value]]


def _canonical(value: Any) -> Any:
    """Return a stable, JSON-like representation for audit records and keys."""
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


class Fidelity(str, Enum):
    OBSERVED = "observed"
    MODELED = "modeled"
    ASSUMED = "assumed"
    SUBSTRATE = "substrate"


class ExecutionMode(str, Enum):
    CONCRETE = "concrete"
    INSTRUMENTED = "instrumented"
    CONCOLIC = "concolic"
    SYMBOLIC = "symbolic"
    EMULATED = "emulated"
    ABSTRACT = "abstract"


@dataclass(frozen=True)
class Provenance:
    source: str
    version: str = "unknown"
    evidence: tuple[str, ...] = ()
    fidelity: Fidelity = Fidelity.ASSUMED


@dataclass(frozen=True)
class EffectLemma:
    """A separately testable intermediate predicate for a larger objective."""

    name: str
    predicate: StatePredicate
    provenance: Provenance = field(default_factory=lambda: Provenance("unspecified"))


@dataclass(frozen=True)
class State:
    """Immutable target/session state with deterministic key ordering."""

    _items: tuple[tuple[str, Value], ...] = field(default_factory=tuple)

    def __init__(self, values: Mapping[str, Value] | None = None, **kwargs: Value) -> None:
        merged = dict(values or {})
        merged.update(kwargs)
        object.__setattr__(self, "_items", tuple(sorted(merged.items(), key=lambda item: item[0])))

    def __getitem__(self, key: str) -> Value:
        for item_key, value in self._items:
            if item_key == key:
                return value
        raise KeyError(key)

    def get(self, key: str, default: Value | None = None) -> Value | None:
        try:
            return self[key]
        except KeyError:
            return default

    def as_dict(self) -> dict[str, Value]:
        return dict(self._items)

    def with_updates(self, **updates: Value) -> "State":
        values = self.as_dict()
        values.update(updates)
        return State(values)

    def canonical(self) -> dict[str, Any]:
        return _canonical(self.as_dict())


@dataclass(frozen=True)
class EntryPoint:
    name: str
    declared: bool = True
    capabilities: frozenset[str] = frozenset()
    provenance: Provenance | None = None


@dataclass(frozen=True)
class Operation:
    """A modeled state transition, kept independent of any runtime."""

    name: str
    entry_point: EntryPoint
    guard: Guard = lambda _state, _request: True
    apply: StateUpdate = lambda state, _request: state
    observe: Observation = lambda _before, _request, _after: {}
    fidelity: Fidelity = Fidelity.MODELED
    provenance: str = "model"
    transforms: tuple[Any, ...] = ()
    recognizers: tuple[Any, ...] = ()
    effects: tuple[str, ...] = ()
    mode: ExecutionMode = ExecutionMode.ABSTRACT
    component: str = ""
    symbolic_transition: Any | None = None

    def __post_init__(self) -> None:
        for transform in self.transforms:
            required = ("transform_id", "input_representation", "output_representation", "partiality", "relation", "information_loss")
            if any(not hasattr(transform, field_name) for field_name in required):
                raise TypeError("operation transforms must use canonical ir.Transform records")
        for recognizer in self.recognizers:
            required = ("recognizer_id", "input_representation", "actual_predicate_ref", "enforcement_point")
            if any(not hasattr(recognizer, field_name) for field_name in required):
                raise TypeError("operation recognizers must use canonical ir.Recognizer records")

    def execute(self, state: State, request: Request) -> tuple[State, Mapping[str, Value]] | None:
        if not self.guard(state, request):
            return None
        next_state = self.apply(state, request)
        observation = dict(self.observe(state, request, next_state))
        return next_state, observation


@dataclass(frozen=True)
class TraceEvent:
    operation: str
    entry_point: str
    request: dict[str, Value]
    before: State
    after: State
    observation: dict[str, Value] = field(default_factory=dict)
    fidelity: Fidelity = Fidelity.MODELED
    mode: ExecutionMode = ExecutionMode.ABSTRACT
    event_id: str = ""
    run_id: str = ""
    trace_id: str = ""
    parent_event_id: str | None = None
    component: str = ""
    input_representation: str = ""
    output_representation: str = ""
    state_before_id: str = ""
    state_after_id: str = ""
    guard_result: bool | None = None
    environment: dict[str, str] = field(default_factory=dict)
    evidence_source: str = ""
    evidence_refs: tuple[str, ...] = ()
    timestamp_ns: int | None = None
    ordering: int = 0
    correlation_uncertain: bool = False

    def canonical(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "entry_point": self.entry_point,
            "request": _canonical(self.request),
            "before": self.before.canonical(),
            "after": self.after.canonical(),
            "observation": _canonical(self.observation),
            "fidelity": self.fidelity.value,
            "mode": self.mode.value,
            "event_id": self.event_id,
            "run_id": self.run_id,
            "trace_id": self.trace_id,
            "parent_event_id": self.parent_event_id,
            "component": self.component,
            "input_representation": self.input_representation,
            "output_representation": self.output_representation,
            "state_before_id": self.state_before_id,
            "state_after_id": self.state_after_id,
            "guard_result": self.guard_result,
            "environment": _canonical(self.environment),
            "evidence_source": self.evidence_source,
            "evidence_refs": list(self.evidence_refs),
            "timestamp_ns": self.timestamp_ns,
            "ordering": self.ordering,
            "correlation_uncertain": self.correlation_uncertain,
        }


@dataclass(frozen=True)
class Authorization:
    subject: str
    scopes: frozenset[str]
    target_ids: frozenset[str] = frozenset()

    def permits(self, target_id: str, scope: str) -> bool:
        return scope in self.scopes and (not self.target_ids or target_id in self.target_ids)


@dataclass(frozen=True)
class Objective:
    name: str
    scope: str
    postcondition: StatePredicate
    constraints: tuple[Callable[[Request], bool], ...] = ()
    effect_lemmas: tuple[EffectLemma, ...] = ()
    description: str = ""

    def accepts_request(self, request: Request) -> bool:
        return all(constraint(request) for constraint in self.constraints)


@dataclass(frozen=True)
class Budget:
    max_depth: int = 4
    max_states: int = 10_000
    max_events: int = 100_000

    def __post_init__(self) -> None:
        if self.max_depth < 0 or self.max_states <= 0 or self.max_events <= 0:
            raise ValueError("budgets must be non-negative depth and positive state/event limits")


@dataclass(frozen=True)
class LearnedExclusion:
    """A bounded, evidence-backed request region rejected by the target."""

    entry_point: str
    key: str
    operator: str
    value: Any
    domain_min: Any | None = None
    domain_max: Any | None = None
    evidence: tuple[str, ...] = ()

    def matches(self, entry_point: str, request: Mapping[str, Any]) -> bool:
        if entry_point != self.entry_point or self.key not in request:
            return False
        actual = request[self.key]
        if self.domain_min is not None and actual < self.domain_min:
            return False
        if self.domain_max is not None and actual > self.domain_max:
            return False
        try:
            return {
                "=": actual == self.value,
                "!=": actual != self.value,
                "<": actual < self.value,
                "<=": actual <= self.value,
                ">": actual > self.value,
                ">=": actual >= self.value,
            }[self.operator]
        except (KeyError, TypeError):
            return False

    def describe(self) -> str:
        scope = f" within [{self.domain_min}, {self.domain_max}]" if self.domain_min is not None or self.domain_max is not None else ""
        return f"{self.entry_point}.{self.key} {self.operator} {self.value}{scope}"


@dataclass(frozen=True)
class TransitionModel:
    target_id: str
    initial_state: State
    inputs: tuple[Request, ...]
    operations: tuple[Operation, ...]
    build_hash: str = "unknown"
    model_version: str = "1"
    assumptions: tuple[str, ...] = ()
    excluded_interactions: tuple[tuple[str, str], ...] = ()
    demoted_assumptions: tuple[str, ...] = ()
    learned_exclusions: tuple[LearnedExclusion, ...] = ()

    def __post_init__(self) -> None:
        if not self.target_id:
            raise ValueError("target_id is required")
        if len({(operation.entry_point.name, operation.name) for operation in self.operations}) != len(self.operations):
            raise ValueError("operation names must be unique per entry point")

    @classmethod
    def from_iterables(
        cls,
        target_id: str,
        initial_state: State,
        inputs: Iterable[Request],
        operations: Iterable[Operation],
        **kwargs: Any,
    ) -> "TransitionModel":
        return cls(target_id, initial_state, tuple(dict(item) for item in inputs), tuple(operations), **kwargs)

    def ordered_operations(self) -> tuple[Operation, ...]:
        return tuple(sorted(self.operations, key=lambda operation: (operation.entry_point.name, operation.name)))

    def ordered_inputs(self) -> tuple[Request, ...]:
        return tuple(sorted(self.inputs, key=lambda request: repr(_canonical(request))))

    def allows(self, entry_point: str, request: Request) -> bool:
        """Apply explicit counterexample restrictions from model refinement."""
        if (entry_point, repr(_canonical(dict(request)))) in self.excluded_interactions:
            return False
        return not any(item.matches(entry_point, request) for item in self.learned_exclusions)

    def with_exclusion(self, entry_point: str, request: Request, *, assumption: str | None = None) -> "TransitionModel":
        exclusion = (entry_point, repr(_canonical(dict(request))))
        assumptions = self.assumptions + ((assumption,) if assumption else ())
        return TransitionModel(
            target_id=self.target_id,
            initial_state=self.initial_state,
            inputs=self.inputs,
            operations=self.operations,
            build_hash=self.build_hash,
            model_version=f"{self.model_version}.refined{len(assumptions)}",
            assumptions=assumptions,
            excluded_interactions=tuple(sorted(set(self.excluded_interactions + (exclusion,)))),
            demoted_assumptions=self.demoted_assumptions,
            learned_exclusions=self.learned_exclusions,
        )

    def with_demoted_assumptions(self, assumptions: Iterable[str]) -> "TransitionModel":
        demoted = tuple(sorted(set(self.demoted_assumptions) | set(assumptions)))
        return TransitionModel(
            target_id=self.target_id,
            initial_state=self.initial_state,
            inputs=self.inputs,
            operations=self.operations,
            build_hash=self.build_hash,
            model_version=f"{self.model_version}.demoted{len(demoted)}",
            assumptions=self.assumptions,
            excluded_interactions=self.excluded_interactions,
            demoted_assumptions=demoted,
            learned_exclusions=self.learned_exclusions,
        )

    def with_learned_exclusion(self, exclusion: LearnedExclusion) -> "TransitionModel":
        learned = tuple(item for item in self.learned_exclusions if item != exclusion) + (exclusion,)
        return TransitionModel(
            target_id=self.target_id,
            initial_state=self.initial_state,
            inputs=self.inputs,
            operations=self.operations,
            build_hash=self.build_hash,
            model_version=f"{self.model_version}.learned{len(learned)}",
            assumptions=self.assumptions,
            excluded_interactions=self.excluded_interactions,
            demoted_assumptions=self.demoted_assumptions,
            learned_exclusions=learned,
        )
