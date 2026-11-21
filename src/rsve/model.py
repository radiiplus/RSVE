"""Typed, runtime-independent model objects used by the analysis engine."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from copy import deepcopy
from typing import Any, Callable, Iterable, Mapping, TypeAlias

Primitive: TypeAlias = None | bool | int | float | str | bytes
Value: TypeAlias = Primitive | tuple[Primitive, ...]
Request: TypeAlias = Mapping[str, Value]
Check: TypeAlias = Callable[["State", tuple["Event", ...]], bool]
Guard: TypeAlias = Callable[["State", Request], bool]
Change: TypeAlias = Callable[["State", Request], "State"]
FailureChange: TypeAlias = Callable[["State", Request, Exception], "State"]
View: TypeAlias = Callable[["State", Request, "State"], Mapping[str, Value]]


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


class Mode(str, Enum):
    CONCRETE = "concrete"
    INSTRUMENTED = "instrumented"
    CONCOLIC = "concolic"
    SYMBOLIC = "symbolic"
    EMULATED = "emulated"
    ABSTRACT = "abstract"


class Decision(str, Enum):
    """Classification of a modeled transition branch."""

    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    UNDEFINED = "UNDEFINED"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Provenance:
    source: str
    version: str = "unknown"
    evidence: tuple[str, ...] = ()
    fidelity: Fidelity = Fidelity.ASSUMED


@dataclass(frozen=True)
class Lemma:
    """A separately testable intermediate predicate for a larger objective."""

    name: str
    predicate: Check
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

    def update(self, **updates: Value) -> "State":
        values = self.as_dict()
        values.update(updates)
        return State(values)

    def canonical(self) -> dict[str, Any]:
        return _canonical(self.as_dict())


@dataclass(frozen=True)
class Entry:
    name: str
    declared: bool = True
    capabilities: frozenset[str] = frozenset()
    provenance: Provenance | None = None


@dataclass(frozen=True)
class Outcome:
    """One possible successor of an operation, including rejected branches."""

    decision: Decision
    after: State
    observation: Mapping[str, Value] = field(default_factory=dict)
    effects: tuple[str, ...] = ()
    reads: frozenset[str] = frozenset()
    writes: frozenset[str] = frozenset()
    must: frozenset[str] = frozenset()
    may: frozenset[str] = frozenset()
    keep: frozenset[str] = frozenset()
    unknown: frozenset[str] = frozenset()
    environment: Mapping[str, Value] = field(default_factory=dict)
    control: str | None = None
    terminal: bool = False
    guard: bool | None = None
    fidelity: Fidelity = Fidelity.MODELED
    mode: Mode = Mode.ABSTRACT
    evidence: tuple[str, ...] = ()
    uncertainty: tuple[str, ...] = ()
    id: str = ""
    lineage: tuple[str, ...] | None = None
    origins: Mapping[str, tuple[str, ...]] | None = None

    def __iter__(self):
        """Keep tuple-unpacking compatible with the original execute API."""
        yield self.after
        yield self.observation

    def event(
        self,
        operation: str,
        entry: str,
        request: Request,
        before: State,
        *,
        component: str = "",
        order: int = 0,
    ) -> "Event":
        observation = dict(self.observation)
        if self.origins is not None:
            records = []
            for path, values in sorted(self.origins.items()):
                for origin in values:
                    source, _, source_path = origin.partition(":")
                    records.append({
                        "source_entry": source,
                        "source_path": source_path,
                        "path": path,
                    })
            observation.setdefault("data_lineage", tuple(records))
        elif self.lineage is not None:
            observation.setdefault(
                "data_lineage",
                tuple({"source_entry": source} for source in self.lineage),
            )
        return Event(
            operation=operation,
            entry_point=entry,
            request=dict(request),
            before=before,
            after=self.after,
            observation=observation,
            fidelity=self.fidelity,
            mode=self.mode,
            component=component,
            guard_result=self.guard,
            decision=self.decision,
            terminal=self.terminal,
            effects=self.effects,
            reads=self.reads,
            writes=self.writes,
            reaction=dict(self.environment),
            evidence_refs=self.evidence,
            uncertainty=self.uncertainty,
            ordering=order,
        )


@dataclass(frozen=True)
class Operation:
    """A modeled state transition, kept independent of any runtime."""

    name: str
    entry_point: Entry
    guard: Guard = lambda _state, _request: True
    apply: Change = lambda state, _request: state
    observe: View = lambda _before, _request, _after: {}
    fidelity: Fidelity = Fidelity.MODELED
    provenance: str = "model"
    transforms: tuple[Any, ...] = ()
    recognizers: tuple[Any, ...] = ()
    effects: tuple[str, ...] = ()
    mode: Mode = Mode.ABSTRACT
    component: str = ""
    symbolic_transition: Any | None = None
    relation: Callable[[State, Request], Iterable[Outcome]] | None = None
    deny: Change | None = None
    watch: View | None = None
    loss: tuple[str, ...] = ()
    deny_effects: tuple[str, ...] = ()
    deny_reads: frozenset[str] = frozenset()
    deny_writes: frozenset[str] = frozenset()
    deny_must: frozenset[str] = frozenset()
    deny_may: frozenset[str] = frozenset()
    deny_keep: frozenset[str] = frozenset()
    deny_unknown: frozenset[str] = frozenset()
    deny_env: Mapping[str, Value] = field(default_factory=dict)
    env: Mapping[str, Value] = field(default_factory=dict)
    stop: bool = False
    error_handler: FailureChange | None = None
    stop_on_error: bool = False
    error_effects: tuple[str, ...] = ()
    error_writes: frozenset[str] = frozenset()
    error_unknown: frozenset[str] = frozenset()
    reads: frozenset[str] = frozenset()
    writes: frozenset[str] = frozenset()
    must: frozenset[str] = frozenset()
    may: frozenset[str] = frozenset()
    keep: frozenset[str] = frozenset()
    unknown: frozenset[str] = frozenset()
    relation_complete: bool = False
    provenance_paths: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    provenance_inputs: tuple[str, ...] = ()
    request_candidates: Callable[[State, Any], Iterable[Request]] | None = None
    client_id: str = ""

    def __post_init__(self) -> None:
        for transform in self.transforms:
            required = ("transform_id", "input_representation", "output_representation", "partiality", "relation", "information_loss")
            if any(not hasattr(transform, field_name) for field_name in required):
                raise TypeError("operation transforms must use canonical ir.Transform records")
        for recognizer in self.recognizers:
            required = ("recognizer_id", "input_representation", "actual_predicate_ref", "enforcement_point")
            if any(not hasattr(recognizer, field_name) for field_name in required):
                raise TypeError("operation recognizers must use canonical ir.Recognizer records")
        for output, inputs in self.provenance_paths.items():
            if not isinstance(output, str) or any(not isinstance(item, str) for item in inputs):
                raise TypeError("operation provenance paths must map string outputs to string inputs")
        if any(not isinstance(item, str) for item in self.provenance_inputs):
            raise TypeError("operation provenance inputs must be strings")

    def branches(self, state: State, request: Request) -> tuple[Outcome, ...]:
        if self.relation is not None:
            try:
                values = self.relation(state, request)
                if isinstance(values, Outcome):
                    values = (values,)
                values = tuple(values)
                if not values and not self.relation_complete:
                    return (Outcome(
                        decision=Decision.UNKNOWN,
                        after=state,
                        terminal=True,
                        fidelity=self.fidelity,
                        mode=self.mode,
                        evidence=(self.provenance,),
                        uncertainty=("operation relation returned no successors without completeness evidence",),
                    ),)
                return values
            except Exception as exc:  # model failures remain explicit outcomes
                return (self._error(state, request, exc),)
        try:
            accepted = bool(self.guard(state, request))
        except Exception as exc:
            return (self._error(state, request, exc),)
        if not accepted:
            next_state = self.deny(state, request) if self.deny is not None else state
            observation = dict(self.watch(state, request, next_state)) if self.watch else {}
            return (Outcome(
                decision=Decision.REJECT,
                after=next_state,
                observation=observation,
                effects=self.deny_effects,
                reads=self.deny_reads,
                writes=self.deny_writes | self.deny_must | self.deny_may,
                must=self.deny_must,
                may=self.deny_may,
                keep=self.deny_keep,
                unknown=self.deny_unknown,
                environment=dict(self.deny_env),
                terminal=self.stop,
                guard=False,
                fidelity=self.fidelity,
                mode=self.mode,
                evidence=(self.provenance,),
            ),)
        try:
            next_state = self.apply(state, request)
            observation = dict(self.observe(state, request, next_state))
        except Exception as exc:
            return (self._error(state, request, exc),)
        return (Outcome(
            decision=Decision.ACCEPT,
            after=next_state,
            observation=observation,
            effects=self.effects,
            reads=self.reads,
            writes=self.writes | self.must | self.may,
            must=self.must,
            may=self.may,
            keep=self.keep,
            unknown=self.unknown,
            environment=dict(self.env),
            guard=True,
            fidelity=self.fidelity,
            mode=self.mode,
            evidence=(self.provenance,),
        ),)

    def execute(self, state: State, request: Request) -> Outcome:
        """Return the first modeled branch; use branches for relations."""
        return self.branches(state, request)[0]

    def _error(self, state: State, request: Request, error: Exception) -> Outcome:
        after = state
        uncertainty = [f"{type(error).__name__}: operation failed"]
        aftermath_modeled = self.error_handler is not None
        if self.error_handler is not None:
            try:
                after = self.error_handler(state, request, error)
            except Exception as handler_error:
                aftermath_modeled = False
                uncertainty.append(f"error handler failed: {type(handler_error).__name__}")
        else:
            uncertainty.append("error aftermath has no modeled state handler")
        return Outcome(
            decision=Decision.ERROR,
            after=after,
            effects=self.error_effects,
            writes=self.error_writes,
            unknown=self.error_unknown or (frozenset() if aftermath_modeled else frozenset({"error-aftermath"})),
            terminal=self.stop_on_error,
            guard=None,
            fidelity=self.fidelity,
            mode=self.mode,
            evidence=(self.provenance,),
            uncertainty=tuple(uncertainty),
        )


@dataclass(frozen=True)
class Event:
    operation: str
    entry_point: str
    request: dict[str, Value]
    before: State
    after: State
    observation: dict[str, Value] = field(default_factory=dict)
    fidelity: Fidelity = Fidelity.MODELED
    mode: Mode = Mode.ABSTRACT
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
    decision: Decision = Decision.ACCEPT
    terminal: bool = False
    effects: tuple[str, ...] = ()
    reads: frozenset[str] = frozenset()
    writes: frozenset[str] = frozenset()
    reaction: dict[str, Value] = field(default_factory=dict)
    uncertainty: tuple[str, ...] = ()
    source: dict[str, Value] = field(default_factory=dict)
    client_id: str = ""

    def __post_init__(self) -> None:
        if self.guard_result is False and self.decision is Decision.ACCEPT:
            object.__setattr__(self, "decision", Decision.REJECT)

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
            "client_id": self.client_id,
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
            "decision": self.decision.value,
            "terminal": self.terminal,
            "effects": list(self.effects),
            "reads": sorted(self.reads),
            "writes": sorted(self.writes),
            "reaction": _canonical(self.reaction),
            "uncertainty": list(self.uncertainty),
            "source": _canonical(self.source),
        }


@dataclass(frozen=True)
class Authorization:
    subject: str
    scopes: frozenset[str]
    target_ids: frozenset[str] = frozenset()

    def permits(self, target_id: str, scope: str) -> bool:
        return scope in self.scopes and (not self.target_ids or target_id in self.target_ids)


@dataclass(frozen=True)
class Goal:
    name: str
    scope: str
    postcondition: Check
    constraints: tuple[Callable[[Request], bool], ...] = ()
    effect_lemmas: tuple[Lemma, ...] = ()
    description: str = ""

    def accept(self, request: Request) -> bool:
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
class Exclusion:
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
class Model:
    target_id: str
    initial_state: State
    inputs: tuple[Request, ...]
    operations: tuple[Operation, ...]
    build_hash: str = "unknown"
    model_version: str = "1"
    assumptions: tuple[str, ...] = ()
    excluded_interactions: tuple[tuple[str, str], ...] = ()
    demoted_assumptions: tuple[str, ...] = ()
    learned_exclusions: tuple[Exclusion, ...] = ()
    observed_transitions: tuple[Event, ...] = ()
    refinement_gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.target_id:
            raise ValueError("target_id is required")
        if len({(operation.entry_point.name, operation.name) for operation in self.operations}) != len(self.operations):
            raise ValueError("operation names must be unique per entry point")

    @classmethod
    def build(
        cls,
        target_id: str,
        initial_state: State,
        inputs: Iterable[Request],
        operations: Iterable[Operation],
        **kwargs: Any,
    ) -> "Model":
        return cls(target_id, initial_state, tuple(dict(item) for item in inputs), tuple(operations), **kwargs)

    def ops(self) -> tuple[Operation, ...]:
        return tuple(sorted(self.operations, key=lambda operation: (operation.entry_point.name, operation.name)))

    def args(self) -> tuple[Request, ...]:
        return tuple(sorted(self.inputs, key=lambda request: repr(_canonical(request))))

    def allows(self, entry_point: str, request: Request) -> bool:
        """Apply explicit counterexample restrictions from model refinement."""
        if (entry_point, repr(_canonical(dict(request)))) in self.excluded_interactions:
            return False
        return not any(item.matches(entry_point, request) for item in self.learned_exclusions)

    def record_observations(self, events: Iterable[Event]) -> "Model":
        """Add exact-context runtime facts without generalizing their behavior."""
        records = list(self.observed_transitions)
        keys = {repr(_canonical(item.canonical())) for item in records}
        for event in events:
            if getattr(event.fidelity, "value", event.fidelity) != Fidelity.OBSERVED.value:
                continue
            key = repr(_canonical(event.canonical()))
            if key not in keys:
                records.append(deepcopy(event))
                keys.add(key)
        if len(records) == len(self.observed_transitions):
            return self
        return replace(
            self,
            model_version=f"{self.model_version}.observed{len(records)}",
            observed_transitions=tuple(records),
        )

    def record_refinement_gap(self, identity: str) -> "Model":
        if not identity or identity in self.refinement_gaps:
            return self
        gaps = self.refinement_gaps + (identity,)
        return replace(
            self,
            model_version=f"{self.model_version}.gap{len(gaps)}",
            refinement_gaps=gaps,
        )

    def observations_for(
        self,
        entry_point: str,
        request: Request,
        before: State,
        *,
        component: str = "",
        environment: Mapping[str, Any] | None = None,
        client_id: str = "",
        operation: str = "",
    ) -> tuple[Event, ...]:
        request_key = repr(_canonical(dict(request)))
        environment_key = repr(_canonical(dict(environment or {})))
        matches = tuple(
            event for event in self.observed_transitions
            if event.entry_point == entry_point
            and (not operation or event.operation == operation)
            and repr(_canonical(event.request)) == request_key
            and event.before == before
            and (not component or not event.component or event.component == component)
            and (not event.environment or repr(_canonical(event.environment)) == environment_key)
            and (not event.client_id or event.client_id == client_id)
        )
        outcomes: dict[str, Event] = {}
        for event in matches:
            key = repr(_canonical({
                "decision": event.decision.value,
                "after": event.after.canonical(),
                "observation": event.observation,
                "effects": event.effects,
                "reads": event.reads,
                "writes": event.writes,
                "reaction": event.reaction,
                "terminal": event.terminal,
                "guard": event.guard_result,
            }))
            prior = outcomes.get(key)
            if prior is None:
                outcomes[key] = event
            else:
                outcomes[key] = replace(
                    prior,
                    evidence_refs=tuple(dict.fromkeys(prior.evidence_refs + event.evidence_refs)),
                )
        return tuple(outcomes.values())

    def exclude(self, entry_point: str, request: Request, *, assumption: str | None = None) -> "Model":
        exclusion = (entry_point, repr(_canonical(dict(request))))
        assumptions = self.assumptions + ((assumption,) if assumption else ())
        return Model(
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
            observed_transitions=self.observed_transitions,
            refinement_gaps=self.refinement_gaps,
        )

    def demote(self, assumptions: Iterable[str]) -> "Model":
        demoted = tuple(sorted(set(self.demoted_assumptions) | set(assumptions)))
        return Model(
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
            observed_transitions=self.observed_transitions,
            refinement_gaps=self.refinement_gaps,
        )

    def learn(self, exclusion: Exclusion) -> "Model":
        learned = tuple(item for item in self.learned_exclusions if item != exclusion) + (exclusion,)
        return Model(
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
            observed_transitions=self.observed_transitions,
            refinement_gaps=self.refinement_gaps,
        )
