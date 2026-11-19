"""Small extensional objective language for bounded, authorized lab analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Mapping, Sequence

from .constraints import (
    AllOf,
    AnyOf,
    Constraint,
    Equal,
    FiniteEnum,
    IntRange,
    Literal,
    NamedAssumption,
    Negate,
    StateRelation,
    Variable,
)
from .model import Authorization, State, TraceEvent, _canonical
from .graph import ProfileInstance, ProfileRequirement, ProfileVerification
from .schema import SCHEMA_VERSION, SchemaMixin, encode


class ObjectiveValidationError(ValueError):
    """Raised when an objective is outside the authorized harness."""


class Predicate:
    type_name: ClassVar[str]

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        raise NotImplementedError

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    def to_record(self) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "type": self.type_name, "payload": self.to_dict()}


@dataclass(frozen=True)
class ConstraintPredicate(Predicate):
    type_name: ClassVar[str] = "constraint_predicate"
    constraint: Constraint

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        environment = state.as_dict()
        if trace:
            environment.update({f"event.{key}": value for key, value in trace[-1].observation.items()})
        return _evaluate_constraint(self.constraint, environment)

    def to_dict(self) -> dict[str, Any]:
        return {"constraint": self.constraint.to_record()}


@dataclass(frozen=True)
class StateEquals(Predicate):
    type_name: ClassVar[str] = "state_equals"
    key: str
    expected: Any

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        return state.get(self.key) == self.expected

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "expected": encode(self.expected)}


@dataclass(frozen=True)
class FlowToSink(Predicate):
    type_name: ClassVar[str] = "flow_to_sink"
    source_entry: str
    canary: str
    sink: str
    require_lineage: bool = False

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        source_seen = False
        for event in trace:
            if event.entry_point == self.source_entry and _contains(event.request, self.canary):
                source_seen = True
            if source_seen and (
                event.component == self.sink
                or event.operation == self.sink
                or event.observation.get("sink") == self.sink
            ):
                if self.require_lineage:
                    lineage = event.observation.get("data_lineage")
                    if not isinstance(lineage, (tuple, list)):
                        continue
                    if not any(
                        isinstance(item, Mapping)
                        and item.get("source_entry") == self.source_entry
                        and _contains(item.get("value"), self.canary)
                        for item in lineage
                    ):
                        continue
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_entry": self.source_entry,
            "canary": self.canary,
            "sink": self.sink,
            "require_lineage": self.require_lineage,
        }


@dataclass(frozen=True)
class AllowedStateChanges(Predicate):
    type_name: ClassVar[str] = "allowed_state_changes"
    keys: frozenset[str]

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        if not trace:
            return True
        initial = trace[0].before.as_dict()
        changed = {
            key for key in set(initial) | set(state.as_dict())
            if initial.get(key) != state.get(key)
        }
        return changed <= self.keys

    def to_dict(self) -> dict[str, Any]:
        return {"keys": sorted(self.keys)}


@dataclass(frozen=True)
class GuardInvariant(Predicate):
    type_name: ClassVar[str] = "guard_invariant"
    entry_point: str | None = None
    expected: bool = True

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        matched = tuple(
            event for event in trace
            if event.guard_result is not None
            and (self.entry_point is None or event.entry_point == self.entry_point)
        )
        if self.expected is False and not matched:
            return False
        return all(event.guard_result is self.expected for event in matched)

    def to_dict(self) -> dict[str, Any]:
        return {"entry_point": self.entry_point, "expected": self.expected}


@dataclass(frozen=True)
class EntrySequence(Predicate):
    type_name: ClassVar[str] = "entry_sequence"
    entries: tuple[str, ...]

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        actual = [event.entry_point for event in trace]
        cursor = 0
        for entry in self.entries:
            try:
                cursor = actual.index(entry, cursor) + 1
            except ValueError:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {"entries": list(self.entries)}


@dataclass(frozen=True)
class AllPredicates(Predicate):
    type_name: ClassVar[str] = "all_predicates"
    predicates: tuple[Predicate, ...]

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        return all(predicate.evaluate(state, trace) for predicate in self.predicates)

    def to_dict(self) -> dict[str, Any]:
        return {"predicates": [predicate.to_record() for predicate in self.predicates]}


@dataclass(frozen=True)
class AnyPredicate(Predicate):
    type_name: ClassVar[str] = "any_predicate"
    predicates: tuple[Predicate, ...]

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        return any(predicate.evaluate(state, trace) for predicate in self.predicates)

    def to_dict(self) -> dict[str, Any]:
        return {"predicates": [predicate.to_record() for predicate in self.predicates]}


@dataclass(frozen=True)
class NotPredicate(Predicate):
    type_name: ClassVar[str] = "not_predicate"
    predicate: Predicate

    def evaluate(self, state: State, trace: Sequence[TraceEvent]) -> bool:
        return not self.predicate.evaluate(state, trace)

    def to_dict(self) -> dict[str, Any]:
        return {"predicate": self.predicate.to_record()}


@dataclass(frozen=True)
class ObjectiveBudget(SchemaMixin):
    max_trace_length: int = 2
    max_states: int = 1_000
    max_events: int = 10_000
    max_time_ms: int = 5_000
    solver_timeout_ms: int = 1_000
    replay_runs: int = 1

    def __post_init__(self) -> None:
        if self.max_trace_length < 0 or min(self.max_states, self.max_events, self.max_time_ms, self.solver_timeout_ms, self.replay_runs) <= 0:
            raise ValueError("objective budgets require non-negative trace length and positive limits")

    @property
    def max_depth(self) -> int:
        return self.max_trace_length


@dataclass(frozen=True)
class ObjectiveDefinition(SchemaMixin):
    """Declarative objective restricted to one explicitly authorized harness."""

    objective_id: str
    target_id: str
    authorization_scope: str
    postconditions: tuple[Predicate, ...]
    permitted_sinks: frozenset[str] = frozenset()
    environment_boundaries: Mapping[str, str] = field(default_factory=dict)
    allowed_state_changes: frozenset[str] = frozenset()
    checkpoints: tuple[Predicate, ...] = ()
    assumptions: tuple[str, ...] = ()
    profile_requirements: tuple[ProfileRequirement, ...] = ()
    budget: ObjectiveBudget = field(default_factory=ObjectiveBudget)
    version: str = "1"

    def __post_init__(self) -> None:
        if not self.objective_id or not self.target_id or not self.authorization_scope:
            raise ValueError("objective identity, target, and authorization scope are required")
        if not self.postconditions:
            raise ValueError("at least one postcondition is required")

    @property
    def name(self) -> str:
        return self.objective_id

    @property
    def scope(self) -> str:
        return self.authorization_scope

    @property
    def postcondition(self) -> Predicate:
        return self.postconditions[0] if len(self.postconditions) == 1 else AllPredicates(self.postconditions)

    def validate(
        self,
        authorization: Authorization,
        *,
        harness_sinks: set[str] | frozenset[str] = frozenset(),
        environment: Mapping[str, str] | None = None,
        execution_profile: ProfileInstance | None = None,
    ) -> None:
        if not authorization.permits(self.target_id, self.authorization_scope):
            raise ObjectiveValidationError("objective is outside the authorized target/scope")
        referenced_sinks = set(self.permitted_sinks)
        for predicate in self._predicates():
            if isinstance(predicate, FlowToSink):
                referenced_sinks.add(predicate.sink)
        if referenced_sinks and not referenced_sinks <= set(harness_sinks):
            raise ObjectiveValidationError("objective references a sink outside the controlled harness")
        if environment is not None:
            for key, expected in self.environment_boundaries.items():
                if environment.get(key) != expected:
                    raise ObjectiveValidationError(f"environment boundary does not match: {key}")
        if execution_profile is not None:
            observed_target = execution_profile.execution_scope.get("target_id")
            if observed_target is not None and observed_target != self.target_id:
                raise ObjectiveValidationError("objective target does not match the observed target profile")
        if self.profile_requirements:
            if execution_profile is None:
                raise ObjectiveValidationError("objective requires profiles but no profile was observed")
            verifications = tuple(requirement.verify(execution_profile) for requirement in self.profile_requirements)
            if any(item.status.value != "MATCH" for item in verifications):
                detail = ", ".join(sorted({item.requirement_id for item in verifications if item.status.value != "MATCH"}))
                raise ObjectiveValidationError(
                    f"objective profile requirements are unresolved: {detail}"
                )

    def verify_profile(self, execution_profile: ProfileInstance | None) -> tuple[ProfileVerification, ...] | None:
        if not self.profile_requirements:
            return None
        return tuple(requirement.verify(execution_profile) for requirement in self.profile_requirements)

    def evaluate(self, final_state: State, trace: Sequence[TraceEvent]) -> bool:
        if not all(predicate.evaluate(final_state, trace) for predicate in self.postconditions):
            return False
        if self.allowed_state_changes and not AllowedStateChanges(self.allowed_state_changes).evaluate(final_state, trace):
            return False
        return True

    def checkpoints_satisfied(self, initial_state: State, trace: Sequence[TraceEvent]) -> bool:
        checkpoints = [(initial_state, ())]
        checkpoints.extend((event.after, trace[:index]) for index, event in enumerate(trace, 1))
        return all(any(predicate.evaluate(state, prefix) for state, prefix in checkpoints) for predicate in self.checkpoints)

    def _predicates(self) -> tuple[Predicate, ...]:
        found: list[Predicate] = []

        def visit(predicate: Predicate) -> None:
            found.append(predicate)
            if isinstance(predicate, (AllPredicates, AnyPredicate)):
                for child in predicate.predicates:
                    visit(child)
            elif isinstance(predicate, NotPredicate):
                visit(predicate.predicate)

        for predicate in self.postconditions + self.checkpoints:
            visit(predicate)
        return tuple(found)

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "type": "ObjectiveDefinition",
            "payload": {
                "objective_id": self.objective_id,
                "target_id": self.target_id,
                "authorization_scope": self.authorization_scope,
                "postconditions": [predicate.to_record() for predicate in self.postconditions],
                "permitted_sinks": sorted(self.permitted_sinks),
                "environment_boundaries": dict(self.environment_boundaries),
                "allowed_state_changes": sorted(self.allowed_state_changes),
                "checkpoints": [predicate.to_record() for predicate in self.checkpoints],
                "assumptions": list(self.assumptions),
                "profile_requirements": [requirement.to_record() for requirement in self.profile_requirements],
                "budget": self.budget.to_record(),
                "version": self.version,
            },
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "ObjectiveDefinition":
        if record.get("schema_version") != SCHEMA_VERSION or record.get("type") != "ObjectiveDefinition":
            raise ValueError("unsupported objective schema version or type")
        payload = record.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("objective payload must be an object")
        return cls(
            objective_id=payload["objective_id"],
            target_id=payload["target_id"],
            authorization_scope=payload["authorization_scope"],
            postconditions=tuple(_predicate_from_record(item) for item in payload["postconditions"]),
            permitted_sinks=frozenset(payload.get("permitted_sinks", ())),
            environment_boundaries=dict(payload.get("environment_boundaries", {})),
            allowed_state_changes=frozenset(payload.get("allowed_state_changes", ())),
            checkpoints=tuple(_predicate_from_record(item) for item in payload.get("checkpoints", ())),
            assumptions=tuple(payload.get("assumptions", ())),
            profile_requirements=tuple(ProfileRequirement.from_record(item) for item in payload.get("profile_requirements", ())),
            budget=ObjectiveBudget.from_record(payload.get("budget", ObjectiveBudget().to_record())),
            version=payload.get("version", "1"),
        )


def _contains(value: Any, needle: str) -> bool:
    if isinstance(value, Mapping):
        return any(_contains(key, needle) or _contains(item, needle) for key, item in value.items())
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(_contains(item, needle) for item in value)
    return needle in str(value)


def _evaluate_constraint(node: Constraint, environment: Mapping[str, Any]) -> bool:
    def value(term: Constraint) -> Any:
        if isinstance(term, Variable):
            return environment.get(term.name)
        if isinstance(term, Literal):
            return term.value
        raise ValueError(f"constraint term is not a value: {type(term).__name__}")

    if isinstance(node, Equal):
        return value(node.left) == value(node.right)
    if isinstance(node, IntRange):
        item = value(node.value)
        return item is not None and node.minimum <= item <= node.maximum
    if isinstance(node, FiniteEnum):
        return value(node.value) in node.values
    if isinstance(node, AllOf):
        return all(_evaluate_constraint(item, environment) for item in node.terms)
    if isinstance(node, AnyOf):
        return any(_evaluate_constraint(item, environment) for item in node.terms)
    if isinstance(node, Negate):
        return not _evaluate_constraint(node.term, environment)
    if isinstance(node, NamedAssumption):
        return _evaluate_constraint(node.term, environment)
    if isinstance(node, StateRelation):
        left, right = value(node.left), value(node.right)
        return {"=": left == right, "==": left == right, "!=": left != right, "<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right}[node.relation]
    raise ValueError(f"unsupported objective constraint: {type(node).__name__}")


def _predicate_from_record(record: Mapping[str, Any]) -> Predicate:
    if record.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported predicate schema version")
    kind = record.get("type")
    payload = record.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("predicate payload must be an object")
    if kind == ConstraintPredicate.type_name:
        return ConstraintPredicate(Constraint.from_record(payload["constraint"]))
    if kind == StateEquals.type_name:
        return StateEquals(payload["key"], payload["expected"])
    if kind == FlowToSink.type_name:
        return FlowToSink(
            payload["source_entry"],
            payload["canary"],
            payload["sink"],
            bool(payload.get("require_lineage", False)),
        )
    if kind == AllowedStateChanges.type_name:
        return AllowedStateChanges(frozenset(payload["keys"]))
    if kind == GuardInvariant.type_name:
        return GuardInvariant(payload.get("entry_point"), bool(payload.get("expected", True)))
    if kind == EntrySequence.type_name:
        return EntrySequence(tuple(payload["entries"]))
    if kind == AllPredicates.type_name:
        return AllPredicates(tuple(_predicate_from_record(item) for item in payload["predicates"]))
    if kind == AnyPredicate.type_name:
        return AnyPredicate(tuple(_predicate_from_record(item) for item in payload["predicates"]))
    if kind == NotPredicate.type_name:
        return NotPredicate(_predicate_from_record(payload["predicate"]))
    raise ValueError(f"unsupported objective predicate: {kind!r}")
