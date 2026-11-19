"""Canonical executable composition for modeled regions and environments."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable, Mapping

from .environment import Context, Signal, World
from .graph import Graph
from .model import Decision, Event, Model, Operation, Outcome, State
from .semantic import Interpreter


@dataclass(frozen=True)
class Frame:
    """One composed target/environment configuration."""

    target: State
    environment: State = State()
    uncertain: bool = False
    reasons: tuple[str, ...] = ()
    regions: Mapping[str, State] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        return {
            "target": self.target.canonical(),
            "environment": self.environment.canonical(),
            "uncertain": self.uncertain,
            "reasons": self.reasons,
            "regions": {key: value.canonical() for key, value in sorted(self.regions.items())},
        }


@dataclass(frozen=True)
class Move:
    """One executable outcome and its composed successor configuration."""

    operation: Operation
    outcome: Outcome
    before: Frame
    after: Frame
    event: Event


@dataclass(frozen=True)
class Workspace:
    """Execute flat models and graph-backed compositions through one boundary."""

    model: Model
    graph: Graph | None = None
    world: World | None = None
    initial: Frame | None = None
    transforms: Mapping[str, Callable[[Any, State], Any | tuple[Any, ...]]] = field(default_factory=dict)
    recognizers: Mapping[str, Callable[[Any, State], bool]] = field(default_factory=dict)
    effects: Mapping[str, Callable[[State, Any], State]] = field(default_factory=dict)

    @classmethod
    def flat(
        cls,
        model: Model,
        *,
        graph: Graph | None = None,
        world: World | None = None,
        environment: State | None = None,
        transforms: Mapping[str, Callable[[Any, State], Any | tuple[Any, ...]]] | None = None,
        recognizers: Mapping[str, Callable[[Any, State], bool]] | None = None,
        regions: Mapping[str, State] | None = None,
        effects: Mapping[str, Callable[[State, Any], State]] | None = None,
    ) -> "Workspace":
        initial_environment = (
            environment
            if environment is not None
            else world.initial.environment
            if world is not None
            else State()
        )
        return cls(
            model,
            graph,
            world,
            Frame(model.initial_state, initial_environment, regions=dict(regions or {})),
            dict(transforms or {}),
            dict(recognizers or {}),
            dict(effects or {}),
        )

    def start(self) -> Frame:
        if self.initial is not None:
            return self.initial
        environment = self.world.initial.environment if self.world is not None else State()
        return Frame(self.model.initial_state, environment)

    def validate(self) -> Any:
        return self.graph.validate() if self.graph is not None else None

    def moves(
        self,
        frame: Frame,
        entry: str,
        request: Mapping[str, Any],
        *,
        operation: Operation | None = None,
    ) -> tuple[Move, ...]:
        operations = (
            (operation,)
            if operation is not None
            else tuple(item for item in self.model.ops() if item.entry_point.name == entry)
        )
        moves: list[Move] = []
        for item in operations:
            if not self._transitions(item):
                for outcome in item.branches(frame.target, request):
                    moves.extend(self._move(item, outcome, frame, entry, request))
                continue
            for outcome, transformed in self._outcomes(item, frame, request):
                if outcome.decision is Decision.ACCEPT:
                    for branch in item.branches(outcome.after, transformed):
                        combined = self._combine(outcome, branch)
                        moves.extend(self._move(item, combined, frame, entry, transformed))
                else:
                    moves.extend(self._move(item, outcome, frame, entry, request))
        return tuple(moves)

    def _transitions(self, operation: Operation) -> tuple[Any, ...]:
        if self.graph is None:
            return ()
        return tuple(
            transition
            for transition in self.graph.transitions
            if transition.transition_id == operation.name
            or transition.entry_point == operation.entry_point.name
        )

    def _outcomes(
        self,
        operation: Operation,
        frame: Frame,
        request: Mapping[str, Any],
    ) -> tuple[tuple[Outcome, Mapping[str, Any]], ...]:
        transitions = self._transitions(operation)
        interpreter = Interpreter(
            self.graph,
            transforms=self.transforms,
            recognizers=self.recognizers,
            effects=self.effects,
        )
        value: Any = request
        lowered: list[tuple[Outcome, Mapping[str, Any]]] = []
        for transition in transitions:
            graph_outcomes = interpreter.outcomes(transition.transition_id, value, state=frame.target)
            for graph_outcome in graph_outcomes:
                if graph_outcome.decision is Decision.ACCEPT:
                    transformed = _request(graph_outcome.observation.get("value"), request)
                    lowered.append((graph_outcome, transformed))
                else:
                    lowered.append((graph_outcome, request))
        return tuple(lowered)

    @staticmethod
    def _combine(graph: Outcome, operation: Outcome) -> Outcome:
        if graph.decision is Decision.UNKNOWN:
            return replace(
                graph,
                after=operation.after,
                observation=operation.observation,
                effects=graph.effects + operation.effects,
                reads=graph.reads | operation.reads,
                writes=graph.writes | operation.writes,
                uncertainty=graph.uncertainty + operation.uncertainty,
            )
        if graph.decision is Decision.REJECT:
            return graph
        return replace(
            operation,
            effects=graph.effects + operation.effects,
            reads=graph.reads | operation.reads,
            writes=graph.writes | operation.writes,
            evidence=graph.evidence + operation.evidence,
        )

    def _move(
        self,
        item: Operation,
        outcome: Outcome,
        frame: Frame,
        entry: str,
        request: Mapping[str, Any],
    ) -> tuple[Move, ...]:
        moves: list[Move] = []
        target = outcome.after
        environment = _merge(frame.environment, outcome.environment)
        uncertain = frame.uncertain or outcome.decision is Decision.UNKNOWN
        reasons = list(frame.reasons) + list(outcome.uncertainty)
        transition = None
        if self.world is not None:
            if item.name in self.world.transitions:
                transition = item.name
            elif entry in self.world.transitions:
                transition = entry
        reactions = (
            self.world.options(transition, Context(target, environment), request)
            if transition is not None and self.world is not None
            else (None,)
        )
        for reaction in reactions:
            branch = outcome
            successor = target
            current = environment
            branch_uncertain = uncertain
            branch_reasons = list(reasons)
            if reaction is not None:
                successor = reaction.after.target
                current = reaction.after.environment
                if reaction.status is Signal.UNKNOWN:
                    branch_uncertain = True
                    branch_reasons.extend(reaction.reasons)
                    branch = replace(branch, decision=Decision.UNKNOWN, uncertainty=tuple(branch_reasons))
                branch = replace(branch, environment=dict(reaction.outputs))
            regions = dict(frame.regions)
            if item.component in regions:
                regions[item.component] = successor
            after = Frame(successor, current, branch_uncertain, tuple(branch_reasons), regions)
            event = branch.event(
                item.name,
                entry,
                request,
                frame.target,
                component=item.component,
            )
            if reaction is not None:
                event = replace(event, after=successor, reaction=dict(branch.environment), uncertainty=after.reasons)
            moves.append(Move(item, branch, frame, after, event))
        return tuple(moves)


def _merge(state: State, values: Mapping[str, Any]) -> State:
    if not values:
        return state
    merged = state.as_dict()
    merged.update(values)
    return State(merged)


def _request(value: Any, original: Mapping[str, Any]) -> dict[str, Any]:
    """Map a transformed value back to an operation request explicitly."""
    if isinstance(value, Mapping):
        return dict(value)
    if len(original) == 1:
        key = next(iter(original))
        return {key: value}
    return {**dict(original), "value": value}
