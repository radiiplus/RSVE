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

    def canonical(self) -> dict[str, Any]:
        return {
            "target": self.target.canonical(),
            "environment": self.environment.canonical(),
            "uncertain": self.uncertain,
            "reasons": self.reasons,
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
            Frame(model.initial_state, initial_environment),
            dict(transforms or {}),
            dict(recognizers or {}),
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
            for original in item.branches(frame.target, request):
                for outcome in self._graph(item, frame, request, original):
                    yield_move = self._move(item, outcome, frame, entry, request)
                    moves.extend(yield_move)
        return tuple(moves)

    def _graph(
        self,
        operation: Operation,
        frame: Frame,
        request: Mapping[str, Any],
        original: Outcome,
    ) -> tuple[Outcome, ...]:
        if self.graph is None:
            return (original,)
        transitions = tuple(
            transition
            for transition in self.graph.transitions
            if transition.transition_id == operation.name
            or transition.entry_point == operation.entry_point.name
        )
        if not transitions:
            return (original,)
        interpreter = Interpreter(
            self.graph,
            transforms=self.transforms,
            recognizers=self.recognizers,
        )
        value: Any = request
        lowered: list[Outcome] = []
        for transition in transitions:
            for graph_outcome in interpreter.outcomes(transition.transition_id, value, state=frame.target):
                if graph_outcome.decision is Decision.UNKNOWN:
                    lowered.append(replace(
                        original,
                        decision=Decision.UNKNOWN,
                        uncertainty=tuple(original.uncertainty) + graph_outcome.uncertainty,
                        evidence=tuple(original.evidence) + graph_outcome.evidence,
                    ))
                elif graph_outcome.decision is Decision.REJECT:
                    lowered.append(graph_outcome)
                else:
                    lowered.append(replace(
                        original,
                        evidence=tuple(original.evidence) + graph_outcome.evidence,
                    ))
        return tuple(lowered) or (original,)

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
            after = Frame(successor, current, branch_uncertain, tuple(branch_reasons))
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
