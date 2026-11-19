"""Canonical executable composition for modeled regions and environments."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from .environment import Context, Signal, World
from .graph import Graph
from .model import Decision, Event, Model, Operation, Outcome, State


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

    @classmethod
    def flat(
        cls,
        model: Model,
        *,
        graph: Graph | None = None,
        world: World | None = None,
        environment: State | None = None,
    ) -> "Workspace":
        return cls(model, graph, world, Frame(model.initial_state, environment or State()))

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
                outcome = original
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
