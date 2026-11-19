"""Canonical executable composition for modeled regions and environments."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable, Mapping

from .environment import Context, Signal, World
from .graph import Graph
from .model import Decision, Entry, Event, Model, Operation, Outcome, State
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

    def view(self) -> State:
        """Expose global state plus qualified region values to predicates."""
        values = self.target.as_dict()
        for region, state in self.regions.items():
            values.update({f"{region}.{key}": value for key, value in state.as_dict().items()})
        return State(values)


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
    mappers: Mapping[str, Callable[[Any, Mapping[str, Any]], Mapping[str, Any]]] = field(default_factory=dict)
    entries: frozenset[str] = frozenset()

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
        mappers: Mapping[str, Callable[[Any, Mapping[str, Any]], Mapping[str, Any]]] | None = None,
        entries: frozenset[str] | set[str] = frozenset(),
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
            dict(mappers or {}),
            frozenset(entries),
        )

    def start(self) -> Frame:
        if self.initial is not None:
            return self.initial
        environment = self.world.initial.environment if self.world is not None else State()
        return Frame(self.model.initial_state, environment)

    def validate(self) -> Any:
        return self.graph.validate() if self.graph is not None else None

    def operations(self, entry: str | None = None) -> tuple[Operation, ...]:
        """Return model operations plus executable graph-only entry routes."""
        model_operations = tuple(
            item for item in self.model.ops()
            if entry is None or item.entry_point.name == entry
        )
        if self.graph is None:
            return model_operations
        known = {(item.name, item.entry_point.name) for item in model_operations}
        graph_operations = tuple(
            Operation(
                transition.transition_id,
                Entry(transition.entry_point),
                component=transition.region_id or "",
            )
            for transition in self.graph.transitions
            if (entry is None or transition.entry_point == entry)
            and (entry is not None or not self.entries or transition.entry_point in self.entries)
            and (transition.transition_id, transition.entry_point) not in known
        )
        return model_operations + graph_operations

    def moves(
        self,
        frame: Frame,
        entry: str,
        request: Mapping[str, Any],
        *,
        operation: Operation | None = None,
    ) -> tuple[Move, ...]:
        operations = (operation,) if operation is not None else self.operations(entry)
        moves: list[Move] = []
        for item in operations:
            if not self._transitions(item):
                for outcome in item.branches(self._local(frame, item), request):
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

    @staticmethod
    def _local(frame: Frame, operation: Operation) -> State:
        return frame.regions.get(operation.component, frame.target)

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
        lowered: list[tuple[Outcome, Mapping[str, Any]]] = []
        for transition in transitions:
            lowered.extend(self._walk(interpreter, transition, request, self._local(frame, operation), (transition.transition_id,)))
        return tuple(lowered)

    def _walk(
        self,
        interpreter: Interpreter,
        transition: Any,
        value: Any,
        state: State,
        seen: tuple[str, ...],
    ) -> tuple[tuple[Outcome, Mapping[str, Any]], ...]:
        outcomes = interpreter.outcomes(transition.transition_id, value, state=state)
        results: list[tuple[Outcome, Mapping[str, Any]]] = []
        for outcome in outcomes:
            if outcome.decision is not Decision.ACCEPT:
                results.append((outcome, value if isinstance(value, Mapping) else {"value": value}))
                continue
            edges = self._edges(transition)
            if not edges:
                mapped = self._map(transition.transition_id, outcome.observation.get("value"), value)
                if mapped is None:
                    results.append((replace(
                        outcome,
                        decision=Decision.UNKNOWN,
                        uncertainty=outcome.uncertainty + (f"no request mapping for {transition.transition_id}",),
                    ), value if isinstance(value, Mapping) else {"value": value}))
                else:
                    results.append((outcome, mapped))
                continue
            for edge in edges:
                destinations = self._destinations(edge)
                converted = self._convert(edge, outcome.observation.get("value"), outcome.after)
                if converted is None:
                    results.append((replace(
                        outcome,
                        decision=Decision.UNKNOWN,
                        uncertainty=outcome.uncertainty + (f"opaque connection: {edge.connection_id}",),
                    ), value if isinstance(value, Mapping) else {"value": value}))
                    continue
                if not converted:
                    continue
                if not destinations:
                    for converted_value in converted:
                        mapped = self._map(transition.transition_id, converted_value, value)
                        if mapped is not None:
                            results.append((outcome, mapped))
                    continue
                for next_value in converted:
                    for destination in destinations:
                        if destination.transition_id in seen:
                            results.append((replace(
                                outcome,
                                decision=Decision.UNKNOWN,
                                uncertainty=outcome.uncertainty + (f"cyclic graph route at {destination.transition_id}",),
                            ), value if isinstance(value, Mapping) else {"value": value}))
                            continue
                        if len(seen) >= self.graph.budget.max_depth:
                            results.append((replace(
                                outcome,
                                decision=Decision.UNKNOWN,
                                uncertainty=outcome.uncertainty + ("graph route depth budget reached",),
                            ), value if isinstance(value, Mapping) else {"value": value}))
                            continue
                        for next_outcome, mapped in self._walk(
                            interpreter,
                            destination,
                            next_value,
                            outcome.after,
                            seen + (destination.transition_id,),
                        ):
                            results.append((self._join(outcome, next_outcome), mapped))
        return tuple(results)

    def _edges(self, transition: Any) -> tuple[Any, ...]:
        ports = {port.port_id: port for port in self.graph.ports}
        return tuple(
            edge for edge in self.graph.connections
            if edge.output_representation == transition.output_representation
            and (
                transition.region_id is None
                or ports.get(edge.source_port_id) is None
                or ports[edge.source_port_id].region_id == transition.region_id
            )
        )

    def _destinations(self, edge: Any) -> tuple[Any, ...]:
        ports = {port.port_id: port for port in self.graph.ports}
        destination_region = ports.get(edge.destination_port_id).region_id if ports.get(edge.destination_port_id) else None
        return tuple(
            transition for transition in self.graph.transitions
            if transition.input_representation == edge.input_representation
            and (transition.region_id is None or transition.region_id == destination_region)
        )

    def _convert(self, edge: Any, value: Any, state: State) -> tuple[Any, ...] | None:
        if edge.transform_id is None:
            return (value,)
        evaluator = self.transforms.get(edge.transform_id)
        if evaluator is None:
            return None
        try:
            values = evaluator(value, state)
            if isinstance(values, (str, bytes, bytearray, Mapping)) or values is None:
                return (values,)
            return tuple(values)
        except Exception:
            return None

    @staticmethod
    def _join(first: Outcome, second: Outcome) -> Outcome:
        return replace(
            second,
            effects=first.effects + second.effects,
            reads=first.reads | second.reads,
            writes=first.writes | second.writes,
            evidence=first.evidence + second.evidence,
            uncertainty=first.uncertainty + second.uncertainty,
        )

    def _map(self, transition_id: str, value: Any, original: Any) -> Mapping[str, Any] | None:
        if isinstance(value, Mapping):
            return dict(value)
        mapper = self.mappers.get(transition_id)
        if mapper is None:
            return None
        return dict(mapper(value, original if isinstance(original, Mapping) else {}))

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
        owned = item.component in frame.regions
        local_before = self._local(frame, item)
        target = frame.target if owned else outcome.after
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
            if owned:
                regions[item.component] = outcome.after
            after = Frame(successor, current, branch_uncertain, tuple(branch_reasons), regions)
            event = branch.event(
                item.name,
                entry,
                request,
                local_before,
                component=item.component,
            )
            if reaction is not None:
                event = replace(event, after=outcome.after if owned else successor, reaction=dict(branch.environment), uncertainty=after.reasons)
            moves.append(Move(item, branch, frame, after, event))
        return tuple(moves)


def _merge(state: State, values: Mapping[str, Any]) -> State:
    if not values:
        return state
    merged = state.as_dict()
    merged.update(values)
    return State(merged)
