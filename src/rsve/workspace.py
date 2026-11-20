"""Canonical executable composition for modeled regions and environments."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
from typing import Any, Callable, Iterable, Mapping

from .environment import Context, Signal, World
from .graph import Graph, Quality, Shape
from .ir import Partiality, Relation, Semantic
from .model import Decision, Entry, Event, Model, Operation, Outcome, State
from .semantic import Interpreter
from .wp import Symbolic


_MISSING = object()
Probe = Callable[[int], Iterable[Mapping[str, Any]]]


@dataclass(frozen=True)
class Frame:
    """One composed target/environment configuration."""

    target: State
    environment: State = State()
    uncertain: bool = False
    reasons: tuple[str, ...] = ()
    regions: Mapping[str, State] = field(default_factory=dict)
    aliases: tuple[tuple[str, ...], ...] = ()

    def canonical(self) -> dict[str, Any]:
        return {
            "target": self.target.canonical(),
            "environment": self.environment.canonical(),
            "uncertain": self.uncertain,
            "reasons": self.reasons,
            "regions": {key: value.canonical() for key, value in sorted(self.regions.items())},
            "aliases": self.aliases,
        }

    def view(self) -> State:
        """Expose global, region, and environment values to predicates."""
        values = self.target.as_dict()
        for region, state in self.regions.items():
            values.update({f"{region}.{key}": value for key, value in state.as_dict().items()})
        values.update({f"env.{key}": value for key, value in self.environment.as_dict().items()})
        for group in self.aliases:
            shared = next((values[key] for key in group if values.get(key, _MISSING) is not _MISSING), _MISSING)
            if shared is not _MISSING:
                values.update({key: shared for key in group})
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
class GraphResult:
    """One graph route outcome plus its region-scoped successor state."""

    outcome: Outcome
    request: Mapping[str, Any]
    target: State
    regions: Mapping[str, State]


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
    symbolics: Mapping[str, Symbolic] = field(default_factory=dict)
    aliases: tuple[tuple[str, ...], ...] = ()
    resources: Mapping[str, str] = field(default_factory=dict)
    probes: Mapping[str, tuple[Mapping[str, Any], ...]] = field(default_factory=dict)
    expanders: Mapping[str, Probe] = field(default_factory=dict)

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
        symbolics: Mapping[str, Symbolic] | None = None,
        aliases: tuple[tuple[str, ...], ...] = (),
        resources: Mapping[str, str] | None = None,
        probes: Mapping[str, tuple[Mapping[str, Any], ...]] | None = None,
        expanders: Mapping[str, Probe] | None = None,
    ) -> "Workspace":
        initial_environment = (
            environment
            if environment is not None
            else world.initial.environment
            if world is not None
            else State()
        )
        initial_regions = (
            dict(regions)
            if regions is not None
            else {
                region.region_id: model.initial_state
                for region in (graph.regions if graph is not None else ())
            }
        )
        return cls(
            model,
            graph,
            world,
            Frame(model.initial_state, initial_environment, regions=initial_regions, aliases=tuple(aliases)),
            dict(transforms or {}),
            dict(recognizers or {}),
            dict(effects or {}),
            dict(mappers or {}),
            frozenset(entries),
            dict(symbolics or {}),
            tuple(aliases),
            dict(resources or {}),
            {entry: tuple(dict(request) for request in requests) for entry, requests in (probes or {}).items()},
            dict(expanders or {}),
        )

    def probes_for(self, entry: str, limit: int | None = None) -> tuple[Mapping[str, Any], ...]:
        """Return a deterministic, finite concrete probe domain for an entry."""
        bound = max(0, limit if limit is not None else 256)
        candidates = list(self.probes.get(entry, ()))
        expander = self.expanders.get(entry)
        if expander is not None and len(candidates) < bound:
            candidates.extend(expander(bound - len(candidates)))
        unique: list[Mapping[str, Any]] = []
        seen: set[str] = set()
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                raise TypeError(f"probe for {entry} must be a mapping")
            value = dict(candidate)
            key = json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
            if key in seen:
                continue
            seen.add(key)
            unique.append(value)
            if len(unique) >= bound:
                break
        return tuple(unique)

    def contracts(self) -> tuple[Semantic, ...]:
        """Describe which executable directions each semantic binding supports."""
        records: list[Semantic] = []
        transforms: list[Any] = list(self.graph.transforms if self.graph is not None else ())
        known_transforms = {item.transform_id for item in transforms}
        for operation in self.model.operations:
            for transform in operation.transforms:
                if transform.transform_id not in known_transforms:
                    transforms.append(transform)
                    known_transforms.add(transform.transform_id)
        for transform in transforms:
            semantic = self.symbolics.get(transform.transform_id)
            forward = transform.transform_id in self.transforms
            backward = semantic is not None
            limitations: list[str] = []
            if not forward:
                limitations.append("forward evaluator is unavailable")
            if not backward:
                entries = self._transform_entries(transform.transform_id)
                if any(self.probes.get(entry) for entry in entries) or any(entry in self.expanders for entry in entries):
                    limitations.append("backward reasoning is bounded by concrete probes")
                else:
                    limitations.append("symbolic relation is unavailable")
            if transform.relation is Relation.UNKNOWN:
                limitations.append("transform relation is unknown")
            if transform.partiality is Partiality.UNKNOWN:
                limitations.append("transform partiality is unknown")
            if semantic is not None and not self._matches(transform.semantics_ref, transform.semantics_version, semantic):
                limitations.append("forward and backward semantics references do not match")
            if semantic is not None:
                if semantic.relation == "unknown":
                    limitations.append("symbolic relation is unknown")
                if transform.relation is Relation.RELATION and not self.symbolics[transform.transform_id].alternatives:
                    limitations.append("relational transform has no explicit finite alternatives")
            complete = forward and backward and not limitations
            records.append(Semantic(
                transform.transform_id,
                transform.semantics_ref,
                transform.semantics_version,
                forward,
                backward,
                complete,
                transform.relation,
                transform.partiality,
                tuple(limitations),
                transform.evidence,
            ))
        for operation in self.model.operations:
            semantic = operation.symbolic_transition
            if operation.relation is None and semantic is None:
                continue
            forward = True
            backward = semantic is not None
            limitations = []
            if not backward:
                if self.probes.get(operation.entry_point.name) or operation.entry_point.name in self.expanders:
                    limitations.append("backward reasoning is bounded by concrete probes")
                else:
                    limitations.append("symbolic relation is unavailable")
            relation = Relation.RELATION if operation.relation is not None else Relation.FUNCTION
            reference = semantic.semantics_ref if semantic is not None else "rsve.operation"
            version = semantic.semantics_version if semantic is not None else "1"
            if semantic is not None and semantic.relation == "unknown":
                limitations.append("symbolic relation is unknown")
            records.append(Semantic(
                operation.name,
                reference,
                version,
                forward,
                backward,
                forward and backward and not limitations,
                relation,
                Partiality.UNKNOWN,
                tuple(limitations),
                (),
            ))
        if self.graph is not None:
            for recognizer in self.graph.recognizers:
                semantic = self.symbolics.get(recognizer.recognizer_id)
                limitations: list[str] = []
                forward = recognizer.recognizer_id in self.recognizers
                backward = semantic is not None
                if not forward:
                    limitations.append("forward evaluator is unavailable")
                if not backward:
                    limitations.append("symbolic predicate is unavailable")
                if semantic is not None and semantic.relation == "unknown":
                    limitations.append("symbolic relation is unknown")
                records.append(Semantic(
                    recognizer.recognizer_id,
                    recognizer.actual_predicate_ref,
                    "1",
                    forward,
                    backward,
                    forward and backward and not limitations,
                    Relation.FUNCTION,
                    Partiality.TOTAL,
                    tuple(limitations),
                    recognizer.evidence,
                ))
            for effect in self.graph.effects:
                semantic = self.symbolics.get(effect.effect_id)
                limitations = []
                forward = effect.effect_id in self.effects
                backward = semantic is not None
                if not forward:
                    limitations.append("forward evaluator is unavailable")
                if not backward:
                    limitations.append("symbolic effect relation is unavailable")
                if semantic is not None and semantic.relation == "unknown":
                    limitations.append("symbolic relation is unknown")
                records.append(Semantic(
                    effect.effect_id,
                    effect.observable,
                    "1",
                    forward,
                    backward,
                    forward and backward and not limitations,
                    Relation.FUNCTION,
                    Partiality.TOTAL,
                    tuple(limitations),
                    effect.evidence,
                ))
        return tuple(records)

    def contract(self, semantic_id: str) -> Semantic | None:
        """Return the authoritative semantic contract for one graph binding."""
        return next((item for item in self.contracts() if item.semantic_id == semantic_id), None)

    def _transform_entries(self, transform_id: str) -> tuple[str, ...]:
        entries = [
            transition.entry_point
            for transition in self.graph.transitions
            if self.graph is not None and transform_id in transition.transform_ids
        ] if self.graph is not None else []
        entries.extend(
            operation.entry_point.name
            for operation in self.model.operations
            if any(transform.transform_id == transform_id for transform in operation.transforms)
        )
        return tuple(dict.fromkeys(entries))

    @staticmethod
    def _matches(reference: str, version: str, semantic: Symbolic) -> bool:
        if semantic.semantics_ref == "rsve.symbolic/1":
            return True
        return semantic.semantics_ref == reference and semantic.semantics_version == version

    def start(self) -> Frame:
        if self.initial is not None:
            return self.initial
        environment = self.world.initial.environment if self.world is not None else State()
        return Frame(self.model.initial_state, environment, aliases=self.aliases)

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

    def routes(
        self,
        operation: Operation,
    ) -> tuple[tuple[tuple[Any, ...], tuple[Any, ...]], ...]:
        """Return bounded graph routes that can feed an operation."""
        if self.graph is None:
            return ()
        routes: list[tuple[tuple[Any, ...], tuple[Any, ...]]] = []

        def walk(
            transition: Any,
            transitions: tuple[Any, ...],
            connections: tuple[Any, ...],
            seen: tuple[str, ...],
        ) -> None:
            edges = self._edges(transition)
            if not edges:
                routes.append((transitions, connections))
                return
            for edge in edges:
                destinations = self._destinations(edge)
                if not destinations:
                    routes.append((transitions, connections + (edge,)))
                    continue
                for destination in destinations:
                    if destination.transition_id in seen or len(seen) >= self.graph.budget.max_depth:
                        continue
                    walk(
                        destination,
                        transitions + (destination,),
                        connections + (edge,),
                        seen + (destination.transition_id,),
                    )

        for transition in self._transitions(operation):
            walk(transition, (transition,), (), (transition.transition_id,))
        return tuple(routes)

    def route_notes(self, operation: Operation) -> tuple[str, ...]:
        """Report graph routes excluded by cycle or depth bounds."""
        if self.graph is None:
            return ()
        notes: set[str] = set()

        def walk(transition: Any, seen: tuple[str, ...]) -> None:
            for edge in self._edges(transition):
                destinations = self._destinations(edge)
                for destination in destinations:
                    if destination.transition_id in seen:
                        notes.add(f"cycle route excluded at {destination.transition_id}")
                    elif len(seen) >= self.graph.budget.max_depth:
                        notes.add("symbolic graph route depth budget reached")
                    else:
                        walk(destination, seen + (destination.transition_id,))

        for transition in self._transitions(operation):
            walk(transition, (transition.transition_id,))
        return tuple(sorted(notes))

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
            if item.component and self.graph is not None and item.component in {region.region_id for region in self.graph.regions} and item.component not in frame.regions:
                moves.extend(self._missing_region(item, frame, entry, request))
                continue
            if not self._transitions(item):
                for outcome in item.branches(self._local(frame, item), request):
                    moves.extend(self._move(item, outcome, frame, entry, request, source=request))
                continue
            for result in self._outcomes(item, frame, request):
                outcome = result.outcome
                if outcome.decision is Decision.ACCEPT:
                    routed = replace(frame, target=result.target, regions=dict(result.regions))
                    for branch in item.branches(self._local(routed, item), result.request):
                        combined = self._combine(outcome, branch)
                        moves.extend(self._move(item, combined, routed, entry, result.request, source=request))
                else:
                    routed = replace(frame, target=result.target, regions=dict(result.regions))
                    moves.extend(self._move(item, outcome, routed, entry, request, source=request))
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
    ) -> tuple[GraphResult, ...]:
        transitions = self._transitions(operation)
        interpreter = Interpreter(
            self.graph,
            transforms=self.transforms,
            recognizers=self.recognizers,
            effects=self.effects,
        )
        lowered: list[GraphResult] = []
        for transition in transitions:
            lowered.extend(self._walk(
                interpreter,
                transition,
                request,
                frame.target,
                frame.regions,
                (transition.transition_id,),
            ))
        return tuple(lowered)

    def _walk(
        self,
        interpreter: Interpreter,
        transition: Any,
        value: Any,
        target: State,
        regions: Mapping[str, State],
        seen: tuple[str, ...],
    ) -> tuple[GraphResult, ...]:
        owned = transition.region_id is not None
        if owned and transition.region_id not in regions:
            missing = Outcome(
                Decision.UNKNOWN,
                target,
                terminal=True,
                uncertainty=(f"region state unavailable: {transition.region_id}",),
            )
            return (GraphResult(
                missing,
                value if isinstance(value, Mapping) else {"value": value},
                target,
                dict(regions),
            ),)
        state = regions[transition.region_id] if owned else target
        outcomes = interpreter.outcomes(transition.transition_id, value, state=state)
        results: list[GraphResult] = []
        for outcome in outcomes:
            next_target = target
            next_regions = dict(regions)
            if not owned:
                next_target = outcome.after
            else:
                next_regions[transition.region_id] = outcome.after
            if outcome.decision is not Decision.ACCEPT:
                results.append(GraphResult(
                    outcome,
                    value if isinstance(value, Mapping) else {"value": value},
                    next_target,
                    next_regions,
                ))
                continue
            edges = self._edges(transition)
            if not edges:
                mapped = self._map(transition.transition_id, outcome.observation.get("value"), value)
                if mapped is None:
                    results.append(GraphResult(
                        replace(
                            outcome,
                            decision=Decision.UNKNOWN,
                            uncertainty=outcome.uncertainty + (f"no request mapping for {transition.transition_id}",),
                        ),
                        value if isinstance(value, Mapping) else {"value": value},
                        next_target,
                        next_regions,
                    ))
                else:
                    results.append(GraphResult(outcome, mapped, next_target, next_regions))
                continue
            for edge in edges:
                destinations = self._destinations(edge)
                edge_outcome = outcome
                if edge.correlation_quality is Quality.UNCORRELATED:
                    edge_outcome = replace(
                        edge_outcome,
                        uncertainty=edge_outcome.uncertainty + (
                            f"uncorrelated connection: {edge.connection_id}",
                        ),
                    )
                converted = self._convert(edge, outcome.observation.get("value"), outcome.after)
                if converted is None:
                    results.append(GraphResult(
                        replace(
                            edge_outcome,
                            decision=Decision.UNKNOWN,
                            uncertainty=outcome.uncertainty + (f"opaque connection: {edge.connection_id}",),
                        ),
                        value if isinstance(value, Mapping) else {"value": value},
                        next_target,
                        next_regions,
                    ))
                    continue
                if not converted:
                    if self._connection_complete(edge):
                        continue
                    results.append(GraphResult(
                        replace(
                            edge_outcome,
                            decision=Decision.UNKNOWN,
                            uncertainty=edge_outcome.uncertainty + (
                                f"connection relation returned no successors without completeness evidence: {edge.connection_id}",
                            ),
                        ),
                        value if isinstance(value, Mapping) else {"value": value},
                        next_target,
                        next_regions,
                    ))
                    continue
                if not destinations:
                    for converted_value in converted:
                        mapped = self._map(transition.transition_id, converted_value, value)
                        if mapped is None:
                            results.append(GraphResult(
                                replace(
                                    edge_outcome,
                                    decision=Decision.UNKNOWN,
                                    uncertainty=edge_outcome.uncertainty + (
                                        f"no request mapping for {transition.transition_id}",
                                    ),
                                ),
                                value if isinstance(value, Mapping) else {"value": value},
                                next_target,
                                next_regions,
                            ))
                        else:
                            results.append(GraphResult(edge_outcome, mapped, next_target, next_regions))
                    continue
                for next_value in converted:
                    for destination in destinations:
                        if destination.transition_id in seen:
                            results.append(GraphResult(
                                replace(
                                    outcome,
                                    decision=Decision.UNKNOWN,
                                    uncertainty=outcome.uncertainty + (f"cyclic graph route at {destination.transition_id}",),
                                ),
                                value if isinstance(value, Mapping) else {"value": value},
                                next_target,
                                next_regions,
                            ))
                            continue
                        if len(seen) >= self.graph.budget.max_depth:
                            results.append(GraphResult(
                                replace(
                                    outcome,
                                    decision=Decision.UNKNOWN,
                                    uncertainty=outcome.uncertainty + ("graph route depth budget reached",),
                                ),
                                value if isinstance(value, Mapping) else {"value": value},
                                next_target,
                                next_regions,
                            ))
                            continue
                        for next_result in self._walk(
                            interpreter,
                            destination,
                            next_value,
                            next_target,
                            next_regions,
                            seen + (destination.transition_id,),
                        ):
                            results.append(GraphResult(
                                    self._join(edge_outcome, next_result.outcome),
                                next_result.request,
                                next_result.target,
                                next_result.regions,
                            ))
        return tuple(results)

    def _edges(self, transition: Any) -> tuple[Any, ...]:
        ports = {port.port_id: port for port in self.graph.ports}
        return tuple(
            edge for edge in self.graph.connections
            if edge.relationship_type is Shape.DATA
            and edge.output_representation == transition.output_representation
            and (
                transition.region_id is None
                or ports.get(edge.source_port_id) is None
                or ports[edge.source_port_id].region_id == transition.region_id
            )
        )

    def _connection_complete(self, edge: Any) -> bool:
        if edge.transform_id is None:
            return True
        transform = next(
            (item for item in self.graph.transforms if item.transform_id == edge.transform_id),
            None,
        )
        return bool(transform is not None and transform.complete)

    def _missing_region(
        self,
        operation: Operation,
        frame: Frame,
        entry: str,
        request: Mapping[str, Any],
    ) -> tuple[Move, ...]:
        reason = f"region state unavailable: {operation.component}"
        outcome = Outcome(
            Decision.UNKNOWN,
            frame.target,
            terminal=True,
            uncertainty=(reason,),
        )
        return self._move(operation, outcome, frame, entry, request, source=request)

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
        *,
        source: Mapping[str, Any] | None = None,
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
            resource_reason = self._resource_reason(item, branch)
            if resource_reason is not None:
                branch_uncertain = True
                branch_reasons.append(resource_reason)
                branch = replace(
                    branch,
                    decision=Decision.UNKNOWN,
                    uncertainty=tuple(branch_reasons),
                )
            regions = dict(frame.regions)
            if owned:
                regions[item.component] = outcome.after
            after = Frame(
                successor,
                current,
                branch_uncertain,
                tuple(branch_reasons),
                regions,
                frame.aliases,
            )
            after = self._sync(after, item, branch)
            event = branch.event(
                item.name,
                entry,
                request,
                local_before,
                component=item.component,
            )
            event = replace(
                event,
                source=dict(request if source is None else source),
                correlation_uncertain=any(
                    "uncorrelated connection:" in reason
                    for reason in branch.uncertainty
                ),
            )
            if reaction is not None:
                event = replace(event, after=outcome.after if owned else successor, reaction=dict(branch.environment), uncertainty=after.reasons)
            moves.append(Move(item, branch, frame, after, event))
        return tuple(moves)

    def _resource_reason(self, operation: Operation, outcome: Outcome) -> str | None:
        return self._resource_reason_for(operation.component, outcome.writes | outcome.must | outcome.may)

    def symbolic_resource_reason(self, operation: Operation, symbolic: Symbolic) -> str | None:
        assignments = set(symbolic.assignments)
        for alternative in symbolic.alternatives:
            assignments.update(alternative)
        keys = tuple(
            key.removeprefix("state.")
            for key in assignments
            if key.startswith("state.resource.")
        )
        return self._resource_reason_for(operation.component, keys)

    def _resource_reason_for(self, component: str, keys: Any) -> str | None:
        for key in keys:
            if not key.startswith("resource."):
                continue
            resource = key.removeprefix("resource.")
            owner = self.resources.get(resource)
            if owner is None:
                return f"resource ownership is unknown: {resource}"
            if owner != component:
                return f"resource write denied outside owner {owner}: {resource}"
        return None

    def _sync(self, frame: Frame, operation: Operation, outcome: Outcome) -> Frame:
        if not frame.aliases:
            return frame
        target = frame.target
        environment = frame.environment
        regions = dict(frame.regions)
        for key in outcome.writes | outcome.must | outcome.may:
            qualified = (
                key
                if "." in key or operation.component not in regions
                else f"{operation.component}.{key}"
            )
            group = next((group for group in frame.aliases if qualified in group), None)
            if group is None:
                continue
            value = self._read(frame, qualified)
            if value is _MISSING:
                continue
            for alias in group:
                target, environment, regions = self._write(target, environment, regions, alias, value)
        return Frame(target, environment, frame.uncertain, frame.reasons, regions, frame.aliases)

    @staticmethod
    def _read(frame: Frame, key: str) -> Any:
        if key.startswith("env."):
            return frame.environment.as_dict().get(key.removeprefix("env."), _MISSING)
        if "." in key:
            region, local = key.split(".", 1)
            if region in frame.regions:
                return frame.regions[region].as_dict().get(local, _MISSING)
        return frame.target.as_dict().get(key, _MISSING)

    @staticmethod
    def _write(
        target: State,
        environment: State,
        regions: Mapping[str, State],
        key: str,
        value: Any,
    ) -> tuple[State, State, dict[str, State]]:
        updated = dict(regions)
        if key.startswith("env."):
            return target, environment.update(**{key.removeprefix("env."): value}), updated
        if "." in key:
            region, local = key.split(".", 1)
            if region in updated:
                updated[region] = updated[region].update(**{local: value})
                return target, environment, updated
        return target.update(**{key: value}), environment, updated


def _merge(state: State, values: Mapping[str, Any]) -> State:
    if not values:
        return state
    merged = state.as_dict()
    merged.update(values)
    return State(merged)
