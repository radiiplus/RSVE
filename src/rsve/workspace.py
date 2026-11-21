"""Canonical executable composition for modeled regions and environments."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
from typing import Any, Callable, Iterable, Mapping

from .environment import Context, Signal, Step, World
from .graph import Fit, Graph, Quality, Shape
from .ir import Partiality, Relation, Semantic
from .model import Decision, Entry, Event, Fidelity, Model, Operation, Outcome, State
from .semantic import Interpreter
from .transforms import ObservedTransformModel
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
    lineage: tuple[str, ...] | None = None
    origins: Mapping[str, tuple[str, ...]] | None = None
    logical_step: int = 0
    pending_events: tuple[Any, ...] = ()
    clients: Mapping[str, State] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        return {
            "target": self.target.canonical(),
            "environment": self.environment.canonical(),
            "uncertain": self.uncertain,
            "reasons": self.reasons,
            "regions": {key: value.canonical() for key, value in sorted(self.regions.items())},
            "aliases": self.aliases,
            "lineage": self.lineage,
            "origins": self.origins,
            "logical_step": self.logical_step,
            "pending_events": tuple({
                "event_id": item.event_id,
                "transition_id": item.transition_id,
                "due_step": item.due_step,
                "payload": dict(item.payload),
            } for item in self.pending_events),
            "clients": {key: value.canonical() for key, value in sorted(self.clients.items())},
        }

    def view(self) -> State:
        """Expose global, region, and environment values to predicates."""
        values = self.target.as_dict()
        for region, state in self.regions.items():
            values.update({f"{region}.{key}": value for key, value in state.as_dict().items()})
        for client, state in self.clients.items():
            values.update({f"client.{client}.{key}": value for key, value in state.as_dict().items()})
        values.update({f"env.{key}": value for key, value in self.environment.as_dict().items()})
        values["env.logical_step"] = self.logical_step
        values["env.pending_count"] = len(self.pending_events)
        values["env.pending_transitions"] = tuple(item.transition_id for item in self.pending_events)
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
class ClientAction:
    entry: str
    request: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InterleavingRun:
    order: tuple[str, ...]
    moves: tuple[Move, ...]
    final: Frame
    completed: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class InterleavingExploration:
    runs: tuple[InterleavingRun, ...]
    complete: bool
    explored_prefixes: int
    reasons: tuple[str, ...] = ()


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
    scope_id: str = "workspace"
    scope_unknowns: tuple[str, ...] = ()

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
        clients: Mapping[str, State] | None = None,
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
            Frame(
                model.initial_state,
                initial_environment,
                regions=initial_regions,
                aliases=tuple(aliases),
                logical_step=world.initial.logical_step if world is not None else 0,
                pending_events=world.initial.pending if world is not None else (),
                clients=dict(clients or {}),
            ),
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
        """Return a deterministic, finite concrete probe domain for an entry.

        Inputs observed at the first transform of a route are added as seeds.
        They remain probes: their presence does not establish transform
        completeness or behavior outside the exact recorded input/state pair.
        """
        bound = max(0, limit if limit is not None else 256)
        if bound == 0:
            return ()
        candidates = list(self.probes.get(entry, ()))
        first_transform_ids = {
            transition.transform_ids[0]
            for transition in (self.graph.transitions if self.graph is not None else ())
            if transition.entry_point == entry and transition.transform_ids
        }
        first_transform_ids.update(
            operation.transforms[0].transform_id
            for operation in self.operations(entry)
            if operation.transforms
        )
        for transform_id in sorted(first_transform_ids):
            evaluator = self.transforms.get(transform_id)
            if not isinstance(evaluator, ObservedTransformModel):
                continue
            candidates.extend(
                evaluator.probe_inputs(
                    max(0, bound - len(candidates)),
                    mappings_only=True,
                )
            )
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
            evaluator = self.transforms.get(transform.transform_id)
            forward = evaluator is not None
            backward = semantic is not None
            limitations: list[str] = []
            if isinstance(evaluator, ObservedTransformModel):
                limitations.append("observations are exact-context samples and do not establish the full transform relation")
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
                self._operation_id(operation),
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
                if semantic is not None and not self._matches(
                    recognizer.actual_predicate_ref,
                    recognizer.semantics_version,
                    semantic,
                ):
                    limitations.append("forward and backward semantics references do not match")
                records.append(Semantic(
                    recognizer.recognizer_id,
                    recognizer.actual_predicate_ref,
                    recognizer.semantics_version,
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
                if semantic is not None and not self._matches(
                    effect.semantics_ref,
                    effect.semantics_version,
                    semantic,
                ):
                    limitations.append("forward and backward semantics references do not match")
                records.append(Semantic(
                    effect.effect_id,
                    effect.semantics_ref,
                    effect.semantics_version,
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

    @staticmethod
    def _operation_id(operation: Operation) -> str:
        return f"operation:{operation.entry_point.name}:{operation.name}"

    def contract_for(self, operation: Operation) -> Semantic | None:
        return self.contract(self._operation_id(operation))

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
        return semantic.semantics_ref == reference and semantic.semantics_version == version

    def start(self) -> Frame:
        if self.initial is not None:
            return self.initial
        environment = self.world.initial.environment if self.world is not None else State()
        return Frame(
            self.model.initial_state,
            environment,
            aliases=self.aliases,
            logical_step=self.world.initial.logical_step if self.world is not None else 0,
            pending_events=self.world.initial.pending if self.world is not None else (),
            clients=self.initial.clients if self.initial is not None else {},
        )

    def validate(self) -> Any:
        return self.graph.validate() if self.graph is not None else None

    def component_view(self, region_id: str) -> "Workspace":
        """Project this workspace onto one region and retain omitted seams as unknowns."""
        if self.graph is None:
            raise ValueError("component views require a graph-backed workspace")
        regions = {region.region_id for region in self.graph.regions}
        if region_id not in regions:
            raise KeyError(f"unknown graph region: {region_id}")

        ports = {port.port_id: port for port in self.graph.ports}
        local_ports = tuple(port for port in self.graph.ports if port.region_id == region_id)
        local_port_ids = {port.port_id for port in local_ports}
        local_connections = tuple(
            edge for edge in self.graph.connections
            if edge.source_port_id in local_port_ids and edge.destination_port_id in local_port_ids
        )
        local_binding_ids = {
            binding_id
            for edge in local_connections
            for binding_id in (edge.source_binding_id, edge.destination_binding_id)
            if binding_id is not None
        }
        seams = tuple(sorted(
            f"unknown seam {edge.connection_id}: "
            f"{ports[edge.source_port_id].region_id if edge.source_port_id in ports else 'missing-region'}"
            f"->{ports[edge.destination_port_id].region_id if edge.destination_port_id in ports else 'missing-region'}"
            for edge in self.graph.connections
            if edge not in local_connections
            and (edge.source_port_id in local_port_ids or edge.destination_port_id in local_port_ids)
        ))
        local_operations = tuple(
            operation for operation in self.model.operations
            if operation.component == region_id
        )
        omitted_operations = tuple(
            f"component scope {region_id} omits operation {operation.name} "
            f"from {operation.component or 'unscoped/global region'}"
            for operation in self.model.operations
            if operation.component != region_id
        )
        local_entries = {operation.entry_point.name for operation in local_operations}
        local_transitions = tuple(
            transition for transition in self.graph.transitions
            if transition.region_id == region_id
        )
        omitted_transitions = tuple(
            f"component scope {region_id} omits transition {transition.transition_id} "
            f"from {transition.region_id or 'unscoped/global region'}"
            for transition in self.graph.transitions
            if transition.region_id != region_id
        )
        projected_graph = replace(
            self.graph,
            graph_id=f"{self.graph.graph_id}:component:{region_id}",
            regions=tuple(region for region in self.graph.regions if region.region_id == region_id),
            ports=local_ports,
            connections=local_connections,
            transitions=local_transitions,
            bindings=tuple(
                binding for binding in self.graph.bindings
                if binding.binding_id in local_binding_ids
                or not binding.attached_regions
                or set(binding.attached_regions) <= {region_id}
            ),
        )
        initial = self.start()
        projected_initial = replace(
            initial,
            regions={region_id: initial.regions[region_id]} if region_id in initial.regions else {},
        )
        projected_model = replace(self.model, operations=local_operations)
        return replace(
            self,
            model=projected_model,
            graph=projected_graph,
            initial=projected_initial,
            entries=frozenset(local_entries),
            scope_id=f"component:{region_id}",
            scope_unknowns=tuple(dict.fromkeys(self.scope_unknowns + seams + omitted_operations + omitted_transitions + (
                f"component scope {region_id} omits other regions and their interactions",
            ))),
        )

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
            observations = self.model.observations_for(
                entry,
                request,
                self._local(frame, item),
                component=item.component,
                environment=frame.environment.as_dict(),
                client_id=item.client_id,
                operation=item.name,
            )
            if observations:
                for observed in observations:
                    reason = "observed transition is specific to this exact request and pre-state; successor completeness is unknown"
                    outcome = Outcome(
                        observed.decision,
                        observed.after,
                        observation=observed.observation,
                        effects=observed.effects,
                        reads=observed.reads,
                        writes=observed.writes,
                        environment=observed.reaction,
                        terminal=observed.terminal,
                        guard=observed.guard_result,
                        fidelity=Fidelity.OBSERVED,
                        mode=observed.mode,
                        evidence=observed.evidence_refs,
                        uncertainty=(reason,),
                    )
                    for move in self._move(item, outcome, frame, entry, request, source=request):
                        after = replace(
                            move.after,
                            uncertain=True,
                            reasons=tuple(dict.fromkeys(move.after.reasons + (reason,))),
                        )
                        event = replace(
                            move.event,
                            event_id=observed.event_id,
                            run_id=observed.run_id,
                            trace_id=observed.trace_id,
                            evidence_source=observed.evidence_source,
                            timestamp_ns=observed.timestamp_ns,
                            uncertainty=tuple(dict.fromkeys(move.event.uncertainty + (reason,))),
                        )
                        moves.append(replace(move, after=after, event=event))
                continue
            if not self._transitions(item):
                for outcome in item.branches(self._local(frame, item), request):
                    moves.extend(self._move(item, outcome, frame, entry, request, source=request))
                continue
            for result in self._outcomes(item, frame, entry, request):
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

    def explore_interleavings(
        self,
        client_actions: Mapping[str, Iterable[ClientAction | tuple[str, Mapping[str, Any]]]],
        *,
        frame: Frame | None = None,
        max_schedules: int = 256,
        max_expansions: int = 10000,
        max_branches_per_action: int = 256,
        max_total_steps: int = 128,
    ) -> InterleavingExploration:
        """Explore bounded order-preserving schedules for exactly two clients.

        Each client's program order is preserved; choices between clients are
        explored against one shared Frame. This predicts modeled schedules and
        does not observe Go goroutines, CPU scheduling, or kernel execution.
        """
        if len(client_actions) != 2 or any(not name for name in client_actions):
            raise ValueError("interleaving exploration requires exactly two named clients")
        if min(max_schedules, max_expansions, max_branches_per_action, max_total_steps) <= 0:
            raise ValueError("interleaving bounds must be positive")
        clients = tuple(sorted(client_actions))
        actions: dict[str, tuple[ClientAction, ...]] = {}
        total_steps = 0
        for client in clients:
            normalized = []
            for item in client_actions[client]:
                if total_steps >= max_total_steps:
                    raise ValueError("interleaving action count exceeds max_total_steps")
                action = item if isinstance(item, ClientAction) else ClientAction(str(item[0]), dict(item[1]))
                normalized.append(action)
                total_steps += 1
            actions[client] = tuple(normalized)
        if any(not sequence for sequence in actions.values()):
            raise ValueError("both clients need at least one modeled action")
        initial = frame or self.start()
        indices0 = tuple(0 for _ in clients)
        runs: list[InterleavingRun] = []
        explored = 0
        truncated = False
        reasons: list[str] = []

        def visit(
            current: Frame,
            indices: tuple[int, ...],
            order: tuple[str, ...],
            moves_so_far: tuple[Move, ...],
            run_reasons: tuple[str, ...] = (),
        ) -> None:
            nonlocal explored, truncated
            if truncated:
                return
            if all(indices[i] >= len(actions[client]) for i, client in enumerate(clients)):
                if len(runs) >= max_schedules:
                    truncated = True
                    reasons.append("interleaving schedule cap reached")
                    return
                runs.append(InterleavingRun(order, moves_so_far, current, True, run_reasons))
                return
            if explored >= max_expansions:
                truncated = True
                reasons.append("interleaving prefix expansion cap reached")
                return
            explored += 1
            for client_index, client in enumerate(clients):
                action_index = indices[client_index]
                if action_index >= len(actions[client]):
                    continue
                action = actions[client][action_index]
                candidates = tuple(
                    item for item in self.operations(action.entry) if item.client_id == client
                )
                if not candidates:
                    if len(runs) < max_schedules:
                        runs.append(InterleavingRun(
                            order + (client,), moves_so_far, current, False,
                            run_reasons + (f"no operation for client {client!r} at {action.entry!r}",),
                        ))
                    else:
                        truncated = True
                        reasons.append("interleaving schedule cap reached")
                    continue
                successors: list[Move] = []
                action_truncated = False
                for operation in candidates:
                    candidate_moves = self.moves(current, action.entry, action.request, operation=operation)
                    remaining = max_branches_per_action - len(successors)
                    if len(candidate_moves) > remaining:
                        successors.extend(candidate_moves[:remaining])
                        action_truncated = True
                        break
                    successors.extend(candidate_moves)
                for move in successors:
                    next_indices = list(indices)
                    next_indices[client_index] += 1
                    next_order = order + (client,)
                    next_moves = moves_so_far + (move,)
                    if move.outcome.terminal and not all(
                        next_indices[i] >= len(actions[name]) for i, name in enumerate(clients)
                    ):
                        if len(runs) < max_schedules:
                            runs.append(InterleavingRun(
                                next_order, next_moves, move.after, False,
                                run_reasons + (f"terminal outcome at {action.entry}",),
                            ))
                        else:
                            truncated = True
                            reasons.append("interleaving schedule cap reached")
                        continue
                    visit(move.after, tuple(next_indices), next_order, next_moves, run_reasons)
                    if truncated:
                        return
                if action_truncated:
                    truncated = True
                    reasons.append(f"branch cap reached for {client}:{action.entry}")
                    return
                if not successors and not truncated:
                    if len(runs) < max_schedules:
                        runs.append(InterleavingRun(
                            order + (client,), moves_so_far, current, False,
                            run_reasons + (f"no modeled successor for {client}:{action.entry}",),
                        ))
                    else:
                        truncated = True
                        reasons.append("interleaving schedule cap reached")

        visit(initial, indices0, (), ())
        return InterleavingExploration(
            tuple(runs), not truncated, explored, tuple(dict.fromkeys(reasons)),
        )

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
        if operation.client_id:
            values = frame.clients.get(operation.client_id, State()).as_dict()
            values.update({f"shared.{key}": value for key, value in frame.target.as_dict().items()})
            values.update({f"env.{key}": value for key, value in frame.environment.as_dict().items()})
            return State(values)
        return frame.regions.get(operation.component, frame.target)

    def _outcomes(
        self,
        operation: Operation,
        frame: Frame,
        entry: str,
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
                _request_lineage(entry, request),
                _request_origins(entry, request),
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
        lineage: tuple[str, ...] | None,
        origins: Mapping[str, tuple[str, ...]] | None,
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
        outcomes = interpreter.outcomes(
            transition.transition_id,
            value,
            state=state,
            lineage=lineage,
            origins=origins,
        )
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
                        lineage=None,
                        origins=None,
                        uncertainty=edge_outcome.uncertainty + (
                            f"uncorrelated connection: {edge.connection_id}",
                        ),
                    )
                converted = self._convert(
                    edge,
                    outcome.observation.get("value"),
                    edge_outcome.after,
                    edge_outcome.lineage,
                    edge_outcome.origins,
                )
                if converted is None:
                    results.append(GraphResult(
                        replace(
                            edge_outcome,
                            decision=Decision.UNKNOWN,
                                    uncertainty=edge_outcome.uncertainty + (f"opaque connection: {edge.connection_id}",),
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
                    for converted_value, converted_lineage, transfer_reason, converted_origins in converted:
                        mapped = self._map(transition.transition_id, converted_value, value)
                        mapped_outcome = replace(
                            edge_outcome,
                            lineage=converted_lineage,
                            origins=converted_origins,
                            uncertainty=edge_outcome.uncertainty + ((transfer_reason,) if transfer_reason else ()),
                        )
                        if mapped is None:
                            results.append(GraphResult(
                                replace(
                                    mapped_outcome,
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
                            results.append(GraphResult(mapped_outcome, mapped, next_target, next_regions))
                    continue
                for next_value, next_lineage, transfer_reason, next_origins in converted:
                    routed_outcome = replace(
                        edge_outcome,
                        lineage=next_lineage,
                        origins=next_origins,
                        uncertainty=edge_outcome.uncertainty + ((transfer_reason,) if transfer_reason else ()),
                    )
                    for destination in destinations:
                        if destination.transition_id in seen:
                            results.append(GraphResult(
                                replace(
                                    routed_outcome,
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
                                    routed_outcome,
                                    decision=Decision.UNKNOWN,
                                    uncertainty=routed_outcome.uncertainty + ("graph route depth budget reached",),
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
                            next_lineage,
                            next_origins,
                        ):
                            results.append(GraphResult(
                                self._join(routed_outcome, next_result.outcome),
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
            return edge.status is Fit.VERIFIED and edge.input_representation == edge.output_representation
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

    def _convert(
        self,
        edge: Any,
        value: Any,
        state: State,
        lineage: tuple[str, ...] | None,
        origins: Mapping[str, tuple[str, ...]] | None,
    ) -> tuple[tuple[Any, tuple[str, ...] | None, str | None, Mapping[str, tuple[str, ...]] | None], ...] | None:
        if edge.status is Fit.UNVERIFIED:
            return None
        if edge.transform_id is None:
            if edge.status is Fit.VERIFIED and edge.input_representation == edge.output_representation:
                return ((value, lineage, None, origins),)
            return None
        evaluator = self.transforms.get(edge.transform_id)
        if evaluator is None:
            return None
        try:
            values = evaluator(value, state)
            if isinstance(values, (str, bytes, bytearray, Mapping)) or values is None:
                values = (values,)
            transform = next(
                (item for item in self.graph.transforms if item.transform_id == edge.transform_id),
                None,
            )
            mode = getattr(transform, "provenance", "unknown")
            transferred = _lineage(mode, lineage)
            transferred_origins = _transfer_origins(
                mode,
                getattr(transform, "provenance_paths", {}),
                origins,
            )
            reason = "; ".join(item for item in (transferred[1], transferred_origins[1]) if item) or None
            return tuple((item, transferred[0], reason, transferred_origins[0]) for item in values)
        except Exception:
            return None

    @staticmethod
    def _join(first: Outcome, second: Outcome) -> Outcome:
        observation = dict(first.observation)
        first_lineage = (
            _origin_records(first.origins)
            if first.origins is not None and first.observation.get("effect_observables")
            else ()
        )
        second_lineage = tuple(observation.get("data_lineage", ()))
        if first_lineage:
            observation["data_lineage"] = tuple(dict.fromkeys(first_lineage + second_lineage))
        observation.update(second.observation)
        if second.observation.get("data_lineage") and first_lineage:
            observation["data_lineage"] = tuple(dict.fromkeys(
                first_lineage + second_lineage + tuple(second.observation["data_lineage"])
            ))
        return replace(
            second,
            observation=observation,
            effects=first.effects + second.effects,
            reads=first.reads | second.reads,
            writes=first.writes | second.writes,
            evidence=first.evidence + second.evidence,
            uncertainty=first.uncertainty + second.uncertainty,
            lineage=second.lineage if second.lineage is not None else first.lineage,
            origins=second.origins if second.origins is not None else first.origins,
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
        observation = dict(graph.observation)
        observation.update(operation.observation)
        if graph.decision is Decision.UNKNOWN:
            return replace(
                graph,
                after=operation.after,
                observation=observation,
                effects=graph.effects + operation.effects,
                reads=graph.reads | operation.reads,
                writes=graph.writes | operation.writes,
                uncertainty=graph.uncertainty + operation.uncertainty,
                lineage=operation.lineage if operation.lineage is not None else graph.lineage,
                origins=operation.origins if operation.origins is not None else graph.origins,
            )
        if graph.decision is Decision.REJECT:
            return graph
        return replace(
            operation,
            observation=observation,
            effects=graph.effects + operation.effects,
            reads=graph.reads | operation.reads,
            writes=graph.writes | operation.writes,
            evidence=graph.evidence + operation.evidence,
            lineage=operation.lineage if operation.lineage is not None else graph.lineage,
            origins=operation.origins if operation.origins is not None else graph.origins,
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
        clients = dict(frame.clients)
        if item.client_id:
            values = outcome.after.as_dict()
            shared = {
                key.removeprefix("shared."): value
                for key, value in values.items()
                if key.startswith("shared.")
            }
            target = frame.target.update(**shared)
            clients[item.client_id] = State({key: value for key, value in values.items() if not key.startswith("shared.") and not key.startswith("env.")})
        else:
            target = frame.target if owned else outcome.after
        environment = _merge(frame.environment, outcome.environment)
        uncertain = frame.uncertain or outcome.decision is Decision.UNKNOWN
        reasons = list(frame.reasons) + list(outcome.uncertainty)
        lineage = outcome.lineage
        origins = outcome.origins
        if origins is None and not any("provenance" in reason for reason in outcome.uncertainty):
            request_origins = _request_origins(entry, request)
            if item.provenance_paths:
                origins, transfer_reason = _transfer_origins(
                    "preserve",
                    item.provenance_paths,
                    _merge_origins(frame.origins, request_origins),
                )
                if transfer_reason:
                    uncertain = True
                    reasons.append(transfer_reason)
            else:
                origins = (
                    frame.origins
                    if not request_origins and frame.origins == {}
                    else request_origins or None
                )
            if lineage is None and origins is not None:
                lineage = _lineage_from_origins(origins) or ((entry,) if request_origins else ())
        transition = None
        if self.world is not None:
            if item.name in self.world.transitions:
                transition = item.name
            elif entry in self.world.transitions:
                transition = entry
        if self.world is not None:
            context = Context(target, environment, logical_step=frame.logical_step, pending=frame.pending_events)
            reactions = (
                self.world.options(transition, context, request)
                if transition is not None
                else (Step("operation", context, context),)
            )
            reaction_ticks = tuple(
                (reaction, tick)
                for reaction in reactions
                for tick in self.world.tick(reaction.after)
            )
        else:
            reaction_ticks = ((None, None),)
        for reaction, tick in reaction_ticks:
            branch = replace(outcome, lineage=lineage, origins=origins)
            if item.provenance_inputs:
                observation = dict(branch.observation)
                existing = tuple(observation.get("provenance_consumed", ()))
                observation["provenance_consumed"] = tuple(dict.fromkeys(
                    existing + tuple(item.provenance_inputs)
                ))
                branch = replace(branch, observation=observation)
            successor = target
            current = environment
            logical_step = frame.logical_step
            pending_events = frame.pending_events
            reaction_outputs: dict[str, Any] = {}
            branch_uncertain = uncertain
            branch_reasons = list(reasons)
            if reaction is not None:
                successor = reaction.after.target
                current = reaction.after.environment
                if reaction.status is Signal.UNKNOWN:
                    branch_uncertain = True
                    branch_reasons.extend(reaction.reasons)
                    branch = replace(branch, decision=Decision.UNKNOWN, uncertainty=tuple(branch_reasons))
                reaction_outputs.update(reaction.outputs)
            if tick is not None:
                successor = tick.after.target
                current = tick.after.environment
                logical_step = tick.after.logical_step
                pending_events = tick.after.pending
                if tick.outputs:
                    reaction_outputs.update(tick.outputs)
                if tick.status is Signal.UNKNOWN:
                    branch_uncertain = True
                    branch_reasons.extend(tick.reasons)
                    branch = replace(branch, decision=Decision.UNKNOWN, uncertainty=tuple(branch_reasons))
            if reaction is not None or tick is not None:
                branch = replace(branch, environment=reaction_outputs)
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
                lineage,
                origins,
                logical_step,
                pending_events,
                clients,
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
                client_id=item.client_id,
                correlation_uncertain=any(
                    "uncorrelated connection:" in reason
                    for reason in branch.uncertainty
                ),
            )
            if reaction is not None or tick is not None:
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
        return Frame(
            target, environment, frame.uncertain, frame.reasons, regions, frame.aliases,
            frame.lineage, frame.origins, frame.logical_step, frame.pending_events, frame.clients,
        )

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


def _lineage(mode: str, lineage: tuple[str, ...] | None) -> tuple[tuple[str, ...] | None, str | None]:
    if lineage is None:
        return None, "provenance is already unknown"
    if mode in {"preserve", "duplicate", "combine"}:
        return lineage, None
    if mode == "discard":
        return (), None
    return None, "provenance transfer is unknown"


def _request_origins(
    entry: str,
    request: Mapping[str, Any],
    previous: Mapping[str, tuple[str, ...]] | None = None,
) -> dict[str, tuple[str, ...]]:
    result = dict(previous or {})
    for key, value in request.items():
        result.update(_request_origin_paths(entry, str(key), value))
    return result


def _request_origin_paths(entry: str, path: str, value: Any) -> dict[str, tuple[str, ...]]:
    if isinstance(value, Mapping):
        result: dict[str, tuple[str, ...]] = {}
        for key, item in value.items():
            result.update(_request_origin_paths(entry, f"{path}.{key}", item))
        return result
    if isinstance(value, (tuple, list)):
        result = {}
        for index, item in enumerate(value):
            result.update(_request_origin_paths(entry, f"{path}.{index}", item))
        return result
    return {path: (f"{entry}:{path}",)}


def _request_lineage(entry: str, request: Mapping[str, Any]) -> tuple[str, ...]:
    return (entry,) if request else ()


def _merge_origins(
    previous: Mapping[str, tuple[str, ...]] | None,
    current: Mapping[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    result = dict(previous or {})
    result.update(current)
    return result


def _lineage_from_origins(origins: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(
        source
        for values in origins.values()
        for origin in values
        for source, _, _path in (origin.partition(":"),)
        if source
    ))


def _origin_records(origins: Mapping[str, tuple[str, ...]]) -> tuple[Mapping[str, str], ...]:
    return tuple(
        {
            "source_entry": source,
            "source_path": source_path,
            "path": path,
        }
        for path, values in sorted(origins.items())
        for origin in values
        for source, _, source_path in (origin.partition(":"),)
    )


def _transfer_origins(
    mode: str,
    paths: Mapping[str, tuple[str, ...]],
    origins: Mapping[str, tuple[str, ...]] | None,
) -> tuple[Mapping[str, tuple[str, ...]] | None, str | None]:
    if origins is None:
        return None, "value provenance is already unknown"
    if mode == "discard":
        return {}, None
    if mode not in {"preserve", "duplicate", "combine"}:
        return None, "value provenance transfer is unknown"
    if not paths:
        return None, "value provenance paths are required for value-level transfer"
    result: dict[str, tuple[str, ...]] = {}
    for output, inputs in paths.items():
        values: list[str] = []
        for source in inputs:
            values.extend(origins.get(source, ()))
        result[output] = tuple(dict.fromkeys(values))
    if any(not values for values in result.values()):
        return None, "value provenance transfer is incomplete"
    return result, None


def _merge(state: State, values: Mapping[str, Any]) -> State:
    if not values:
        return state
    merged = state.as_dict()
    merged.update(values)
    return State(merged)
