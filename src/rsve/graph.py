"""Composable, runtime-neutral analysis and evidence graphs.

The topology graph records modeled connectivity.  The execution graph records
observed events and the evidence that relates them.  Keeping those graphs
separate prevents an available adapter or a possible edge from being treated
as proof that an interaction occurred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .ir import Effect, Recognizer, Representation, Transform, Transition
from .model import Fidelity, Provenance, TraceEvent
from .schema import SchemaMixin


class PortDirection(str, Enum):
    INPUT = "input"
    OUTPUT = "output"
    BIDIRECTIONAL = "bidirectional"


class RelationshipType(str, Enum):
    DATA = "data"
    CONTROL = "control"
    STATE = "state"
    CONTEXT = "context"
    OWNERSHIP = "ownership"
    ALIAS = "alias"
    LIFETIME = "lifetime"
    RESOURCE = "resource"
    CAUSAL = "causal"
    COMPARISON = "comparison"


class ConnectionStatus(str, Enum):
    VERIFIED = "verified_compatibility"
    TRANSFORM_REQUIRED = "explicit_transformation_required"
    UNVERIFIED = "unverified_relationship"


class CorrelationQuality(str, Enum):
    DIRECT = "directly_identified"
    DETERMINISTIC_DERIVED = "deterministically_derived"
    INFERRED = "inferred_with_uncertainty"
    UNCORRELATED = "uncorrelated"


@dataclass(frozen=True)
class DependencyRelationship(SchemaMixin):
    """Evidence about shared implementation dependencies between profiles."""

    relationship_id: str
    dependency: str
    dependency_version: str = "unknown"
    dependency_digest: str = ""
    scope: Mapping[str, str] = field(default_factory=dict)
    provenance: Provenance = field(default_factory=lambda: Provenance("profile.dependency"))


@dataclass(frozen=True)
class ProfileInstance(SchemaMixin):
    """An independently identifiable implementation in one execution scope."""

    profile_id: str
    family: str
    component: str
    implementation: str
    version: str = "unknown"
    build_digest: str = ""
    configuration_digest: str = ""
    execution_scope: Mapping[str, str] = field(default_factory=dict)
    feature_set: frozenset[str] = frozenset()
    provenance: Provenance = field(default_factory=lambda: Provenance("profile"))
    independence_relationships: tuple[DependencyRelationship, ...] = ()

    def __post_init__(self) -> None:
        if not self.profile_id or not self.family or not self.component or not self.implementation:
            raise ValueError("profile_id, family, component, and implementation are required")


class ProfileMatchStatus(str, Enum):
    MATCH = "MATCH"
    DRIFT = "DRIFT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ProfileRequirement(SchemaMixin):
    requirement_id: str
    family: str
    component: str
    implementation: str = ""
    version: str = "unknown"
    build_digest: str = ""
    configuration_digest: str = ""
    execution_scope: Mapping[str, str] = field(default_factory=dict)

    def verify(self, profile: ProfileInstance | None) -> "ProfileVerification":
        if profile is None:
            return ProfileVerification(self.requirement_id, ProfileMatchStatus.UNKNOWN, unknown=(self.requirement_id,))
        drifted: list[str] = []
        unknown: list[str] = []
        checks = (
            ("family", self.family, profile.family),
            ("component", self.component, profile.component),
            ("implementation", self.implementation, profile.implementation),
            ("version", self.version, profile.version),
            ("build_digest", self.build_digest, profile.build_digest),
            ("configuration_digest", self.configuration_digest, profile.configuration_digest),
        )
        for name, expected, actual in checks:
            if not expected or expected == "unknown":
                continue
            if not actual or actual == "unknown":
                unknown.append(name)
            elif expected != actual:
                drifted.append(name)
        for key, expected in self.execution_scope.items():
            actual = profile.execution_scope.get(key)
            if actual is None or actual == "unknown":
                unknown.append(key)
            elif actual != expected:
                drifted.append(key)
        status = ProfileMatchStatus.DRIFT if drifted else ProfileMatchStatus.UNKNOWN if unknown else ProfileMatchStatus.MATCH
        return ProfileVerification(self.requirement_id, status, tuple(sorted(set(drifted))), tuple(sorted(set(unknown))))


@dataclass(frozen=True)
class ProfileVerification(SchemaMixin):
    requirement_id: str
    status: ProfileMatchStatus
    drifted: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()


@dataclass(frozen=True)
class GraphRegion(SchemaMixin):
    region_id: str
    profile_id: str
    name: str
    scope: Mapping[str, str] = field(default_factory=dict)
    external: bool = True
    child_graph_id: str | None = None
    provenance: Provenance = field(default_factory=lambda: Provenance("region"))

    def __post_init__(self) -> None:
        if not self.region_id or not self.profile_id or not self.name:
            raise ValueError("region_id, profile_id, and name are required")


@dataclass(frozen=True)
class TypedPort(SchemaMixin):
    port_id: str
    region_id: str
    name: str
    direction: PortDirection
    representation_id: str
    type_name: str
    scope: Mapping[str, str] = field(default_factory=dict)
    provenance: Provenance = field(default_factory=lambda: Provenance("port"))

    def __post_init__(self) -> None:
        if not self.port_id or not self.region_id or not self.representation_id:
            raise ValueError("port_id, region_id, and representation_id are required")


@dataclass(frozen=True)
class ExtensionInstance(SchemaMixin):
    extension_instance_id: str
    extension_id: str
    manifest_contract: str
    configuration: Mapping[str, str] = field(default_factory=dict)
    execution_scope: Mapping[str, str] = field(default_factory=dict)
    provenance: Provenance = field(default_factory=lambda: Provenance("extension.instance"))


@dataclass(frozen=True)
class WorkspaceBinding(SchemaMixin):
    binding_id: str
    profile_instance_id: str
    extension_instance_id: str
    role: str
    attached_regions: tuple[str, ...]
    provided_ports: tuple[str, ...] = ()
    consumed_ports: tuple[str, ...] = ()
    capabilities: frozenset[str] = frozenset()
    execution_scope: Mapping[str, str] = field(default_factory=dict)
    correlation_contracts: tuple[str, ...] = ()
    reset_participation: str = "unknown"
    evidence_scope: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.binding_id or not self.profile_instance_id or not self.extension_instance_id or not self.role:
            raise ValueError("binding identity, profile, extension, and role are required")
        if not self.attached_regions:
            raise ValueError("a workspace binding must attach to at least one region")


@dataclass(frozen=True)
class StateSlot(SchemaMixin):
    slot_id: str
    region_id: str
    representation_id: str
    scope: str = "session"
    dependencies: tuple[str, ...] = ()
    provenance: Provenance = field(default_factory=lambda: Provenance("state.slot"))


@dataclass(frozen=True)
class TypedConnection(SchemaMixin):
    connection_id: str
    source_port_id: str
    destination_port_id: str
    output_representation: str
    input_representation: str
    transform_id: str | None = None
    correlation_contract: str = ""
    correlation_quality: CorrelationQuality = CorrelationQuality.UNCORRELATED
    fidelity: Fidelity = Fidelity.ASSUMED
    provenance: Provenance = field(default_factory=lambda: Provenance("connection"))
    scope: Mapping[str, str] = field(default_factory=dict)
    status: ConnectionStatus = ConnectionStatus.UNVERIFIED
    relationship_type: RelationshipType = RelationshipType.DATA
    source_binding_id: str | None = None
    destination_binding_id: str | None = None

    def __post_init__(self) -> None:
        if not self.connection_id or not self.source_port_id or not self.destination_port_id:
            raise ValueError("connection identity and endpoints are required")
        if self.source_port_id == self.destination_port_id:
            raise ValueError("a connection cannot connect a port to itself")


@dataclass(frozen=True)
class CapabilityManifest(SchemaMixin):
    """Namespaced extension contract understood without runtime-specific code."""

    extension_id: str
    namespace: str
    version: str
    provides: frozenset[str] = frozenset()
    requires: frozenset[str] = frozenset()
    prerequisites: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    evidence_quality: str = "unknown"
    scope: Mapping[str, str] = field(default_factory=dict)
    provenance: Provenance = field(default_factory=lambda: Provenance("capability.manifest"))

    @property
    def contract_id(self) -> str:
        return f"{self.namespace}/{self.version}"

    def __post_init__(self) -> None:
        if not self.extension_id or not self.namespace or not self.version:
            raise ValueError("extension_id, namespace, and version are required")


@dataclass(frozen=True)
class CapabilityPath(SchemaMixin):
    path_id: str
    region_ids: tuple[str, ...]
    required: frozenset[str]

    def __post_init__(self) -> None:
        if not self.path_id or not self.region_ids:
            raise ValueError("capability paths require an id and at least one region")


@dataclass(frozen=True)
class CapabilityResolution(SchemaMixin):
    path_id: str
    available: frozenset[str]
    missing: frozenset[str]
    manifest_ids: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.missing


class CapabilityRegistry(SchemaMixin):
    """Registry for independently versioned extension manifests."""

    def __init__(self, manifests: Iterable[CapabilityManifest] = ()) -> None:
        self._manifests: dict[str, CapabilityManifest] = {}
        for manifest in manifests:
            self.register(manifest)

    @property
    def manifests(self) -> tuple[CapabilityManifest, ...]:
        return tuple(self._manifests[key] for key in sorted(self._manifests))

    def register(self, manifest: CapabilityManifest) -> None:
        key = f"{manifest.extension_id}:{manifest.contract_id}"
        if key in self._manifests and self._manifests[key] != manifest:
            raise ValueError(f"capability manifest already registered: {key}")
        self._manifests[key] = manifest

    def resolve_path(self, path: CapabilityPath) -> CapabilityResolution:
        available: set[str] = set()
        manifest_ids: list[str] = []
        for manifest in self.manifests:
            if not manifest.scope or any(path_scope_matches(manifest.scope, path_scope) for path_scope in ({"path_id": path.path_id},)):
                available.update(manifest.provides)
                manifest_ids.append(manifest.extension_id)
        return CapabilityResolution(
            path_id=path.path_id,
            available=frozenset(sorted(available)),
            missing=frozenset(sorted(path.required - available)),
            manifest_ids=tuple(sorted(set(manifest_ids))),
        )


@dataclass(frozen=True)
class GraphValidation(SchemaMixin):
    valid: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    unverified_connections: tuple[str, ...] = ()
    missing_capabilities: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphBudget(SchemaMixin):
    max_events: int = 100_000
    max_time_ms: int = 60_000
    max_depth: int = 32
    per_region_events: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_events <= 0 or self.max_time_ms <= 0 or self.max_depth < 0:
            raise ValueError("graph budgets require positive events/time and non-negative depth")
        if any(value <= 0 for value in self.per_region_events.values()):
            raise ValueError("per-region event budgets must be positive")


@dataclass(frozen=True)
class BudgetUsage(SchemaMixin):
    events: int = 0
    time_ms: int = 0
    depth: int = 0
    per_region_events: Mapping[str, int] = field(default_factory=dict)

    def within(self, budget: GraphBudget) -> bool:
        return (
            self.events <= budget.max_events
            and self.time_ms <= budget.max_time_ms
            and self.depth <= budget.max_depth
            and all(self.per_region_events.get(region, 0) <= limit for region, limit in budget.per_region_events.items())
        )


@dataclass(frozen=True)
class CompositeSnapshot(SchemaMixin):
    snapshot_id: str
    graph_id: str
    extension_snapshots: Mapping[str, Any] = field(default_factory=dict)
    restorable_regions: frozenset[str] = frozenset()
    non_restorable_regions: frozenset[str] = frozenset()
    provenance: Provenance = field(default_factory=lambda: Provenance("graph.snapshot"))


@dataclass(frozen=True)
class ProfileComparison(SchemaMixin):
    left_profile_id: str
    right_profile_id: str
    comparable: bool
    same_behavioral_scope: bool
    differences: tuple[str, ...] = ()
    shared_dependencies: tuple[str, ...] = ()


def compare_profiles(left: ProfileInstance, right: ProfileInstance) -> ProfileComparison:
    differences: list[str] = []
    if left.family != right.family:
        differences.append("family")
    if left.component != right.component:
        differences.append("component")
    if left.execution_scope != right.execution_scope:
        differences.append("execution_scope")
    if left.implementation != right.implementation:
        differences.append("implementation")
    if left.version != right.version:
        differences.append("version")
    if left.build_digest and right.build_digest and left.build_digest != right.build_digest:
        differences.append("build_digest")
    if left.configuration_digest and right.configuration_digest and left.configuration_digest != right.configuration_digest:
        differences.append("configuration_digest")
    left_deps = {item.dependency for item in left.independence_relationships}
    right_deps = {item.dependency for item in right.independence_relationships}
    shared = tuple(sorted(left_deps & right_deps))
    comparable = not {"family", "component", "execution_scope"} & set(differences)
    same_scope = "execution_scope" not in differences
    return ProfileComparison(left.profile_id, right.profile_id, comparable, same_scope, tuple(differences), shared)


@dataclass(frozen=True)
class AnalysisGraph(SchemaMixin):
    """Topology/model graph; possible connectivity is not execution evidence."""

    graph_id: str
    profiles: tuple[ProfileInstance, ...] = ()
    regions: tuple[GraphRegion, ...] = ()
    ports: tuple[TypedPort, ...] = ()
    connections: tuple[TypedConnection, ...] = ()
    nested_graphs: tuple["AnalysisGraph", ...] = ()
    capabilities: tuple[CapabilityManifest, ...] = ()
    extensions: tuple[ExtensionInstance, ...] = ()
    bindings: tuple[WorkspaceBinding, ...] = ()
    representations: tuple[Representation, ...] = ()
    transforms: tuple[Transform, ...] = ()
    recognizers: tuple[Recognizer, ...] = ()
    effects: tuple[Effect, ...] = ()
    transitions: tuple[Transition, ...] = ()
    state_slots: tuple[StateSlot, ...] = ()
    budget: GraphBudget = field(default_factory=GraphBudget)

    def __post_init__(self) -> None:
        if not self.graph_id:
            raise ValueError("graph_id is required")

    @classmethod
    def for_profile(
        cls,
        profile: ProfileInstance,
        *,
        graph_id: str,
        region_id: str,
        region_name: str,
        capabilities: Iterable[CapabilityManifest] = (),
        scope: Mapping[str, str] | None = None,
    ) -> "AnalysisGraph":
        graph = cls(graph_id).add_profile(profile)
        graph = graph.add_region(GraphRegion(region_id, profile.profile_id, region_name, dict(scope or profile.execution_scope)))
        for manifest in capabilities:
            graph = graph.register_capability(manifest)
        return graph

    def add_profile(self, profile: ProfileInstance) -> "AnalysisGraph":
        if profile.profile_id in {item.profile_id for item in self.profiles}:
            raise ValueError(f"duplicate profile id: {profile.profile_id}")
        return self._replace(profiles=self.profiles + (profile,))

    def add_region(self, region: GraphRegion) -> "AnalysisGraph":
        if region.region_id in {item.region_id for item in self.regions}:
            raise ValueError(f"duplicate region id: {region.region_id}")
        if region.profile_id not in {item.profile_id for item in self.profiles}:
            raise ValueError(f"region references unknown profile: {region.profile_id}")
        return self._replace(regions=self.regions + (region,))

    def add_port(self, port: TypedPort) -> "AnalysisGraph":
        if port.port_id in {item.port_id for item in self.ports}:
            raise ValueError(f"duplicate port id: {port.port_id}")
        if port.region_id not in {item.region_id for item in self.regions}:
            raise ValueError(f"port references unknown region: {port.region_id}")
        return self._replace(ports=self.ports + (port,))

    def connect(
        self,
        source_port_id: str,
        destination_port_id: str,
        *,
        connection_id: str,
        transform_id: str | None = None,
        correlation_contract: str = "",
        correlation_quality: CorrelationQuality = CorrelationQuality.UNCORRELATED,
        fidelity: Fidelity = Fidelity.ASSUMED,
        provenance: Provenance | None = None,
        scope: Mapping[str, str] | None = None,
        relationship_type: RelationshipType = RelationshipType.DATA,
        source_binding_id: str | None = None,
        destination_binding_id: str | None = None,
    ) -> "AnalysisGraph":
        ports = {port.port_id: port for port in self.ports}
        source = ports.get(source_port_id)
        destination = ports.get(destination_port_id)
        if source is None or destination is None:
            raise ValueError("connection endpoints must be registered ports")
        if source.direction is PortDirection.INPUT or destination.direction is PortDirection.OUTPUT:
            raise ValueError("connection direction is incompatible with port directions")
        status = (
            ConnectionStatus.VERIFIED
            if source.representation_id == destination.representation_id
            else ConnectionStatus.TRANSFORM_REQUIRED if transform_id else ConnectionStatus.UNVERIFIED
        )
        edge = TypedConnection(
            connection_id=connection_id,
            source_port_id=source_port_id,
            destination_port_id=destination_port_id,
            output_representation=source.representation_id,
            input_representation=destination.representation_id,
            transform_id=transform_id,
            correlation_contract=correlation_contract,
            correlation_quality=correlation_quality,
            fidelity=fidelity,
            provenance=provenance or Provenance("graph.connection"),
            scope=dict(scope or {}),
            status=status,
            relationship_type=relationship_type,
            source_binding_id=source_binding_id,
            destination_binding_id=destination_binding_id,
        )
        if any(item.connection_id == connection_id for item in self.connections):
            raise ValueError(f"duplicate connection id: {connection_id}")
        return self._replace(connections=self.connections + (edge,))

    def add_nested_graph(self, graph: "AnalysisGraph") -> "AnalysisGraph":
        if graph.graph_id == self.graph_id or graph.graph_id in {item.graph_id for item in self.nested_graphs}:
            raise ValueError(f"duplicate or recursive nested graph: {graph.graph_id}")
        return self._replace(nested_graphs=self.nested_graphs + (graph,))

    def register_capability(self, manifest: CapabilityManifest) -> "AnalysisGraph":
        if any(item.extension_id == manifest.extension_id and item.contract_id == manifest.contract_id for item in self.capabilities):
            raise ValueError(f"duplicate capability manifest: {manifest.extension_id}:{manifest.contract_id}")
        return self._replace(capabilities=self.capabilities + (manifest,))

    def add_extension(self, extension: ExtensionInstance) -> "AnalysisGraph":
        if extension.extension_instance_id in {item.extension_instance_id for item in self.extensions}:
            raise ValueError(f"duplicate extension instance: {extension.extension_instance_id}")
        return self._replace(extensions=self.extensions + (extension,))

    def bind(self, binding: WorkspaceBinding) -> "AnalysisGraph":
        if binding.binding_id in {item.binding_id for item in self.bindings}:
            raise ValueError(f"duplicate binding: {binding.binding_id}")
        if binding.profile_instance_id not in {item.profile_id for item in self.profiles}:
            raise ValueError(f"binding references unknown profile: {binding.profile_instance_id}")
        if binding.extension_instance_id not in {item.extension_instance_id for item in self.extensions}:
            raise ValueError(f"binding references unknown extension: {binding.extension_instance_id}")
        return self._replace(bindings=self.bindings + (binding,))

    def add_representation(self, representation: Representation) -> "AnalysisGraph":
        if representation.representation_id in {item.representation_id for item in self.representations}:
            raise ValueError(f"duplicate representation: {representation.representation_id}")
        return self._replace(representations=self.representations + (representation,))

    def add_transform(self, transform: Transform) -> "AnalysisGraph":
        if transform.transform_id in {item.transform_id for item in self.transforms}:
            raise ValueError(f"duplicate transform: {transform.transform_id}")
        known = {item.representation_id for item in self.representations}
        if known and (transform.input_representation not in known or transform.output_representation not in known):
            raise ValueError(f"transform {transform.transform_id} references an unknown representation")
        return self._replace(transforms=self.transforms + (transform,))

    def add_recognizer(self, recognizer: Recognizer) -> "AnalysisGraph":
        if recognizer.recognizer_id in {item.recognizer_id for item in self.recognizers}:
            raise ValueError(f"duplicate recognizer: {recognizer.recognizer_id}")
        return self._replace(recognizers=self.recognizers + (recognizer,))

    def add_effect(self, effect: Effect) -> "AnalysisGraph":
        if effect.effect_id in {item.effect_id for item in self.effects}:
            raise ValueError(f"duplicate effect: {effect.effect_id}")
        return self._replace(effects=self.effects + (effect,))

    def add_transition(self, transition: Transition) -> "AnalysisGraph":
        if transition.transition_id in {item.transition_id for item in self.transitions}:
            raise ValueError(f"duplicate transition: {transition.transition_id}")
        return self._replace(transitions=self.transitions + (transition,))

    def add_state_slot(self, slot: StateSlot) -> "AnalysisGraph":
        if slot.slot_id in {item.slot_id for item in self.state_slots}:
            raise ValueError(f"duplicate state slot: {slot.slot_id}")
        return self._replace(state_slots=self.state_slots + (slot,))

    def validate(self, paths: Sequence[CapabilityPath] = ()) -> GraphValidation:
        errors: list[str] = []
        warnings: list[str] = []
        unverified: list[str] = []
        profile_ids = {profile.profile_id for profile in self.profiles}
        region_ids = {region.region_id for region in self.regions}
        port_ids = {port.port_id for port in self.ports}
        representation_ids = {item.representation_id for item in self.representations}
        transform_ids = {item.transform_id for item in self.transforms}
        recognizer_ids = {item.recognizer_id for item in self.recognizers}
        effect_ids = {item.effect_id for item in self.effects}
        transition_ids = {item.transition_id for item in self.transitions}
        extension_ids = {item.extension_instance_id for item in self.extensions}
        binding_ids = {item.binding_id for item in self.bindings}
        for region in self.regions:
            if region.profile_id not in profile_ids:
                errors.append(f"region {region.region_id} references unknown profile {region.profile_id}")
        for port in self.ports:
            if port.region_id not in region_ids:
                errors.append(f"port {port.port_id} references unknown region {port.region_id}")
            if representation_ids and port.representation_id not in representation_ids:
                errors.append(f"port {port.port_id} references unknown representation {port.representation_id}")
        for transform in self.transforms:
            if representation_ids and (transform.input_representation not in representation_ids or transform.output_representation not in representation_ids):
                errors.append(f"transform {transform.transform_id} references an unknown representation")
        for transition in self.transitions:
            missing = set(transition.transform_ids) - transform_ids | set(transition.recognizer_ids) - recognizer_ids | set(transition.effect_ids) - effect_ids
            if missing:
                errors.append(f"transition {transition.transition_id} references unknown semantics: {sorted(missing)}")
        for binding in self.bindings:
            if binding.extension_instance_id not in extension_ids:
                errors.append(f"binding {binding.binding_id} references unknown extension")
            if any(region not in region_ids for region in binding.attached_regions):
                errors.append(f"binding {binding.binding_id} references an unknown region")
        for edge in self.connections:
            if edge.source_port_id not in port_ids or edge.destination_port_id not in port_ids:
                errors.append(f"connection {edge.connection_id} references an unknown port")
            if edge.status is ConnectionStatus.UNVERIFIED:
                unverified.append(edge.connection_id)
                warnings.append(f"connection {edge.connection_id} has no verified representation bridge")
            if edge.correlation_quality is CorrelationQuality.UNCORRELATED:
                warnings.append(f"connection {edge.connection_id} has no event correlation")
            if edge.source_binding_id and edge.source_binding_id not in binding_ids:
                errors.append(f"connection {edge.connection_id} references unknown source binding")
            if edge.destination_binding_id and edge.destination_binding_id not in binding_ids:
                errors.append(f"connection {edge.connection_id} references unknown destination binding")
        registry = CapabilityRegistry(self.capabilities)
        missing = {path.path_id: tuple(sorted(registry.resolve_path(path).missing)) for path in paths if not registry.resolve_path(path).complete}
        return GraphValidation(not errors, tuple(errors), tuple(warnings), tuple(unverified), missing)

    def reachable_regions(self, start_region_id: str, *, max_depth: int | None = None) -> tuple[str, ...]:
        edges = {port.port_id: port.region_id for port in self.ports}
        outgoing: dict[str, list[str]] = {}
        for connection in self.connections:
            source = edges.get(connection.source_port_id)
            destination = edges.get(connection.destination_port_id)
            if source is not None and destination is not None:
                outgoing.setdefault(source, []).append(destination)
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(start_region_id, 0)]
        while queue:
            region_id, depth = queue.pop(0)
            if region_id in visited or (max_depth is not None and depth > max_depth):
                continue
            visited.add(region_id)
            queue.extend((child, depth + 1) for child in sorted(outgoing.get(region_id, ())))
        return tuple(sorted(visited))

    def _replace(self, **changes: Any) -> "AnalysisGraph":
        values = {
            "graph_id": self.graph_id,
            "profiles": self.profiles,
            "regions": self.regions,
            "ports": self.ports,
            "connections": self.connections,
            "nested_graphs": self.nested_graphs,
            "capabilities": self.capabilities,
            "extensions": self.extensions,
            "bindings": self.bindings,
            "representations": self.representations,
            "transforms": self.transforms,
            "recognizers": self.recognizers,
            "effects": self.effects,
            "transitions": self.transitions,
            "state_slots": self.state_slots,
            "budget": self.budget,
        }
        values.update(changes)
        return AnalysisGraph(**values)


@dataclass(frozen=True)
class CorrelationLink(SchemaMixin):
    link_id: str
    source_event_id: str
    destination_event_id: str
    quality: CorrelationQuality
    method: str
    provenance: Provenance = field(default_factory=lambda: Provenance("correlation"))
    scope: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceGraph(SchemaMixin):
    """Execution/evidence graph; links are explicit and quality-graded."""

    graph_id: str
    events: tuple[TraceEvent, ...] = ()
    correlations: tuple[CorrelationLink, ...] = ()

    def add_event(self, event: TraceEvent) -> "EvidenceGraph":
        if event.event_id and any(item.event_id == event.event_id for item in self.events):
            raise ValueError(f"duplicate evidence event: {event.event_id}")
        return EvidenceGraph(self.graph_id, self.events + (event,), self.correlations)

    def correlate(self, link: CorrelationLink) -> "EvidenceGraph":
        event_ids = {event.event_id for event in self.events if event.event_id}
        if link.source_event_id not in event_ids or link.destination_event_id not in event_ids:
            raise ValueError("correlation endpoints must be observed events")
        if any(item.link_id == link.link_id for item in self.correlations):
            raise ValueError(f"duplicate correlation link: {link.link_id}")
        return EvidenceGraph(self.graph_id, self.events, self.correlations + (link,))

    def causal_links(self, event_id: str) -> tuple[CorrelationLink, ...]:
        return tuple(link for link in self.correlations if link.source_event_id == event_id or link.destination_event_id == event_id)

    def validate(self) -> tuple[str, ...]:
        event_ids = {event.event_id for event in self.events if event.event_id}
        errors: list[str] = []
        for link in self.correlations:
            if link.source_event_id not in event_ids or link.destination_event_id not in event_ids:
                errors.append(f"correlation {link.link_id} references an unknown event")
        return tuple(errors)


class GraphExtension(Protocol):
    """Minimal lifecycle contract for independent extension implementations."""

    def manifest(self) -> CapabilityManifest: ...

    def attach(self, graph: AnalysisGraph) -> AnalysisGraph: ...

    def detach(self, graph: AnalysisGraph) -> AnalysisGraph: ...


@dataclass(frozen=True)
class GraphSession(SchemaMixin):
    """Transactional composition boundary for extension lifecycle operations."""

    graph: AnalysisGraph
    evidence: EvidenceGraph | None = None
    attached_extensions: tuple[str, ...] = ()
    budget_usage: BudgetUsage = field(default_factory=BudgetUsage)

    def attach(self, extension: GraphExtension, *, required_paths: Sequence[CapabilityPath] = ()) -> "GraphSession":
        manifest = extension.manifest()
        if manifest.extension_id in self.attached_extensions:
            raise ValueError(f"extension already attached: {manifest.extension_id}")
        candidate = extension.attach(self.graph).register_capability(manifest)
        validation = candidate.validate(required_paths)
        if not validation.valid or validation.missing_capabilities:
            raise ValueError(
                f"extension attachment rejected: errors={validation.errors}; missing={dict(validation.missing_capabilities)}"
            )
        return GraphSession(candidate, self.evidence, self.attached_extensions + (manifest.extension_id,), self.budget_usage)

    def detach(self, extension: GraphExtension) -> "GraphSession":
        manifest = extension.manifest()
        if manifest.extension_id not in self.attached_extensions:
            raise ValueError(f"extension is not attached: {manifest.extension_id}")
        candidate = extension.detach(self.graph)
        capabilities = tuple(item for item in candidate.capabilities if item.extension_id != manifest.extension_id)
        candidate = candidate._replace(capabilities=capabilities)
        return GraphSession(candidate, self.evidence, tuple(item for item in self.attached_extensions if item != manifest.extension_id), self.budget_usage)

    def record_usage(self, usage: BudgetUsage) -> "GraphSession":
        if not usage.within(self.graph.budget):
            raise RuntimeError("composite graph budget exhausted")
        return GraphSession(self.graph, self.evidence, self.attached_extensions, usage)

    def snapshot(self, extension_snapshots: Mapping[str, Any], *, restorable_regions: Iterable[str] = (), non_restorable_regions: Iterable[str] = ()) -> CompositeSnapshot:
        return CompositeSnapshot(
            snapshot_id=f"{self.graph.graph_id}-snapshot-{len(extension_snapshots)}",
            graph_id=self.graph.graph_id,
            extension_snapshots=dict(extension_snapshots),
            restorable_regions=frozenset(restorable_regions),
            non_restorable_regions=frozenset(non_restorable_regions),
        )


def path_scope_matches(manifest_scope: Mapping[str, str], path_scope: Mapping[str, str]) -> bool:
    return all(path_scope.get(key) in (None, value) for key, value in manifest_scope.items())


ConnectionGraph = AnalysisGraph
