import unittest

from rsve import (
    AnalysisGraph,
    BudgetUsage,
    CapabilityManifest,
    CapabilityPath,
    CapabilityRegistry,
    CompositeSnapshot,
    ConnectionStatus,
    ConnectionGraph,
    CorrelationLink,
    CorrelationQuality,
    EvidenceGraph,
    Fidelity,
    GraphRegion,
    ExtensionInstance,
    GraphSession,
    PortDirection,
    ProfileInstance,
    Provenance,
    State,
    TraceEvent,
    TypedPort,
    WorkspaceBinding,
)


class GraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.node = ProfileInstance("node-a", "runtime", "javascript", "node", "24")
        self.kernel = ProfileInstance("kernel-a", "os", "kernel", "linux", "6")
        self.graph = AnalysisGraph("system")
        self.graph = self.graph.add_profile(self.node).add_profile(self.kernel)
        self.graph = self.graph.add_region(GraphRegion("app", "node-a", "application"))
        self.graph = self.graph.add_region(GraphRegion("sys", "kernel-a", "syscall"))
        self.graph = self.graph.add_port(TypedPort("app-out", "app", "out", PortDirection.OUTPUT, "js-value", "JavaScriptValue"))
        self.graph = self.graph.add_port(TypedPort("sys-in", "sys", "in", PortDirection.INPUT, "syscall-arg", "SyscallArgument"))

    def test_profiles_and_nested_graphs_coexist(self):
        child = AnalysisGraph("child").add_profile(ProfileInstance("evm-a", "blockchain", "execution", "anvil", "1"))
        graph = self.graph.add_nested_graph(child)
        self.assertEqual(graph.nested_graphs[0].graph_id, "child")
        self.assertEqual(len(graph.profiles), 2)
        self.assertIs(ConnectionGraph, AnalysisGraph)

    def test_typed_connections_are_explicit_about_representation_bridges(self):
        graph = self.graph.connect("app-out", "sys-in", connection_id="c1")
        self.assertEqual(graph.connections[0].status, ConnectionStatus.UNVERIFIED)
        graph = graph.connect("app-out", "sys-in", connection_id="c2", transform_id="js-to-syscall")
        self.assertEqual(graph.connections[1].status, ConnectionStatus.TRANSFORM_REQUIRED)
        validation = graph.validate()
        self.assertIn("c1", validation.unverified_connections)
        self.assertTrue(validation.valid)
        self.assertTrue(validation.warnings)

    def test_cycles_are_traversed_with_stable_visited_set(self):
        graph = self.graph.add_port(TypedPort("sys-out", "sys", "out", PortDirection.OUTPUT, "syscall-arg", "SyscallArgument"))
        graph = graph.add_port(TypedPort("app-in", "app", "in", PortDirection.INPUT, "js-value", "JavaScriptValue"))
        graph = graph.connect("app-out", "sys-in", connection_id="forward")
        graph = graph.connect("sys-out", "app-in", connection_id="return")
        self.assertEqual(graph.reachable_regions("app"), ("app", "sys"))

    def test_capability_resolution_is_path_specific(self):
        registry = CapabilityRegistry((CapabilityManifest("node-ext", "rsve.node", "1", frozenset({"entry", "async"}), scope={"path_id": "app-to-sys"}),))
        complete = registry.resolve_path(CapabilityPath("app-to-sys", ("app", "sys"), frozenset({"entry"})))
        missing = registry.resolve_path(CapabilityPath("other", ("app",), frozenset({"entry"})))
        self.assertTrue(complete.complete)
        self.assertEqual(missing.missing, frozenset({"entry"}))

    def test_evidence_links_do_not_infer_causality(self):
        before = State({})
        first = TraceEvent("app.call", "app", {}, before, before, event_id="e1")
        second = TraceEvent("syscall", "sys", {}, before, before, event_id="e2")
        evidence = EvidenceGraph("run").add_event(first).add_event(second)
        self.assertEqual(evidence.causal_links("e1"), ())
        evidence = evidence.correlate(CorrelationLink("l1", "e1", "e2", CorrelationQuality.INFERRED, "temporal-window", Provenance("test", fidelity=Fidelity.OBSERVED)))
        self.assertEqual(evidence.causal_links("e1")[0].quality, CorrelationQuality.INFERRED)
        self.assertEqual(evidence.validate(), ())

    def test_profile_comparison_records_shared_dependency_without_claiming_independence(self):
        from rsve import DependencyRelationship, compare_profiles

        dep = DependencyRelationship("d1", "shared-engine", "1")
        left = ProfileInstance("left", "runtime", "execution", "a", independence_relationships=(dep,))
        right = ProfileInstance("right", "runtime", "execution", "b", independence_relationships=(dep,))
        comparison = compare_profiles(left, right)
        self.assertIn("implementation", comparison.differences)
        self.assertEqual(comparison.shared_dependencies, ("shared-engine",))

    def test_extension_attachment_and_budget_are_transactional(self):
        class Extension:
            def manifest(self):
                return CapabilityManifest("ext", "rsve.test", "1", frozenset({"observe"}))

            def attach(self, graph):
                return graph

            def detach(self, graph):
                return graph

        session = GraphSession(self.graph)
        attached = session.attach(Extension(), required_paths=(CapabilityPath("p", ("app",), frozenset({"observe"})),))
        self.assertEqual(attached.attached_extensions, ("ext",))
        self.assertEqual(attached.record_usage(BudgetUsage(events=1)).budget_usage.events, 1)
        snapshot = attached.snapshot({"ext": "snapshot"}, restorable_regions=("app",))
        self.assertIsInstance(snapshot, CompositeSnapshot)

    def test_binding_attaches_one_extension_to_multiple_regions(self):
        graph = self.graph.add_region(GraphRegion("aux", "node-a", "auxiliary"))
        graph = graph.add_extension(ExtensionInstance("node-ext-1", "rsve.node", "rsve.node/runtime-observation/1"))
        graph = graph.bind(WorkspaceBinding("binding", "node-a", "node-ext-1", "observer", ("app", "aux"), capabilities=frozenset({"entry.discovery"})))
        self.assertEqual(graph.validate().errors, ())
        self.assertEqual(graph.bindings[0].attached_regions, ("app", "aux"))


if __name__ == "__main__":
    unittest.main()
