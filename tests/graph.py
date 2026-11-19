import unittest

from rsve import (
    Graph,
    Usage,
    Manifest,
    Path,
    Registry,
    Snapshot,
    Fit,
    Network,
    Link,
    Quality,
    Proofs,
    Fidelity,
    Zone,
    Extension,
    Session,
    Direction,
    Persona,
    Provenance,
    State,
    Event,
    Port,
    Binding,
)


class Suite(unittest.TestCase):
    def setUp(self) -> None:
        self.node = Persona("node-a", "runtime", "javascript", "node", "24")
        self.kernel = Persona("kernel-a", "os", "kernel", "linux", "6")
        self.graph = Graph("system")
        self.graph = self.graph.persona(self.node).persona(self.kernel)
        self.graph = self.graph.zone(Zone("app", "node-a", "application"))
        self.graph = self.graph.zone(Zone("sys", "kernel-a", "syscall"))
        self.graph = self.graph.port(Port("app-out", "app", "out", Direction.OUTPUT, "js-value", "JavaScriptValue"))
        self.graph = self.graph.port(Port("sys-in", "sys", "in", Direction.INPUT, "syscall-arg", "SyscallArgument"))

    def test_profiles_and_nested_graphs_coexist(self):
        child = Graph("child").persona(Persona("evm-a", "blockchain", "execution", "anvil", "1"))
        graph = self.graph.nest(child)
        self.assertEqual(graph.nested_graphs[0].graph_id, "child")
        self.assertEqual(len(graph.profiles), 2)
        self.assertIs(Network, Graph)

    def test_typed_connections_are_explicit_about_representation_bridges(self):
        graph = self.graph.connect("app-out", "sys-in", connection_id="c1")
        self.assertEqual(graph.connections[0].status, Fit.UNVERIFIED)
        graph = graph.connect("app-out", "sys-in", connection_id="c2", transform_id="js-to-syscall")
        self.assertEqual(graph.connections[1].status, Fit.TRANSFORM_REQUIRED)
        validation = graph.validate()
        self.assertIn("c1", validation.unverified_connections)
        self.assertFalse(validation.structural)
        self.assertFalse(validation.ready)
        self.assertTrue(validation.errors)
        self.assertTrue(validation.warnings)

    def test_unverified_seam_is_structural_but_not_ready(self):
        graph = self.graph.connect("app-out", "sys-in", connection_id="c1")
        validation = graph.validate()
        self.assertTrue(validation.structural)
        self.assertFalse(validation.ready)
        self.assertTrue(validation.warnings)

    def test_cycles_are_traversed_with_stable_visited_set(self):
        graph = self.graph.port(Port("sys-out", "sys", "out", Direction.OUTPUT, "syscall-arg", "SyscallArgument"))
        graph = graph.port(Port("app-in", "app", "in", Direction.INPUT, "js-value", "JavaScriptValue"))
        graph = graph.connect("app-out", "sys-in", connection_id="forward")
        graph = graph.connect("sys-out", "app-in", connection_id="return")
        self.assertEqual(graph.reachable("app"), ("app", "sys"))

    def test_capability_resolution_is_path_specific(self):
        registry = Registry((Manifest("node-ext", "rsve.node", "1", frozenset({"entry", "async"}), scope={"path_id": "app-to-sys"}),))
        complete = registry.resolve(Path("app-to-sys", ("app", "sys"), frozenset({"entry"})))
        missing = registry.resolve(Path("other", ("app",), frozenset({"entry"})))
        self.assertTrue(complete.complete)
        self.assertEqual(missing.missing, frozenset({"entry"}))

    def test_evidence_links_do_not_infer_causality(self):
        before = State({})
        first = Event("app.call", "app", {}, before, before, event_id="e1")
        second = Event("syscall", "sys", {}, before, before, event_id="e2")
        evidence = Proofs("run").event(first).event(second)
        self.assertEqual(evidence.links("e1"), ())
        evidence = evidence.correlate(Link("l1", "e1", "e2", Quality.INFERRED, "temporal-window", Provenance("test", fidelity=Fidelity.OBSERVED)))
        self.assertEqual(evidence.links("e1")[0].quality, Quality.INFERRED)
        self.assertEqual(evidence.validate(), ())

    def test_profile_comparison_records_shared_dependency_without_claiming_independence(self):
        from rsve import Dependency, match

        dep = Dependency("d1", "shared-engine", "1")
        left = Persona("left", "runtime", "execution", "a", independence_relationships=(dep,))
        right = Persona("right", "runtime", "execution", "b", independence_relationships=(dep,))
        comparison = match(left, right)
        self.assertIn("implementation", comparison.differences)
        self.assertEqual(comparison.shared_dependencies, ("shared-engine",))

    def test_extension_attachment_and_budget_are_transactional(self):
        class Extension:
            def manifest(self):
                return Manifest("ext", "rsve.test", "1", frozenset({"observe"}))

            def attach(self, graph):
                return graph

            def detach(self, graph):
                return graph

        session = Session(self.graph)
        attached = session.attach(Extension(), required_paths=(Path("p", ("app",), frozenset({"observe"})),))
        self.assertEqual(attached.attached_extensions, ("ext",))
        self.assertEqual(attached.use(Usage(events=1)).budget_usage.events, 1)
        snapshot = attached.snapshot({"ext": "snapshot"}, restorable_regions=("app",))
        self.assertIsInstance(snapshot, Snapshot)

    def test_binding_attaches_one_extension_to_multiple_regions(self):
        graph = self.graph.zone(Zone("aux", "node-a", "auxiliary"))
        graph = graph.extend(Extension("node-ext-1", "rsve.node", "rsve.node/runtime-observation/1"))
        graph = graph.bind(Binding("binding", "node-a", "node-ext-1", "observer", ("app", "aux"), capabilities=frozenset({"entry.discovery"})))
        self.assertEqual(graph.validate().errors, ())
        self.assertEqual(graph.bindings[0].attached_regions, ("app", "aux"))


if __name__ == "__main__":
    unittest.main()
