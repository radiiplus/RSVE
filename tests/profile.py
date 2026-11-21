import unittest

from rsve import (
    Binding,
    Direction,
    Extension,
    Fidelity,
    Graph,
    Invertibility,
    Loss,
    Manifest,
    Match,
    Need,
    Partiality,
    Persona,
    Port,
    Relation,
    Representation,
    Transform,
    Zone,
)


class Suite(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = Persona(
            "node-a",
            "runtime",
            "node.js",
            "rsve.node",
            "24.21.0",
            build_digest="build",
            execution_scope={"target_id": "fixture", "os": "linux"},
        )

    def test_requirement_round_trips_and_matches_scoped_profile(self):
        requirement = Need(
            "node-runtime",
            "runtime",
            "node.js",
            "rsve.node",
            "24.21.0",
            execution_scope={"target_id": "fixture"},
        )
        self.assertEqual(Need.from_record(requirement.to_record()), requirement)
        self.assertEqual(requirement.verify(self.profile).status, Match.MATCH)

    def test_drift_and_unknown_are_distinct(self):
        drift = Need("node-runtime", "runtime", "node.js", "rsve.node", "25.0").verify(self.profile)
        self.assertEqual(drift.status, Match.DRIFT)
        unknown = Need("node-runtime", "runtime", "node.js", "rsve.node", "unknown", execution_scope={"kernel": "6"}).verify(self.profile)
        self.assertEqual(unknown.status, Match.UNKNOWN)

    def test_profiles_and_extensions_compose_with_namespaced_references(self):
        def profile_graph(direction: Direction) -> Graph:
            profile = Persona("profile", "runtime", "component", "implementation", "1")
            graph = Graph.for_profile(
                profile,
                graph_id="component",
                region_id="region",
                region_name="component region",
            )
            graph = graph.value(Representation("data", "bytes", "opaque"))
            port_id = "port"
            graph = graph.port(Port(port_id, "region", "data", direction, "data", "bytes"))
            manifest = Manifest("adapter", "fixture.adapter", "1", provides=frozenset({"observe"}))
            graph = graph.register(manifest)
            graph = graph.extend(Extension("instance", "adapter", manifest.contract_id))
            graph = graph.bind(Binding(
                "binding", "profile", "instance", "instrumentation", ("region",),
                provided_ports=(port_id,) if direction is Direction.OUTPUT else (),
                consumed_ports=(port_id,) if direction is Direction.INPUT else (),
                capabilities=frozenset({"observe"}),
            ))
            return graph

        source = profile_graph(Direction.OUTPUT)
        destination = profile_graph(Direction.INPUT)
        composed = Graph.compose("composed", (("engine", source), ("host", destination)))
        self.assertEqual({item.profile_id for item in composed.profiles}, {"engine::profile", "host::profile"})
        self.assertEqual({item.region_id for item in composed.regions}, {"engine::region", "host::region"})
        self.assertEqual({item.extension_instance_id for item in composed.extensions}, {"engine::instance", "host::instance"})

        composed = composed.transform(Transform(
            "bridge", "engine::data", "host::data", "fixture.bridge", "1",
            Partiality.TOTAL, Relation.FUNCTION, Invertibility.UNKNOWN, Loss.NONE,
        ))
        composed = composed.connect(
            "engine::port", "host::port", connection_id="network-bridge", transform_id="bridge"
        )
        self.assertTrue(composed.validate().structural)


if __name__ == "__main__":
    unittest.main()
