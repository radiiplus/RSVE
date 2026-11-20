import unittest

from rsve import (
    Graph,
    Evidence,
    Fidelity,
    Zone,
    Loss,
    Invertibility,
    Partiality,
    Persona,
    Recognizer,
    Relation,
    Representation,
    Interpreter,
    Meaning,
    Transform,
    Transition,
    State,
)


class Suite(unittest.TestCase):
    def test_three_region_transform_chain_composes_and_rejects_unknown_semantics(self):
        profile = Persona("p", "fixture", "target", "synthetic", "1")
        graph = Graph("workspace").persona(profile)
        for region in ("entry", "validator", "sink"):
            graph = graph.zone(Zone(region, "p", region))
        for representation in (
            Representation("raw", "bytes"),
            Representation("decoded", "text"),
            Representation("normalized", "text"),
            Representation("sink", "canary"),
        ):
            graph = graph.value(representation)
        evidence = (Evidence("fixture", Fidelity.MODELED, "test"),)
        graph = graph.transform(Transform("decode", "raw", "decoded", "fixture.decode", "1", Partiality.TOTAL, Relation.FUNCTION, Invertibility.UNKNOWN, Loss.NONE, evidence=evidence))
        graph = graph.transform(Transform("normalize", "decoded", "normalized", "fixture.normalize", "1", Partiality.TOTAL, Relation.FUNCTION, Invertibility.MANY_TO_ONE, Loss.CONFIRMED, evidence=evidence))
        graph = graph.transform(Transform("sink-map", "normalized", "sink", "fixture.map", "1", Partiality.PARTIAL, Relation.FUNCTION, Invertibility.UNKNOWN, Loss.POSSIBLE, evidence=evidence))
        graph = graph.guard(Recognizer("guard", "normalized", "fixture.guard", None, "validator", evidence=evidence))
        graph = graph.transition(Transition("path", "entry", "raw", "sink", ("decode", "normalize", "sink-map"), ("guard",)))
        interpreter = Interpreter(
            graph,
            transforms={"decode": lambda value, _state: value.decode(), "normalize": lambda value, _state: value.strip().lower(), "sink-map": lambda value, _state: value},
            recognizers={"guard": lambda value, _state: value == "canary"},
        )
        result = interpreter.execute("path", b" CANARY ")
        self.assertEqual(result[0].value, "canary")
        self.assertEqual(result[0].status, Meaning.ACCEPTED)
        self.assertEqual(len(result[0].representations), 3)

        opaque = Interpreter(graph).execute("path", b" CANARY ")
        self.assertEqual(opaque[0].status, Meaning.UNKNOWN)
        self.assertTrue(any("opaque transform" in reason for reason in opaque[0].reasons))

    def test_provenance_transfer_is_explicit(self):
        profile = Persona("p", "fixture", "target", "synthetic", "1")
        graph = Graph("lineage-workspace").persona(profile).zone(Zone("region", "p", "region"))
        graph = graph.value(Representation("lineage-in", "text")).value(Representation("lineage-out", "bytes"))
        for mode in ("preserve", "duplicate", "combine", "discard", "unknown"):
            graph = graph.transform(Transform(
                f"lineage-{mode}",
                "lineage-in",
                "lineage-out",
                f"fixture.lineage.{mode}",
                "1",
                Partiality.TOTAL,
                Relation.FUNCTION,
                Invertibility.UNKNOWN,
                Loss.NONE,
                provenance=mode,
            ))
            graph = graph.transition(Transition(f"lineage-{mode}", f"lineage-{mode}", "lineage-in", "lineage-out", (f"lineage-{mode}",)))
        interpreter = Interpreter(graph, transforms={f"lineage-{mode}": lambda value, _state: value for mode in ("preserve", "duplicate", "combine", "discard", "unknown")})
        self.assertEqual(interpreter.outcomes("lineage-preserve", "encoded", lineage=("source",))[0].lineage, ("source",))
        self.assertEqual(interpreter.outcomes("lineage-duplicate", "encoded", lineage=("source",))[0].lineage, ("source",))
        self.assertEqual(interpreter.outcomes("lineage-combine", "encoded", lineage=("source",))[0].lineage, ("source",))
        self.assertEqual(interpreter.outcomes("lineage-discard", "encoded", lineage=("source",))[0].lineage, ())
        unknown = interpreter.outcomes("lineage-unknown", "encoded", lineage=("source",))[0]
        self.assertIsNone(unknown.lineage)
        self.assertIn("provenance transfer is unknown", unknown.uncertainty)
        unknown_value = interpreter.outcomes(
            "lineage-unknown",
            {"proof": "encoded"},
            origins={"proof": ("source:proof",)},
        )[0]
        self.assertIsNone(unknown_value.origins)
        self.assertIn("value provenance transfer is unknown", unknown_value.uncertainty)

    def test_value_provenance_requires_explicit_paths_and_combines_inputs(self):
        profile = Persona("p", "fixture", "target", "synthetic", "1")
        graph = Graph("value-lineage-workspace").persona(profile).zone(Zone("region", "p", "region"))
        graph = graph.value(Representation("input", "mapping")).value(Representation("output", "mapping"))
        graph = graph.transform(Transform(
            "combine",
            "input",
            "output",
            "fixture.combine",
            "1",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.UNKNOWN,
            Loss.NONE,
            provenance="combine",
            provenance_paths={"payload": ("left", "right")},
        ))
        graph = graph.transform(Transform(
            "implicit",
            "input",
            "output",
            "fixture.implicit",
            "1",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.UNKNOWN,
            Loss.NONE,
            provenance="combine",
        ))
        graph = graph.transition(Transition("combine", "combine", "input", "output", ("combine",)))
        graph = graph.transition(Transition("implicit", "implicit", "input", "output", ("implicit",)))
        interpreter = Interpreter(
            graph,
            transforms={"combine": lambda value, _state: {"payload": value}, "implicit": lambda value, _state: value},
        )
        combined = interpreter.outcomes(
            "combine",
            {"left": "l", "right": "r"},
            origins={"left": ("source:left",), "right": ("source:right",)},
        )[0]
        self.assertEqual(
            combined.origins,
            {"payload": ("source:left", "source:right")},
        )
        implicit = interpreter.outcomes(
            "implicit",
            {"left": "l", "right": "r"},
            origins={"left": ("source:left",), "right": ("source:right",)},
        )[0]
        self.assertIsNone(implicit.origins)
        self.assertTrue(any("value provenance paths are required" in reason for reason in implicit.uncertainty))


if __name__ == "__main__":
    unittest.main()
