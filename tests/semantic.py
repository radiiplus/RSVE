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


if __name__ == "__main__":
    unittest.main()
