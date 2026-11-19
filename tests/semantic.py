import unittest

from rsve import (
    AnalysisGraph,
    Evidence,
    Fidelity,
    GraphRegion,
    InformationLoss,
    Invertibility,
    Partiality,
    ProfileInstance,
    Recognizer,
    RelationKind,
    Representation,
    SemanticInterpreter,
    SemanticStatus,
    Transform,
    Transition,
)


class SemanticGraphTests(unittest.TestCase):
    def test_three_region_transform_chain_composes_and_rejects_unknown_semantics(self):
        profile = ProfileInstance("p", "fixture", "target", "synthetic", "1")
        graph = AnalysisGraph("workspace").add_profile(profile)
        for region in ("entry", "validator", "sink"):
            graph = graph.add_region(GraphRegion(region, "p", region))
        for representation in (
            Representation("raw", "bytes"),
            Representation("decoded", "text"),
            Representation("normalized", "text"),
            Representation("sink", "canary"),
        ):
            graph = graph.add_representation(representation)
        evidence = (Evidence("fixture", Fidelity.MODELED, "test"),)
        graph = graph.add_transform(Transform("decode", "raw", "decoded", "fixture.decode", "1", Partiality.TOTAL, RelationKind.FUNCTION, Invertibility.UNKNOWN, InformationLoss.NONE, evidence=evidence))
        graph = graph.add_transform(Transform("normalize", "decoded", "normalized", "fixture.normalize", "1", Partiality.TOTAL, RelationKind.FUNCTION, Invertibility.MANY_TO_ONE, InformationLoss.CONFIRMED, evidence=evidence))
        graph = graph.add_transform(Transform("sink-map", "normalized", "sink", "fixture.map", "1", Partiality.PARTIAL, RelationKind.FUNCTION, Invertibility.UNKNOWN, InformationLoss.POSSIBLE, evidence=evidence))
        graph = graph.add_recognizer(Recognizer("guard", "normalized", "fixture.guard", None, "validator", evidence=evidence))
        graph = graph.add_transition(Transition("path", "entry", "raw", "sink", ("decode", "normalize", "sink-map"), ("guard",)))
        interpreter = SemanticInterpreter(
            graph,
            transforms={"decode": lambda value, _state: value.decode(), "normalize": lambda value, _state: value.strip().lower(), "sink-map": lambda value, _state: value},
            recognizers={"guard": lambda value, _state: value == "canary"},
        )
        result = interpreter.execute_transition("path", b" CANARY ")
        self.assertEqual(result[0].value, "canary")
        self.assertEqual(result[0].status, SemanticStatus.ACCEPTED)
        self.assertEqual(len(result[0].representations), 3)

        opaque = SemanticInterpreter(graph).execute_transition("path", b" CANARY ")
        self.assertEqual(opaque[0].status, SemanticStatus.UNKNOWN)
        self.assertTrue(any("opaque transform" in reason for reason in opaque[0].reasons))


if __name__ == "__main__":
    unittest.main()
