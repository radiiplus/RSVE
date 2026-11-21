import unittest

from rsve import (
    Graph,
    Evidence,
    Fidelity,
    Effect,
    Zone,
    Loss,
    Invertibility,
    Partiality,
    Persona,
    Recognizer,
    Relation,
    Regressor,
    Representation,
    Interpreter,
    Meaning,
    Add,
    Arithmetic,
    Equal,
    Literal,
    Query,
    Sort,
    Symbolic,
    Truth,
    Variable,
    Verdict,
    Model,
    Workspace,
    Transform,
    Transition,
    State,
    WP,
    Zed,
    UTF8Decoder,
    ObservedTransformModel,
)


class Suite(unittest.TestCase):
    def test_observed_transform_outputs_remain_unknown_and_exact_context_scoped(self):
        evidence = Evidence("runtime-sample-1", Fidelity.OBSERVED, "local-adapter")
        model = ObservedTransformModel("opaque")
        model = model.observe({"raw": 2}, State({"mode": "a"}), {"value": 4}, evidence)
        graph = Graph("observed-transform").persona(
            Persona("observed-profile", "fixture", "target", "synthetic", "1")
        ).zone(Zone("observed-region", "observed-profile", "entry"))
        graph = graph.value(Representation("raw", "mapping")).value(Representation("out", "mapping"))
        graph = graph.transform(Transform(
            "opaque", "raw", "out", "fixture.opaque", "1",
            Partiality.UNKNOWN, Relation.UNKNOWN, Invertibility.UNKNOWN, Loss.UNKNOWN,
        ))
        graph = graph.guard(Recognizer("accept-observed", "out", "fixture.guard", None, "observed-region"))
        graph = graph.transition(Transition("route", "route", "raw", "out", ("opaque",), ("accept-observed",)))
        interpreter = Interpreter(
            graph,
            transforms={"opaque": model},
            recognizers={"accept-observed": lambda _value, _state: True},
        )

        observed = interpreter.execute("route", {"raw": 2}, state=State({"mode": "a"}))[0]
        self.assertEqual(observed.value, {"value": 4})
        self.assertEqual(observed.status, Meaning.UNKNOWN)
        self.assertIn("runtime-sample-1", observed.reasons[0])

        different_state = interpreter.execute("route", {"raw": 2}, state=State({"mode": "b"}))[0]
        self.assertEqual(different_state.value, {"raw": 2})
        self.assertEqual(different_state.status, Meaning.UNKNOWN)
        self.assertIn("no observation matches", different_state.reasons[0])

    def test_conflicting_observations_remain_multiple_uncertain_outputs(self):
        model = ObservedTransformModel("nondeterministic")
        model = model.observe("x", State(), "a", Evidence("sample-a", Fidelity.OBSERVED, "adapter"))
        model = model.observe("x", State(), "b", Evidence("sample-b", Fidelity.OBSERVED, "adapter"))
        result = model("x", State())
        self.assertEqual(result.values, ("a", "b"))
        self.assertFalse(result.complete)
        self.assertEqual(result.evidence_ids, ("sample-a", "sample-b"))

    def test_observed_output_preserves_container_type_and_is_detached(self):
        model = ObservedTransformModel("container-shape").observe(
            "input", State(), [1, {"nested": 2}],
            Evidence("container-sample", Fidelity.OBSERVED, "adapter"),
        )
        first = model("input", State()).values[0]
        self.assertIsInstance(first, list)
        self.assertIsInstance(first[1], dict)
        first[1]["nested"] = 99
        self.assertEqual(model("input", State()).values[0], [1, {"nested": 2}])

    def test_rejected_recognizer_branch_still_runs_declared_effects(self):
        graph = Graph("reject-side-effects").persona(
            Persona("p", "fixture", "target", "synthetic", "1")
        ).zone(Zone("region", "p", "entry"))
        graph = graph.value(Representation("raw", "value")).value(Representation("checked", "value"))
        graph = graph.transform(Transform(
            "identity", "raw", "checked", "fixture.identity", "1",
            Partiality.TOTAL, Relation.FUNCTION, Invertibility.BIJECTIVE, Loss.NONE, complete=True,
        ))
        graph = graph.guard(Recognizer("reject", "checked", "fixture.reject", None, "region"))
        graph = graph.effect(Effect("audit", "attempt", ("attempts",)))
        graph = graph.transition(Transition(
            "call", "call", "raw", "checked", ("identity",), ("reject",), ("audit",),
        ))
        interpreter = Interpreter(
            graph,
            transforms={"identity": lambda value, _state: value},
            recognizers={"reject": lambda _value, _state: False},
            effects={"audit": lambda state, _value: state.update(attempts=state.get("attempts", 0) + 1)},
        )

        branch = interpreter.execute("call", "input", state=State({"attempts": 0}))[0]
        outcome = interpreter.outcomes("call", "input", state=State({"attempts": 0}))[0]
        self.assertEqual(branch.status, Meaning.REJECTED)
        self.assertEqual(branch.state.get("attempts"), 1)
        self.assertEqual(outcome.decision.value, "REJECT")
        self.assertEqual(outcome.after.get("attempts"), 1)

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
        graph = graph.guard(Recognizer("guard", "sink", "fixture.guard", None, "validator", evidence=evidence))
        graph = graph.transition(Transition("path", "entry", "raw", "sink", ("decode", "normalize", "sink-map"), ("guard",)))
        interpreter = Interpreter(
            graph,
            transforms={"decode": lambda value, _state: value.decode(), "normalize": lambda value, _state: value.strip().lower(), "sink-map": lambda value, _state: value},
            recognizers={"guard": lambda value, _state: value == "canary"},
        )
        result = interpreter.execute("path", b" CANARY ")
        self.assertEqual(result[0].value, "canary")
        self.assertEqual(result[0].status, Meaning.ACCEPTED)
        self.assertEqual(result[0].representations, ("raw", "decoded", "normalized", "sink"))

        opaque = Interpreter(graph).execute("path", b" CANARY ")
        self.assertEqual(opaque[0].status, Meaning.UNKNOWN)
        self.assertTrue(any("opaque transform" in reason for reason in opaque[0].reasons))

    def test_semantic_representation_needs_no_binary_stage(self):
        graph = Graph("semantic-only").persona(
            Persona("semantic-profile", "fixture", "target", "synthetic", "1")
        ).zone(Zone("semantic-region", "semantic-profile", "semantic"))
        graph = graph.value(Representation("text", "Unicode text", "unicode"))
        graph = graph.guard(Recognizer("text-guard", "text", "fixture.text-guard", None, "semantic-region"))
        graph = graph.transition(Transition("text-check", "check", "text", "text", recognizer_ids=("text-guard",)))

        self.assertTrue(graph.validate().structural)
        branch = Interpreter(
            graph,
            recognizers={"text-guard": lambda value, _state: value == "ready"},
        ).execute("text-check", "ready")[0]
        self.assertEqual(branch.status, Meaning.ACCEPTED)
        self.assertEqual(branch.representations, ("text",))

    def test_representation_change_requires_explicit_transform(self):
        graph = Graph("missing-transform").persona(
            Persona("missing-profile", "fixture", "target", "synthetic", "1")
        ).zone(Zone("missing-region", "missing-profile", "missing"))
        graph = graph.value(Representation("text", "Unicode text", "unicode"))
        graph = graph.value(Representation("bytes", "byte sequence", "bytes"))
        graph = graph.transition(Transition("implicit-decode", "decode", "bytes", "text"))

        validation = graph.validate()
        branch = Interpreter(graph).execute("implicit-decode", b"ready")[0]
        self.assertFalse(validation.structural)
        self.assertEqual(branch.status, Meaning.UNKNOWN)
        self.assertTrue(any("without a declared transform" in reason for reason in branch.reasons))

    def test_utf8_decoder_runs_concretely_and_symbolically(self):
        decoder = UTF8Decoder()
        graph = Graph("utf8-decoder").persona(
            Persona("utf8-profile", "fixture", "target", "synthetic", "1")
        ).zone(Zone("utf8-region", "utf8-profile", "decode"))
        graph = graph.value(Representation("bytes", "byte sequence", "bytes"))
        graph = graph.value(Representation("unicode-text", "Unicode text", "unicode"))
        graph = graph.transform(decoder.transform)
        graph = graph.transition(Transition(
            "decode", "decode", "bytes", "unicode-text", (decoder.transform_id,)
        ))
        self.assertTrue(graph.validate().structural)

        concrete = Interpreter(
            graph,
            transforms={decoder.transform_id: decoder.forward},
        ).execute("decode", b"caf\xc3\xa9")[0]
        self.assertEqual(concrete.value, "caf\u00e9")
        self.assertEqual(concrete.representations, ("bytes", "unicode-text"))

        postcondition = Equal(
            Variable("output.text", Sort.STRING),
            Literal("caf\u00e9", Sort.STRING),
        )
        preimage = WP().derive(postcondition, (decoder.symbolic_for("caf\u00e9"),))
        self.assertTrue(preimage.exact, preimage.reason)
        answer = Zed().solve(Query("utf8-preimage", preimage.precondition))
        self.assertEqual(answer.status.value, "SAT")
        self.assertEqual(answer.model["input.bytes"], b"caf\xc3\xa9")

        with self.assertRaises(UnicodeDecodeError):
            decoder.forward(b"\xff")
        limited = UTF8Decoder(max_bytes=1)
        with self.assertRaises(ValueError):
            limited.forward(b"ab")
        with self.assertRaises(ValueError):
            limited.symbolic_for("\u00e9")

    def test_ordered_transforms_compose_for_synthesis_and_reject_representation_gaps(self):
        profile = Persona("compose-profile", "fixture", "target", "synthetic", "1")
        graph = Graph("compose-workspace").persona(profile).zone(
            Zone("compose-region", "compose-profile", "compose")
        )
        for representation in ("raw", "middle", "output", "wrong"):
            graph = graph.value(Representation(representation, "integer"))
        graph = graph.transform(Transform(
            "increment", "raw", "middle", "fixture.increment", "1",
            Partiality.TOTAL, Relation.FUNCTION, Invertibility.BIJECTIVE, Loss.NONE,
        ))
        graph = graph.transform(Transform(
            "double", "middle", "output", "fixture.double", "1",
            Partiality.TOTAL, Relation.FUNCTION, Invertibility.BIJECTIVE, Loss.NONE,
        ))
        graph = graph.guard(Recognizer("ten", "output", "fixture.is-ten", None, "compose-region"))
        graph = graph.transition(Transition(
            "compose", "compose", "raw", "output", ("increment", "double"), ("ten",)
        ))
        self.assertFalse(graph.transition_composition_issues("compose"))
        self.assertTrue(graph.validate().structural)

        true = Equal(Literal(True, Sort.BOOL), Literal(True, Sort.BOOL))
        increment = Symbolic(
            "increment", "increment", true,
            {"output.value": Add(Variable("input.value", Sort.INT), Literal(1, Sort.INT))},
            semantics_ref="fixture.increment",
        )
        double = Symbolic(
            "double", "double", true,
            {"output.value": Arithmetic("*", Variable("input.value", Sort.INT), Literal(2, Sort.INT))},
            semantics_ref="fixture.double",
        )
        ten = Symbolic(
            "ten", "ten",
            Equal(Variable("input.value", Sort.INT), Literal(10, Sort.INT)),
            semantics_ref="fixture.is-ten",
        )
        workspace = Workspace.flat(
            Model("compose-model", State(), (), ()),
            graph=graph,
            transforms={"increment": lambda value, _state: value + 1, "double": lambda value, _state: value * 2},
            recognizers={"ten": lambda value, _state: value == 10},
            symbolics={"increment": increment, "double": double, "ten": ten},
        )
        steps, _, missing = Regressor._route_symbols(workspace, (graph.transitions[0],), ())
        self.assertFalse(missing)
        post = Equal(Variable("route.2.value", Sort.INT), Literal(10, Sort.INT))
        preimage = WP().derive(post, steps)
        self.assertEqual(preimage.status, Truth.EXACT)
        answer = Zed().solve(Query("composed-transform", preimage.precondition))
        self.assertEqual(answer.status, Verdict.SAT)
        self.assertEqual(answer.model["route.0.value"], 4)

        incompatible = graph.transform(Transform(
            "gap", "wrong", "output", "fixture.gap", "1",
            Partiality.TOTAL, Relation.FUNCTION, Invertibility.BIJECTIVE, Loss.NONE,
        ))
        incompatible = incompatible.transition(Transition(
            "broken-compose", "broken-compose", "raw", "output", ("increment", "gap"), ("ten",)
        ))
        self.assertTrue(incompatible.transition_composition_issues("broken-compose"))
        self.assertFalse(incompatible.validate().structural)
        broken_workspace = Workspace.flat(Model("broken-model", State(), (), ()), graph=incompatible)
        _, _, broken_semantics = Regressor._route_symbols(
            broken_workspace, (incompatible.transitions[-1],), ()
        )
        self.assertTrue(any("transition:broken-compose" in item for item in broken_semantics))
        branch = Interpreter(incompatible, transforms={"increment": lambda value, _state: value + 1}).execute(
            "broken-compose", 4
        )[0]
        self.assertEqual(branch.status, Meaning.UNKNOWN)
        self.assertTrue(any("incompatible transform composition" in reason for reason in branch.reasons))

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
