import unittest
from pathlib import Path

from rsve import (
    Add,
    Authorization,
    Decision,
    Order,
    Entry,
    Flow,
    Range,
    Guard,
    Planner,
    Need,
    Objective,
    Limits,
    Operation,
    Outcome,
    State,
    Same,
    Sort,
    Symbolic,
    Event,
    Loss,
    Invertibility,
    Partiality,
    Relation,
    Transform,
    Model,
    Variable,
)
from rsve.extensions import Node
from rsve.diff import Analyzer, Kind
from rsve.planner import Regressor
from rsve.result import Status


FIXTURE = Path(__file__).parent / "fixtures" / "node" / "fixture.mjs"


def fixture_model(*, max_amount: int = 10, inputs=None) -> Model:
    def apply(entry, state, request):
        history = list(state.get("history", []))
        history.append({"entry": entry, "amount": request["amount"]})
        return state.update(count=state["count"] + request["amount"], history=history)

    def operation(entry):
        return Operation(
            name="state.mutation",
            entry_point=Entry(entry),
            guard=lambda _state, request: isinstance(request.get("amount"), int) and 0 < request["amount"] <= max_amount,
            apply=lambda state, request, entry=entry: apply(entry, state, request),
            observe=lambda _before, _request, after: {"count": after["count"]},
            component="fixture.state",
        )

    return Model(
        target_id="node-fixture",
        initial_state=State({"count": 0, "history": []}),
        inputs=inputs or (
            {"amount": 1, "canary": "RSVE-CANARY"},
            {"amount": 2, "canary": "RSVE-CANARY"},
        ),
        operations=(operation("increment"), operation("async_increment")),
        build_hash="fixture-build",
    )


class Suite(unittest.TestCase):
    def setUp(self):
        self.authorization = Authorization("planner-tests", frozenset({"node-lab"}), frozenset({"node-fixture"}))

    def test_seeded_trace_keeps_same_entry_alternatives(self):
        first = Operation(
            "first",
            Entry("shared"),
            guard=lambda _state, request: request.get("kind") == "first",
            apply=lambda state, _request: state.update(value="first"),
        )
        second = Operation(
            "second",
            Entry("shared"),
            guard=lambda _state, request: request.get("kind") == "second",
            apply=lambda state, _request: state.update(value="second"),
        )
        model = Model("node-fixture", State({"value": "none"}), (), (first, second))
        traces = Planner._model_traces(model, ({"entry_point": "shared", "request": {"kind": "second"}},))
        self.assertEqual(len(traces), 2)
        self.assertEqual({trace[1][0].operation for trace in traces}, {"first", "second"})

    def test_unknown_branch_does_not_become_bounded_unsat(self):
        operation = Operation(
            "opaque",
            Entry("opaque"),
            relation=lambda state, _request: (Outcome(Decision.UNKNOWN, state.update(goal=True), terminal=True),),
        )
        model = Model("node-fixture", State({"goal": False}), ({},), (operation,))
        objective = Objective(
            "opaque-goal",
            "node-fixture",
            "node-lab",
            (Same("goal", True),),
            budget=Limits(max_trace_length=1),
        )
        report = Planner().plan(model, objective, self.authorization)
        self.assertEqual(report.status, Status.UNKNOWN)

    def test_known_branch_survives_same_state_unknown_branch(self):
        operation = Operation(
            "fork",
            Entry("fork"),
            relation=lambda state, _request: (
                Outcome(Decision.UNKNOWN, state.update(goal=True), effects=("opaque",), terminal=True),
                Outcome(Decision.ACCEPT, state.update(goal=True), effects=("known",), terminal=True),
            ),
        )
        model = Model("node-fixture", State({"goal": False}), ({},), (operation,))
        objective = Objective(
            "known-goal",
            "node-fixture",
            "node-lab",
            (Same("goal", True),),
            budget=Limits(max_trace_length=1),
        )
        report = Planner().plan(model, objective, self.authorization)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.witness.events[0].effects, ("known",))

    def test_single_entry_is_replay_validated(self):
        objective = Objective(
            "reach-two",
            "node-fixture",
            "node-lab",
            (Same("count", 2), Flow("increment", "RSVE-CANARY", "fixture.state"), Guard()),
            permitted_sinks=frozenset({"fixture.state"}),
            budget=Limits(max_trace_length=1, replay_runs=2),
        )
        adapter = Node(FIXTURE, target_id="node-fixture")
        report = Planner(harness_sinks={"fixture.state"}).plan(
            fixture_model(), objective, self.authorization, adapter=adapter,
        )
        self.assertEqual(report.status, Status.VALIDATED_WITNESS)
        self.assertTrue(report.witness.validated)
        self.assertEqual(report.replay_runs, 2)
        self.assertTrue(report.execution_profile_id.startswith("node-fixture:"))
        self.assertEqual(report.witness.final_state["count"], 2)
        self.assertTrue(any(event.operation == "entry.outcome" for event in report.witness.events))

    def test_stateful_multi_entry_objective_is_replay_validated(self):
        objective = Objective(
            "increment-then-async",
            "node-fixture",
            "node-lab",
            (
                Same("count", 2),
                Order(("increment", "async_increment")),
                Flow("increment", "RSVE-CANARY", "fixture.state"),
            ),
            permitted_sinks=frozenset({"fixture.state"}),
            checkpoints=(Same("count", 1),),
            budget=Limits(max_trace_length=2),
        )
        adapter = Node(FIXTURE, target_id="node-fixture")
        report = Planner(harness_sinks={"fixture.state"}).plan(
            fixture_model(), objective, self.authorization, adapter=adapter,
        )
        self.assertEqual(report.status, Status.VALIDATED_WITNESS)
        self.assertEqual([item["entry_point"] for item in report.witness.interactions], ["increment", "async_increment"])
        self.assertEqual(report.witness.final_state["count"], 2)

    def test_model_only_result_is_not_a_validated_witness(self):
        objective = Objective(
            "reach-two",
            "node-fixture",
            "node-lab",
            (Same("count", 2),),
            budget=Limits(max_trace_length=1),
        )
        report = Planner().plan(fixture_model(), objective, self.authorization)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertFalse(report.witness.validated)

    def test_symbolic_wp_and_solver_guide_forward_candidates(self):
        operation = Operation(
            name="state.mutation",
            entry_point=Entry("symbolic.increment"),
            guard=lambda _state, request: 0 < request.get("amount", 0) <= 10,
            apply=lambda state, request: state.update(count=state["count"] + request["amount"]),
            transforms=(Transform("decode", "bytes", "text", "fixture.decode", "1", Partiality.PARTIAL, Relation.FUNCTION, Invertibility.NON_INVERTIBLE, Loss.CONFIRMED),),
            symbolic_transition=Symbolic(
                "symbolic-increment",
                "symbolic.increment",
                Range(Variable("input.amount", Sort.INT), 1, 10),
                {"state.count": Add(Variable("state.count", Sort.INT), Variable("input.amount", Sort.INT))},
            ),
        )
        model = Model(
            target_id="symbolic-lab",
            initial_state=State({"count": 0}),
            inputs=(),
            operations=(operation,),
        )
        objective = Objective(
            "symbolic-reach-two",
            "symbolic-lab",
            "node-lab",
            (Same("count", 2),),
            budget=Limits(max_trace_length=1),
        )
        auth = Authorization("symbolic-tests", frozenset({"node-lab"}), frozenset({"symbolic-lab"}))
        backward = Regressor().regress(model, objective)
        self.assertIn(("symbolic.increment", {"amount": 2}), backward.required_actions)
        self.assertIn("preimage+solver", backward.method)
        report = Planner().plan(model, objective, auth)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.witness.interactions[0]["request"], {"amount": 2})

    def test_multi_step_symbolic_regression_seeds_unsupplied_trace(self):
        def operation(name, variable):
            return Operation(
                name="state.mutation",
                entry_point=Entry(name),
                guard=lambda _state, request: 0 < request.get("amount", 0) <= 10,
                apply=lambda state, request: state.update(count=state["count"] + request["amount"]),
                symbolic_transition=Symbolic(
                    f"{name}-symbolic",
                    name,
                    Range(Variable(variable, Sort.INT), 1, 10),
                    {"state.count": Add(Variable("state.count", Sort.INT), Variable(variable, Sort.INT))},
                ),
            )

        model = Model(
            target_id="sequence-lab",
            initial_state=State({"count": 0}),
            inputs=(),
            operations=(operation("step.one", "input.0.amount"), operation("step.two", "input.1.amount")),
        )
        objective = Objective(
            "symbolic-reach-three",
            "sequence-lab",
            "node-lab",
            (Same("count", 3),),
            budget=Limits(max_trace_length=2),
        )
        auth = Authorization("sequence-tests", frozenset({"node-lab"}), frozenset({"sequence-lab"}))
        backward = Regressor().regress(model, objective)
        self.assertTrue(backward.required_traces)
        self.assertEqual(len(backward.required_traces[0]), 2)
        report = Planner().plan(model, objective, auth)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(len(report.witness.interactions), 2)
        self.assertEqual(sum(item["request"]["amount"] for item in report.witness.interactions), 3)

    def test_observed_phantom_entry_is_probed_before_model_search(self):
        model = Model(
            target_id="node-fixture",
            initial_state=State({"count": 0, "history": []}),
            inputs=(),
            operations=(),
        )
        objective = Objective(
            "reach-phantom",
            "node-fixture",
            "node-lab",
            (Order(("dynamic_debug",)),),
            budget=Limits(max_trace_length=1, replay_runs=2),
        )
        adapter = Node(FIXTURE, target_id="node-fixture")
        try:
            report = Planner().plan(model, objective, self.authorization, adapter=adapter)
        finally:
            adapter.teardown()
        self.assertEqual(report.status, Status.VALIDATED_WITNESS)
        self.assertEqual(report.witness.interactions[0]["entry_point"], "dynamic_debug")
        self.assertIsNone(report.witness.model_aligned)
        self.assertIn("dynamic_debug", report.surface_scope)

    def test_planner_reports_bounded_unsat(self):
        objective = Objective(
            "reach-nine",
            "node-fixture",
            "node-lab",
            (Same("count", 9),),
            budget=Limits(max_trace_length=1),
        )
        report = Planner().plan(fixture_model(), objective, self.authorization)
        self.assertEqual(report.status, Status.UNSAT_BOUNDED)
        self.assertIn("max_trace_length", report.proof.query)
        self.assertEqual(report.proof.fidelity_limitations[0], "bounded surface and trace length")

    def test_objective_round_trip_preserves_budget_and_predicates(self):
        objective = Objective(
            "round-trip",
            "node-fixture",
            "node-lab",
            (Order(("increment", "async_increment")), Guard("increment")),
            permitted_sinks=frozenset({"fixture.state"}),
            profile_requirements=(Need("node-runtime", "runtime", "node.js", "rsve.node", "24.21.0"),),
            budget=Limits(max_trace_length=3, replay_runs=2),
        )
        self.assertEqual(Objective.from_record(objective.to_record()), objective)

    def test_profile_drift_is_rejected_before_search(self):
        objective = Objective(
            "wrong-runtime",
            "node-fixture",
            "node-lab",
            (Same("count", 2),),
            profile_requirements=(Need("node-runtime", "runtime", "node.js", "rsve.node", "0.0.0"),),
        )
        adapter = Node(FIXTURE, target_id="node-fixture")
        with self.assertRaisesRegex(ValueError, "profile requirements are unresolved"):
            Planner().plan(fixture_model(), objective, self.authorization, adapter=adapter)
        adapter.teardown()

    def test_wrong_guard_diverges_and_refinement_excludes_counterexample(self):
        objective = Objective(
            "reach-eleven",
            "node-fixture",
            "node-lab",
            (Same("count", 11),),
            budget=Limits(max_trace_length=1),
        )
        model = fixture_model(max_amount=100, inputs=({"amount": 11},))
        adapter = Node(FIXTURE, target_id="node-fixture")
        report = Planner().plan(model, objective, self.authorization, adapter=adapter)
        self.assertEqual(report.status, Status.MODEL_DIVERGENCE)
        self.assertEqual(report.divergences[0].kind, Kind.MODEL_TOO_LOOSE.value)

        adapter = Node(FIXTURE, target_id="node-fixture")
        adapter.prepare()
        try:
            baseline = adapter.snapshot()
            adapter.reset(baseline)
            observed = adapter.trace(report.witness.interactions, self.authorization)
        finally:
            adapter.teardown()
        refinement = Analyzer().refine(model, report.divergences, observed, invalidated_queries=("q-1",))
        self.assertIn("q-1", refinement.delta.invalidated_queries)
        self.assertFalse(refinement.model.allows(report.witness.interactions[0]["entry_point"], {"amount": 11}))

    def test_unexpected_semantic_events_diverge_and_demote_assumptions(self):
        before = State({"count": 0})
        after = State({"count": 1})
        expected = Event("state.mutation", "known", {}, before, after, component="fixture.state")
        unexpected = Event("state.mutation", "phantom", {}, before, after, component="fixture.state")
        analyzer = Analyzer()
        divergences = analyzer.compare((expected,), (unexpected, expected))
        self.assertEqual(divergences[0].kind, Kind.MODEL_TOO_STRICT.value)
        self.assertEqual(divergences[0].observed_index, 0)
        model = Model(
            target_id="fixture",
            initial_state=before,
            inputs=(),
            operations=(),
            assumptions=("trusted declared surface",),
        )
        refinement = analyzer.refine(model, divergences, (unexpected, expected))
        self.assertEqual(refinement.delta.demoted_assumptions, ("trusted declared surface",))
        self.assertIn("trusted declared surface", refinement.model.demoted_assumptions)

    def test_counterexample_probes_promote_only_bounded_numeric_region(self):
        before = State({"count": 0})
        expected = Event("state.mutation", "increment", {"amount": 11}, before, before, guard_result=True)
        observed = Event("guard.decision", "increment", {"amount": 11}, before, before, guard_result=False)
        analyzer = Analyzer()
        divergences = analyzer.compare((expected,), (observed,))
        model = fixture_model(max_amount=100, inputs=({"amount": 11},))
        refinement = analyzer.refine(
            model,
            divergences,
            (observed,),
            probe=lambda _entry, request: request["amount"] <= 10,
            probe_radius=2,
        )
        learned = refinement.model.learned_exclusions[0]
        self.assertEqual(learned.operator, ">=")
        self.assertEqual(learned.value, 11)
        self.assertFalse(refinement.model.allows("increment", {"amount": 12}))
        self.assertTrue(refinement.model.allows("increment", {"amount": 100}))
        self.assertIn("bounded-neighbor-probes", learned.evidence)

    def test_objective_scope_and_sink_are_hard_constraints(self):
        objective = Objective(
            "outside",
            "node-fixture",
            "node-lab",
            (Flow("increment", "RSVE-CANARY", "external"),),
            permitted_sinks=frozenset({"external"}),
        )
        with self.assertRaises(ValueError):
            Planner(harness_sinks={"fixture.state"}).plan(fixture_model(), objective, self.authorization)


if __name__ == "__main__":
    unittest.main()
