import unittest
from pathlib import Path

from rsve import (
    Add,
    Authorization,
    EntrySequence,
    EntryPoint,
    FlowToSink,
    IntRange,
    GuardInvariant,
    HybridPlanner,
    ProfileRequirement,
    ObjectiveDefinition,
    ObjectiveBudget,
    Operation,
    State,
    StateEquals,
    Sort,
    SymbolicTransition,
    TraceEvent,
    InformationLoss,
    Invertibility,
    Partiality,
    RelationKind,
    Transform,
    TransitionModel,
    Variable,
)
from rsve.extensions import NodeTargetAdapter
from rsve.differential import DifferentialAnalyzer, DivergenceKind
from rsve.planner import BackwardRegressor
from rsve.results import AnalysisStatus


FIXTURE = Path(__file__).parent / "fixtures" / "node" / "fixture.mjs"


def fixture_model(*, max_amount: int = 10, inputs=None) -> TransitionModel:
    def apply(entry, state, request):
        history = list(state.get("history", []))
        history.append({"entry": entry, "amount": request["amount"]})
        return state.with_updates(count=state["count"] + request["amount"], history=history)

    def operation(entry):
        return Operation(
            name="state.mutation",
            entry_point=EntryPoint(entry),
            guard=lambda _state, request: isinstance(request.get("amount"), int) and 0 < request["amount"] <= max_amount,
            apply=lambda state, request, entry=entry: apply(entry, state, request),
            observe=lambda _before, _request, after: {"count": after["count"]},
            component="fixture.state",
        )

    return TransitionModel(
        target_id="node-fixture",
        initial_state=State({"count": 0, "history": []}),
        inputs=inputs or (
            {"amount": 1, "canary": "RSVE-CANARY"},
            {"amount": 2, "canary": "RSVE-CANARY"},
        ),
        operations=(operation("increment"), operation("async_increment")),
        build_hash="fixture-build",
    )


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.authorization = Authorization("planner-tests", frozenset({"node-lab"}), frozenset({"node-fixture"}))

    def test_single_entry_is_replay_validated(self):
        objective = ObjectiveDefinition(
            "reach-two",
            "node-fixture",
            "node-lab",
            (StateEquals("count", 2), FlowToSink("increment", "RSVE-CANARY", "fixture.state"), GuardInvariant()),
            permitted_sinks=frozenset({"fixture.state"}),
            budget=ObjectiveBudget(max_trace_length=1, replay_runs=2),
        )
        adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture")
        report = HybridPlanner(harness_sinks={"fixture.state"}).plan(
            fixture_model(), objective, self.authorization, adapter=adapter,
        )
        self.assertEqual(report.status, AnalysisStatus.VALIDATED_WITNESS)
        self.assertTrue(report.witness.validated)
        self.assertEqual(report.replay_runs, 2)
        self.assertTrue(report.execution_profile_id.startswith("node-fixture:"))
        self.assertEqual(report.witness.final_state["count"], 2)
        self.assertTrue(any(event.operation == "entry.outcome" for event in report.witness.events))

    def test_stateful_multi_entry_objective_is_replay_validated(self):
        objective = ObjectiveDefinition(
            "increment-then-async",
            "node-fixture",
            "node-lab",
            (
                StateEquals("count", 2),
                EntrySequence(("increment", "async_increment")),
                FlowToSink("increment", "RSVE-CANARY", "fixture.state"),
            ),
            permitted_sinks=frozenset({"fixture.state"}),
            checkpoints=(StateEquals("count", 1),),
            budget=ObjectiveBudget(max_trace_length=2),
        )
        adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture")
        report = HybridPlanner(harness_sinks={"fixture.state"}).plan(
            fixture_model(), objective, self.authorization, adapter=adapter,
        )
        self.assertEqual(report.status, AnalysisStatus.VALIDATED_WITNESS)
        self.assertEqual([item["entry_point"] for item in report.witness.interactions], ["increment", "async_increment"])
        self.assertEqual(report.witness.final_state["count"], 2)

    def test_model_only_result_is_not_a_validated_witness(self):
        objective = ObjectiveDefinition(
            "reach-two",
            "node-fixture",
            "node-lab",
            (StateEquals("count", 2),),
            budget=ObjectiveBudget(max_trace_length=1),
        )
        report = HybridPlanner().plan(fixture_model(), objective, self.authorization)
        self.assertEqual(report.status, AnalysisStatus.SAT_CANDIDATE)
        self.assertFalse(report.witness.validated)

    def test_symbolic_wp_and_solver_guide_forward_candidates(self):
        operation = Operation(
            name="state.mutation",
            entry_point=EntryPoint("symbolic.increment"),
            guard=lambda _state, request: 0 < request.get("amount", 0) <= 10,
            apply=lambda state, request: state.with_updates(count=state["count"] + request["amount"]),
            transforms=(Transform("decode", "bytes", "text", "fixture.decode", "1", Partiality.PARTIAL, RelationKind.FUNCTION, Invertibility.NON_INVERTIBLE, InformationLoss.CONFIRMED),),
            symbolic_transition=SymbolicTransition(
                "symbolic-increment",
                "symbolic.increment",
                IntRange(Variable("input.amount", Sort.INT), 1, 10),
                {"state.count": Add(Variable("state.count", Sort.INT), Variable("input.amount", Sort.INT))},
            ),
        )
        model = TransitionModel(
            target_id="symbolic-lab",
            initial_state=State({"count": 0}),
            inputs=(),
            operations=(operation,),
        )
        objective = ObjectiveDefinition(
            "symbolic-reach-two",
            "symbolic-lab",
            "node-lab",
            (StateEquals("count", 2),),
            budget=ObjectiveBudget(max_trace_length=1),
        )
        auth = Authorization("symbolic-tests", frozenset({"node-lab"}), frozenset({"symbolic-lab"}))
        backward = BackwardRegressor().regress(model, objective)
        self.assertIn(("symbolic.increment", {"amount": 2}), backward.required_actions)
        self.assertIn("weakest_precondition+solver", backward.method)
        report = HybridPlanner().plan(model, objective, auth)
        self.assertEqual(report.status, AnalysisStatus.SAT_CANDIDATE)
        self.assertEqual(report.witness.interactions[0]["request"], {"amount": 2})

    def test_multi_step_symbolic_regression_seeds_unsupplied_trace(self):
        def operation(name, variable):
            return Operation(
                name="state.mutation",
                entry_point=EntryPoint(name),
                guard=lambda _state, request: 0 < request.get("amount", 0) <= 10,
                apply=lambda state, request: state.with_updates(count=state["count"] + request["amount"]),
                symbolic_transition=SymbolicTransition(
                    f"{name}-symbolic",
                    name,
                    IntRange(Variable(variable, Sort.INT), 1, 10),
                    {"state.count": Add(Variable("state.count", Sort.INT), Variable(variable, Sort.INT))},
                ),
            )

        model = TransitionModel(
            target_id="sequence-lab",
            initial_state=State({"count": 0}),
            inputs=(),
            operations=(operation("step.one", "input.0.amount"), operation("step.two", "input.1.amount")),
        )
        objective = ObjectiveDefinition(
            "symbolic-reach-three",
            "sequence-lab",
            "node-lab",
            (StateEquals("count", 3),),
            budget=ObjectiveBudget(max_trace_length=2),
        )
        auth = Authorization("sequence-tests", frozenset({"node-lab"}), frozenset({"sequence-lab"}))
        backward = BackwardRegressor().regress(model, objective)
        self.assertTrue(backward.required_traces)
        self.assertEqual(len(backward.required_traces[0]), 2)
        report = HybridPlanner().plan(model, objective, auth)
        self.assertEqual(report.status, AnalysisStatus.SAT_CANDIDATE)
        self.assertEqual(len(report.witness.interactions), 2)
        self.assertEqual(sum(item["request"]["amount"] for item in report.witness.interactions), 3)

    def test_observed_phantom_entry_is_probed_before_model_search(self):
        model = TransitionModel(
            target_id="node-fixture",
            initial_state=State({"count": 0, "history": []}),
            inputs=(),
            operations=(),
        )
        objective = ObjectiveDefinition(
            "reach-phantom",
            "node-fixture",
            "node-lab",
            (EntrySequence(("dynamic_debug",)),),
            budget=ObjectiveBudget(max_trace_length=1, replay_runs=2),
        )
        adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture")
        try:
            report = HybridPlanner().plan(model, objective, self.authorization, adapter=adapter)
        finally:
            adapter.teardown()
        self.assertEqual(report.status, AnalysisStatus.VALIDATED_WITNESS)
        self.assertEqual(report.witness.interactions[0]["entry_point"], "dynamic_debug")
        self.assertIsNone(report.witness.model_aligned)
        self.assertIn("dynamic_debug", report.surface_scope)

    def test_planner_reports_bounded_unsat(self):
        objective = ObjectiveDefinition(
            "reach-nine",
            "node-fixture",
            "node-lab",
            (StateEquals("count", 9),),
            budget=ObjectiveBudget(max_trace_length=1),
        )
        report = HybridPlanner().plan(fixture_model(), objective, self.authorization)
        self.assertEqual(report.status, AnalysisStatus.UNSAT_BOUNDED)
        self.assertIn("max_trace_length", report.proof.query)
        self.assertEqual(report.proof.fidelity_limitations[0], "bounded surface and trace length")

    def test_objective_round_trip_preserves_budget_and_predicates(self):
        objective = ObjectiveDefinition(
            "round-trip",
            "node-fixture",
            "node-lab",
            (EntrySequence(("increment", "async_increment")), GuardInvariant("increment")),
            permitted_sinks=frozenset({"fixture.state"}),
            profile_requirements=(ProfileRequirement("node-runtime", "runtime", "node.js", "rsve.node", "24.21.0"),),
            budget=ObjectiveBudget(max_trace_length=3, replay_runs=2),
        )
        self.assertEqual(ObjectiveDefinition.from_record(objective.to_record()), objective)

    def test_profile_drift_is_rejected_before_search(self):
        objective = ObjectiveDefinition(
            "wrong-runtime",
            "node-fixture",
            "node-lab",
            (StateEquals("count", 2),),
            profile_requirements=(ProfileRequirement("node-runtime", "runtime", "node.js", "rsve.node", "0.0.0"),),
        )
        adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture")
        with self.assertRaisesRegex(ValueError, "profile requirements are unresolved"):
            HybridPlanner().plan(fixture_model(), objective, self.authorization, adapter=adapter)
        adapter.teardown()

    def test_wrong_guard_diverges_and_refinement_excludes_counterexample(self):
        objective = ObjectiveDefinition(
            "reach-eleven",
            "node-fixture",
            "node-lab",
            (StateEquals("count", 11),),
            budget=ObjectiveBudget(max_trace_length=1),
        )
        model = fixture_model(max_amount=100, inputs=({"amount": 11},))
        adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture")
        report = HybridPlanner().plan(model, objective, self.authorization, adapter=adapter)
        self.assertEqual(report.status, AnalysisStatus.MODEL_DIVERGENCE)
        self.assertEqual(report.divergences[0].kind, DivergenceKind.MODEL_TOO_LOOSE.value)

        adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture")
        adapter.prepare()
        try:
            baseline = adapter.snapshot()
            adapter.reset(baseline)
            observed = adapter.execute_trace(report.witness.interactions, self.authorization)
        finally:
            adapter.teardown()
        refinement = DifferentialAnalyzer().refine(model, report.divergences, observed, invalidated_queries=("q-1",))
        self.assertIn("q-1", refinement.delta.invalidated_queries)
        self.assertFalse(refinement.model.allows(report.witness.interactions[0]["entry_point"], {"amount": 11}))

    def test_unexpected_semantic_events_diverge_and_demote_assumptions(self):
        before = State({"count": 0})
        after = State({"count": 1})
        expected = TraceEvent("state.mutation", "known", {}, before, after, component="fixture.state")
        unexpected = TraceEvent("state.mutation", "phantom", {}, before, after, component="fixture.state")
        analyzer = DifferentialAnalyzer()
        divergences = analyzer.compare((expected,), (unexpected, expected))
        self.assertEqual(divergences[0].kind, DivergenceKind.MODEL_TOO_STRICT.value)
        self.assertEqual(divergences[0].observed_index, 0)
        model = TransitionModel(
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
        expected = TraceEvent("state.mutation", "increment", {"amount": 11}, before, before, guard_result=True)
        observed = TraceEvent("guard.decision", "increment", {"amount": 11}, before, before, guard_result=False)
        analyzer = DifferentialAnalyzer()
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
        objective = ObjectiveDefinition(
            "outside",
            "node-fixture",
            "node-lab",
            (FlowToSink("increment", "RSVE-CANARY", "external"),),
            permitted_sinks=frozenset({"external"}),
        )
        with self.assertRaises(ValueError):
            HybridPlanner(harness_sinks={"fixture.state"}).plan(fixture_model(), objective, self.authorization)


if __name__ == "__main__":
    unittest.main()
