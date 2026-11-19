import unittest
from pathlib import Path

from rsve import (
    Authorization,
    EntrySequence,
    EntryPoint,
    FlowToSink,
    GuardInvariant,
    HybridPlanner,
    NodeTargetAdapter,
    LayerPin,
    ObjectiveDefinition,
    ObjectiveBudget,
    Operation,
    State,
    StateEquals,
    TransitionModel,
)
from rsve.differential import DifferentialAnalyzer, DivergenceKind
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
        self.assertTrue(report.execution_profile_id.startswith("profile-"))
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
            profile_pins=(LayerPin("runtime", "node", "24.21.0"),),
            budget=ObjectiveBudget(max_trace_length=3, replay_runs=2),
        )
        self.assertEqual(ObjectiveDefinition.from_record(objective.to_record()), objective)

    def test_profile_drift_is_rejected_before_search(self):
        objective = ObjectiveDefinition(
            "wrong-runtime",
            "node-fixture",
            "node-lab",
            (StateEquals("count", 2),),
            profile_pins=(LayerPin("runtime", "node", "0.0.0"),),
        )
        adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture")
        with self.assertRaisesRegex(ValueError, "execution profile is DRIFT"):
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
            observed = adapter.execute_trace(report.witness.interactions)
        finally:
            adapter.teardown()
        refinement = DifferentialAnalyzer().refine(model, report.divergences, observed, invalidated_queries=("q-1",))
        self.assertIn("q-1", refinement.delta.invalidated_queries)
        self.assertFalse(refinement.model.allows(report.witness.interactions[0]["entry_point"], {"amount": 11}))

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
