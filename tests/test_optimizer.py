import unittest
from pathlib import Path

from rsve import (
    Authorization,
    ObjectiveBudget,
    ObjectiveDefinition,
    RealizationOptimizer,
    StateEquals,
    Witness,
    NodeTargetAdapter,
)


FIXTURE = Path(__file__).parent / "fixtures" / "node" / "fixture.mjs"


class RealizationOptimizerTests(unittest.TestCase):
    def test_shorter_equivalent_realization_is_replay_validated(self):
        adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture")
        authorization = Authorization("optimizer-tests", frozenset({"node-lab"}), frozenset({"node-fixture"}))
        objective = ObjectiveDefinition(
            "reach-two",
            "node-fixture",
            "node-lab",
            (StateEquals("count", 2),),
            budget=ObjectiveBudget(max_trace_length=2, replay_runs=2),
        )
        original_interactions = (
            {"entry_point": "increment", "request": {"amount": 1}},
            {"entry_point": "increment", "request": {"amount": 1}},
        )
        try:
            adapter.prepare()
            baseline = adapter.snapshot()
            adapter.reset(baseline)
            events = adapter.execute_trace(original_interactions, authorization)
            original = Witness(
                objective=objective.objective_id,
                target_id="node-fixture",
                events=events,
                final_state=events[-1].after,
                validated=True,
                interactions=original_interactions,
            )
            adapter.reset(baseline)
            result = RealizationOptimizer().optimize(
                original,
                (({"entry_point": "increment", "request": {"amount": 2}},),),
                objective,
                authorization,
                adapter=adapter,
            )
        finally:
            adapter.teardown()

        self.assertEqual(result.status.value, "OPTIMIZED")
        self.assertEqual(len(result.selected.interactions), 1)
        self.assertLess(result.selected_cost.interaction_count, result.original_cost.interaction_count)
        self.assertEqual(len(result.equivalence_evidence), 3)


if __name__ == "__main__":
    unittest.main()
