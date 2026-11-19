import unittest
from pathlib import Path

from rsve import (
    Add,
    Authorization,
    Entry,
    Range,
    Operation,
    Limits,
    Objective,
    Optimizer,
    State,
    Same,
    Sort,
    Symbolic,
    Model,
    Variable,
    Witness,
)
from rsve.extensions import Node


FIXTURE = Path(__file__).parent / "fixtures" / "node" / "fixture.mjs"


class Suite(unittest.TestCase):
    def test_shorter_equivalent_realization_is_replay_validated(self):
        adapter = Node(FIXTURE, target_id="node-fixture")
        authorization = Authorization("optimizer-tests", frozenset({"node-lab"}), frozenset({"node-fixture"}))
        objective = Objective(
            "reach-two",
            "node-fixture",
            "node-lab",
            (Same("count", 2),),
            budget=Limits(max_trace_length=2, replay_runs=2),
        )
        original_interactions = (
            {"entry_point": "increment", "request": {"amount": 1}},
            {"entry_point": "increment", "request": {"amount": 1}},
        )
        try:
            adapter.prepare()
            baseline = adapter.snapshot()
            adapter.reset(baseline)
            events = adapter.trace(original_interactions, authorization)
            original = Witness(
                objective=objective.objective_id,
                target_id="node-fixture",
                events=events,
                final_state=events[-1].after,
                validated=True,
                interactions=original_interactions,
            )
            adapter.reset(baseline)
            result = Optimizer().optimize(
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

    def test_optimize_synthesizes_model_alternatives(self):
        adapter = Node(FIXTURE, target_id="node-fixture")
        authorization = Authorization("optimizer-synthesis", frozenset({"node-lab"}), frozenset({"node-fixture"}))
        objective = Objective(
            "reach-two-synthesized",
            "node-fixture",
            "node-lab",
            (Same("count", 2),),
            budget=Limits(max_trace_length=2, replay_runs=2),
        )
        operation = Operation(
            "state.mutation",
            Entry("increment"),
            guard=lambda _state, request: 0 < request.get("amount", 0) <= 10,
            apply=lambda state, request: state.update(count=state["count"] + request["amount"]),
            symbolic_transition=Symbolic(
                "increment-synthesis",
                "increment",
                Range(Variable("input.amount", Sort.INT), 1, 10),
                {"state.count": Add(Variable("state.count", Sort.INT), Variable("input.amount", Sort.INT))},
            ),
        )
        model = Model("node-fixture", State({"count": 0}), (), (operation,))
        original_interactions = (
            {"entry_point": "increment", "request": {"amount": 1}},
            {"entry_point": "increment", "request": {"amount": 1}},
        )
        try:
            adapter.prepare()
            baseline = adapter.snapshot()
            adapter.reset(baseline)
            events = adapter.trace(original_interactions, authorization)
            original = Witness(
                objective=objective.objective_id,
                target_id="node-fixture",
                events=events,
                final_state=events[-1].after,
                validated=True,
                interactions=original_interactions,
            )
            adapter.reset(baseline)
            result = Optimizer().optimize(
                original,
                model,
                objective,
                authorization,
                adapter=adapter,
            )
        finally:
            adapter.teardown()
        self.assertEqual(result.status.value, "OPTIMIZED")
        self.assertEqual(result.selected.interactions[0]["request"], {"amount": 2})


if __name__ == "__main__":
    unittest.main()
