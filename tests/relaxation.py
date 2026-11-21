import unittest
from dataclasses import replace

from rsve import (
    Axiom,
    Authorization,
    Decision,
    Entry,
    Every,
    Equal,
    Limits,
    Literal,
    Model,
    Objective,
    Operation,
    Outcome,
    Range,
    Same,
    Sort,
    State,
    Variable,
    Workspace,
)
from rsve.relaxation import AlternativeStatus, RelaxationAnalyzer
from rsve.result import Verdict
from rsve.solver import Answer, Query, Zed


class Suite(unittest.TestCase):
    def test_core_directed_single_relaxation_is_counterfactual(self):
        x = Variable("x", Sort.INT)
        query = Query(
            "conflict",
            Every((
                Axiom("nonnegative", Range(x, 0, 3)),
                Axiom("negative", Range(x, -3, -1)),
            )),
        )

        report = RelaxationAnalyzer().explore(query)

        self.assertEqual(report.baseline.status, Verdict.UNSAT_BOUNDED)
        self.assertEqual({item.relaxed for item in report.alternatives}, {"nonnegative", "negative"})
        self.assertTrue(all(item.answer.status is Verdict.SAT for item in report.alternatives))
        self.assertTrue(all(item.status is AlternativeStatus.COUNTERFACTUAL for item in report.alternatives))
        self.assertTrue(any("counterfactual" in item for item in report.limitations))

    def test_irrelevant_assumptions_are_not_relaxed(self):
        x = Variable("x", Sort.INT)
        y = Variable("y", Sort.INT)
        query = Query(
            "core-only",
            Every((
                Axiom("nonnegative", Range(x, 0, 3)),
                Axiom("negative", Range(x, -3, -1)),
                Axiom("irrelevant_axiom", Equal(y, Literal(4, Sort.INT))),
            )),
            assumptions=("irrelevant_assumption",),
        )

        report = RelaxationAnalyzer().explore(query)

        self.assertEqual({item.relaxed for item in report.alternatives}, {"nonnegative", "negative"})

    def test_forged_baseline_core_is_ignored_and_recomputed(self):
        x = Variable("x", Sort.INT)
        query = Query(
            "forged-core",
            Every((
                Axiom("nonnegative", Range(x, 0, 3)),
                Axiom("negative", Range(x, -3, -1)),
                Axiom("irrelevant", Equal(Variable("y", Sort.INT), Literal(4, Sort.INT))),
            )),
        )
        real = Zed().solve(query)
        forged = replace(real, unsat_core=("irrelevant",))

        report = RelaxationAnalyzer().explore(query, baseline=forged)

        self.assertNotIn("irrelevant", report.core)
        self.assertEqual({item.relaxed for item in report.alternatives}, {"nonnegative", "negative"})
        self.assertTrue(any("ignored" in item for item in report.limitations))

    def test_duplicate_axiom_and_query_assumption_names_are_rejected(self):
        x = Variable("x", Sort.INT)
        query = Query(
            "duplicate-name",
            Every((Axiom("same", Equal(x, Literal(1, Sort.INT))), Equal(x, Literal(2, Sort.INT)))),
            assumptions=("same",),
        )

        with self.assertRaisesRegex(ValueError, "duplicate top-level relaxation identifiers"):
            RelaxationAnalyzer().explore(query)

    def test_workspace_route_confirms_model_not_runtime_reachability(self):
        x = Variable("x", Sort.INT)
        query = Query(
            "route-conflict",
            Every((
                Axiom("profile.limit", Equal(x, Literal(2, Sort.INT))),
                Equal(x, Literal(1, Sort.INT)),
            )),
        )
        operation = Operation(
            "set-value",
            Entry("set-value"),
            guard=lambda _state, _request: True,
            apply=lambda state, _request: state.update(done=True),
            writes=frozenset({"done"}),
        )
        model = Model.build("relax-fixture", State({"done": False}), (), (operation,))
        workspace = Workspace.flat(model)
        objective = Objective(
            "relaxed-goal",
            "relax-fixture",
            "authorized-fixture",
            (Same("done", True),),
            state_keys=frozenset({"done"}),
            budget=Limits(max_trace_length=1, max_states=8, max_time_ms=1_000),
        )

        report = RelaxationAnalyzer().explore(
            query,
            trace_builder=lambda assignment: ({
                "entry_point": "set-value",
                "request": {"value": assignment["x"]},
            },),
            model_bindings={"x": ((0, "value"),)},
            workspace=workspace,
            objective=objective,
            authorization=Authorization(
                "relax-test",
                frozenset({"authorized-fixture"}),
                frozenset({"relax-fixture"}),
            ),
        )

        self.assertEqual(len(report.alternatives), 1)
        self.assertEqual(report.alternatives[0].status, AlternativeStatus.MODEL_CONFIRMED)
        self.assertIn("certain Workspace route", report.alternatives[0].evidence[0])

        mismapped = RelaxationAnalyzer().explore(
            query,
            trace_builder=lambda assignment: ({
                "entry_point": "set-value",
                "request": {"value": assignment["x"] + 1},
            },),
            model_bindings={"x": ((0, "value"),)},
            workspace=workspace,
            objective=objective,
            authorization=Authorization(
                "relax-test",
                frozenset({"authorized-fixture"}),
                frozenset({"relax-fixture"}),
            ),
        )
        self.assertEqual(mismapped.alternatives[0].status, AlternativeStatus.COUNTERFACTUAL)
        self.assertTrue(any("does not match" in item for item in mismapped.alternatives[0].evidence))

    def test_uncertain_intermediate_event_cannot_confirm_route(self):
        x = Variable("x", Sort.INT)
        query = Query(
            "uncertain-route",
            Every((
                Axiom("profile.limit", Equal(x, Literal(2, Sort.INT))),
                Equal(x, Literal(1, Sort.INT)),
            )),
        )
        first = Operation(
            "uncertain-step",
            Entry("uncertain-step"),
            relation=lambda state, _request: (Outcome(
                Decision.ACCEPT,
                state.update(step=True),
                uncertainty=("correlation evidence missing",),
            ),),
            relation_complete=True,
        )
        finish = Operation(
            "finish",
            Entry("finish"),
            guard=lambda state, _request: state.get("step") is True,
            apply=lambda state, _request: state.update(done=True),
            writes=frozenset({"done"}),
        )
        model = Model.build("uncertain-fixture", State({"done": False}), (), (first, finish))
        workspace = Workspace.flat(model)
        objective = Objective(
            "uncertain-goal",
            "uncertain-fixture",
            "authorized-fixture",
            (Same("done", True),),
            state_keys=frozenset({"done"}),
            budget=Limits(max_trace_length=2, max_states=8, max_time_ms=1_000),
        )

        report = RelaxationAnalyzer().explore(
            query,
            trace_builder=lambda assignment: (
                {"entry_point": "uncertain-step", "request": {"value": assignment["x"]}},
                {"entry_point": "finish", "request": {}},
            ),
            model_bindings={"x": ((0, "value"),)},
            workspace=workspace,
            objective=objective,
            authorization=Authorization(
                "relax-test",
                frozenset({"authorized-fixture"}),
                frozenset({"uncertain-fixture"}),
            ),
        )

        self.assertEqual(report.alternatives[0].status, AlternativeStatus.COUNTERFACTUAL)
        self.assertIn("certain branch", report.alternatives[0].evidence[-1])


if __name__ == "__main__":
    unittest.main()
