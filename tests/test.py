import unittest

from rsve import (
    Authorization,
    Decision,
    EntryPoint,
    GuardInvariant,
    HybridPlanner,
    Index,
    ObjectiveBudget,
    ObjectiveDefinition,
    Operation,
    Outcome,
    State,
    StateEquals,
    TransitionModel,
)
from rsve.residual import CandidateRegion, ResidualKind, mismatch
from rsve.result import AnalysisStatus


class Causal(unittest.TestCase):
    def auth(self):
        return Authorization("test", frozenset({"lab"}), frozenset({"target"}))

    def testreject(self):
        op = Operation("check", EntryPoint("check"), guard=lambda _state, _request: False)
        out = op.execute(State({"value": 0}), {"value": 1})
        self.assertEqual(out.decision, Decision.REJECT)
        self.assertFalse(out.guard)
        self.assertTrue(out.terminal)
        event = out.event("check", "check", {"value": 1}, State({"value": 0}))
        self.assertFalse(event.guard_result)
        self.assertEqual(event.decision, Decision.REJECT)

    def testpartial(self):
        deny = Operation(
            "deny",
            EntryPoint("deny"),
            guard=lambda _state, request: request.get("kind") == "go",
            deny=lambda state, _request: state.with_updates(ready=True),
            stop=False,
        )
        use = Operation(
            "use",
            EntryPoint("use"),
            guard=lambda state, request: state.get("ready") is True and request.get("kind") == "go",
            apply=lambda state, _request: state.with_updates(done=True),
            writes=frozenset({"done"}),
        )
        model = TransitionModel(
            "target",
            State({"ready": False, "done": False}),
            ({"kind": "bad"}, {"kind": "go"}),
            (deny, use),
        )
        goal = ObjectiveDefinition(
            "goal", "target", "lab", (StateEquals("done", True), GuardInvariant("deny", False)),
            budget=ObjectiveBudget(max_trace_length=2),
        )
        report = HybridPlanner().plan(model, goal, self.auth())
        self.assertEqual(report.status, AnalysisStatus.SAT_CANDIDATE)
        self.assertEqual([event.decision for event in report.witness.events], [Decision.REJECT, Decision.ACCEPT])

    def testguard(self):
        self.assertFalse(GuardInvariant("check", False).evaluate(State(), ()))

    def testindex(self):
        writer = Operation(
            "write",
            EntryPoint("early"),
            apply=lambda state, _request: state.with_updates(goal=True),
            writes=frozenset({"goal"}),
        )
        filler = Operation("fill", EntryPoint("middle"))
        model = TransitionModel("target", State({"goal": False}), ({},), (writer, filler))
        found = Index.build(model).predecessors(("goal",))
        self.assertEqual([item.entry for item in found], ["early"])

    def testbranch(self):
        def route(state, _request):
            return (
                Outcome(Decision.ACCEPT, state.with_updates(value=1)),
                Outcome(Decision.REJECT, state.with_updates(value=-1), guard=False),
            )
        op = Operation("route", EntryPoint("route"), relation=route)
        self.assertEqual({item.decision for item in op.branches(State(), {})}, {Decision.ACCEPT, Decision.REJECT})

    def testresidual(self):
        item = mismatch(
            ResidualKind.UNMODELED,
            CandidateRegion("region", ()),
            "observed transition is absent from the model",
            transition="step",
        )
        self.assertEqual(item.kind, ResidualKind.UNMODELED)
        self.assertEqual(item.transition, "step")


if __name__ == "__main__":
    unittest.main()
