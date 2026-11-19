import unittest

from rsve import (
    Authorization,
    Budget,
    Decision,
    Engine,
    Entry,
    Guard,
    Planner,
    Index,
    Limits,
    Objective,
    Operation,
    Outcome,
    Goal,
    State,
    Same,
    Model,
)
from rsve.residual import Area, Type, mismatch
from rsve.result import Status


class Causal(unittest.TestCase):
    def auth(self):
        return Authorization("test", frozenset({"lab"}), frozenset({"target"}))

    def testreject(self):
        op = Operation("check", Entry("check"), guard=lambda _state, _request: False)
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
            Entry("deny"),
            guard=lambda _state, request: request.get("kind") == "go",
            deny=lambda state, _request: state.update(ready=True),
            deny_writes=frozenset({"ready"}),
            stop=False,
        )
        use = Operation(
            "use",
            Entry("use"),
            guard=lambda state, request: state.get("ready") is True and request.get("kind") == "go",
            apply=lambda state, _request: state.update(done=True),
            writes=frozenset({"done"}),
        )
        model = Model(
            "target",
            State({"ready": False, "done": False}),
            ({"kind": "bad"}, {"kind": "go"}),
            (deny, use),
        )
        goal = Objective(
            "goal", "target", "lab", (Same("done", True), Guard("deny", False)),
            budget=Limits(max_trace_length=2),
        )
        report = Planner().plan(model, goal, self.auth())
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual([event.decision for event in report.witness.events], [Decision.REJECT, Decision.ACCEPT])
        self.assertEqual(Index.build(model).predecessors(("ready",))[0].decision, Decision.REJECT)

    def testdeny(self):
        op = Operation(
            "deny",
            Entry("deny"),
            guard=lambda _state, _request: False,
            deny=lambda state, _request: state.update(ready=True),
            effects=("accepted-effect",),
            writes=frozenset({"accepted"}),
            deny_effects=("rejected-effect",),
            deny_writes=frozenset({"ready"}),
        )
        outcome = op.execute(State({"ready": False}), {})
        self.assertEqual(outcome.effects, ("rejected-effect",))
        self.assertEqual(outcome.writes, frozenset({"ready"}))

    def testunknown(self):
        op = Operation(
            "opaque",
            Entry("opaque"),
            relation=lambda state, _request: (Outcome(Decision.UNKNOWN, state.update(goal=True), terminal=True),),
        )
        model = Model("target", State({"goal": False}), ({},), (op,))
        goal = Goal("goal", "lab", lambda state, _trace: state.get("goal") is True)
        report = Engine().analyze(model, goal, self.auth(), Budget(max_depth=1))
        self.assertEqual(report.status, Status.UNKNOWN)

    def testguard(self):
        self.assertFalse(Guard("check", False).evaluate(State(), ()))

    def testindex(self):
        writer = Operation(
            "write",
            Entry("early"),
            apply=lambda state, _request: state.update(goal=True),
            reads=frozenset({"ready"}),
            writes=frozenset({"goal"}),
        )
        filler = Operation(
            "fill",
            Entry("middle"),
            apply=lambda state, _request: state.update(ready=True),
            writes=frozenset({"ready"}),
        )
        model = Model("target", State({"goal": False, "ready": False}), ({},), (writer, filler))
        index = Index.build(model)
        found = index.predecessors(("goal",))
        self.assertEqual([item.entry for item in found], ["early"])
        chain = index.chain(("goal",))
        self.assertEqual({item.entry for item in chain}, {"early", "middle"})

    def testbranch(self):
        def route(state, _request):
            return (
                Outcome(Decision.ACCEPT, state.update(value=1)),
                Outcome(Decision.REJECT, state.update(value=-1), guard=False),
            )
        op = Operation("route", Entry("route"), relation=route)
        self.assertEqual({item.decision for item in op.branches(State(), {})}, {Decision.ACCEPT, Decision.REJECT})

    def testresidual(self):
        item = mismatch(
            Type.UNMODELED,
            Area("region", ()),
            "observed transition is absent from the model",
            transition="step",
        )
        self.assertEqual(item.kind, Type.UNMODELED)
        self.assertEqual(item.transition, "step")


if __name__ == "__main__":
    unittest.main()
