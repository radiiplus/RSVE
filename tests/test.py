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
        op = Operation("check", Entry("check"), guard=lambda _state, _request: False, stop=True)
        out = op.execute(State({"value": 0}), {"value": 1})
        self.assertEqual(out.decision, Decision.REJECT)
        self.assertFalse(out.guard)
        self.assertTrue(out.terminal)
        event = out.event("check", "check", {"value": 1}, State({"value": 0}))
        self.assertFalse(event.guard_result)
        self.assertEqual(event.decision, Decision.REJECT)

    def test_error_handler_preserves_downstream_routes_after_failure(self):
        broken = Operation(
            "decode",
            Entry("decode"),
            apply=lambda _state, _request: (_ for _ in ()).throw(ValueError("malformed")),
            error_handler=lambda state, _request, _error: state.update(error_seen=True, retries=1),
            error_effects=("decode.error",),
            error_writes=frozenset({"error_seen", "retries"}),
        )
        recover = Operation(
            "recover",
            Entry("recover"),
            guard=lambda state, _request: state.get("error_seen") is True,
            apply=lambda state, _request: state.update(done=True),
            reads=frozenset({"error_seen"}),
            writes=frozenset({"done"}),
        )
        model = Model(
            "target", State({"error_seen": False, "retries": 0, "done": False}), ({},), (broken, recover),
        )
        goal = Goal("goal", "lab", lambda state, _trace: state.get("done") is True)
        report = Engine().analyze(model, goal, self.auth(), Budget(max_depth=2))

        self.assertEqual(report.status, Status.MODEL_SAT)
        self.assertEqual([event.decision for event in report.witness.events], [Decision.ERROR, Decision.ACCEPT])
        self.assertTrue(report.witness.events[0].effects == ("decode.error",))
        self.assertTrue(report.witness.events[0].after["error_seen"])

    def test_unhandled_operation_error_is_nonterminal_and_marks_unmodeled_aftermath(self):
        broken = Operation(
            "broken", Entry("broken"), apply=lambda _state, _request: (_ for _ in ()).throw(ValueError())
        )
        outcome = broken.execute(State(), {})

        self.assertEqual(outcome.decision, Decision.ERROR)
        self.assertFalse(outcome.terminal)
        self.assertIn("error-aftermath", outcome.unknown)

        broken_handler = Operation(
            "broken-handler", Entry("broken-handler"),
            apply=lambda _state, _request: (_ for _ in ()).throw(ValueError()),
            error_handler=lambda _state, _request, _error: (_ for _ in ()).throw(RuntimeError()),
        ).execute(State(), {})
        self.assertIn("error-aftermath", broken_handler.unknown)

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

    def test_rejection_is_nonterminal_by_default(self):
        reject = Operation(
            "reject", Entry("reject"), guard=lambda _state, _request: False,
            deny=lambda state, _request: state.update(flagged=True),
            deny_writes=frozenset({"flagged"}),
        )
        follow = Operation(
            "follow", Entry("follow"), guard=lambda state, _request: state.get("flagged") is True,
            apply=lambda state, _request: state.update(done=True),
        )
        model = Model("target", State({"flagged": False, "done": False}), ({},), (reject, follow))
        goal = Goal("goal", "lab", lambda state, _trace: state.get("done") is True)
        report = Engine().analyze(model, goal, self.auth(), Budget(max_depth=2))

        self.assertEqual(report.status, Status.MODEL_SAT)
        self.assertEqual([event.decision for event in report.witness.events], [Decision.REJECT, Decision.ACCEPT])

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
