import unittest

from rsve import (
    Authorization,
    Context,
    Decision,
    Entry,
    Graph,
    Limits,
    Objective,
    Operation,
    Outcome,
    Persona,
    Planner,
    Same,
    State,
    Zone,
    World,
    Workspace,
    Guard,
    Model,
    Reach,
    Evidence,
    Fidelity,
    Loss,
    Invertibility,
    Partiality,
    Relation,
    Representation,
    Recognizer,
    Transform,
    Transition,
)
from rsve.result import Status


class Suite(unittest.TestCase):
    def test_environment_reaction_changes_composed_reachability(self):
        gate = Operation(
            "gate",
            Entry("gate"),
            guard=lambda _state, _request: False,
            deny=lambda state, _request: state.update(ready=True),
            deny_writes=frozenset({"ready"}),
            stop=False,
        )
        use = Operation(
            "use",
            Entry("use"),
            guard=lambda state, _request: state.get("ready") is True,
            apply=lambda state, _request: state.update(done=True),
            writes=frozenset({"done"}),
        )
        model = Model(
            "target",
            State({"ready": False, "done": False}),
            ({"kind": "bad"}, {"kind": "go"}),
            (gate, use),
        )
        world = World(
            Context(model.initial_state, State({"quota": 0})),
            {
                "gate": lambda context, _request: (
                    context.target.update(ready=True),
                    context.environment.update(quota=1),
                    {"quota": 1},
                ),
                "use": lambda context, _request: (
                    context.target,
                    context.environment,
                    {"quota": context.environment.get("quota")},
                ),
            },
        )
        graph = Graph("workspace").persona(Persona("target", "fixture", "target", "synthetic", "1"))
        graph = graph.zone(Zone("target", "target", "target"))
        workspace = Workspace.flat(model, graph=graph, world=world)
        self.assertTrue(workspace.validate().ready)
        objective = Objective(
            "done",
            "target",
            "lab",
            (Same("done", True), Guard("gate", False)),
            budget=Limits(max_trace_length=2),
        )
        report = Planner().plan(
            model,
            objective,
            Authorization("test", frozenset({"lab"}), frozenset({"target"})),
            workspace=workspace,
        )
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual([event.decision for event in report.witness.events], [Decision.REJECT, Decision.ACCEPT])
        self.assertEqual(report.witness.events[0].after["ready"], True)
        self.assertEqual(report.witness.events[0].reaction, {"quota": 1})

    def test_graph_semantics_lower_into_canonical_rejection_outcome(self):
        operation = Operation(
            "check",
            Entry("check"),
            apply=lambda state, _request: state.update(done=True),
        )
        model = Model("graph-fixture", State({"done": False}), ({"ok": False},), (operation,))
        profile = Persona("fixture", "test", "target", "graph", "1")
        graph = Graph("graph-workspace").persona(profile).zone(Zone("region", "fixture", "region"))
        graph = graph.value(Representation("input", "mapping"))
        graph = graph.value(Representation("output", "mapping"))
        graph = graph.transform(Transform(
            "identity",
            "input",
            "output",
            "fixture.identity",
            "1",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.BIJECTIVE,
            Loss.NONE,
            evidence=(Evidence("e", Fidelity.MODELED, "test"),),
        ))
        graph = graph.guard(Recognizer("check.guard", "output", "fixture.guard", None, "region"))
        graph = graph.transition(Transition("check", "check", "input", "output", ("identity",), ("check.guard",)))
        workspace = Workspace.flat(
            model,
            graph=graph,
            transforms={"identity": lambda value, _state: value},
            recognizers={"check.guard": lambda value, _state: value.get("ok") is True},
        )
        moves = workspace.moves(workspace.start(), "check", {"ok": False}, operation=operation)
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0].outcome.decision, Decision.REJECT)
        self.assertFalse(moves[0].event.guard_result)
        self.assertFalse(moves[0].after.target.get("done"))

    def test_model_reachability_distinguishes_possible_and_guaranteed(self):
        deterministic = Operation(
            "finish",
            Entry("finish"),
            apply=lambda state, _request: state.update(done=True),
        )
        model = Model("reach-fixture", State({"done": False}), ({},), (deterministic,))
        objective = Objective("done", "reach-fixture", "lab", (Same("done", True),), budget=Limits(max_trace_length=1))
        auth = Authorization("test", frozenset({"lab"}), frozenset({"reach-fixture"}))
        report = Planner().plan(model, objective, auth)
        self.assertEqual(report.reachability, Reach.GUARANTEED)

        nondeterministic = Operation(
            "finish",
            Entry("finish"),
            relation=lambda state, _request: (
                Outcome(Decision.ACCEPT, state.update(done=True), terminal=True),
                Outcome(Decision.ACCEPT, state.update(done=False), terminal=True),
            ),
        )
        model = Model("reach-fixture", State({"done": False}), ({},), (nondeterministic,))
        report = Planner().plan(model, objective, auth)
        self.assertEqual(report.reachability, Reach.POSSIBLE)


if __name__ == "__main__":
    unittest.main()
