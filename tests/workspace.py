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
    Effect,
)
from rsve.result import Status
from rsve.planner import Regressor


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

    def test_graph_transform_feeds_operation_and_effect_state(self):
        operation = Operation(
            "check",
            Entry("check"),
            guard=lambda _state, request: isinstance(request.get("amount"), int),
            apply=lambda state, request: state.update(done=request["amount"] == 10),
            effects=("operation",),
        )
        model = Model("transform-fixture", State({"done": False}), ({"amount": "10"},), (operation,))
        profile = Persona("fixture", "test", "target", "graph", "1")
        graph = Graph("transform-workspace").persona(profile).zone(Zone("region", "fixture", "region"))
        graph = graph.value(Representation("raw", "text"))
        graph = graph.value(Representation("number", "integer"))
        graph = graph.transform(Transform(
            "parse",
            "raw",
            "number",
            "fixture.parse",
            "1",
            Partiality.PARTIAL,
            Relation.FUNCTION,
            Invertibility.NON_INVERTIBLE,
            Loss.POSSIBLE,
        ))
        graph = graph.effect(Effect("parsed", "state", ("parsed",)))
        graph = graph.guard(Recognizer("positive", "number", "fixture.positive", None, "region"))
        graph = graph.transition(Transition("check", "check", "raw", "number", ("parse",), ("positive",), ("parsed",)))
        workspace = Workspace.flat(
            model,
            graph=graph,
            transforms={"parse": lambda value, _state: int(value["amount"])},
            recognizers={"positive": lambda value, _state: value == 10},
            effects={"parsed": lambda state, _value: state.update(parsed=True)},
        )
        moves = workspace.moves(workspace.start(), "check", {"amount": "10"}, operation=operation)
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0].outcome.decision, Decision.ACCEPT)
        self.assertEqual(moves[0].event.request, {"amount": 10})
        self.assertTrue(moves[0].after.target.get("done"))
        self.assertTrue(moves[0].after.target.get("parsed"))
        self.assertEqual(moves[0].event.effects, ("parsed", "operation"))
        objective = Objective("done", "transform-fixture", "lab", (Same("done", True),), budget=Limits(max_trace_length=1))
        backward = Regressor().regress(model, objective, workspace=workspace)
        self.assertIn(("check", {"amount": "10"}), backward.required_actions)

    def test_empty_graph_relation_does_not_fall_back_to_operation(self):
        operation = Operation("empty", Entry("empty"), apply=lambda state, _request: state.update(done=True))
        model = Model("empty-fixture", State({"done": False}), ({"value": "x"},), (operation,))
        profile = Persona("fixture", "test", "target", "graph", "1")
        graph = Graph("empty-workspace").persona(profile).zone(Zone("region", "fixture", "region"))
        graph = graph.value(Representation("raw", "mapping"))
        graph = graph.value(Representation("out", "mapping"))
        graph = graph.transform(Transform("empty", "raw", "out", "fixture.empty", "1", Partiality.PARTIAL, Relation.RELATION, Invertibility.UNKNOWN, Loss.UNKNOWN))
        graph = graph.transition(Transition("empty", "empty", "raw", "out", ("empty",)))
        workspace = Workspace.flat(model, graph=graph, transforms={"empty": lambda _value, _state: ()})
        self.assertEqual(workspace.moves(workspace.start(), "empty", {"value": "x"}, operation=operation), ())

    def test_declared_uncontrolled_environment_is_unknown(self):
        world = World(
            Context(State({"done": False}), State({"quota": 0})),
            {"react": lambda context, _request: (
                (context.target.update(done=True), context.environment.update(quota=1), {}),
                (context.target.update(done=False), context.environment.update(quota=0), {}),
            )},
            nondeterministic=frozenset({"react"}),
        )
        options = world.options("react", world.initial, {})
        self.assertEqual(len(options), 2)
        self.assertTrue(all(step.status.value == "unknown" for step in options))

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
