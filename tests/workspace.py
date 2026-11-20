import unittest
from dataclasses import replace

from rsve import (
    Authorization,
    Context,
    Decision,
    Flow,
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
    Direction,
    Port,
    Add,
    Equal,
    Literal,
    Range,
    Sort,
    Symbolic,
    Variable,
    Semantic,
    Shape,
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

    def test_unknown_transform_stays_unknown_through_recognizer(self):
        operation = Operation("check", Entry("check"), apply=lambda state, _request: state.update(done=True))
        model = Model("unknown-fixture", State({"done": False}), ({"ok": False},), (operation,))
        profile = Persona("fixture", "test", "target", "graph", "1")
        graph = Graph("unknown-workspace").persona(profile).zone(Zone("region", "fixture", "region"))
        graph = graph.value(Representation("raw", "mapping"))
        graph = graph.value(Representation("out", "mapping"))
        graph = graph.transform(Transform("opaque", "raw", "out", "fixture.opaque", "1", Partiality.UNKNOWN, Relation.UNKNOWN, Invertibility.UNKNOWN, Loss.UNKNOWN))
        graph = graph.guard(Recognizer("check", "out", "fixture.check", None, "region"))
        graph = graph.transition(Transition("check", "check", "raw", "out", ("opaque",), ("check",)))
        workspace = Workspace.flat(model, graph=graph, recognizers={"check": lambda _value, _state: False})
        moves = workspace.moves(workspace.start(), "check", {"ok": False}, operation=operation)
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0].outcome.decision, Decision.UNKNOWN)

    def test_missing_graph_effect_is_unknown(self):
        operation = Operation("check", Entry("check"), apply=lambda state, _request: state.update(done=True))
        model = Model("effect-fixture", State({"done": False}), ({"ok": True},), (operation,))
        profile = Persona("fixture", "test", "target", "graph", "1")
        graph = Graph("effect-workspace").persona(profile).zone(Zone("region", "fixture", "region"))
        graph = graph.value(Representation("raw", "mapping"))
        graph = graph.value(Representation("out", "mapping"))
        graph = graph.effect(Effect("required", "state", ("reserved",)))
        graph = graph.transition(Transition("check", "check", "raw", "out", effect_ids=("required",)))
        workspace = Workspace.flat(model, graph=graph)
        moves = workspace.moves(workspace.start(), "check", {"ok": True}, operation=operation)
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0].outcome.decision, Decision.UNKNOWN)

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
            mappers={"check": lambda value, _original: {"amount": value}},
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
        graph = graph.transform(Transform("empty", "raw", "out", "fixture.empty", "1", Partiality.PARTIAL, Relation.RELATION, Invertibility.UNKNOWN, Loss.UNKNOWN, complete=True))
        graph = graph.transition(Transition("empty", "empty", "raw", "out", ("empty",)))
        workspace = Workspace.flat(model, graph=graph, transforms={"empty": lambda _value, _state: ()})
        self.assertEqual(workspace.moves(workspace.start(), "empty", {"value": "x"}, operation=operation), ())

    def test_incomplete_empty_graph_relation_is_unknown(self):
        operation = Operation("empty-unknown", Entry("empty-unknown"))
        model = Model("empty-unknown-fixture", State({"done": False}), ({},), (operation,))
        graph = Graph("empty-unknown-workspace").persona(Persona("fixture", "test", "target", "fixture", "1")).zone(Zone("region", "fixture", "region"))
        graph = graph.value(Representation("raw-unknown", "mapping"))
        graph = graph.value(Representation("out-unknown", "mapping"))
        graph = graph.transform(Transform(
            "empty-unknown-transform",
            "raw-unknown",
            "out-unknown",
            "fixture.empty-unknown",
            "1",
            Partiality.PARTIAL,
            Relation.RELATION,
            Invertibility.UNKNOWN,
            Loss.UNKNOWN,
        ))
        graph = graph.transition(Transition("empty-unknown", "empty-unknown", "raw-unknown", "out-unknown", ("empty-unknown-transform",)))
        workspace = Workspace.flat(
            model,
            graph=graph,
            transforms={"empty-unknown-transform": lambda _value, _state: ()},
        )
        moves = workspace.moves(workspace.start(), "empty-unknown", {}, operation=operation)
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0].outcome.decision, Decision.UNKNOWN)
        self.assertIn("without completeness evidence", moves[0].event.uncertainty[0])

    def test_empty_operation_relation_requires_completeness(self):
        incomplete = Operation(
            "relation-empty",
            Entry("relation-empty"),
            relation=lambda _state, _request: (),
        )
        complete = Operation(
            "relation-empty-complete",
            Entry("relation-empty-complete"),
            relation=lambda _state, _request: (),
            relation_complete=True,
        )
        state = State({})
        self.assertEqual(incomplete.branches(state, {})[0].decision, Decision.UNKNOWN)
        self.assertEqual(complete.branches(state, {}), ())

    def test_missing_owned_region_state_is_unknown(self):
        operation = Operation("owned", Entry("owned"), component="owned")
        model = Model("missing-region-fixture", State({}), ({},), (operation,))
        graph = Graph("missing-region-workspace").persona(Persona("fixture", "test", "target", "fixture", "1")).zone(Zone("owned", "fixture", "owned"))
        workspace = Workspace.flat(model, graph=graph, regions={})
        frame = replace(workspace.start(), regions={})
        moves = workspace.moves(frame, "owned", {}, operation=operation)
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0].outcome.decision, Decision.UNKNOWN)
        self.assertIn("region state unavailable", moves[0].event.uncertainty[0])

    def test_non_data_connection_is_not_a_value_route(self):
        model = Model("shape-fixture", State({"done": False}), (), ())
        graph = Graph("shape-workspace").persona(Persona("fixture", "test", "target", "fixture", "1"))
        graph = graph.zone(Zone("a", "fixture", "a")).zone(Zone("b", "fixture", "b"))
        graph = graph.value(Representation("shape-mid", "mapping"))
        graph = graph.transition(Transition("shape-start", "shape", "shape-mid", "shape-mid"))
        graph = graph.transition(Transition("shape-end", "internal", "shape-mid", "shape-mid", region_id="b"))
        graph = graph.port(Port("shape-out", "a", "out", Direction.OUTPUT, "shape-mid", "mapping"))
        graph = graph.port(Port("shape-in", "b", "in", Direction.INPUT, "shape-mid", "mapping"))
        graph = graph.connect(
            "shape-out",
            "shape-in",
            connection_id="shape-control",
            relationship_type=Shape.CONTROL,
        )
        workspace = Workspace.flat(model, graph=graph, entries={"shape"}, regions={"b": State({})})
        moves = workspace.moves(workspace.start(), "shape", {})
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0].event.operation, "shape-start")
        self.assertFalse(moves[0].after.regions["b"].as_dict())

    def test_contract_mismatch_blocks_symbolic_graph_synthesis(self):
        model = Model("contract-mismatch-fixture", State({"done": False}), (), ())
        graph = Graph("contract-mismatch-workspace").persona(Persona("fixture", "test", "target", "fixture", "1")).zone(Zone("region", "fixture", "region"))
        graph = graph.value(Representation("mismatch-raw", "mapping"))
        graph = graph.value(Representation("mismatch-out", "mapping"))
        graph = graph.transform(Transform(
            "mismatch-transform",
            "mismatch-raw",
            "mismatch-out",
            "fixture.v2",
            "2",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.BIJECTIVE,
            Loss.NONE,
        ))
        graph = graph.transition(Transition("mismatch-route", "mismatch", "mismatch-raw", "mismatch-out", ("mismatch-transform",)))
        symbolic = Symbolic(
            "mismatch-symbolic",
            "mismatch",
            Literal(True, Sort.BOOL),
            semantics_ref="fixture.v1",
            semantics_version="1",
        )
        workspace = Workspace.flat(
            model,
            graph=graph,
            transforms={"mismatch-transform": lambda value, _state: value},
            symbolics={"mismatch-transform": symbolic},
            entries={"mismatch"},
        )
        record = workspace.contract("mismatch-transform")
        self.assertIsNotNone(record)
        self.assertFalse(record.complete)
        objective = Objective("mismatch-goal", "contract-mismatch-fixture", "lab", (Same("done", True),))
        plan = Regressor().regress(model, objective, workspace=workspace)
        self.assertEqual(plan.required_actions, ())
        self.assertTrue(any("references do not match" in item for item in plan.uncertainty))

    def test_graph_only_probe_expander_is_regressed(self):
        model = Model("graph-probe-fixture", State({"done": False}), (), ())
        graph = Graph("graph-probe-workspace").persona(Persona("fixture", "test", "target", "fixture", "1")).zone(Zone("region", "fixture", "region"))
        graph = graph.value(Representation("probe-raw", "mapping"))
        graph = graph.value(Representation("probe-out", "mapping"))
        graph = graph.effect(Effect("probe-done", "done", ("done",)))
        graph = graph.transform(Transform(
            "probe-transform",
            "probe-raw",
            "probe-out",
            "fixture.probe",
            "1",
            Partiality.UNKNOWN,
            Relation.UNKNOWN,
            Invertibility.UNKNOWN,
            Loss.UNKNOWN,
        ))
        graph = graph.transition(Transition("probe-route", "probe-entry", "probe-raw", "probe-out", ("probe-transform",), effect_ids=("probe-done",)))
        workspace = Workspace.flat(
            model,
            graph=graph,
            transforms={"probe-transform": lambda value, _state: {"amount": value["amount"]}},
            effects={"probe-done": lambda state, _value: state.update(done=True)},
            entries={"probe-entry"},
            expanders={"probe-entry": lambda limit: ({"amount": 1} for _ in range(limit))},
        )
        objective = Objective("graph-probe-goal", "graph-probe-fixture", "lab", (Same("done", True),))
        plan = Regressor().regress(model, objective, workspace=workspace)
        self.assertIn(("probe-entry", {"amount": 1}), plan.required_actions)

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

    def test_verified_connections_compose_graph_only_route(self):
        model = Model("route-fixture", State({"done": False}), ({"value": "ok"},), ())
        left = Persona("left", "test", "target", "graph", "1")
        right = Persona("right", "test", "target", "graph", "1")
        graph = Graph("route-workspace").persona(left).persona(right)
        graph = graph.zone(Zone("a", "left", "a")).zone(Zone("b", "right", "b"))
        graph = graph.value(Representation("raw", "mapping"))
        graph = graph.value(Representation("mid", "text"))
        graph = graph.value(Representation("final", "mapping"))
        graph = graph.transform(Transform("parse", "raw", "mid", "fixture.parse", "1", Partiality.TOTAL, Relation.FUNCTION, Invertibility.UNKNOWN, Loss.NONE))
        graph = graph.transform(Transform("bridge", "mid", "final", "fixture.bridge", "1", Partiality.TOTAL, Relation.FUNCTION, Invertibility.UNKNOWN, Loss.NONE))
        graph = graph.guard(Recognizer("accept", "final", "fixture.accept", None, "b"))
        graph = graph.effect(Effect("finish", "state", ("done",)))
        graph = graph.transition(Transition("start", "route", "raw", "mid", ("parse",), region_id="a"))
        graph = graph.transition(Transition("finish", "internal", "final", "final", (), ("accept",), ("finish",), region_id="b"))
        graph = graph.port(Port("a-out", "a", "out", Direction.OUTPUT, "mid", "text"))
        graph = graph.port(Port("b-in", "b", "in", Direction.INPUT, "final", "mapping"))
        graph = graph.connect("a-out", "b-in", connection_id="a-to-b", transform_id="bridge")
        workspace = Workspace.flat(
            model,
            graph=graph,
            transforms={"parse": lambda value, _state: value["value"], "bridge": lambda value, _state: {"value": value}},
            recognizers={"accept": lambda value, _state: value.get("value") == "ok"},
            effects={"finish": lambda state, _value: state.update(done=True)},
            entries={"route"},
        )
        self.assertTrue(workspace.validate().ready)
        moves = workspace.moves(workspace.start(), "route", {"value": "ok"})
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0].outcome.decision, Decision.ACCEPT)
        self.assertTrue(moves[0].after.regions["b"].get("done"))
        self.assertIn("finish", moves[0].event.effects)
        objective = Objective("done", "route-fixture", "lab", (Same("b.done", True),), budget=Limits(max_trace_length=1))
        report = Planner().plan(
            model,
            objective,
            Authorization("test", frozenset({"lab"}), frozenset({"route-fixture"})),
            workspace=workspace,
        )
        self.assertEqual(report.status, Status.SAT_CANDIDATE)

    def test_operations_use_owned_region_state(self):
        operation = Operation(
            "use",
            Entry("use"),
            component="region-b",
            guard=lambda state, _request: state.get("ready") is True,
            apply=lambda state, _request: state.update(done=True),
        )
        model = Model("region-fixture", State({"ready": False}), ({},), (operation,))
        workspace = Workspace.flat(
            model,
            regions={"region-b": State({"ready": True, "done": False})},
        )
        moves = workspace.moves(workspace.start(), "use", {}, operation=operation)
        self.assertEqual(len(moves), 1)
        self.assertTrue(moves[0].after.regions["region-b"].get("done"))
        self.assertFalse(moves[0].after.target.get("done"))
        objective = Objective("region-done", "region-fixture", "lab", (Same("region-b.done", True),), budget=Limits(max_trace_length=1))
        report = Planner().plan(
            model,
            objective,
            Authorization("test", frozenset({"lab"}), frozenset({"region-fixture"})),
            workspace=workspace,
        )
        self.assertEqual(report.status, Status.SAT_CANDIDATE)

    def test_connected_graph_effect_updates_destination_region(self):
        model = Model("region-route-fixture", State({"done": False}), (({"value": "ok"},)), ())
        left = Persona("left-region", "test", "target", "graph", "1")
        right = Persona("right-region", "test", "target", "graph", "1")
        graph = Graph("region-route-workspace").persona(left).persona(right)
        graph = graph.zone(Zone("a", "left-region", "a")).zone(Zone("b", "right-region", "b"))
        graph = graph.value(Representation("raw", "mapping"))
        graph = graph.value(Representation("mid", "text"))
        graph = graph.value(Representation("final", "mapping"))
        graph = graph.transform(Transform(
            "parse-region",
            "raw",
            "mid",
            "fixture.parse-region",
            "1",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.UNKNOWN,
            Loss.NONE,
        ))
        graph = graph.transform(Transform(
            "bridge-region",
            "mid",
            "final",
            "fixture.bridge-region",
            "1",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.UNKNOWN,
            Loss.NONE,
        ))
        graph = graph.guard(Recognizer("accept-region", "final", "fixture.accept-region", None, "b"))
        graph = graph.effect(Effect("finish-region", "state", ("b.done",)))
        graph = graph.transition(Transition("start-region", "route", "raw", "mid", ("parse-region",), region_id="a"))
        graph = graph.transition(Transition(
            "finish-region",
            "internal",
            "final",
            "final",
            recognizer_ids=("accept-region",),
            effect_ids=("finish-region",),
            region_id="b",
        ))
        graph = graph.port(Port("a-out-region", "a", "out", Direction.OUTPUT, "mid", "text"))
        graph = graph.port(Port("b-in-region", "b", "in", Direction.INPUT, "final", "mapping"))
        graph = graph.connect(
            "a-out-region",
            "b-in-region",
            connection_id="a-to-b-region",
            transform_id="bridge-region",
        )
        workspace = Workspace.flat(
            model,
            graph=graph,
            regions={"a": State({"done": False}), "b": State({"done": False})},
            transforms={
                "parse-region": lambda value, _state: value["value"],
                "bridge-region": lambda value, _state: {"value": value},
            },
            recognizers={"accept-region": lambda value, _state: value.get("value") == "ok"},
            effects={"finish-region": lambda state, _value: state.update(done=True)},
            entries={"route"},
        )
        moves = workspace.moves(workspace.start(), "route", {"value": "ok"})
        self.assertEqual(len(moves), 1)
        self.assertTrue(moves[0].after.regions["b"].get("done"))
        self.assertFalse(moves[0].after.target.get("done"))

    def test_symbolic_regression_crosses_graph_transform(self):
        operation = Operation(
            "finish",
            Entry("route"),
            guard=lambda _state, request: isinstance(request.get("amount"), int),
            apply=lambda state, request: state.update(count=state["count"] + request["amount"]),
            symbolic_transition=Symbolic(
                "finish-symbolic",
                "route",
                Range(Variable("input.amount", Sort.INT), 1, 10),
                {"state.count": Add(Variable("state.count", Sort.INT), Variable("input.amount", Sort.INT))},
            ),
        )
        model = Model("symbolic-graph-fixture", State({"count": 0}), (), (operation,))
        profile = Persona("fixture", "test", "target", "graph", "1")
        graph = Graph("symbolic-graph-workspace").persona(profile).zone(Zone("region", "fixture", "region"))
        graph = graph.value(Representation("raw", "mapping"))
        graph = graph.value(Representation("request", "mapping"))
        graph = graph.transform(Transform(
            "scale",
            "raw",
            "request",
            "fixture.scale",
            "1",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.NON_INVERTIBLE,
            Loss.NONE,
        ))
        graph = graph.transition(Transition("decode", "route", "raw", "request", ("scale",)))
        workspace = Workspace.flat(
            model,
            graph=graph,
            transforms={"scale": lambda value, _state: {"amount": value["amount"] * 2}},
            symbolics={
                "scale": Symbolic(
                    "scale-symbolic",
                    "route",
                    Range(Variable("input.amount", Sort.INT), 1, 10),
                    {"output.amount": Add(Variable("input.amount", Sort.INT), Variable("input.amount", Sort.INT))},
                semantics_ref="fixture.scale",
                semantics_version="1",
                ),
            },
            entries={"route"},
        )
        objective = Objective(
            "scaled-count",
            "symbolic-graph-fixture",
            "lab",
            (Same("count", 6),),
            budget=Limits(max_trace_length=1),
        )
        auth = Authorization("workspace-symbolic", frozenset({"lab"}), frozenset({"symbolic-graph-fixture"}))
        backward = Regressor().regress(model, objective, workspace=workspace)
        self.assertIn(("route", {"amount": 3}), backward.required_actions)
        report = Planner().plan(model, objective, auth, workspace=workspace)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.witness.interactions[0]["request"], {"amount": 3})

    def test_symbolic_regression_crosses_graph_only_effect_route(self):
        model = Model("graph-effect-fixture", State({"done": False}), (), ())
        left = Persona("effect-left", "test", "target", "graph", "1")
        right = Persona("effect-right", "test", "target", "graph", "1")
        graph = Graph("graph-effect-workspace").persona(left).persona(right)
        graph = graph.zone(Zone("a", "effect-left", "a")).zone(Zone("b", "effect-right", "b"))
        graph = graph.value(Representation("raw-effect", "mapping"))
        graph = graph.value(Representation("mid-effect", "mapping"))
        graph = graph.value(Representation("final-effect", "mapping"))
        graph = graph.transform(Transform(
            "parse-effect",
            "raw-effect",
            "mid-effect",
            "fixture.parse-effect",
            "1",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.BIJECTIVE,
            Loss.NONE,
        ))
        graph = graph.transform(Transform(
            "bridge-effect",
            "mid-effect",
            "final-effect",
            "fixture.bridge-effect",
            "1",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.BIJECTIVE,
            Loss.NONE,
        ))
        graph = graph.guard(Recognizer("accept-effect", "final-effect", "fixture.accept-effect", None, "b"))
        graph = graph.effect(Effect("finish-effect", "state", ("b.done",), semantics_ref="fixture.finish-effect"))
        graph = graph.transition(Transition("start-effect", "route", "raw-effect", "mid-effect", ("parse-effect",), region_id="a"))
        graph = graph.transition(Transition(
            "finish-effect",
            "internal",
            "final-effect",
            "final-effect",
            recognizer_ids=("accept-effect",),
            effect_ids=("finish-effect",),
            region_id="b",
        ))
        graph = graph.port(Port("a-out-effect", "a", "out", Direction.OUTPUT, "mid-effect", "mapping"))
        graph = graph.port(Port("b-in-effect", "b", "in", Direction.INPUT, "final-effect", "mapping"))
        graph = graph.connect(
            "a-out-effect",
            "b-in-effect",
            connection_id="a-to-b-effect",
            transform_id="bridge-effect",
        )
        same = Equal(Variable("input.value", Sort.STRING), Literal("ok", Sort.STRING))
        workspace = Workspace.flat(
            model,
            graph=graph,
            regions={"a": State({}), "b": State({"done": False})},
            transforms={"parse-effect": lambda value, _state: value, "bridge-effect": lambda value, _state: value},
            recognizers={"accept-effect": lambda value, _state: value.get("value") == "ok"},
            effects={"finish-effect": lambda state, _value: state.update(done=True)},
            symbolics={
                "parse-effect": Symbolic("parse-effect-symbolic", "route", same, {"output.value": Variable("input.value", Sort.STRING)}, semantics_ref="fixture.parse-effect", semantics_version="1"),
                "bridge-effect": Symbolic("bridge-effect-symbolic", "route", same, {"output.value": Variable("input.value", Sort.STRING)}, semantics_ref="fixture.bridge-effect", semantics_version="1"),
                "accept-effect": Symbolic("accept-effect-symbolic", "route", same, semantics_ref="fixture.accept-effect", semantics_version="1"),
                "finish-effect": Symbolic("finish-effect-symbolic", "route", same, {"state.b.done": Literal(True, Sort.BOOL)}, semantics_ref="fixture.finish-effect", semantics_version="1"),
            },
            entries={"route"},
        )
        objective = Objective(
            "graph-effect",
            "graph-effect-fixture",
            "lab",
            (Same("b.done", True),),
            budget=Limits(max_trace_length=1),
        )
        auth = Authorization("graph-effect-tests", frozenset({"lab"}), frozenset({"graph-effect-fixture"}))
        backward = Regressor().regress(model, objective, workspace=workspace)
        self.assertIn(("route", {"value": "ok"}), backward.required_actions)
        report = Planner().plan(model, objective, auth, workspace=workspace)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.witness.interactions[0]["request"], {"value": "ok"})

    def test_symbolic_regression_crosses_reactive_environment(self):
        operation = Operation(
            "go",
            Entry("go"),
            guard=lambda _state, request: request.get("token") == "run",
            symbolic_transition=Symbolic(
                "go-symbolic",
                "go",
                Equal(Variable("input.token", Sort.STRING), Literal("run", Sort.STRING)),
            ),
        )
        model = Model("environment-symbolic-fixture", State({"done": False}), (), (operation,))
        world = World(
            Context(model.initial_state, State({"quota": 0})),
            {
                "go": lambda context, _request: (
                    context.target,
                    context.environment.update(quota=1),
                    {"quota": 1},
                ),
            },
        )
        workspace = Workspace.flat(
            model,
            world=world,
            symbolics={
                "go": Symbolic(
                    "go-environment-symbolic",
                    "go",
                    Literal(True, Sort.BOOL),
                    {"state.env.quota": Literal(1, Sort.INT)},
                ),
            },
        )
        objective = Objective(
            "quota-reach",
            "environment-symbolic-fixture",
            "lab",
            (Same("env.quota", 1),),
            budget=Limits(max_trace_length=1),
        )
        auth = Authorization("environment-symbolic-tests", frozenset({"lab"}), frozenset({"environment-symbolic-fixture"}))
        backward = Regressor().regress(model, objective, workspace=workspace)
        self.assertIn(("go", {"token": "run"}), backward.required_actions)
        report = Planner().plan(model, objective, auth, workspace=workspace)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.witness.interactions[0]["request"], {"token": "run"})

    def test_bounded_probe_regresses_opaque_graph_transform(self):
        operation = Operation(
            "finish-probe",
            Entry("route-probe"),
            guard=lambda _state, request: isinstance(request.get("amount"), int),
            apply=lambda state, request: state.update(count=request["amount"]),
        )
        model = Model("probe-fixture", State({"count": 0}), (), (operation,))
        profile = Persona("probe-profile", "test", "target", "graph", "1")
        graph = Graph("probe-workspace").persona(profile).zone(Zone("probe", "probe-profile", "probe"))
        graph = graph.value(Representation("probe-raw", "mapping"))
        graph = graph.value(Representation("probe-request", "mapping"))
        graph = graph.transform(Transform(
            "opaque-scale",
            "probe-raw",
            "probe-request",
            "fixture.opaque-scale",
            "1",
            Partiality.UNKNOWN,
            Relation.UNKNOWN,
            Invertibility.UNKNOWN,
            Loss.UNKNOWN,
        ))
        graph = graph.transition(Transition("probe-decode", "route-probe", "probe-raw", "probe-request", ("opaque-scale",)))
        workspace = Workspace.flat(
            model,
            graph=graph,
            transforms={"opaque-scale": lambda value, _state: {"amount": value["amount"] * 2}},
            entries={"route-probe"},
            probes={"route-probe": ({"amount": 3},)},
        )
        objective = Objective(
            "probe-count",
            "probe-fixture",
            "lab",
            (Same("count", 6),),
            budget=Limits(max_trace_length=1),
        )
        auth = Authorization("probe-tests", frozenset({"lab"}), frozenset({"probe-fixture"}))
        backward = Regressor().regress(model, objective, workspace=workspace)
        self.assertIn(("route-probe", {"amount": 3}), backward.required_actions)
        self.assertTrue(any("bounded probes" in item for item in backward.uncertainty))
        report = Planner().plan(model, objective, auth, workspace=workspace)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.witness.interactions[0]["request"], {"amount": 3})

    def test_bounded_probe_regresses_unenumerated_relation(self):
        operation = Operation(
            "relation-probe",
            Entry("relation-probe"),
            relation=lambda state, request: (
                Outcome(Decision.ACCEPT, state.update(done=True), terminal=True)
                if request.get("token") == "go"
                else Outcome(Decision.REJECT, state, terminal=True, guard=False)
            ,),
        )
        model = Model("relation-probe-fixture", State({"done": False}), (), (operation,))
        workspace = Workspace.flat(
            model,
            probes={"relation-probe": ({"token": "stop"}, {"token": "go"})},
        )
        objective = Objective(
            "relation-probe-goal",
            "relation-probe-fixture",
            "lab",
            (Same("done", True),),
            budget=Limits(max_trace_length=1),
        )
        auth = Authorization("relation-probe-tests", frozenset({"lab"}), frozenset({"relation-probe-fixture"}))
        backward = Regressor().regress(model, objective, workspace=workspace)
        self.assertIn(("relation-probe", {"token": "go"}), backward.required_actions)
        report = Planner().plan(model, objective, auth, workspace=workspace)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)

    def test_probe_expander_discovers_opaque_candidate_on_demand(self):
        operation = Operation(
            "expand-probe",
            Entry("expand-probe"),
            guard=lambda _state, request: request.get("amount") == 3,
            apply=lambda state, _request: state.update(done=True),
        )
        model = Model("expander-fixture", State({"done": False}), (), (operation,))
        workspace = Workspace.flat(
            model,
            expanders={"expand-probe": lambda limit: ({"amount": value} for value in range(limit))},
        )
        objective = Objective(
            "expander-goal",
            "expander-fixture",
            "lab",
            (Same("done", True),),
            budget=Limits(max_trace_length=1, max_states=5),
        )
        auth = Authorization("expander-tests", frozenset({"lab"}), frozenset({"expander-fixture"}))
        backward = Regressor().regress(model, objective, workspace=workspace)
        self.assertIn(("expand-probe", {"amount": 3}), backward.required_actions)
        self.assertTrue(any("bounded probes" in item for item in backward.uncertainty))

    def test_probe_expander_failure_is_unknown(self):
        operation = Operation("broken-probe", Entry("broken-probe"), apply=lambda state, _request: state)
        model = Model("broken-expander-fixture", State({"done": False}), (), (operation,))

        def fail(_limit):
            raise RuntimeError("probe source unavailable")

        workspace = Workspace.flat(model, expanders={"broken-probe": fail})
        objective = Objective(
            "broken-expander-goal",
            "broken-expander-fixture",
            "lab",
            (Same("done", True),),
            budget=Limits(max_trace_length=1),
        )
        auth = Authorization("broken-expander-tests", frozenset({"lab"}), frozenset({"broken-expander-fixture"}))
        report = Planner().plan(model, objective, auth, workspace=workspace)
        self.assertEqual(report.status, Status.UNKNOWN)

    def test_semantic_contract_reports_forward_and_backward_bindings(self):
        operation = Operation("contract", Entry("contract"), apply=lambda state, _request: state)
        model = Model("contract-fixture", State({}), (), (operation,))
        profile = Persona("contract-profile", "test", "target", "fixture", "1")
        graph = Graph("contract-workspace").persona(profile).zone(Zone("region", "contract-profile", "region"))
        graph = graph.value(Representation("raw-contract", "mapping"))
        graph = graph.value(Representation("out-contract", "mapping"))
        graph = graph.transform(Transform(
            "contract-transform",
            "raw-contract",
            "out-contract",
            "fixture.contract",
            "1",
            Partiality.TOTAL,
            Relation.FUNCTION,
            Invertibility.BIJECTIVE,
            Loss.NONE,
        ))
        graph = graph.transition(Transition("contract-transition", "contract", "raw-contract", "out-contract", ("contract-transform",)))
        symbolic = Symbolic(
            "contract-symbolic",
            "contract",
            Literal(True, Sort.BOOL),
            semantics_ref="fixture.contract",
            semantics_version="1",
        )
        workspace = Workspace.flat(
            model,
            graph=graph,
            transforms={"contract-transform": lambda value, _state: value},
            symbolics={"contract-transform": symbolic},
        )
        record = workspace.contracts()[0]
        self.assertTrue(record.forward)
        self.assertTrue(record.backward)
        self.assertTrue(record.complete)
        self.assertEqual(Semantic.from_record(record.to_record()), record)

        graph = graph.guard(Recognizer("contract-guard", "out-contract", "fixture.guard", None, "region"))
        graph = graph.effect(Effect("contract-effect", "state", ("done",), semantics_ref="fixture.effect"))
        guarded = Workspace.flat(
            model,
            graph=graph,
            transforms={"contract-transform": lambda value, _state: value},
            recognizers={"contract-guard": lambda _value, _state: True},
            effects={"contract-effect": lambda state, _value: state.update(done=True)},
            symbolics={
                "contract-transform": symbolic,
                "contract-guard": Symbolic(
                    "guard-symbolic",
                    "contract",
                    Literal(True, Sort.BOOL),
                    semantics_ref="wrong.guard",
                    semantics_version="1",
                ),
                "contract-effect": Symbolic(
                    "effect-symbolic",
                    "contract",
                    Literal(True, Sort.BOOL),
                    semantics_ref="wrong.effect",
                    semantics_version="1",
                ),
            },
        )
        self.assertFalse(guarded.contract("contract-guard").complete)
        self.assertFalse(guarded.contract("contract-effect").complete)
        self.assertTrue(any("references do not match" in item for item in guarded.contract("contract-guard").limitations))
        self.assertTrue(any("references do not match" in item for item in guarded.contract("contract-effect").limitations))

        bounded = Workspace.flat(
            model,
            graph=graph,
            transforms={"contract-transform": lambda value, _state: value},
            probes={"contract": ({"value": 1},)},
        )
        bounded_record = bounded.contracts()[0]
        self.assertTrue(bounded_record.forward)
        self.assertFalse(bounded_record.backward)
        self.assertFalse(bounded_record.complete)
        self.assertIn("bounded by concrete probes", bounded_record.limitations[0])

    def test_discarded_value_provenance_is_not_resurrected(self):
        source = Operation(
            "source",
            Entry("source"),
            relation=lambda state, _request: (
                Outcome(Decision.ACCEPT, state, lineage=(), origins={}),
            ),
        )
        sink = Operation(
            "sink",
            Entry("sink"),
            component="controlled.sink",
        )
        model = Model("provenance-fixture", State({}), ({"proof": "RSVE-CANARY"}, {}), (source, sink))
        workspace = Workspace.flat(model)
        first = workspace.moves(workspace.start(), "source", {"proof": "RSVE-CANARY"}, operation=source)
        self.assertEqual(len(first), 1)
        second = workspace.moves(first[0].after, "sink", {}, operation=sink)
        self.assertEqual(len(second), 1)
        self.assertEqual(second[0].after.origins, {})
        objective = Flow("source", "RSVE-CANARY", "controlled.sink", require_lineage=True)
        self.assertFalse(objective.evaluate(second[0].after.view(), (first[0].event, second[0].event)))

    def test_alias_groups_sync_and_resource_ownership_is_enforced(self):
        update = Operation(
            "update-alias",
            Entry("update-alias"),
            component="a",
            apply=lambda state, _request: state.update(value=5),
            writes=frozenset({"value"}),
        )
        model = Model("alias-fixture", State({}), (), (update,))
        workspace = Workspace.flat(
            model,
            regions={"a": State({"value": 0}), "b": State({"value": 0})},
            aliases=(("a.value", "b.value"),),
        )
        moves = workspace.moves(workspace.start(), "update-alias", {}, operation=update)
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0].after.regions["a"].get("value"), 5)
        self.assertEqual(moves[0].after.regions["b"].get("value"), 5)
        self.assertEqual(moves[0].after.view().get("b.value"), 5)

        denied = Operation(
            "write-resource",
            Entry("write-resource"),
            component="b",
            apply=lambda state, _request: state.update(**{"resource.lock": True}),
            writes=frozenset({"resource.lock"}),
        )
        denied_model = Model("resource-fixture", State({}), (), (denied,))
        denied_workspace = Workspace.flat(
            denied_model,
            regions={"a": State({}), "b": State({})},
            resources={"lock": "a"},
        )
        denied_move = denied_workspace.moves(denied_workspace.start(), "write-resource", {}, operation=denied)[0]
        self.assertEqual(denied_move.outcome.decision, Decision.UNKNOWN)
        self.assertTrue(any("outside owner a" in reason for reason in denied_move.outcome.uncertainty))

    def test_symbolic_aliases_and_resource_ownership_are_regressed(self):
        update = Operation(
            "update-symbolic-alias",
            Entry("update-symbolic-alias"),
            component="a",
            guard=lambda _state, request: request.get("token") == "go",
            apply=lambda state, _request: state.update(value=5),
            writes=frozenset({"value"}),
            symbolic_transition=Symbolic(
                "update-symbolic-alias",
                "update-symbolic-alias",
                Equal(Variable("input.token", Sort.STRING), Literal("go", Sort.STRING)),
                {"state.a.value": Literal(5, Sort.INT)},
            ),
        )
        model = Model("symbolic-alias-fixture", State({}), (), (update,))
        workspace = Workspace.flat(
            model,
            regions={"a": State({"value": 0}), "b": State({"value": 0})},
            aliases=(("a.value", "b.value"),),
        )
        objective = Objective(
            "symbolic-alias-goal",
            "symbolic-alias-fixture",
            "lab",
            (Same("b.value", 5),),
            budget=Limits(max_trace_length=1),
        )
        auth = Authorization("symbolic-alias-tests", frozenset({"lab"}), frozenset({"symbolic-alias-fixture"}))
        backward = Regressor().regress(model, objective, workspace=workspace)
        self.assertIn(("update-symbolic-alias", {"token": "go"}), backward.required_actions)

        resource = Operation(
            "symbolic-resource",
            Entry("symbolic-resource"),
            component="b",
            symbolic_transition=Symbolic(
                "symbolic-resource",
                "symbolic-resource",
                Literal(True, Sort.BOOL),
                {"state.resource.lock": Literal(True, Sort.BOOL)},
            ),
        )
        resource_model = Model("symbolic-resource-fixture", State({}), (), (resource,))
        resource_workspace = Workspace.flat(
            resource_model,
            regions={"a": State({}), "b": State({})},
            resources={"lock": "a"},
        )
        resource_objective = Objective(
            "symbolic-resource-goal",
            "symbolic-resource-fixture",
            "lab",
            (Same("resource.lock", True),),
            budget=Limits(max_trace_length=1),
        )
        resource_plan = Regressor().regress(resource_model, resource_objective, workspace=resource_workspace)
        self.assertTrue(any("outside owner a" in item for item in resource_plan.uncertainty))

    def test_workspace_flow_requires_actual_value_provenance(self):
        def make_workspace(mode):
            model = Model("workspace-flow", State({}), (), ())
            profile = Persona("flow-profile", "test", "target", "fixture", "1")
            graph = Graph("workspace-flow-graph").persona(profile)
            graph = graph.zone(Zone("a", "flow-profile", "a")).zone(Zone("b", "flow-profile", "b"))
            graph = graph.value(Representation("raw-flow", "mapping"))
            graph = graph.value(Representation("mid-flow", "mapping"))
            graph = graph.value(Representation("final-flow", "mapping"))
            graph = graph.transform(Transform(
                "decode-flow",
                "raw-flow",
                "mid-flow",
                "fixture.decode-flow",
                "1",
                Partiality.TOTAL,
                Relation.FUNCTION,
                Invertibility.UNKNOWN,
                Loss.NONE,
                provenance=mode,
                provenance_paths={"payload": ("proof",)} if mode == "preserve" else {},
            ))
            graph = graph.transform(Transform(
                "bridge-flow",
                "mid-flow",
                "final-flow",
                "fixture.bridge-flow",
                "1",
                Partiality.TOTAL,
                Relation.FUNCTION,
                Invertibility.UNKNOWN,
                Loss.NONE,
                provenance="preserve",
                provenance_paths={"payload": ("payload",)},
            ))
            graph = graph.effect(Effect("sink-flow", "controlled.sink", ("done",)))
            graph = graph.transition(Transition(
                "source-flow",
                "source",
                "raw-flow",
                "mid-flow",
                ("decode-flow",),
                region_id="a",
            ))
            graph = graph.transition(Transition(
                "sink-flow",
                "internal",
                "final-flow",
                "final-flow",
                effect_ids=("sink-flow",),
                region_id="b",
            ))
            graph = graph.port(Port("flow-out", "a", "out", Direction.OUTPUT, "mid-flow", "mapping"))
            graph = graph.port(Port("flow-in", "b", "in", Direction.INPUT, "final-flow", "mapping"))
            graph = graph.connect("flow-out", "flow-in", connection_id="flow-bridge", transform_id="bridge-flow")
            symbolics = {
                "decode-flow": Symbolic(
                    "decode-flow-symbolic",
                    "source",
                    Literal(True, Sort.BOOL),
                    {"output.payload": Variable("input.proof", Sort.STRING)},
                    semantics_ref="fixture.decode-flow",
                ),
                "bridge-flow": Symbolic(
                    "bridge-flow-symbolic",
                    "source",
                    Literal(True, Sort.BOOL),
                    {"output.payload": Variable("input.payload", Sort.STRING)},
                    semantics_ref="fixture.bridge-flow",
                ),
                "sink-flow": Symbolic(
                    "sink-flow-symbolic",
                    "internal",
                    Literal(True, Sort.BOOL),
                    {"state.b.done": Literal(True, Sort.BOOL)},
                    semantics_ref="rsve.effect",
                ),
            }
            return Workspace.flat(
                model,
                graph=graph,
                regions={"a": State({}), "b": State({"done": False})},
                transforms={
                    "decode-flow": lambda value, _state: {"payload": value["proof"]},
                    "bridge-flow": lambda value, _state: dict(value),
                },
                effects={"sink-flow": lambda state, _value: state.update(done=True)},
                entries={"source"},
                symbolics=symbolics,
            )

        objective = Flow("source", "RSVE-CANARY", "controlled.sink", require_lineage=True)
        for mode, expected in (("preserve", True), ("discard", False)):
            workspace = make_workspace(mode)
            moves = workspace.moves(workspace.start(), "source", {"proof": "RSVE-CANARY"})
            self.assertEqual(len(moves), 1)
            self.assertEqual(moves[0].after.regions["b"].get("done"), True)
            self.assertEqual(objective.evaluate(moves[0].after.view(), (moves[0].event,)), expected)
            backward = Regressor().regress(
                workspace.model,
                Objective(
                    "workspace-flow-goal",
                    "workspace-flow",
                    "lab",
                    (objective,),
                    budget=Limits(max_trace_length=1),
                ),
                workspace=workspace,
            )
            if expected:
                self.assertTrue(backward.required_traces)
                self.assertEqual(backward.required_traces[0][0]["request"], {"proof": "RSVE-CANARY"})
            else:
                self.assertFalse(backward.required_traces)


if __name__ == "__main__":
    unittest.main()
