import unittest
from dataclasses import replace

from rsve import (
    Archive,
    Anneal,
    Authorization,
    Beam,
    Bounds,
    Decision,
    Entry,
    EvidenceLevel,
    Event,
    Fidelity,
    Evolve,
    Explorer,
    Frontier,
    Guide,
    Limits,
    Mcts,
    Model,
    Objective,
    Operation,
    Portfolio,
    Same,
    Signature,
    State,
    Trial,
    Workspace,
)
from rsve.result import Status
from rsve.logic import Sort
from rsve.source import SourceFunction, SourceIndex
from rsve.source_profile import (
    BindingSpace,
    SourceFunctionProfile,
    SourceProfile,
    SourceSymbolBinding,
)


class Suite(unittest.TestCase):
    def test_candidate_priority_prefers_objective_progress_over_novelty(self):
        progress = Trial(
            False,
            None,
            progress=0.35,
            addressed_conditions=1,
            exposed_transitions=("write-objective",),
            route_potential=2,
        )
        novelty_only = Trial(False, None)

        self.assertGreater(progress.priority().score, novelty_only.priority(novelty=3).score)
        self.assertGreater(
            progress.priority().score,
            replace(progress, computation_cost_ms=100).priority().score,
        )

    def test_evolution_selects_progressing_candidate_over_novelty_only(self):
        seeds = tuple(
            ({"entry_point": "step", "request": {"value": value}},)
            for value in (0, 1)
        )
        archive = Archive()
        archive, _ = archive.offer(self.trial(seeds[0]).signature)
        selected = []

        def assess(candidate):
            value = candidate[-1]["request"]["value"]
            return replace(
                self.trial(candidate),
                accepted=False,
                progress=0.4 if value == 0 else 0.0,
                status=Status.SAT_CANDIDATE,
            )

        def mutate(candidate):
            selected.append(candidate[-1]["request"]["value"])
            return ()

        Evolve().search(
            seeds,
            mutate,
            assess,
            budget=Bounds(max_candidates=3, max_trace_length=1, max_time_ms=1_000),
            archive=archive,
            size=1,
        )
        self.assertEqual(selected, [0])

    def test_missing_seed_domain_is_unknown_not_bounded_unsat(self):
        empty = ()
        result = Mcts().search(
            empty,
            lambda _candidate: (),
            lambda _candidate: Trial(False, None),
        )
        self.assertEqual(result.status, Status.UNKNOWN)
        self.assertEqual(result.evidence[0].level, EvidenceLevel.HYPOTHESIZED)

    @staticmethod
    def trial(candidate):
        value = candidate[-1]["request"].get("value", 0)
        event = Event(
            operation="step",
            entry_point="step",
            request={"value": value},
            before=State({"value": max(0, value - 1)}),
            after=State({"value": value}),
            component="fixture.state",
            guard_result=True,
            decision=Decision.ACCEPT,
            writes=frozenset({"value"}),
        )
        signature = Signature.make(
            (event,),
            State({"value": value}),
            target="fixture",
            profile="profile-a",
            keys={"value"},
        )
        return Trial(
            value == 2,
            signature,
            status=Status.VALIDATED_WITNESS if value == 2 else Status.SAT_CANDIDATE,
            replayed=True,
            stable=True,
        )

    @staticmethod
    def grow(candidate):
        value = candidate[-1]["request"].get("value", 0)
        return (candidate + ({"entry_point": "step", "request": {"value": value + 1}},),)

    def test_expands_deterministically_until_validator_accepts(self) -> None:
        seeds = (({"entry_point": "start", "request": {"value": 0}},),)

        def expand(candidate):
            value = candidate[-1]["request"]["value"]
            return (
                candidate + ({"entry_point": "step", "request": {"value": value + 1}},),
            )

        result = Explorer().search(
            seeds,
            expand,
            lambda candidate: len(candidate) == 3,
            budget=Bounds(max_candidates=10, max_trace_length=3, max_time_ms=1_000),
            evidence_level=EvidenceLevel.REPLAY_VALIDATED,
        )

        self.assertEqual(result.status, Status.VALIDATED_WITNESS)
        self.assertEqual(result.candidate[-1]["request"]["value"], 2)
        self.assertEqual(result.attempts, 3)

    def test_reports_budget_exhaustion_instead_of_global_unsat(self) -> None:
        result = Explorer().search(
            (({"entry_point": "start", "request": {}},),),
            lambda candidate: (candidate + ({"entry_point": "step", "request": {}},),),
            lambda _candidate: False,
            budget=Bounds(max_candidates=1, max_trace_length=4, max_time_ms=1_000),
        )

        self.assertEqual(result.status, Status.BUDGET_EXHAUSTED)
        self.assertIn("explicit candidate/time budget", result.detail)

    def test_mcts_expands_and_uses_behavior_assessments(self) -> None:
        result = Mcts().search(
            (({"entry_point": "start", "request": {"value": 0}},),),
            self.grow,
            self.trial,
            budget=Bounds(max_candidates=10, max_trace_length=3, max_time_ms=1_000),
        )
        self.assertEqual(result.status, Status.VALIDATED_WITNESS)
        self.assertEqual(result.candidate[-1]["request"]["value"], 2)
        self.assertGreaterEqual(result.attempts, 1)

    def test_evolution_selects_novel_mutations(self) -> None:
        result = Evolve().search(
            (({"entry_point": "start", "request": {"value": 0}},),),
            self.grow,
            self.trial,
            budget=Bounds(max_candidates=10, max_trace_length=3, max_time_ms=1_000),
            size=2,
        )
        self.assertEqual(result.status, Status.VALIDATED_WITNESS)
        self.assertEqual(result.candidate[-1]["request"]["value"], 2)

    def test_novelty_strategies_report_missing_signatures(self) -> None:
        def assess(candidate):
            return Trial(False, None, "execution evidence did not produce a signature")

        result = Mcts().search(
            (({"entry_point": "start", "request": {}},),),
            lambda candidate: (),
            assess,
            budget=Bounds(max_candidates=1, max_trace_length=1, max_time_ms=1_000),
        )
        self.assertEqual(result.status, Status.BUDGET_EXHAUSTED)
        self.assertIn("no behavior signature", result.detail)

    def test_archive_is_supplied_and_updated_without_input_based_novelty(self) -> None:
        archive = Archive()
        candidate = ({"entry_point": "start", "request": {"value": 0}},)
        result = Mcts().search(
            (candidate, candidate),
            lambda _candidate: (),
            self.trial,
            archive=archive,
            budget=Bounds(max_candidates=2, max_trace_length=1, max_time_ms=1_000),
        )
        self.assertEqual(result.status, Status.UNSAT_BOUNDED)
        self.assertEqual(result.attempts, 1)
        self.assertEqual(len(result.archive.states), 1)

    def test_model_acceptance_is_not_reported_as_validated_witness(self) -> None:
        result = Beam().search(
            (({"entry_point": "start", "request": {}},),),
            lambda _candidate: (),
            lambda _candidate: Trial(True, None, status=Status.MODEL_SAT),
            budget=Bounds(max_candidates=1, max_trace_length=1, max_time_ms=1_000),
        )
        self.assertEqual(result.status, Status.MODEL_SAT)

    def test_beam_retains_a_bounded_novel_population(self) -> None:
        result = Beam().search(
            (({"entry_point": "start", "request": {"value": 0}},),),
            self.grow,
            self.trial,
            budget=Bounds(max_candidates=10, max_trace_length=3, max_time_ms=1_000),
            width=2,
        )
        self.assertEqual(result.status, Status.VALIDATED_WITNESS)
        self.assertEqual(result.candidate[-1]["request"]["value"], 2)

    def test_frontier_expands_novel_behavior(self) -> None:
        result = Frontier().search(
            (({"entry_point": "start", "request": {"value": 0}},),),
            self.grow,
            self.trial,
            budget=Bounds(max_candidates=10, max_trace_length=3, max_time_ms=1_000),
        )
        self.assertEqual(result.status, Status.VALIDATED_WITNESS)
        self.assertEqual(result.candidate[-1]["request"]["value"], 2)

    def test_anneal_is_reproducible_and_can_escape_to_objective(self) -> None:
        first = Anneal().search(
            (({"entry_point": "start", "request": {"value": 0}},),),
            self.grow,
            self.trial,
            budget=Bounds(max_candidates=10, max_trace_length=3, max_time_ms=1_000),
            seed=7,
        )
        second = Anneal().search(
            (({"entry_point": "start", "request": {"value": 0}},),),
            self.grow,
            self.trial,
            budget=Bounds(max_candidates=10, max_trace_length=3, max_time_ms=1_000),
            seed=7,
        )
        self.assertEqual(first.status, Status.VALIDATED_WITNESS)
        self.assertEqual(first.candidate, second.candidate)

    def test_expansion_budget_limits_generated_candidates(self) -> None:
        generated = []

        def expand(_candidate):
            for value in range(100):
                generated.append(value)
                yield ({"entry_point": "step", "request": {"value": value}},)

        result = Frontier().search(
            (({"entry_point": "start", "request": {}},),),
            expand,
            lambda _candidate: Trial(False, None),
            budget=Bounds(max_candidates=3, max_trace_length=1, max_time_ms=1_000),
        )
        self.assertEqual(result.status, Status.BUDGET_EXHAUSTED)
        self.assertLessEqual(result.generated, 3)

    def test_guide_connects_regression_workspace_and_novelty_search(self) -> None:
        operation = Operation(
            "finish",
            Entry("finish"),
            guard=lambda _state, request: request.get("value") == 1,
            apply=lambda state, _request: state.update(done=True),
            writes=frozenset({"done"}),
        )
        model = Model.build("guide-fixture", State({"done": False}), ({"value": 1},), (operation,))
        objective = Objective(
            "finish-objective",
            "guide-fixture",
            "guide-lab",
            (Same("done", True),),
            state_keys=frozenset({"done"}),
            budget=Limits(max_trace_length=1, max_states=16, max_time_ms=1_000),
        )
        guide = Guide(
            Workspace.flat(model),
            objective,
            Authorization("guide-test", frozenset({"guide-lab"}), frozenset({"guide-fixture"})),
        )

        result = guide.search("frontier")

        self.assertEqual(result.status, Status.MODEL_SAT)
        self.assertEqual(result.candidate[0]["request"], {"value": 1})
        self.assertEqual(len(result.archive.states), 1)
        trial = guide.assess(({"entry_point": "finish", "request": {"value": 1}},))
        self.assertEqual(trial.progress, 1.0)
        self.assertEqual(trial.addressed_conditions, 1)
        self.assertEqual(trial.exposed_transitions, ("finish",))

    def test_guide_refines_model_and_keeps_runtime_divergence(self):
        operation = Operation(
            "finish",
            Entry("finish"),
            apply=lambda state, _request: state.update(value=1),
            writes=frozenset({"value"}),
        )
        model = Model("refinement-guide", State({"value": 0}), ({"amount": 1},), (operation,))
        objective = Objective(
            "refinement-goal",
            "refinement-guide",
            "guide-lab",
            (Same("value", 1),),
            state_keys=frozenset({"value"}),
            budget=Limits(max_trace_length=1, max_states=8, max_time_ms=1_000),
        )
        observed = Event(
            "finish",
            "finish",
            {"amount": 1},
            State({"value": 0}),
            State({"value": 2}),
            fidelity=Fidelity.OBSERVED,
            guard_result=True,
            writes=frozenset({"value"}),
            evidence_refs=("runtime-finish-1",),
        )

        class Adapter:
            def prepare(self):
                pass

            def snapshot(self):
                return None

            def reset(self, _snapshot):
                pass

            def trace(self, _candidate, _authorization):
                return (observed,)

            def teardown(self):
                pass

            def identity(self):
                return {"profile_id": "refinement-adapter"}

        guide = Guide(
            Workspace.flat(model),
            objective,
            Authorization("guide-refinement", frozenset({"guide-lab"}), frozenset({"refinement-guide"})),
            adapter=Adapter(),
        )
        result = guide.search("frontier")

        self.assertEqual(result.status, Status.MODEL_DIVERGENCE)
        self.assertEqual(len(result.refinements), 1)
        self.assertNotEqual(result.refinements[0].delta.parent_revision, result.refinements[0].delta.revision)
        self.assertTrue(result.refinements[0].delta.invalidated_queries)
        self.assertEqual(guide.workspace.model.observed_transitions[0].after.get("value"), 2)
        replayed = guide.workspace.moves(
            guide.workspace.start(),
            "finish",
            {"amount": 1},
            operation=operation,
        )[0]
        self.assertEqual(replayed.after.target.get("value"), 2)
        self.assertTrue(replayed.after.uncertain)

    def test_guide_portfolio_runs_with_automatic_semantic_callbacks(self) -> None:
        operation = Operation(
            "finish",
            Entry("finish"),
            guard=lambda _state, request: request.get("value") == 1,
            apply=lambda state, _request: state.update(done=True),
            writes=frozenset({"done"}),
        )
        model = Model.build("portfolio-fixture", State({"done": False}), ({"value": 1},), (operation,))
        objective = Objective(
            "portfolio-objective",
            "portfolio-fixture",
            "guide-lab",
            (Same("done", True),),
            state_keys=frozenset({"done"}),
            budget=Limits(max_trace_length=1, max_states=20, max_time_ms=2_000),
        )
        guide = Guide(
            Workspace.flat(model),
            objective,
            Authorization("guide-test", frozenset({"guide-lab"}), frozenset({"portfolio-fixture"})),
        )

        result = guide.search("portfolio")

        self.assertEqual(result.status, Status.MODEL_SAT)
        self.assertEqual(result.candidate[0]["request"], {"value": 1})
        self.assertIn("mcts", result.detail)

    def test_guide_discovers_profile_bound_source_operation(self) -> None:
        function = SourceFunction(
            package="fixture/ledger",
            symbol="commit",
            file="ledger.go",
            start_line=1,
            end_line=4,
            parameters=({"name": "req", "type": "Request"},),
            calls=(),
            conditions=({
                "line": 2,
                "expr": {
                    "kind": "binary",
                    "operator": "==",
                    "left": {
                        "kind": "selector",
                        "base": {"kind": "variable", "name": "req"},
                        "field": "amount",
                    },
                    "right": {"kind": "literal", "value": "7", "value_kind": "INT"},
                },
            },),
            assignments=({
                "line": 3,
                "target": "done",
                "value": {"kind": "literal", "value": "true", "value_kind": "BOOL"},
                "path": [],
            },),
            returns=(),
        )
        source_index = SourceIndex((function,))
        source_profile = SourceProfile(
            "source-guide-fixture",
            "profile-source-guide",
            {
                function.identity: SourceFunctionProfile(
                    function.identity,
                    "commit",
                    {
                    "req.amount": SourceSymbolBinding(BindingSpace.REQUEST, "amount", Sort.BITVECTOR, 8, True),
                    "done": SourceSymbolBinding(BindingSpace.STATE, "done", Sort.BOOL),
                    },
                    {"done": "done"},
                    guard_lines=(2,),
                    guard_senses={2: True},
                    assignment_lines=(3,),
                    operation_name="ledger.commit",
                    component="ledger.state",
                ),
            },
        )
        model = Model.build("source-guide-fixture", State({"done": False}), (), ())
        objective = Objective(
            "source-guide-objective",
            "source-guide-fixture",
            "guide-lab",
            (Same("done", True),),
            state_keys=frozenset({"done"}),
            budget=Limits(max_trace_length=1, max_states=16, max_time_ms=1_000),
        )
        guide = Guide(
            Workspace.flat(model),
            objective,
            Authorization("guide-test", frozenset({"guide-lab"}), frozenset({"source-guide-fixture"})),
            source_index=source_index,
            source_profile=source_profile,
        )

        result = guide.search("frontier")

        self.assertEqual(result.status, Status.MODEL_SAT)
        self.assertEqual(result.candidate[0]["entry_point"], "commit")
        self.assertEqual(result.candidate[0]["request"], {"amount": 7})
        self.assertEqual(guide.workspace.model.target_id, "source-guide-fixture")
        self.assertEqual(guide._signature((), guide.workspace.start()).profile, "profile-source-guide")

    def test_portfolio_shares_archive_and_candidate_budget(self) -> None:
        calls = 0

        def assess(candidate):
            nonlocal calls
            calls += 1
            signature = replace(self.trial(candidate).signature, profile=f"profile-{calls}")
            return Trial(False, signature)

        result = Portfolio().search(
            (({"entry_point": "start", "request": {"value": 0}},),),
            lambda _candidate: (),
            assess,
            budget=Bounds(max_candidates=10, max_trace_length=2, max_time_ms=2_000),
        )

        self.assertEqual(result.status, Status.UNSAT_BOUNDED)
        self.assertEqual(result.attempts, 5)
        self.assertEqual(len(result.archive.transitions), 5)

        limited = Portfolio(strategies=("frontier", "beam")).search(
            (({"entry_point": "start", "request": {"value": 0}},),),
            lambda _candidate: (),
            assess,
            budget=Bounds(max_candidates=1, max_trace_length=2, max_time_ms=2_000),
        )
        self.assertEqual(limited.status, Status.BUDGET_EXHAUSTED)

    def test_guide_composes_state_conditioned_candidates(self) -> None:
        prepare = Operation(
            "prepare",
            Entry("prepare"),
            guard=lambda _state, request: request.get("credential") == "derived",
            apply=lambda state, _request: state.update(ticket="issued"),
            writes=frozenset({"ticket"}),
            request_candidates=lambda state, _objective: (
                ({"credential": "derived"},) if state.get("ticket") is None else ()
            ),
        )
        finish = Operation(
            "finish",
            Entry("finish"),
            guard=lambda state, request: request.get("ticket") == state.get("ticket") == "issued",
            apply=lambda state, _request: state.update(done=True),
            writes=frozenset({"done"}),
            request_candidates=lambda state, _objective: (
                ({"ticket": state.get("ticket")},) if state.get("ticket") == "issued" else ()
            ),
        )
        model = Model.build("composed-fixture", State({"done": False}), (), (prepare, finish))
        objective = Objective(
            "composed-objective",
            "composed-fixture",
            "guide-lab",
            (Same("done", True),),
            state_keys=frozenset({"done", "ticket"}),
            budget=Limits(max_trace_length=2, max_states=32, max_time_ms=1_000),
        )
        guide = Guide(
            Workspace.flat(model),
            objective,
            Authorization("guide-test", frozenset({"guide-lab"}), frozenset({"composed-fixture"})),
        )
        prepared = ({"entry_point": "prepare", "request": {"credential": "derived"}},)

        generated = guide.expand(prepared)
        self.assertTrue(any(
            item[-1]["entry_point"] == "finish"
            and item[-1]["request"] == {"ticket": "issued"}
            for item in generated
        ))

        result = guide.search("frontier")

        self.assertEqual(result.status, Status.MODEL_SAT)
        self.assertEqual(
            tuple(item["entry_point"] for item in result.candidate),
            ("prepare", "finish"),
        )
        self.assertEqual(result.candidate[1]["request"], {"ticket": "issued"})


if __name__ == "__main__":
    unittest.main()
