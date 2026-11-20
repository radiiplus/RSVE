import unittest

from rsve import Archive, Anneal, Beam, Bounds, Decision, Event, Evolve, Explorer, Frontier, Mcts, Signature, State, Trial
from rsve.result import Status


class Suite(unittest.TestCase):
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
        return Trial(value == 2, signature)

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


if __name__ == "__main__":
    unittest.main()
