import unittest

from rsve import Explorer, Bounds
from rsve.result import Status


class Suite(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
