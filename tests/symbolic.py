import unittest

from rsve import (
    Add,
    Every,
    Query,
    Equal,
    Range,
    Literal,
    Scope,
    Sort,
    Verdict,
    Symbolic,
    Variable,
    WP,
    Truth,
    Zed,
)


class Suite(unittest.TestCase):
    def setUp(self):
        self.state_count = Variable("state.count", Sort.INT)
        self.amount = Variable("input.amount", Sort.INT)
        self.increment = Symbolic(
            "increment",
            "increment",
            Range(self.amount, 1, 10),
            {"state.count": Add(self.state_count, self.amount)},
        )

    def test_exact_assignment_wp_composes_and_solves(self):
        post = Equal(self.state_count, Literal(2, Sort.INT))
        result = WP().derive(post, (self.increment,))
        self.assertEqual(result.status, Truth.EXACT)
        self.assertTrue(result.exact)
        self.assertEqual(Symbolic.from_record(self.increment.to_record()), self.increment)

        scope = Scope("fixture", "build", "wp-1", 1, 20)
        solved = Zed().solve(Query("wp-1", result.precondition, scope))
        self.assertEqual(solved.status, Verdict.SAT)
        self.assertEqual(solved.model["input.amount"], 1)

    def test_sequence_regresses_in_reverse_order(self):
        second = Symbolic(
            "add-one",
            "increment",
            Literal(True, Sort.BOOL),
            {"state.count": Add(self.state_count, Literal(1, Sort.INT))},
        )
        post = Equal(self.state_count, Literal(3, Sort.INT))
        result = WP().derive(post, (self.increment, second))
        self.assertEqual(result.status, Truth.EXACT)
        solved = Zed().solve(Query("wp-sequence", result.precondition))
        self.assertEqual(solved.status, Verdict.SAT)

    def test_nondeterministic_transition_is_unknown_not_identity(self):
        relation = Symbolic(
            "opaque",
            "opaque",
            Literal(True, Sort.BOOL),
            relation="relation",
            deterministic=False,
        )
        result = WP().derive(
            Equal(self.state_count, Literal(1, Sort.INT)),
            (relation,),
        )
        self.assertEqual(result.status, Truth.UNKNOWN)
        self.assertIsNone(result.precondition)
        self.assertIn("relational", result.reason or "")


if __name__ == "__main__":
    unittest.main()
