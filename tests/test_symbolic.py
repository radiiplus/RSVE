import unittest

from rsve import (
    Add,
    AllOf,
    ConstraintQuery,
    Equal,
    IntRange,
    Literal,
    ResultScope,
    Sort,
    SolverStatus,
    SymbolicTransition,
    Variable,
    WeakestPreconditionEngine,
    WeakestPreconditionStatus,
    Z3SolverAdapter,
)


class WeakestPreconditionTests(unittest.TestCase):
    def setUp(self):
        self.state_count = Variable("state.count", Sort.INT)
        self.amount = Variable("input.amount", Sort.INT)
        self.increment = SymbolicTransition(
            "increment",
            "increment",
            IntRange(self.amount, 1, 10),
            {"state.count": Add(self.state_count, self.amount)},
        )

    def test_exact_assignment_wp_composes_and_solves(self):
        post = Equal(self.state_count, Literal(2, Sort.INT))
        result = WeakestPreconditionEngine().derive(post, (self.increment,))
        self.assertEqual(result.status, WeakestPreconditionStatus.EXACT)
        self.assertTrue(result.exact)
        self.assertEqual(SymbolicTransition.from_record(self.increment.to_record()), self.increment)

        scope = ResultScope("fixture", "build", "wp-1", 1, 20)
        solved = Z3SolverAdapter().solve(ConstraintQuery("wp-1", result.precondition, scope))
        self.assertEqual(solved.status, SolverStatus.SAT)
        self.assertEqual(solved.model["input.amount"], 1)

    def test_sequence_regresses_in_reverse_order(self):
        second = SymbolicTransition(
            "add-one",
            "increment",
            Literal(True, Sort.BOOL),
            {"state.count": Add(self.state_count, Literal(1, Sort.INT))},
        )
        post = Equal(self.state_count, Literal(3, Sort.INT))
        result = WeakestPreconditionEngine().derive(post, (self.increment, second))
        self.assertEqual(result.status, WeakestPreconditionStatus.EXACT)
        solved = Z3SolverAdapter().solve(ConstraintQuery("wp-sequence", result.precondition))
        self.assertEqual(solved.status, SolverStatus.SAT)

    def test_nondeterministic_transition_is_unknown_not_identity(self):
        relation = SymbolicTransition(
            "opaque",
            "opaque",
            Literal(True, Sort.BOOL),
            relation="relation",
            deterministic=False,
        )
        result = WeakestPreconditionEngine().derive(
            Equal(self.state_count, Literal(1, Sort.INT)),
            (relation,),
        )
        self.assertEqual(result.status, WeakestPreconditionStatus.UNKNOWN)
        self.assertIsNone(result.precondition)
        self.assertIn("relational", result.reason or "")


if __name__ == "__main__":
    unittest.main()
