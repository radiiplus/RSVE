import unittest

from rsve.callgraph import CallBinding, CallGraphBuilder, ContractComposer, FunctionContract
from rsve.logic import Arithmetic, Constraint, Literal, Rel, Sort, Variable


def _facts(calls):
    return (
        {"package": "app", "symbol": "run", "file": "run.go", "start_line": 1,
         "calls": list(calls), "assignments": []},
        {"package": "app", "symbol": "check", "file": "run.go", "start_line": 20,
         "calls": [], "assignments": []},
        {"package": "app", "symbol": "write", "file": "run.go", "start_line": 30,
         "calls": [], "assignments": []},
    )


def _callsite(graph, target, caller="app.run"):
    edge = next(edge for edge in graph.from_function(caller) if edge.target == target)
    return next(item for item in edge.evidence if item.startswith("call:"))


class Suite(unittest.TestCase):
    def test_direct_call_substitutes_preconditions_and_composes_state(self):
        graph = CallGraphBuilder().build(_facts(("check",)))
        self.addCleanup(graph.close)
        caller_state = Variable("state.balance", Sort.INT)
        callee_state = Variable("state.balance", Sort.INT)
        caller_arg = Variable("arg.x", Sort.INT)
        callee_arg = Variable("arg.value", Sort.INT)
        contracts = (
            FunctionContract(
                "app.run", parameters=("x",),
                preconditions=(Rel(caller_arg, ">=", Literal(0, Sort.INT)),),
                state_updates={"balance": Arithmetic("+", caller_state, Literal(1, Sort.INT))},
                effects=("caller.local",), complete=True, evidence=("run contract",),
            ),
            FunctionContract(
                "app.check", parameters=("value",),
                preconditions=(
                    Rel(callee_arg, ">", Literal(0, Sort.INT)),
                    Rel(callee_state, ">=", Literal(10, Sort.INT)),
                ),
                state_updates={"balance": Arithmetic("-", callee_state, Literal(5, Sort.INT))},
                effects=("callee.debit",), complete=True, evidence=("check contract",),
            ),
        )
        bindings = (CallBinding(
            "app.run", "app.check", _callsite(graph, "app.check"),
            arguments={"value": caller_arg}, order=0, complete=True, evidence=("call arguments bound",),
        ),)

        result = ContractComposer().compose(graph, "app.run", contracts, bindings)

        self.assertTrue(result.complete, result.limitations)
        self.assertEqual(result.functions, ("app.run", "app.check"))
        self.assertEqual(result.effects, ("callee.debit", "caller.local"))
        self.assertEqual(len(result.preconditions), 3)
        balance = result.state_updates["balance"]
        self.assertIsInstance(balance, Arithmetic)
        self.assertEqual(balance.operator, "+")
        self.assertIsInstance(balance.left, Arithmetic)
        self.assertEqual(balance.left.operator, "-")

    def test_ambiguous_dispatch_is_preserved_and_not_composed(self):
        facts = (
            {"package": "app", "symbol": "run", "calls": ["check"], "assignments": []},
            {"package": "one", "symbol": "check", "calls": [], "assignments": []},
            {"package": "two", "symbol": "check", "calls": [], "assignments": []},
        )
        graph = CallGraphBuilder().build(facts)
        self.addCleanup(graph.close)
        contracts = (
            FunctionContract("app.run", complete=True),
            FunctionContract("one.check", effects=("wrong.one",), complete=True),
            FunctionContract("two.check", effects=("wrong.two",), complete=True),
        )

        result = ContractComposer().compose(graph, "app.run", contracts, ())

        self.assertFalse(result.complete)
        self.assertEqual(result.effects, ())
        self.assertEqual(len(result.unresolved), 2)
        self.assertTrue(all(item.status == "candidate" for item in result.unresolved))
        self.assertIn("candidate", result.limitations[0])

    def test_transitive_contracts_compose_in_call_order(self):
        facts = (
            {"package": "app", "symbol": "run", "calls": ["check"], "assignments": []},
            {"package": "app", "symbol": "check", "calls": ["write"], "assignments": []},
            {"package": "app", "symbol": "write", "calls": [], "assignments": []},
        )
        graph = CallGraphBuilder().build(facts)
        self.addCleanup(graph.close)
        state = Variable("state.balance", Sort.INT)
        contracts = (
            FunctionContract("app.run", complete=True),
            FunctionContract("app.check", state_updates={
                "balance": Arithmetic("+", state, Literal(2, Sort.INT)),
            }, effects=("check",), complete=True),
            FunctionContract("app.write", state_updates={
                "balance": Arithmetic("*", state, Literal(2, Sort.INT)),
            }, effects=("write",), complete=True),
        )
        bindings = (
            CallBinding("app.run", "app.check", _callsite(graph, "app.check"), {}, order=0, complete=True),
            CallBinding("app.check", "app.write", _callsite(graph, "app.write", "app.check"), {}, order=0, complete=True),
        )

        result = ContractComposer().compose(graph, "app.run", contracts, bindings)

        self.assertTrue(result.complete, result.limitations)
        self.assertEqual(result.functions, ("app.run", "app.check", "app.write"))
        self.assertEqual(result.effects, ("write", "check"))
        update = result.state_updates["balance"]
        self.assertEqual(update.operator, "+")
        self.assertEqual(update.left.operator, "*")

    def test_missing_actual_argument_is_namespaced_and_incomplete(self):
        graph = CallGraphBuilder().build(_facts(("check",)))
        self.addCleanup(graph.close)
        contracts = (
            FunctionContract("app.run", complete=True),
            FunctionContract("app.check", parameters=("value",),
                             preconditions=(Rel(Variable("arg.value", Sort.INT), ">", Literal(0, Sort.INT)),),
                             complete=True),
        )
        binding = CallBinding("app.run", "app.check", _callsite(graph, "app.check"), {}, complete=True)

        result = ContractComposer().compose(graph, "app.run", contracts, (binding,))

        self.assertFalse(result.complete)
        self.assertTrue(any("argument binding missing" in item for item in result.limitations))
        self.assertEqual(result.preconditions[0].left.name, f"frame::{binding.callsite}::arg.value")

    def test_recursive_calls_require_fixed_point_summary(self):
        facts = (
            {"package": "app", "symbol": "run", "calls": ["run"], "assignments": []},
        )
        graph = CallGraphBuilder().build(facts)
        self.addCleanup(graph.close)
        contract = FunctionContract("app.run", complete=True)
        binding = CallBinding("app.run", "app.run", _callsite(graph, "app.run"), {}, complete=True)

        result = ContractComposer().compose(graph, "app.run", (contract,), (binding,))

        self.assertFalse(result.complete)
        self.assertTrue(any("fixed-point" in item for item in result.limitations))
        self.assertEqual(result.unresolved[0].kind, "recursive-call")


if __name__ == "__main__":
    unittest.main()
