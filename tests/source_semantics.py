import unittest

from rsve.logic import Equal, Literal, Sort, Variable
from rsve.model import Decision, State
from rsve.source import SourceFunction, SourceIndex
from rsve.source_profile import (
    BindingSpace,
    SourceFunctionProfile,
    SourceProfile,
    SourceSymbolBinding,
)
from rsve.source_semantics import SourceSemanticLowerer
from rsve.wp import Truth, WP


def _variable(name):
    return {"kind": "variable", "name": name}


class Suite(unittest.TestCase):
    def _function(self, *, calls=()):
        return SourceFunction(
            package="example/profiled",
            symbol="setEnabled",
            file="profiled.go",
            start_line=1,
            end_line=5,
            parameters=(),
            calls=tuple(calls),
            conditions=({"line": 2, "expr": _variable("allowed")},),
            assignments=({
                "line": 3,
                "target": "enabled",
                "value": _variable("nextValue"),
                "path": [],
            },),
            returns=(),
        )

    def _profile(self, function, *, symbols=None, guard_senses=None):
        selected = symbols or {
            "allowed": SourceSymbolBinding(BindingSpace.REQUEST, "allowed", Sort.BOOL),
            "nextValue": SourceSymbolBinding(BindingSpace.REQUEST, "next", Sort.BOOL),
            "enabled": SourceSymbolBinding(BindingSpace.STATE, "enabled", Sort.BOOL),
        }
        return SourceProfile(
            "fixture",
            "profile-1",
            {
                function.identity: SourceFunctionProfile(
                    function.identity,
                    "set-enabled",
                    selected,
                    {"enabled": "enabled"},
                    guard_lines=(2,),
                    guard_senses=guard_senses or {2: True},
                    assignment_lines=(3,),
                )
            },
        )

    def test_exact_profile_binding_lowers_concrete_and_symbolic_operation(self):
        function = self._function()
        index = SourceIndex((function,))
        result = SourceSemanticLowerer().lower(index, self._profile(function), function.identity)

        self.assertTrue(result.complete)
        self.assertIsNotNone(result.operation)
        operation = result.operation
        self.assertEqual(operation.execute(State({"enabled": False}), {"allowed": True, "next": True}).decision, Decision.ACCEPT)
        self.assertTrue(operation.execute(State({"enabled": False}), {"allowed": True, "next": True}).after["enabled"])
        self.assertEqual(operation.execute(State({"enabled": False}), {"allowed": False, "next": True}).decision, Decision.REJECT)
        self.assertEqual(operation.execute(State({"enabled": False}), {"allowed": False}).decision, Decision.REJECT)
        self.assertIsNotNone(operation.symbolic_transition)
        preimage = WP().derive(
            Equal(Variable("state.enabled", Sort.BOOL), Literal(True, Sort.BOOL)),
            (operation.symbolic_transition,),
        )
        self.assertIs(preimage.status, Truth.EXACT)
        self.assertIn("request.allowed", repr(preimage.precondition))

    def test_missing_profile_symbol_does_not_create_permissive_operation(self):
        function = self._function()
        index = SourceIndex((function,))
        profile = self._profile(function, symbols={
            "allowed": SourceSymbolBinding(BindingSpace.REQUEST, "allowed", Sort.BOOL),
        })

        result = SourceSemanticLowerer().lower(index, profile, function.identity)

        self.assertFalse(result.supported)
        self.assertIsNone(result.operation)
        self.assertTrue(any("no bindings" in item for item in result.limitations))

    def test_reversed_guard_polarity_is_used_in_concrete_and_symbolic_routes(self):
        function = self._function()
        index = SourceIndex((function,))
        profile = self._profile(function, guard_senses={2: False})
        operation = SourceSemanticLowerer().lower(index, profile, function.identity).operation
        self.assertIsNotNone(operation)

        rejected = operation.execute(State({"enabled": False}), {"allowed": True, "next": True})
        accepted = operation.execute(State({"enabled": False}), {"allowed": False, "next": True})

        self.assertEqual(rejected.decision, Decision.REJECT)
        self.assertEqual(accepted.decision, Decision.ACCEPT)
        preimage = WP().derive(
            Equal(Variable("state.enabled", Sort.BOOL), Literal(True, Sort.BOOL)),
            (operation.symbolic_transition,),
        )
        self.assertIs(preimage.status, Truth.EXACT)
        self.assertIn("Negate", repr(preimage.precondition))

    def test_dependency_call_is_reported_instead_of_dropped(self):
        function = self._function(calls=("validateDependency",))
        index = SourceIndex((function,))

        result = SourceSemanticLowerer().lower(index, self._profile(function), function.identity)

        self.assertFalse(result.supported)
        self.assertIsNone(result.operation)
        self.assertTrue(any("dependency semantics" in item for item in result.limitations))

    def test_inexact_integer_expressions_execute_as_unknown_composed_outcomes(self):
        function = SourceFunction(
            package="example/inexact",
            symbol="incrementIfPositive",
            file="inexact.go",
            start_line=1,
            end_line=5,
            parameters=(),
            calls=(),
            conditions=({
                "line": 2,
                "expr": {
                    "kind": "binary",
                    "operator": ">",
                    "left": _variable("value"),
                    "right": {"kind": "literal", "value": "0", "value_kind": "INT"},
                },
            },),
            assignments=(
                {
                    "line": 3,
                    "target": "subtotal",
                    "value": {
                        "kind": "binary",
                        "operator": "+",
                        "left": _variable("value"),
                        "right": {"kind": "literal", "value": "1", "value_kind": "INT"},
                    },
                    "path": [],
                },
                {
                    "line": 4,
                    "target": "total",
                    "value": {
                        "kind": "binary",
                        "operator": "*",
                        "left": _variable("subtotal"),
                        "right": {"kind": "literal", "value": "2", "value_kind": "INT"},
                    },
                    "path": [],
                },
            ),
            returns=(),
        )
        profile = SourceProfile(
            "fixture",
            "inexact-profile",
            {
                function.identity: SourceFunctionProfile(
                    function.identity,
                    "increment",
                    {
                        "value": SourceSymbolBinding(BindingSpace.REQUEST, "value", Sort.INT),
                        "subtotal": SourceSymbolBinding(BindingSpace.STATE, "subtotal", Sort.INT),
                        "total": SourceSymbolBinding(BindingSpace.STATE, "total", Sort.INT),
                    },
                    {"subtotal": "subtotal", "total": "total"},
                    guard_lines=(2,),
                    guard_senses={2: True},
                    assignment_lines=(3, 4),
                )
            },
        )

        result = SourceSemanticLowerer().lower(SourceIndex((function,)), profile, function.identity)

        self.assertTrue(result.supported)
        self.assertFalse(result.complete)
        self.assertIsNone(result.operation.symbolic_transition)
        self.assertTrue(any("inexact symbolic semantics" in item for item in result.limitations))
        outcomes = result.operation.branches(State({"total": 0}), {"value": 2})
        self.assertEqual(len(outcomes), 2)
        self.assertTrue(all(item.decision is Decision.UNKNOWN for item in outcomes))
        self.assertTrue(any(
            item.after.get("subtotal") == 3
            and item.after.get("total") == 6
            and {"subtotal", "total"} <= item.unknown
            for item in outcomes
        ))


if __name__ == "__main__":
    unittest.main()
