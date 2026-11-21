import unittest

from rsve.logic import Sort
from rsve.source import SourceFunction, SourceIndex
from rsve.source_profile import (
    BindingSpace,
    SourceFunctionProfile,
    SourceProfile,
    SourceSymbolBinding,
)


class Suite(unittest.TestCase):
    @staticmethod
    def function():
        return SourceFunction(
            package="example/ledger",
            symbol="Apply",
            file="ledger.go",
            start_line=1,
            end_line=8,
            parameters=({"name": "req", "type": "Request"},),
            calls=(),
            conditions=(
                {
                    "line": 3,
                    "expr": {
                        "kind": "binary",
                        "operator": ">=",
                        "left": {"kind": "selector", "base": {"kind": "variable", "name": "req"}, "field": "amount"},
                        "right": {"kind": "literal", "value": "0", "value_kind": "INT"},
                    },
                },
            ),
            assignments=(
                {
                    "line": 5,
                    "target": "balance",
                    "value": {
                        "kind": "binary",
                        "operator": "+",
                        "left": {"kind": "selector", "base": {"kind": "variable", "name": "req"}, "field": "amount"},
                        "right": {"kind": "variable", "name": "balance"},
                    },
                },
            ),
            returns=(),
        )

    def profile_function(self, function):
        return SourceFunctionProfile(
            function_identity=function.identity,
            entry_point="ledger.apply",
            symbols={
                "req.amount": SourceSymbolBinding(BindingSpace.REQUEST, "amount", Sort.BITVECTOR, 64, True),
                "balance": SourceSymbolBinding(BindingSpace.STATE, "balance", Sort.BITVECTOR, 64, True),
            },
            assignment_targets={"balance": "balance"},
            guard_lines=(3,),
            guard_senses={3: True},
            assignment_lines=(5,),
            operation_name="ledger.apply",
            component="ledger.state",
        )

    def test_compiler_bindings_keep_typed_profile_paths(self):
        profile = self.profile_function(self.function())

        bindings = profile.compiler_bindings()

        self.assertEqual(bindings["req.amount"], ("request.amount", Sort.BITVECTOR, 64, True))
        self.assertEqual(bindings["balance"], ("state.balance", Sort.BITVECTOR, 64, True))

    def test_profile_resolves_explicit_nested_request_and_state_values(self):
        profile = self.profile_function(self.function())

        values = profile.source_values({"balance": 17}, {"amount": 5})

        self.assertEqual(values, {"req.amount": 5, "balance": 17})

    def test_source_values_distinguishes_bool_from_integer(self):
        profile = SourceFunctionProfile(
            "example/ledger.Apply",
            "ledger.apply",
            {"enabled": SourceSymbolBinding(BindingSpace.REQUEST, "enabled", Sort.BOOL)},
            {},
        )

        self.assertEqual(profile.source_values({}, {"enabled": True}), {"enabled": True})
        with self.assertRaisesRegex(TypeError, "does not match bool"):
            profile.source_values({}, {"enabled": 1})
        with self.assertRaisesRegex(TypeError, "does not match int"):
            SourceFunctionProfile(
                "example/ledger.Apply",
                "ledger.apply",
                {"count": SourceSymbolBinding(BindingSpace.REQUEST, "count", Sort.INT)},
                {},
            ).source_values({}, {"count": False})

    def test_source_values_rejects_bitvector_overflow_without_wrapping(self):
        signed = SourceFunctionProfile(
            "example/ledger.Apply",
            "ledger.apply",
            {"count": SourceSymbolBinding(BindingSpace.REQUEST, "count", Sort.BITVECTOR, 8, True)},
            {},
        )
        unsigned = SourceFunctionProfile(
            "example/ledger.Apply",
            "ledger.apply",
            {"count": SourceSymbolBinding(BindingSpace.REQUEST, "count", Sort.BITVECTOR, 8, False)},
            {},
        )

        self.assertEqual(signed.source_values({}, {"count": -128}), {"count": -128})
        self.assertEqual(signed.source_values({}, {"count": 127}), {"count": 127})
        self.assertEqual(unsigned.source_values({}, {"count": 255}), {"count": 255})
        for profile, value in ((signed, -129), (signed, 128), (unsigned, -1), (unsigned, 256)):
            with self.subTest(value=value), self.assertRaisesRegex(TypeError, "bit range"):
                profile.source_values({}, {"count": value})

    def test_validate_checks_symbol_targets_and_selected_source_lines(self):
        function = self.function()
        profile = self.profile_function(function)

        profile.validate(function, require_all_assignments=True)

        with self.assertRaisesRegex(ValueError, "no bindings for symbols"):
            SourceFunctionProfile(
                function.identity,
                "ledger.apply",
                {"balance": profile.symbols["balance"]},
                {"balance": "balance"},
                guard_lines=(3,),
                guard_senses={3: True},
                assignment_lines=(5,),
            ).validate(function)
        with self.assertRaisesRegex(ValueError, "undeclared guard lines"):
            SourceFunctionProfile(
                function.identity,
                "ledger.apply",
                profile.symbols,
                profile.assignment_targets,
                guard_lines=(4,),
                guard_senses={4: True},
            ).validate(function)
        with self.assertRaisesRegex(ValueError, "undeclared assignment targets"):
            SourceFunctionProfile(
                function.identity,
                "ledger.apply",
                profile.symbols,
                {"other": "other"},
            ).validate(function)

    def test_each_selected_guard_requires_explicit_boolean_polarity(self):
        function = self.function()
        base = self.profile_function(function)

        with self.assertRaisesRegex(ValueError, "requires exactly one explicit branch sense"):
            SourceFunctionProfile(
                function.identity,
                "ledger.apply",
                base.symbols,
                base.assignment_targets,
                guard_lines=(3,),
            )
        with self.assertRaisesRegex(ValueError, "requires exactly one explicit branch sense"):
            SourceFunctionProfile(
                function.identity,
                "ledger.apply",
                base.symbols,
                base.assignment_targets,
                guard_senses={3: True},
            )
        with self.assertRaisesRegex(TypeError, "must be boolean"):
            SourceFunctionProfile(
                function.identity,
                "ledger.apply",
                base.symbols,
                base.assignment_targets,
                guard_lines=(3,),
                guard_senses={3: 1},
            )
        self.assertEqual(base.canonical()["guard_senses"], {3: True})

    def test_bitvector_binding_requires_width_and_signedness(self):
        with self.assertRaisesRegex(ValueError, "positive width and explicit signedness"):
            SourceSymbolBinding(BindingSpace.STATE, "counter", Sort.BITVECTOR)
        with self.assertRaisesRegex(ValueError, "only to bitvector"):
            SourceSymbolBinding(BindingSpace.REQUEST, "count", Sort.INT, 64, True)

    def test_profile_validates_all_functions_against_an_index(self):
        function = self.function()
        profile_function = self.profile_function(function)
        profile = SourceProfile("ledger-target", "ledger-profile", {function.identity: profile_function})

        profile.validate(SourceIndex((function,)), require_all_assignments=True)

        with self.assertRaisesRegex(ValueError, "absent from index"):
            profile.validate(SourceIndex(()))


if __name__ == "__main__":
    unittest.main()
