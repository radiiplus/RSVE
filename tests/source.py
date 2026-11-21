import unittest
import json
import tempfile
from pathlib import Path

import z3

from rsve.logic import Equal, Literal, Sort, Variable
from rsve.solver import Map
from rsve.source import CompiledAssignment, CompiledFormula, FormulaCompiler, SourceFunction, SourceIndex, _compile_path_guards


class Suite(unittest.TestCase):
    def test_typed_receiver_resolves_only_matching_method(self):
        caller = SourceFunction(
            package="example/caller", symbol="call", file="caller.go", start_line=1, end_line=4,
            parameters=({"name": "pool", "type": "*LegacyPool"},), calls=("pool.validateAuth",),
            conditions=(), assignments=(), returns=(),
            imports={"pool": "example/pool"},
            call_receiver_types={"pool.validateAuth": "*pool.LegacyPool"},
        )
        matching = SourceFunction(
            package="example/pool", symbol="method.*LegacyPool.validateAuth", file="pool.go",
            start_line=1, end_line=2, parameters=(), calls=(), conditions=(), assignments=(), returns=(),
            receiver={"name": "pool", "type": "*LegacyPool"},
        )
        unrelated = SourceFunction(
            package="example/pool", symbol="method.*OtherPool.validateAuth", file="other.go",
            start_line=1, end_line=2, parameters=(), calls=(), conditions=(), assignments=(), returns=(),
            receiver={"name": "pool", "type": "*OtherPool"},
        )
        index = SourceIndex((caller, matching, unrelated))

        self.assertEqual(tuple(item.identity for item in index.callees(caller.identity)), (matching.identity,))

    def test_sqlite_index_uses_typed_receiver_for_dependency_calls(self):
        facts = (
            {
                "kind": "function", "package": "example/caller", "symbol": "call", "file": "caller.go",
                "start_line": 1, "end_line": 4, "parameters": [], "imports": {"pool": "example/pool"},
                "calls": ["pool.validateAuth"], "call_receiver_types": {"pool.validateAuth": "*pool.LegacyPool"},
                "conditions": [], "assignments": [], "returns": [],
                "return_sites": [{"line": 3, "expressions": [{"kind": "literal", "value": "7", "value_kind": "INT"}], "path": []}],
            },
            {
                "kind": "function", "package": "example/pool", "symbol": "method.*LegacyPool.validateAuth",
                "file": "pool.go", "start_line": 1, "end_line": 2, "receiver": {"name": "pool", "type": "*LegacyPool"},
                "parameters": [], "imports": {}, "calls": [], "conditions": [], "assignments": [], "returns": [],
            },
            {
                "kind": "function", "package": "example/pool", "symbol": "method.*OtherPool.validateAuth",
                "file": "pool.go", "start_line": 3, "end_line": 4, "receiver": {"name": "pool", "type": "*OtherPool"},
                "parameters": [], "imports": {}, "calls": [], "conditions": [], "assignments": [], "returns": [],
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "facts.ndjson"
            source.write_text("".join(json.dumps(item) + "\n" for item in facts), encoding="utf-8")
            index = SourceIndex.load_sqlite(source, root / "index.sqlite", max_records=10, max_bytes=1 << 20)
            try:
                caller = index.function("example/caller.call")
                self.assertIsNotNone(caller)
                self.assertEqual(
                    tuple(item.identity for item in index.callees(caller.identity)),
                    ("example/pool.method.*LegacyPool.validateAuth",),
                )
                exits = index.compile_returns(caller.identity, {})
                self.assertEqual(exits[0].values[0].evaluate({}), 7)
            finally:
                index.close()

    def test_sqlite_type_stream_keeps_source_fields_and_nested_path_evidence(self):
        functions = [{
            "kind": "function", "package": "example/empty", "symbol": "run", "file": "run.go",
            "start_line": 1, "end_line": 1, "parameters": [], "imports": {}, "calls": [],
            "conditions": [], "assignments": [], "returns": [],
        }]
        types = [
            {
                "kind": "type", "package": "example/data", "name": "Owner", "file": "owner.go",
                "line": 5, "type_kind": "struct", "type_expr": "struct{ Name string }", "alias": False,
                "imports": {}, "fields": [{"name": "Name", "type": "string", "tag": "json:\"name\"", "kind": "named", "line": 6}],
            },
            {
                "kind": "type", "package": "example/model", "name": "Block", "file": "block.go",
                "line": 3, "type_kind": "struct", "type_expr": "struct{ Owner *data.Owner }", "alias": False,
                "imports": {"data": "example/data"},
                "fields": [{"name": "Owner", "type": "*data.Owner", "kind": "pointer", "line": 4}],
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "facts.ndjson"
            type_source = root / "types.ndjson"
            source.write_text("".join(json.dumps(item) + "\n" for item in functions), encoding="utf-8")
            type_source.write_text("".join(json.dumps(item) + "\n" for item in types), encoding="utf-8")
            index = SourceIndex.load_sqlite(
                source, root / "index.sqlite", max_records=10, max_bytes=1 << 20,
                types_path=type_source, max_type_records=10, max_type_bytes=1 << 20,
            )
            try:
                result = index.field_path("example/model.Block", ("Owner", "Name"))
                self.assertEqual(result.status, "declared")
                self.assertEqual(tuple(item.name for item in result.fields), ("Owner", "Name"))
                self.assertIn("runtime offsets", result.offsets_status)
                owner_type = index.source_type("example/data.Owner")
                self.assertEqual(owner_type.fields[0].tag, 'json:"name"')
                self.assertEqual(index.summary()["types"], 2)
            finally:
                index.close()

    def test_type_stream_limit_is_independent_from_function_fact_limit(self):
        function = {
            "kind": "function", "package": "example/pkg", "symbol": "run", "file": "run.go",
            "start_line": 1, "end_line": 1, "parameters": [], "imports": {}, "calls": [],
            "conditions": [], "assignments": [], "returns": [],
        }
        type_facts = [
            {"kind": "type", "package": "example/pkg", "name": f"T{index}", "file": "types.go",
             "line": index + 1, "type_kind": "named", "type_expr": "int", "alias": False, "imports": {}}
            for index in range(2)
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "facts.ndjson"
            types = root / "types.ndjson"
            source.write_text(json.dumps(function) + "\n", encoding="utf-8")
            types.write_text("".join(json.dumps(item) + "\n" for item in type_facts), encoding="utf-8")
            index = SourceIndex.load_sqlite(
                source, root / "index.sqlite", max_records=10, max_bytes=1 << 20,
                types_path=types, max_type_records=1, max_type_bytes=1 << 20,
            )
            try:
                self.assertIsNotNone(index.function("example/pkg.run"))
                self.assertEqual(index.type_count, 1)
                self.assertTrue(index.type_truncated)
            finally:
                index.close()

    def test_go_signed_arithmetic_has_matching_concrete_and_symbolic_semantics(self):
        bindings = {"value": ("input.value", Sort.BITVECTOR, 8, True)}
        variable = {"kind": "variable", "name": "value"}
        three = {"kind": "literal", "value": "3", "value_kind": "INT"}
        expression = {
            "kind": "binary",
            "operator": "%",
            "left": variable,
            "right": three,
        }
        compiled = FormulaCompiler().compile(expression, bindings)

        self.assertTrue(compiled.supported, compiled.limitations)
        self.assertEqual(compiled.evaluate({"value": -7}), -1)
        self.assertTrue(compiled.semantic.forward)
        self.assertTrue(compiled.semantic.backward)
        self.assertTrue(compiled.semantic.complete)

        term = Equal(compiled.formula, Literal(-1, Sort.BITVECTOR))
        translator = Map()
        predicate = translator.expr(term)
        solver = z3.Solver()
        solver.add(
            translator.variable(Variable("input.value", Sort.BITVECTOR, 8, True))
            == z3.BitVecVal(-7, 8),
            predicate,
        )
        self.assertEqual(solver.check(), z3.sat)

    def test_go_bitwise_and_signed_shift_match_concrete_results(self):
        bindings = {"value": ("input.value", Sort.BITVECTOR, 8, True)}
        value = {"kind": "variable", "name": "value"}
        one = {"kind": "literal", "value": "1", "value_kind": "INT"}
        for operator, input_value, expected in (("&^", 15, 14), (">>", -8, -4)):
            with self.subTest(operator=operator):
                expression = {
                    "kind": "binary",
                    "operator": operator,
                    "left": value,
                    "right": one,
                }
                compiled = FormulaCompiler().compile(expression, bindings)
                self.assertTrue(compiled.supported, compiled.limitations)
                self.assertEqual(compiled.evaluate({"value": input_value}), expected)
                term = Equal(compiled.formula, Literal(expected, Sort.BITVECTOR))
                translator = Map()
                solver = z3.Solver()
                solver.add(
                    translator.variable(Variable("input.value", Sort.BITVECTOR, 8, True))
                    == z3.BitVecVal(input_value, 8),
                    translator.expr(term),
                )
                self.assertEqual(solver.check(), z3.sat)

    def test_control_path_guards_preserve_then_and_else_polarity(self):
        condition = {
            "kind": "binary",
            "operator": ">",
            "left": {"kind": "variable", "name": "value"},
            "right": {"kind": "literal", "value": "0", "value_kind": "INT"},
        }
        conditions = ({"kind": "if", "branch_id": "if@12", "expr": condition},)
        bindings = {"value": ("input.value", Sort.BITVECTOR, 8, True)}
        then_guards, then_limitations = _compile_path_guards(("if@12:then",), conditions, bindings)
        else_guards, else_limitations = _compile_path_guards(("if@12:else",), conditions, bindings)

        self.assertFalse(then_limitations)
        self.assertFalse(else_limitations)
        self.assertTrue(then_guards[0].evaluate({"value": 1}))
        self.assertFalse(then_guards[0].evaluate({"value": -1}))
        self.assertFalse(else_guards[0].evaluate({"value": 1}))
        self.assertTrue(else_guards[0].evaluate({"value": -1}))
        assignment = CompiledAssignment(
            "state.result",
            CompiledFormula(Literal(1, Sort.INT), True),
            20,
            ("if@12:else",),
            else_guards,
        )
        self.assertTrue(assignment.path_complete)
        self.assertIsNotNone(assignment.path_guard)

    def test_scalar_switch_cases_and_default_compile_to_guards(self):
        condition = {
            "kind": "switch", "branch_id": "switch@9",
            "expr": {"kind": "variable", "name": "tag"},
            "case_values": [
                [{"kind": "literal", "value": "1", "value_kind": "INT"}],
                [{"kind": "literal", "value": "2", "value_kind": "INT"}],
                [],
            ],
            "case_default": [False, False, True],
        }
        bindings = {"tag": ("input.tag", Sort.BITVECTOR, 8, False)}
        case_guard, case_limits = _compile_path_guards(("switch@9:case:0",), (condition,), bindings)
        default_guard, default_limits = _compile_path_guards(("switch@9:case:2",), (condition,), bindings)

        self.assertFalse(case_limits)
        self.assertFalse(default_limits)
        self.assertTrue(case_guard[0].evaluate({"tag": 1}))
        self.assertFalse(case_guard[0].evaluate({"tag": 2}))
        self.assertTrue(default_guard[0].evaluate({"tag": 3}))
        self.assertFalse(default_guard[0].evaluate({"tag": 1}))
        translator = Map()
        symbolic_case = translator.expr(case_guard[0].formula)
        symbolic_tag = translator.variable(Variable("input.tag", Sort.BITVECTOR, 8, False))
        solver = z3.Solver()
        solver.add(symbolic_case, symbolic_tag == z3.BitVecVal(1, 8))
        self.assertEqual(solver.check(), z3.sat)
        solver = z3.Solver()
        solver.add(symbolic_case, symbolic_tag == z3.BitVecVal(2, 8))
        self.assertEqual(solver.check(), z3.unsat)

    def test_return_sites_compile_values_and_early_exit_guards(self):
        condition = {
            "kind": "if", "branch_id": "if@5",
            "expr": {
                "kind": "binary", "operator": ">",
                "left": {"kind": "variable", "name": "value"},
                "right": {"kind": "literal", "value": "0", "value_kind": "INT"},
            },
        }
        function = SourceFunction(
            package="example", symbol="run", file="run.go", start_line=1, end_line=10,
            parameters=({"name": "value", "type": "int8"},), calls=(), conditions=(condition,),
            assignments=(), returns=("return 1", "return value"),
            return_sites=(
                {"line": 6, "expressions": [{"kind": "literal", "value": "1", "value_kind": "INT"}], "path": ["if@5:then"]},
                {"line": 9, "expressions": [{"kind": "variable", "name": "value"}], "path": ["if@5:else"]},
            ),
        )
        index = SourceIndex((function,))
        exits = index.compile_returns(
            function.identity, {"value": ("input.value", Sort.BITVECTOR, 8, True)}
        )

        self.assertEqual(len(exits), 2)
        self.assertTrue(all(item.path_complete for item in exits))
        self.assertEqual(exits[0].values[0].evaluate({}), 1)
        self.assertTrue(exits[0].path_guards[0].evaluate({"value": 1}))
        self.assertFalse(exits[0].path_guards[0].evaluate({"value": -1}))
        self.assertEqual(exits[1].values[0].evaluate({"value": -3}), -3)
        self.assertTrue(exits[1].path_guards[0].evaluate({"value": -3}))
        self.assertFalse(exits[1].path_guards[0].evaluate({"value": 3}))

    def test_return_relation_composes_dominating_nested_assignments(self):
        function = SourceFunction(
            package="example", symbol="compose", file="compose.go", start_line=1, end_line=9,
            parameters=({"name": "input", "type": "int8"},), calls=(), conditions=(
                {
                    "kind": "if", "branch_id": "if@2", "line": 2, "path": (),
                    "expr": {"kind": "binary", "operator": ">", "left": {"kind": "variable", "name": "input"},
                             "right": {"kind": "literal", "value": "0", "value_kind": "INT"}},
                },
                {
                    "kind": "if", "branch_id": "if@4", "line": 4, "path": ("if@2:then",),
                    "expr": {"kind": "binary", "operator": ">", "left": {"kind": "variable", "name": "first"},
                             "right": {"kind": "literal", "value": "2", "value_kind": "INT"}},
                },
            ),
            assignments=(
                {"kind": "assignment", "line": 3, "target": "first", "path": ("if@2:then",),
                 "value": {"kind": "binary", "operator": "+", "left": {"kind": "variable", "name": "input"},
                           "right": {"kind": "literal", "value": "1", "value_kind": "INT"}}},
                {"kind": "assignment", "line": 5, "target": "result", "path": ("if@2:then", "if@4:then"),
                 "value": {"kind": "binary", "operator": "*", "left": {"kind": "variable", "name": "first"},
                           "right": {"kind": "literal", "value": "2", "value_kind": "INT"}}},
            ),
            returns=("return result",),
            return_sites=({"line": 7, "expressions": [{"kind": "variable", "name": "result"}],
                           "path": ["if@2:then", "if@4:then"]},),
        )
        index = SourceIndex((function,))
        exit_site = index.compile_returns(
            function.identity, {"input": ("input.value", Sort.BITVECTOR, 8, True)}
        )[0]

        self.assertTrue(exit_site.values[0].supported)
        self.assertEqual(exit_site.values[0].evaluate({"input": 4}), 10)
        self.assertEqual(exit_site.values[0].evaluate({"input": 1}), 4)
        self.assertEqual(exit_site.composed_assignment_lines, (3, 5))
        self.assertEqual(exit_site.source_file, "compose.go")
        self.assertEqual(exit_site.function_identity, "example.compose")
        self.assertTrue(exit_site.path_complete)
        self.assertTrue(exit_site.path_guards[0].evaluate({"input": 4}))
        self.assertFalse(exit_site.path_guards[0].evaluate({"input": -1}))
        self.assertTrue(exit_site.path_guards[1].evaluate({"input": 4}))
        self.assertFalse(exit_site.path_guards[1].evaluate({"input": 1}))

    def test_assignment_in_non_dominating_branch_does_not_bind_return(self):
        function = SourceFunction(
            package="example", symbol="maybe", file="maybe.go", start_line=1, end_line=6,
            parameters=({"name": "input", "type": "int8"},), calls=(), conditions=({
                "kind": "if", "branch_id": "if@2", "line": 2, "path": (),
                "expr": {"kind": "variable", "name": "input"},
            },),
            assignments=({"kind": "assignment", "line": 3, "target": "local", "path": ("if@2:then",),
                          "value": {"kind": "literal", "value": "9", "value_kind": "INT"}},),
            returns=("return local",),
            return_sites=({"line": 5, "expressions": [{"kind": "variable", "name": "local"}], "path": []},),
        )

        exit_site = SourceIndex((function,)).compile_returns(function.identity, {})[0]
        self.assertFalse(exit_site.values[0].supported)
        self.assertIn("source symbol has no profile binding: local", exit_site.values[0].limitations)
        self.assertEqual(exit_site.composed_assignment_lines, ())

    def test_static_slice_range_expands_per_iteration_and_binds_index_value(self):
        collection = {
            "kind": "composite", "type": "[]int", "elements": [
                {"kind": "literal", "value": "0", "value_kind": "INT"},
                {"kind": "literal", "value": "2", "value_kind": "INT"},
            ],
        }
        function = SourceFunction(
            package="example", symbol="rangeValues", file="range.go", start_line=1, end_line=8,
            parameters=(), calls=(), conditions=(
                {"kind": "range", "branch_id": "range@3", "line": 3, "path": (), "expr": collection,
                 "range_key": "index", "range_value": "value"},
                {"kind": "if", "branch_id": "if@4", "line": 4, "path": ("range@3:body",),
                 "expr": {"kind": "binary", "operator": ">", "left": {"kind": "variable", "name": "value"},
                          "right": {"kind": "literal", "value": "1", "value_kind": "INT"}}},
            ),
            assignments=({"kind": "assignment", "line": 5, "target": "result",
                          "path": ("range@3:body", "if@4:then"),
                          "value": {"kind": "binary", "operator": "+", "left": {"kind": "variable", "name": "value"},
                                    "right": {"kind": "variable", "name": "index"}}},),
            returns=("return result",),
            return_sites=({"line": 6, "expressions": [{"kind": "variable", "name": "result"}],
                           "path": ["range@3:body", "if@4:then"]},),
        )

        exits = SourceIndex((function,)).compile_returns(function.identity, {})

        self.assertEqual(len(exits), 2)
        self.assertEqual([exit_site.iteration_indices for exit_site in exits],
                         [(('range@3', 0),), (('range@3', 1),)])
        self.assertTrue(all(exit_site.path_complete for exit_site in exits))
        self.assertFalse(exits[0].path_guards[1].evaluate({}))
        self.assertTrue(exits[1].path_guards[1].evaluate({}))
        self.assertEqual(exits[0].values[0].evaluate({}), 0)
        self.assertEqual(exits[1].values[0].evaluate({}), 3)
        self.assertEqual(exits[0].source_file, "range.go")
        self.assertEqual(exits[0].line, 6)

    def test_static_array_range_uses_prior_local_literal_assignment(self):
        function = SourceFunction(
            package="example", symbol="localRange", file="range.go", start_line=1, end_line=6,
            parameters=(), calls=(), conditions=(
                {"kind": "range", "branch_id": "range@3", "line": 3, "path": (),
                 "expr": {"kind": "variable", "name": "values"}, "range_key": "_", "range_value": "value"},
            ),
            assignments=({"kind": "assignment", "line": 2, "target": "values", "path": (),
                          "value": {"kind": "composite", "type": "[2]int", "elements": [
                              {"kind": "literal", "value": "4", "value_kind": "INT"},
                              {"kind": "literal", "value": "7", "value_kind": "INT"},
                          ]}},),
            returns=("return value",),
            return_sites=({"line": 4, "expressions": [{"kind": "variable", "name": "value"}],
                           "path": ["range@3:body"]},),
        )

        exits = SourceIndex((function,)).compile_returns(function.identity, {})
        self.assertEqual([exit_site.values[0].evaluate({}) for exit_site in exits], [4, 7])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            facts_path = root / "facts.ndjson"
            facts_path.write_text(json.dumps({"kind": "function", **function.__dict__}) + "\n", encoding="utf-8")
            index = SourceIndex.load_sqlite(facts_path, root / "index.sqlite", max_records=10, max_bytes=1 << 20)
            try:
                sqlite_exits = index.compile_returns(function.identity, {})
                self.assertEqual([exit_site.values[0].evaluate({}) for exit_site in sqlite_exits], [4, 7])
                self.assertEqual(sqlite_exits[0].iteration_indices, (("range@3", 0),))
            finally:
                index.close()

    def test_static_range_with_break_remains_explicitly_unresolved(self):
        function = SourceFunction(
            package="example", symbol="breakRange", file="range.go", start_line=1, end_line=5,
            parameters=(), calls=(), conditions=({
                "kind": "range", "branch_id": "range@2", "line": 2, "path": (),
                "expr": {"kind": "composite", "type": "[]int", "elements": [
                    {"kind": "literal", "value": "1", "value_kind": "INT"},
                ]},
                "range_key": "_", "range_value": "value",
            },), assignments=(), returns=("return value",),
            return_sites=({"line": 4, "expressions": [{"kind": "variable", "name": "value"}],
                           "path": ["range@2:body"]},),
            control_transfers=({"kind": "break", "line": 3, "path": ["range@2:body"]},),
        )

        exit_site = SourceIndex((function,)).compile_returns(function.identity, {})[0]
        self.assertFalse(exit_site.path_complete)
        self.assertIn("range@2: break/continue semantics are unresolved", exit_site.path_limitations)

    def test_mutated_slice_during_range_is_not_unrolled(self):
        function = SourceFunction(
            package="example", symbol="mutateRange", file="range.go", start_line=1, end_line=6,
            parameters=(), calls=(), conditions=({
                "kind": "range", "branch_id": "range@3", "line": 3, "path": (),
                "expr": {"kind": "variable", "name": "values"}, "range_key": "index", "range_value": "value",
            },),
            assignments=(
                {"kind": "assignment", "line": 2, "target": "values", "path": (),
                 "value": {"kind": "composite", "type": "[]int", "elements": [
                     {"kind": "literal", "value": "1", "value_kind": "INT"},
                 ]}},
                {"kind": "assignment", "line": 4, "target": "values[index]", "path": ("range@3:body",),
                 "value": {"kind": "literal", "value": "2", "value_kind": "INT"}},
            ),
            returns=("return value",),
            return_sites=({"line": 5, "expressions": [{"kind": "variable", "name": "value"}],
                           "path": ["range@3:body"]},),
        )

        exit_site = SourceIndex((function,)).compile_returns(function.identity, {})[0]
        self.assertFalse(exit_site.path_complete)
        self.assertIn("range@3: ranged collection may be mutated during iteration", exit_site.path_limitations)
