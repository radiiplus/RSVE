"""Bounded indexes over source-derived operation facts."""

from __future__ import annotations

import json
import sqlite3
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .ir import Partiality, Relation, Semantic
from .logic import Arithmetic, Constraint, Either, Every, Equal, Literal, Negate, Rel, Sort, Variable


def _receiver_identity(type_name: str, imports: Mapping[str, str], default_package: str) -> tuple[str, str]:
    normalized = type_name.strip().replace("*", "").replace("(", "").replace(")", "")
    if not normalized:
        return "", ""
    parts = normalized.split(".")
    if len(parts) > 1 and parts[0] in imports:
        return str(imports[parts[0]]), parts[-1]
    return default_package, parts[-1]


def _method_receiver_name(symbol: str) -> str:
    if not symbol.startswith("method.") or "." not in symbol[7:]:
        return ""
    return symbol[7:].rsplit(".", 1)[0].replace("*", "").split(".")[-1]


def _named_type_identity(type_expr: str, imports: Mapping[str, str], default_package: str) -> str | None:
    name = type_expr.strip()
    while name.startswith("*"):
        name = name[1:].strip()
    while name.startswith("[]"):
        name = name[2:].strip()
    if name.startswith("["):
        close = name.find("]")
        if close >= 0:
            name = name[close + 1:].strip()
    if name.startswith("map[") or name.startswith("func(") or name.startswith("interface{"):
        return None
    if "[" in name:
        name = name.split("[", 1)[0].strip()
    if "." in name:
        alias, type_name = name.split(".", 1)
        package = imports.get(alias)
        return f"{package}.{type_name}" if package else None
    if name and name not in {
        "bool", "byte", "complex64", "complex128", "error", "float32", "float64",
        "int", "int8", "int16", "int32", "int64", "rune", "string", "uint",
        "uint8", "uint16", "uint32", "uint64", "uintptr",
    }:
        return f"{default_package}.{name}"
    return None


@dataclass(frozen=True)
class SourceFunction:
    package: str
    symbol: str
    file: str
    start_line: int
    end_line: int
    parameters: tuple[Mapping[str, str], ...]
    calls: tuple[str, ...]
    conditions: tuple[Mapping[str, Any], ...]
    assignments: tuple[Mapping[str, Any], ...]
    returns: tuple[str, ...]
    imports: Mapping[str, str] = field(default_factory=dict)
    receiver: Mapping[str, str] = field(default_factory=dict)
    call_receiver_types: Mapping[str, str] = field(default_factory=dict)
    return_sites: tuple[Mapping[str, Any], ...] = ()
    control_transfers: tuple[Mapping[str, Any], ...] = ()

    @property
    def identity(self) -> str:
        return f"{self.package}.{self.symbol}"


@dataclass(frozen=True)
class SourceTypeField:
    name: str
    type_expr: str
    tag: str = ""
    embedded: bool = False
    kind: str = "unknown"
    line: int = 0


@dataclass(frozen=True)
class SourceType:
    package: str
    name: str
    file: str
    line: int
    type_kind: str
    type_expr: str
    alias: bool
    imports: Mapping[str, str] = field(default_factory=dict)
    fields: tuple[SourceTypeField, ...] = ()

    @property
    def identity(self) -> str:
        return f"{self.package}.{self.name}"


@dataclass(frozen=True)
class FieldPathEvidence:
    type_identity: str
    path: tuple[str, ...]
    status: str
    fields: tuple[SourceTypeField, ...] = ()
    reason: str = ""
    offsets: tuple[int, ...] | None = None
    offsets_status: str = "NOT IMPLEMENTED: source declarations do not establish runtime offsets"


@dataclass(frozen=True)
class CompiledFormula:
    formula: Constraint | None
    exact: bool
    limitations: tuple[str, ...] = ()
    expression: Mapping[str, Any] | None = None
    bindings: Mapping[str, tuple[Any, ...]] | None = None

    @property
    def supported(self) -> bool:
        return self.formula is not None

    @property
    def semantic(self) -> Semantic:
        available = self.supported
        return Semantic(
            semantic_id="source-expression",
            semantics_ref="rsve.source.expression",
            semantics_version="1",
            forward=available,
            backward=self.supported,
            complete=available and self.exact,
            relation=Relation.FUNCTION if available else Relation.UNKNOWN,
            partiality=Partiality.TOTAL if available else Partiality.UNKNOWN,
            limitations=self.limitations,
        )

    def evaluate(self, values: Mapping[str, Any]) -> Any:
        """Evaluate the normalized source expression for concrete source symbols."""
        if not self.supported:
            raise ValueError("source expression has no executable and symbolic binding")
        if self.expression is None or self.bindings is None:
            environment = dict(values)
            for source_name, binding in (self.bindings or {}).items():
                if source_name in values and binding:
                    environment[str(binding[0])] = values[source_name]
            return _evaluate_constraint_formula(self.formula, environment)
        return _evaluate_source_expression(self.expression, self.bindings, values)


@dataclass(frozen=True)
class CompiledAssignment:
    target: str | None
    formula: CompiledFormula
    line: int
    path: tuple[str, ...] = ()
    path_guards: tuple[CompiledFormula, ...] = ()
    path_limitations: tuple[str, ...] = ()

    @property
    def supported(self) -> bool:
        return self.target is not None and self.formula.supported

    @property
    def path_complete(self) -> bool:
        return not self.path_limitations and len(self.path_guards) == len(self.path) and all(
            item.supported and item.exact for item in self.path_guards
        )

    @property
    def path_guard(self) -> Constraint | None:
        if not self.path_complete:
            return None
        guards = tuple(item.formula for item in self.path_guards if item.formula is not None)
        return Every(guards) if guards else Literal(True, Sort.BOOL)


@dataclass(frozen=True)
class CompiledExit:
    line: int
    values: tuple[CompiledFormula, ...]
    path: tuple[str, ...] = ()
    path_guards: tuple[CompiledFormula, ...] = ()
    path_limitations: tuple[str, ...] = ()
    source_file: str = ""
    function_identity: str = ""
    composed_assignment_lines: tuple[int, ...] = ()
    iteration_indices: tuple[tuple[str, int], ...] = ()

    @property
    def path_complete(self) -> bool:
        return not self.path_limitations and len(self.path_guards) == len(self.path) and all(
            item.supported and item.exact for item in self.path_guards
        )

    @property
    def path_guard(self) -> Constraint | None:
        if not self.path_complete:
            return None
        guards = tuple(item.formula for item in self.path_guards if item.formula is not None)
        return Every(guards) if guards else Literal(True, Sort.BOOL)


@dataclass(frozen=True)
class SourceRelation:
    kind: str
    source: str
    target: str
    status: str
    evidence: str


class FormulaCompiler:
    """Translate normalized source expressions into RSVE's constraint IR.

    Language frontends normalize syntax into this small expression shape. The
    compiler only handles pure scalar expressions and requires explicit symbol
    bindings; it never guesses what a source field represents.
    """

    SUPPORTED_BINARY = {
        "+", "-", "*", "/", "%", "&", "|", "^", "&^", "<<", ">>",
        "&&", "||", "==", "!=", "<", "<=", ">", ">=",
    }

    def compile(
        self,
        expression: Mapping[str, Any],
        bindings: Mapping[str, tuple[Any, ...]],
    ) -> CompiledFormula:
        assumptions: list[str] = []
        try:
            formula = self._node(expression, bindings, assumptions)
        except (KeyError, TypeError, ValueError) as exc:
            return CompiledFormula(None, False, (str(exc),))
        return CompiledFormula(formula, not assumptions, tuple(dict.fromkeys(assumptions)), expression, bindings)

    def _node(
        self,
        node: Mapping[str, Any],
        bindings: Mapping[str, tuple[Any, ...]],
        assumptions: list[str],
    ) -> Constraint:
        kind = node.get("kind")
        if kind == "literal":
            value_kind = node.get("value_kind")
            raw = node.get("value")
            if value_kind == "INT":
                value = self._integer(str(raw))
                return Literal(value, Sort.INT)
            if value_kind == "BOOL":
                return Literal(str(raw).lower() == "true", Sort.BOOL)
            if value_kind == "FLOAT":
                raise ValueError("floating-point source expressions are not supported")
            if value_kind in {"STRING", "CHAR"}:
                raise ValueError("string and character literals are redacted or unsupported")
            raise ValueError(f"unsupported source literal kind: {value_kind}")
        if kind in {"variable", "selector"}:
            symbol = self._symbol(node)
            if symbol == "true":
                return Literal(True, Sort.BOOL)
            if symbol == "false":
                return Literal(False, Sort.BOOL)
            binding = bindings.get(symbol)
            if binding is None:
                raise ValueError(f"source symbol has no profile binding: {symbol}")
            if len(binding) not in {2, 4}:
                raise ValueError(f"source binding for {symbol} must specify name/sort and optional width/signedness")
            name, sort = binding[:2]
            width, signed = (binding[2], binding[3]) if len(binding) == 4 else (None, None)
            return Variable(name, sort, width, signed)
        if kind == "unary":
            operator = node.get("operator")
            operand = self._node(node["operand"], bindings, assumptions)
            if operator == "!":
                return Negate(operand)
            if operator == "-":
                if self._numeric_mode(operand) is None:
                    assumptions.append("integer width, signedness, and overflow are not encoded")
                return Arithmetic("-", Literal(0, Sort.INT), operand)
            if operator == "+":
                return operand
            if operator == "^":
                mode = self._numeric_mode(operand)
                if mode is None:
                    raise ValueError("bitwise complement requires an explicitly bound bitvector")
                return Arithmetic("^", operand, Literal(-1, Sort.INT))
            raise ValueError(f"unsupported source unary operator: {operator}")
        if kind == "binary":
            operator = str(node.get("operator"))
            if operator not in self.SUPPORTED_BINARY:
                raise ValueError(f"unsupported source binary operator: {operator}")
            left = self._node(node["left"], bindings, assumptions)
            right = self._node(node["right"], bindings, assumptions)
            if operator == "&&":
                return Every((left, right))
            if operator == "||":
                return Either((left, right))
            if operator == "==":
                return Equal(left, right)
            if operator == "!=":
                return Negate(Equal(left, right))
            if operator in {"+", "-", "*", "/", "%", "&", "|", "^", "&^", "<<", ">>"}:
                numeric_mode = self._merge_numeric_mode(left, right)
                if numeric_mode is None:
                    assumptions.append("integer width, signedness, and overflow are not encoded")
                if operator in {"/", "%"} and numeric_mode is None:
                    raise ValueError("Go division and remainder require an explicit signed bitvector binding")
                if operator in {"&", "|", "^", "&^", "<<", ">>"} and numeric_mode is None:
                    raise ValueError(f"Go {operator} requires an explicit bitvector binding")
                if operator in {"/", "%"} and numeric_mode is not None:
                    operator = ("s" if numeric_mode else "u") + operator
                if operator == ">>" and numeric_mode is not None:
                    operator = ("s" if numeric_mode else "u") + operator
                if operator in {"<<", "s>>", "u>>"} and isinstance(right, Variable):
                    raise ValueError("symbolic shift counts with a distinct source width are unsupported")
                if operator in {"<<", "s>>", "u>>"} and isinstance(right, Literal) and numeric_mode is not None:
                    right = Literal(int(right.value), Sort.BITVECTOR)
                if operator == "&^":
                    return Arithmetic("&^", left, right)
                return Arithmetic(operator, left, right)
            numeric_mode = self._merge_numeric_mode(left, right)
            if numeric_mode is not None:
                operator = ("s" if numeric_mode else "u") + operator
            elif self._contains_integer_variable(left) or self._contains_integer_variable(right):
                assumptions.append("integer width, signedness, and overflow are not encoded")
            return Rel(left, operator, right)
        raise ValueError(f"unsupported source expression kind: {kind}")

    def _symbol(self, node: Mapping[str, Any]) -> str:
        if node.get("kind") == "variable":
            return str(node.get("name", ""))
        if node.get("kind") == "selector":
            return f"{self._symbol(node['base'])}.{node.get('field', '')}"
        raise ValueError("source expression is not a scalar symbol")

    def _numeric_mode(self, node: Constraint) -> bool | None:
        variables = []

        def visit(item: Constraint) -> None:
            if isinstance(item, Variable):
                variables.append(item)
            elif isinstance(item, (Arithmetic, Equal, Rel)):
                visit(item.left)
                visit(item.right)
            elif isinstance(item, (Every, Either)):
                for child in item.terms:
                    visit(child)
            elif isinstance(item, Negate):
                visit(item.term)

        visit(node)
        bitvectors = [item for item in variables if item.sort is Sort.BITVECTOR]
        if not bitvectors:
            return None
        if any(item.sort is not Sort.BITVECTOR for item in variables):
            raise ValueError("mixed bitvector and mathematical integer bindings are unsupported")
        widths = {item.width for item in bitvectors}
        signedness = {item.signed for item in bitvectors}
        if len(widths) != 1 or len(signedness) != 1 or None in signedness:
            raise ValueError("bitvector width and signedness must be explicit and consistent")
        return next(iter(signedness))

    def _merge_numeric_mode(self, left: Constraint, right: Constraint) -> bool | None:
        left_mode = self._numeric_mode(left)
        right_mode = self._numeric_mode(right)
        if left_mode == right_mode:
            return left_mode
        if left_mode is not None and right_mode is None and not self._contains_integer_variable(right):
            return left_mode
        if right_mode is not None and left_mode is None and not self._contains_integer_variable(left):
            return right_mode
        if left_mode is not None or right_mode is not None:
            raise ValueError("mixed or unresolved integer widths/signedness need an explicit profile binding")
        return None

    @staticmethod
    def _contains_integer_variable(node: Constraint) -> bool:
        if isinstance(node, Variable):
            return node.sort is Sort.INT
        if isinstance(node, (Arithmetic, Equal, Rel)):
            return FormulaCompiler._contains_integer_variable(node.left) or FormulaCompiler._contains_integer_variable(node.right)
        if isinstance(node, (Every, Either)):
            return any(FormulaCompiler._contains_integer_variable(child) for child in node.terms)
        if isinstance(node, Negate):
            return FormulaCompiler._contains_integer_variable(node.term)
        return False

    @staticmethod
    def _integer(raw: str) -> int:
        cleaned = raw.replace("_", "")
        try:
            return int(cleaned, 0)
        except ValueError:
            if len(cleaned) > 1 and cleaned.startswith("0"):
                return int(cleaned, 8)
            return int(cleaned, 10)


def _compile_path_guards(
    path: tuple[str, ...],
    conditions: tuple[Mapping[str, Any], ...],
    bindings: Mapping[str, tuple[Any, ...]],
    path_substitutions: Mapping[str, Mapping[str, Any]] | None = None,
    expanded_ranges: frozenset[str] = frozenset(),
) -> tuple[tuple[CompiledFormula, ...], tuple[str, ...]]:
    by_id = {str(item.get("branch_id")): item for item in conditions if item.get("branch_id")}
    compiler = FormulaCompiler()
    guards = []
    limitations = []
    for step in path:
        branch_id = next((candidate for candidate in sorted(by_id, key=len, reverse=True) if step.startswith(candidate + ":")), "")
        arm = step[len(branch_id) + 1:] if branch_id else ""
        condition = by_id.get(branch_id)
        if condition is None or not isinstance(condition.get("expr"), Mapping):
            limitations.append(f"control path has no scalar guard model: {step}")
            continue
        if condition.get("kind") == "switch":
            if condition.get("case_fallthrough"):
                limitations.append(f"switch path includes fallthrough semantics: {step}")
                continue
            try:
                case_index = int(arm.removeprefix("case:"))
            except ValueError:
                limitations.append(f"switch path has an invalid case index: {step}")
                continue
            case_values = condition.get("case_values", ())
            case_defaults = condition.get("case_default", ())
            if case_index >= len(case_values) or not isinstance(condition.get("expr"), Mapping):
                limitations.append(f"switch path lacks a scalar case model: {step}")
                continue
            substitutions = (path_substitutions or {}).get(branch_id, {})
            tag_expression = _substitute_source_expression(condition["expr"], substitutions)
            tag = compiler.compile(tag_expression, bindings)
            if not tag.supported:
                limitations.extend(tag.limitations)
                continue
            values = case_values[case_index]
            comparisons = [
                compiler.compile({"kind": "binary", "operator": "==", "left": tag_expression, "right": _substitute_source_expression(value, substitutions)}, bindings)
                for value in values
            ]
            if any(not item.supported for item in comparisons):
                limitations.extend(reason for item in comparisons for reason in item.limitations)
                continue
            if case_defaults[case_index]:
                all_cases = []
                for values_for_case, is_default in zip(case_values, case_defaults):
                    if is_default:
                        continue
                    all_cases.extend(
                        compiler.compile({"kind": "binary", "operator": "==", "left": tag_expression, "right": _substitute_source_expression(value, substitutions)}, bindings)
                        for value in values_for_case
                    )
                if not all(item.supported for item in all_cases) or not all_cases:
                    limitations.append(f"switch default has no complete scalar case model: {step}")
                    continue
                guards.append(CompiledFormula(
                    Every(tuple(Negate(item.formula) for item in all_cases if item.formula is not None)),
                    all(item.exact for item in all_cases),
                    tuple(reason for item in all_cases for reason in item.limitations),
                    bindings=bindings,
                ))
            elif comparisons:
                guards.append(CompiledFormula(
                    Either(tuple(item.formula for item in comparisons if item.formula is not None)),
                    all(item.exact for item in comparisons),
                    tuple(reason for item in comparisons for reason in item.limitations),
                    bindings=bindings,
                ))
            else:
                limitations.append(f"switch case has no scalar expressions: {step}")
            continue
        if condition.get("kind") == "range":
            if branch_id in expanded_ranges and arm == "body":
                guards.append(CompiledFormula(Literal(True, Sort.BOOL), True, bindings=bindings))
            else:
                limitations.append(f"range path requires a supported bounded literal expansion: {step}")
            continue
        if condition.get("kind") not in {"if", "for"}:
            limitations.append(f"control path requires case or collection semantics: {step}")
            continue
        expression = _substitute_source_expression(
            condition["expr"], (path_substitutions or {}).get(branch_id, {})
        )
        if condition.get("kind") == "if" and arm == "else":
            expression = {"kind": "unary", "operator": "!", "operand": expression}
        compiled = compiler.compile(expression, bindings)
        guards.append(compiled)
        if not compiled.supported:
            limitations.extend(compiled.limitations)
    return tuple(guards), tuple(dict.fromkeys(limitations))


def _substitute_source_expression(
    expression: Any, substitutions: Mapping[str, Mapping[str, Any]] | Mapping[str, Any]
) -> Any:
    if isinstance(expression, list):
        return [_substitute_source_expression(item, substitutions) for item in expression]
    if not isinstance(expression, Mapping):
        return expression
    if expression.get("kind") == "variable":
        replacement = substitutions.get(str(expression.get("name", "")))
        if isinstance(replacement, Mapping):
            return replacement
    return {
        key: _substitute_source_expression(value, substitutions)
        if isinstance(value, (Mapping, list)) else value
        for key, value in expression.items()
    }


def _path_dominates(assignment_path: tuple[str, ...], use_path: tuple[str, ...]) -> bool:
    return all(step in use_path for step in assignment_path)


def _assignments_before(
    assignments: tuple[Mapping[str, Any], ...],
    *,
    line: int,
    use_path: tuple[str, ...],
    initial_substitutions: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], tuple[int, ...]]:
    substitutions: dict[str, Any] = dict(initial_substitutions or {})
    used_lines = []
    for assignment in sorted(assignments, key=lambda item: int(item.get("line", 0))):
        assignment_line = int(assignment.get("line", 0))
        target = str(assignment.get("target", ""))
        value = assignment.get("value")
        if assignment_line <= 0 or assignment_line >= line or not target.isidentifier():
            continue
        if not isinstance(value, Mapping) or not _path_dominates(
            tuple(str(step) for step in assignment.get("path", ())), use_path
        ):
            continue
        substitutions[target] = _substitute_source_expression(value, substitutions)
        used_lines.append(assignment_line)
    return substitutions, tuple(used_lines)


MAX_STATIC_RANGE_EXPANSIONS = 64


def _range_branch_id(path_step: str) -> str:
    return path_step.rsplit(":", 1)[0] if ":" in path_step else ""


def _static_range_elements(
    condition: Mapping[str, Any],
    function: SourceFunction,
    outer_substitutions: Mapping[str, Any],
) -> tuple[tuple[Mapping[str, Any], ...] | None, str, str]:
    expression = condition.get("expr")
    if not isinstance(expression, Mapping):
        return None, "range expression has no normalized syntax", ""
    expression = _substitute_source_expression(expression, outer_substitutions)
    collection_name = str(expression.get("name", "")) if expression.get("kind") == "variable" else ""
    if collection_name:
        path = tuple(str(step) for step in condition.get("path", ()))
        candidates = [
            assignment for assignment in function.assignments
            if str(assignment.get("target", "")) == collection_name
            and 0 < int(assignment.get("line", 0)) < int(condition.get("line", 0))
            and _path_dominates(tuple(str(step) for step in assignment.get("path", ())), path)
        ]
        if not candidates:
            return None, "range collection is not bound to a prior literal", collection_name
        expression = _substitute_source_expression(
            max(candidates, key=lambda item: int(item.get("line", 0))).get("value"), outer_substitutions
        )
    if not isinstance(expression, Mapping) or expression.get("kind") != "composite":
        return None, "range collection is not an array or slice literal", collection_name
    type_name = str(expression.get("type", "")).strip()
    is_slice = type_name.startswith("[]")
    is_array = type_name.startswith("[") and type_name[1:type_name.find("]")].isdigit()
    if not (is_slice or is_array):
        return None, "range literal type is not a statically sized array or slice", collection_name
    elements = expression.get("elements", ())
    if not isinstance(elements, (list, tuple)):
        return None, "range literal elements are malformed", collection_name
    compiler = FormulaCompiler()
    for element in elements:
        if not isinstance(element, Mapping) or element.get("kind") == "key_value":
            return None, "keyed or unsupported range literal elements are unresolved", collection_name
        compiled = compiler.compile(element, {})
        if not compiled.supported or _source_expression_has_symbol(element):
            return None, "range literal contains a non-constant or unsupported scalar", collection_name
        try:
            compiled.evaluate({})
        except (KeyError, TypeError, ValueError, ZeroDivisionError):
            return None, "range literal scalar cannot be evaluated", collection_name
    return tuple(elements), "", collection_name


def _source_expression_has_symbol(expression: Any) -> bool:
    if isinstance(expression, Mapping):
        if expression.get("kind") in {"variable", "selector", "call", "index", "dereference"}:
            return True
        return any(_source_expression_has_symbol(value) for value in expression.values())
    if isinstance(expression, (list, tuple)):
        return any(_source_expression_has_symbol(value) for value in expression)
    return False


def _static_range_variants(
    function: SourceFunction,
    path: tuple[str, ...],
) -> tuple[tuple[Any, ...], tuple[str, ...]]:
    conditions = {str(item.get("branch_id")): item for item in function.conditions if item.get("branch_id")}
    ranges = []
    for step in path:
        branch_id = _range_branch_id(step)
        condition = conditions.get(branch_id)
        if condition is not None and condition.get("kind") == "range":
            if step != branch_id + ":body":
                return (), (f"unsupported range branch path: {step}",)
            ranges.append((branch_id, condition))

    variants: list[tuple[tuple[Mapping[str, Any], ...], tuple[tuple[str, int], ...], frozenset[str]]] = []

    def expand(
        offset: int,
        substitutions: dict[str, Any],
        indices: tuple[tuple[str, int], ...],
        expanded: frozenset[str],
    ) -> tuple[str, ...]:
        if offset == len(ranges):
            variants.append((tuple(substitutions.items()), indices, expanded))
            if len(variants) > MAX_STATIC_RANGE_EXPANSIONS:
                return (f"static range expansion exceeds {MAX_STATIC_RANGE_EXPANSIONS} paths",)
            return ()
        branch_id, condition = ranges[offset]
        elements, reason, collection_name = _static_range_elements(condition, function, substitutions)
        if reason:
            return (f"{branch_id}: {reason}",)
        loop_path = branch_id + ":body"
        if any(loop_path in tuple(str(step) for step in transfer.get("path", ()))
               for transfer in function.control_transfers
               if str(transfer.get("kind", "")).lower() in {"break", "continue"}):
            return (f"{branch_id}: break/continue semantics are unresolved",)
        if collection_name:
            mutated = any(
                loop_path in tuple(str(step) for step in assignment.get("path", ()))
                and (str(assignment.get("target", "")) == collection_name
                     or str(assignment.get("target", "")).startswith(collection_name + "[")
                     or str(assignment.get("target", "")).startswith(collection_name + "."))
                for assignment in function.assignments
            )
            if mutated or any(str(call).rsplit(".", 1)[-1] == "append" for call in function.calls):
                return (f"{branch_id}: ranged collection may be mutated during iteration",)
        for index, element in enumerate(elements or ()):
            iteration = dict(substitutions)
            key_name = str(condition.get("range_key", ""))
            value_name = str(condition.get("range_value", ""))
            if key_name and key_name != "_":
                iteration[key_name] = {"kind": "literal", "value": str(index), "value_kind": "INT"}
            if value_name and value_name != "_":
                iteration[value_name] = element
            limitations = expand(
                offset + 1, iteration, indices + ((branch_id, index),), expanded | {branch_id}
            )
            if limitations:
                return limitations
        return ()

    limitations = expand(0, {}, (), frozenset())
    if limitations:
        return (), limitations
    return tuple(variants), ()


def _compile_return_sites(
    function: SourceFunction,
    bindings: Mapping[str, tuple[Any, ...]],
) -> tuple[CompiledExit, ...]:
    compiler = FormulaCompiler()
    exits = []
    for site in function.return_sites:
        path = tuple(str(item) for item in site.get("path", ()))
        line = int(site.get("line", 0))
        variants, range_limitations = _static_range_variants(function, path)
        if range_limitations:
            variants = (((), (), frozenset()),)
        if not variants:
            continue
        for raw_substitutions, iteration_indices, expanded_ranges in variants:
            iteration_substitutions = dict(raw_substitutions)
            substitutions, assignment_lines = _assignments_before(
                function.assignments, line=line, use_path=path,
                initial_substitutions=iteration_substitutions,
            )
            expressions = site.get("expressions", ())
            values = tuple(
                compiler.compile(_substitute_source_expression(expression, substitutions), bindings)
                if isinstance(expression, Mapping)
                else CompiledFormula(None, False, ("return value has no normalized expression tree",))
                for expression in expressions
            )
            path_substitutions = {}
            for condition in function.conditions:
                branch_id = str(condition.get("branch_id", ""))
                condition_path = tuple(str(step) for step in condition.get("path", ()))
                loop_locals = {}
                for range_id, _ in iteration_indices:
                    if range_id + ":body" not in condition_path:
                        continue
                    range_condition = next(
                        (item for item in function.conditions if item.get("branch_id") == range_id), {}
                    )
                    for variable_name in (range_condition.get("range_key"), range_condition.get("range_value")):
                        if variable_name and variable_name != "_" and variable_name in iteration_substitutions:
                            loop_locals[str(variable_name)] = iteration_substitutions[str(variable_name)]
                path_substitutions[branch_id] = _assignments_before(
                    function.assignments,
                    line=int(condition.get("line", 0)),
                    use_path=condition_path,
                    initial_substitutions=loop_locals,
                )[0]
            guards, limitations = _compile_path_guards(
                path, function.conditions, bindings, path_substitutions, expanded_ranges
            )
            limitations = tuple(dict.fromkeys((*range_limitations, *limitations)))
            exits.append(CompiledExit(
                line=line, values=values, path=path,
                path_guards=guards, path_limitations=limitations,
                source_file=function.file, function_identity=function.identity,
                composed_assignment_lines=assignment_lines,
                iteration_indices=iteration_indices,
            ))
    return tuple(exits)


def _evaluate_constraint_formula(node: Constraint | None, values: Mapping[str, Any]) -> Any:
    if node is None:
        raise ValueError("constraint formula is missing")
    if isinstance(node, Literal):
        return node.value
    if isinstance(node, Variable):
        if node.name not in values:
            raise KeyError(f"concrete value is missing for source symbol: {node.name}")
        value = values[node.name]
        if node.sort is Sort.BITVECTOR and node.width is not None:
            value = _source_integer_value(int(value), (node.width, bool(node.signed)))
        return value
    if isinstance(node, Arithmetic):
        left = _evaluate_constraint_formula(node.left, values)
        right = _evaluate_constraint_formula(node.right, values)
        operation = node.operator.removeprefix("s").removeprefix("u")
        if operation == "+":
            return left + right
        if operation == "-":
            return left - right
        if operation == "*":
            return left * right
        if operation == "&":
            return left & right
        if operation == "|":
            return left | right
        if operation == "^":
            return left ^ right
        if operation == "&^":
            return left & ~right
        if operation == "/":
            if right == 0:
                raise ZeroDivisionError("integer division by zero")
            quotient = abs(int(left)) // abs(int(right))
            return -quotient if (left < 0) != (right < 0) else quotient
        if operation == "%":
            if right == 0:
                raise ZeroDivisionError("integer remainder by zero")
            quotient = abs(int(left)) // abs(int(right))
            quotient = -quotient if (left < 0) != (right < 0) else quotient
            return left - quotient * right
        raise ValueError(f"unsupported concrete constraint arithmetic: {node.operator}")
    if isinstance(node, Equal):
        return _evaluate_constraint_formula(node.left, values) == _evaluate_constraint_formula(node.right, values)
    if isinstance(node, Rel):
        left = _evaluate_constraint_formula(node.left, values)
        right = _evaluate_constraint_formula(node.right, values)
        relation = node.relation.removeprefix("s").removeprefix("u")
        return {"=": left == right, "==": left == right, "!=": left != right, "<": left < right,
                "<=": left <= right, ">": left > right, ">=": left >= right}[relation]
    if isinstance(node, Every):
        return all(_evaluate_constraint_formula(item, values) for item in node.terms)
    if isinstance(node, Either):
        return any(_evaluate_constraint_formula(item, values) for item in node.terms)
    if isinstance(node, Negate):
        return not _evaluate_constraint_formula(node.term, values)
    raise ValueError(f"unsupported concrete constraint formula: {type(node).__name__}")


def _evaluate_source_expression(
    node: Mapping[str, Any],
    bindings: Mapping[str, tuple[Any, ...]],
    values: Mapping[str, Any],
) -> Any:
    kind = node.get("kind")
    if kind == "literal":
        value_kind = node.get("value_kind")
        if value_kind == "INT":
            return FormulaCompiler._integer(str(node.get("value")))
        if value_kind == "BOOL":
            return str(node.get("value")).lower() == "true"
        raise ValueError(f"unsupported concrete source literal kind: {value_kind}")
    if kind in {"variable", "selector"}:
        compiler = FormulaCompiler()
        symbol = compiler._symbol(node)
        if symbol in {"true", "false"}:
            return symbol == "true"
        if symbol not in bindings:
            raise ValueError(f"source symbol has no profile binding: {symbol}")
        if symbol not in values:
            raise KeyError(f"concrete value is missing for source symbol: {symbol}")
        binding = bindings[symbol]
        value = values[symbol]
        if len(binding) == 4 and binding[1] is Sort.BITVECTOR:
            mode = (int(binding[2]), bool(binding[3]))
            value = _source_integer_value(int(value), mode)
        return value
    if kind == "unary":
        operator = node.get("operator")
        operand = _evaluate_source_expression(node["operand"], bindings, values)
        if operator == "!":
            return not operand
        if operator == "+":
            return operand
        if operator == "-":
            result = -operand
            mode = _source_integer_mode(node["operand"], bindings)
            return _source_integer_value(result, mode)
        if operator == "^":
            mode = _source_integer_mode(node["operand"], bindings)
            if mode is None:
                raise ValueError("bitwise complement requires an explicitly bound bitvector")
            return _source_integer_value(~int(operand), mode)
        raise ValueError(f"unsupported concrete source unary operator: {operator}")
    if kind == "binary":
        operator = node.get("operator")
        left = _evaluate_source_expression(node["left"], bindings, values)
        if operator == "&&" and not left:
            return False
        if operator == "||" and left:
            return True
        right = _evaluate_source_expression(node["right"], bindings, values)
        mode = _source_integer_mode(node, bindings)
        if operator in {"+", "-", "*", "/", "%", "&", "|", "^", "&^", "<<", ">>"}:
            if operator in {"/", "%"}:
                if int(right) == 0:
                    raise ZeroDivisionError("Go integer division by zero")
                signed = bool(mode and mode[1])
                dividend = _signed_integer(int(left), mode[0]) if signed else int(left)
                divisor = _signed_integer(int(right), mode[0]) if signed else int(right)
                quotient = abs(dividend) // abs(divisor)
                if (dividend < 0) != (divisor < 0):
                    quotient = -quotient
                result = quotient if operator == "/" else dividend - quotient * divisor
            elif operator == "&":
                result = int(left) & int(right)
            elif operator == "|":
                result = int(left) | int(right)
            elif operator == "^":
                result = int(left) ^ int(right)
            elif operator == "&^":
                result = int(left) & ~int(right)
            elif operator == "<<":
                result = int(left) << int(right)
            elif operator == ">>":
                shift_value = _signed_integer(int(left), mode[0]) if mode and mode[1] else int(left)
                result = shift_value >> int(right)
            else:
                result = {"+": lambda: left + right, "-": lambda: left - right, "*": lambda: left * right}[operator]()
            return _source_integer_value(result, mode)
        if operator == "&&":
            return bool(left and right)
        if operator == "||":
            return bool(left or right)
        if operator == "==":
            return left == right
        if operator == "!=":
            return left != right
        if mode is not None and mode[1]:
            left = _signed_integer(left, mode[0])
            right = _signed_integer(right, mode[0])
        return {"<": lambda: left < right, "<=": lambda: left <= right,
                ">": lambda: left > right, ">=": lambda: left >= right}[str(operator)]()
    raise ValueError(f"unsupported concrete source expression kind: {kind}")


def _source_integer_mode(node: Mapping[str, Any], bindings: Mapping[str, tuple[Any, ...]]) -> tuple[int, bool] | None:
    if node.get("kind") in {"variable", "selector"}:
        symbol = FormulaCompiler()._symbol(node)
        binding = bindings.get(symbol)
        if binding is not None and len(binding) == 4 and binding[1] is Sort.BITVECTOR:
            return int(binding[2]), bool(binding[3])
        return None
    if node.get("kind") in {"binary", "unary"}:
        left = node.get("left", node.get("operand"))
        right = node.get("right")
        return _source_integer_mode(left, bindings) or (
            _source_integer_mode(right, bindings) if isinstance(right, Mapping) else None
        )
    return None


def _wrap_integer(value: int, mode: tuple[int, bool] | None) -> int:
    if mode is None:
        return value
    return value & ((1 << mode[0]) - 1)


def _source_integer_value(value: int, mode: tuple[int, bool] | None) -> int:
    encoded = _wrap_integer(value, mode)
    if mode is not None and mode[1]:
        return _signed_integer(encoded, mode[0])
    return encoded


def _signed_integer(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    value &= (1 << width) - 1
    return value - (1 << width) if value & sign else value


class SourceIndex:
    """Resolve source call names and enumerate bounded paths between functions.

    Extracted syntax is modeled evidence. It is not an executable transition
    relation and does not establish that a branch is feasible at runtime.
    """

    def __init__(self, functions: tuple[SourceFunction, ...], *, truncated: bool = False) -> None:
        self.functions = functions
        self.truncated = truncated
        self._by_identity = {item.identity: item for item in functions}
        self._by_symbol: dict[str, list[SourceFunction]] = {}
        for item in functions:
            short_name = item.symbol.rsplit(".", 1)[-1]
            self._by_symbol.setdefault(short_name, []).append(item)
        resolutions = [
            self._resolve(item, call)
            for item in functions
            for call in item.calls
        ]
        self.unresolved_calls = sum(not targets for targets in resolutions)
        self.ambiguous_calls = sum(len(targets) > 1 for targets in resolutions)
        self._edges = {
            item.identity: tuple(
                sorted(
                    target
                    for call in item.calls
                    for target in self._resolve(item, call)
                )
            )
            for item in functions
        }

    @classmethod
    def load_sqlite(
        cls,
        source_path: str | Path,
        index_path: str | Path,
        *,
        max_records: int = 500_000,
        max_bytes: int = 384 << 20,
        max_line_bytes: int = 1 << 20,
        types_path: str | Path | None = None,
        max_type_records: int = 200_000,
        max_type_bytes: int = 64 << 20,
        max_type_line_bytes: int = 64 << 10,
    ) -> "SQLiteSourceIndex":
        return SQLiteSourceIndex.build(
            source_path,
            index_path,
            max_records=max_records,
            max_bytes=max_bytes,
            max_line_bytes=max_line_bytes,
            types_path=types_path,
            max_type_records=max_type_records,
            max_type_bytes=max_type_bytes,
            max_type_line_bytes=max_type_line_bytes,
        )

    @classmethod
    def load_ndjson(
        cls,
        path: str | Path,
        *,
        max_records: int = 100_000,
        max_bytes: int = 64 << 20,
        max_line_bytes: int = 1 << 20,
        package_prefix: str | None = None,
    ) -> "SourceIndex":
        if min(max_records, max_bytes, max_line_bytes) <= 0:
            raise ValueError("source index limits must be positive")
        functions: list[SourceFunction] = []
        consumed = 0
        records_seen = 0
        truncated = False
        with Path(path).open("rb") as source:
            while True:
                line = source.readline(max_line_bytes + 1)
                if not line:
                    break
                consumed += len(line)
                if len(line) > max_line_bytes or consumed > max_bytes:
                    truncated = True
                    break
                item = json.loads(line)
                if item.get("kind") == "source-facts.limit":
                    truncated = True
                    break
                if item.get("kind") != "function":
                    continue
                records_seen += 1
                if records_seen > max_records:
                    truncated = True
                    break
                if package_prefix and not str(item.get("package", "")).startswith(package_prefix):
                    continue
                functions.append(SourceFunction(
                    package=str(item.get("package", "")),
                    symbol=str(item.get("symbol", "")),
                    file=str(item.get("file", "")),
                    start_line=int(item.get("start_line", 0)),
                    end_line=int(item.get("end_line", 0)),
                    parameters=tuple(item.get("parameters", ())),
                    calls=tuple(str(value) for value in item.get("calls", ())),
                    conditions=tuple(item.get("conditions", ())),
                    assignments=tuple(item.get("assignments", ())),
                    returns=tuple(str(value) for value in item.get("returns", ())),
                    imports=dict(item.get("imports", {})),
                    receiver=dict(item.get("receiver", {})),
                    call_receiver_types=dict(item.get("call_receiver_types", {})),
                    return_sites=tuple(item.get("return_sites", ())),
                    control_transfers=tuple(item.get("control_transfers", ())),
                ))
        return cls(tuple(functions), truncated=truncated)

    def _resolve(self, caller: SourceFunction, call: str) -> tuple[str, ...]:
        name = call.rsplit(".", 1)[-1]
        qualifier = call.split(".", 1)[0]
        receiver_type = caller.call_receiver_types.get(call, "")
        receiver_package, receiver_name = _receiver_identity(receiver_type, caller.imports, caller.package)
        if receiver_name:
            methods = tuple(
                item.identity for item in self._by_symbol.get(name, ())
                if item.symbol.startswith("method.")
                and _method_receiver_name(item.symbol) == receiver_name
                and (not receiver_package or item.package == receiver_package)
            )
            return methods
        import_path = caller.imports.get(qualifier)
        if import_path:
            imported = tuple(
                item.identity for item in self._by_symbol.get(name, ()) if item.package == import_path
            )
            return imported
        local = tuple(
            item.identity
            for item in self._by_symbol.get(name, ())
            if item.package == caller.package
        )
        if local:
            return local
        remote = tuple(item.identity for item in self._by_symbol.get(name, ()))
        return remote if len(remote) == 1 else ()

    def function(self, identity: str) -> SourceFunction | None:
        return self._by_identity.get(identity)

    def callees(self, identity: str) -> tuple[SourceFunction, ...]:
        return tuple(
            self._by_identity[target]
            for target in self._edges.get(identity, ())
            if target in self._by_identity
        )

    def callers(self, identity: str) -> tuple[SourceFunction, ...]:
        return tuple(
            self._by_identity[source]
            for source, targets in sorted(self._edges.items())
            if identity in targets
        )

    def relations(self, identity: str) -> tuple[SourceRelation, ...]:
        """Return candidate call and address-alias relations for one function."""
        function = self.function(identity)
        if function is None:
            raise KeyError(f"source function not found: {identity}")
        relations = []
        for call in function.calls:
            candidates = self._resolve(function, call)
            status = "resolved" if len(candidates) == 1 else "ambiguous" if candidates else "unresolved"
            relations.extend(
                SourceRelation("call", identity, candidate, status, call)
                for candidate in candidates
            )
            if not candidates:
                relations.append(SourceRelation("call", identity, call, status, call))
        for assignment in function.assignments:
            expression = assignment.get("value")
            if not isinstance(expression, Mapping) or expression.get("kind") != "unary" or expression.get("operator") != "&":
                continue
            target = str(assignment.get("target", ""))
            source = self._expression_symbol(expression.get("operand"))
            if target and source:
                relations.append(SourceRelation(
                    "address-alias-candidate",
                    target,
                    source,
                    "candidate",
                    f"{identity}:{assignment.get('line', 0)}",
                ))
        return tuple(relations)

    def compile_conditions(
        self,
        identity: str,
        bindings: Mapping[str, tuple[Any, ...]],
    ) -> tuple[CompiledFormula, ...]:
        function = self.function(identity)
        if function is None:
            raise KeyError(f"source function not found: {identity}")
        compiler = FormulaCompiler()
        return tuple(
            compiler.compile(condition["expr"], bindings)
            if isinstance(condition.get("expr"), Mapping)
            else CompiledFormula(None, False, ("condition has no normalized expression tree",))
            for condition in function.conditions
        )

    def compile_assignments(
        self,
        identity: str,
        bindings: Mapping[str, tuple[Any, ...]],
        targets: Mapping[str, str],
    ) -> tuple[CompiledAssignment, ...]:
        function = self.function(identity)
        if function is None:
            raise KeyError(f"source function not found: {identity}")
        compiler = FormulaCompiler()
        assignments = []
        for assignment in function.assignments:
            expression = assignment.get("value")
            if not isinstance(expression, Mapping):
                formula = CompiledFormula(None, False, ("assignment is not a supported single-value assignment",))
            else:
                formula = compiler.compile(expression, bindings)
            path = tuple(str(item) for item in assignment.get("path", ()))
            path_guards, path_limitations = _compile_path_guards(path, function.conditions, bindings)
            assignments.append(CompiledAssignment(
                target=targets.get(str(assignment.get("target", ""))),
                formula=formula,
                line=int(assignment.get("line", 0)),
                path=path,
                path_guards=path_guards,
                path_limitations=path_limitations,
            ))
        return tuple(assignments)

    def compile_returns(
        self, identity: str, bindings: Mapping[str, tuple[Any, ...]]
    ) -> tuple[CompiledExit, ...]:
        function = self.function(identity)
        if function is None:
            raise KeyError(f"source function not found: {identity}")
        return _compile_return_sites(function, bindings)

    def paths(
        self,
        source: str,
        target: str,
        *,
        max_depth: int = 16,
        max_paths: int = 1000,
    ) -> tuple[tuple[str, ...], ...]:
        if max_depth < 0 or max_paths <= 0:
            raise ValueError("source path bounds must be non-negative depth and positive count")
        if source not in self._by_identity or target not in self._by_identity:
            return ()
        queue = deque([(source, (source,))])
        found: list[tuple[str, ...]] = []
        frontier_limit = max_paths * max(1, max_depth)
        while queue and len(found) < max_paths:
            current, path = queue.popleft()
            if current == target:
                found.append(path)
                continue
            if len(path) - 1 >= max_depth:
                continue
            for next_id in self._edges.get(current, ()):
                if next_id not in path:
                    if len(queue) >= frontier_limit:
                        raise OverflowError("source route frontier exceeded its explicit bound")
                    queue.append((next_id, path + (next_id,)))
        return tuple(found)

    def summary(self) -> Mapping[str, Any]:
        return {
            "status": "PARTIAL" if self.truncated or self.unresolved_calls or self.ambiguous_calls else "IMPLEMENTED",
            "functions": len(self.functions),
            "candidate_call_edges": sum(len(targets) for targets in self._edges.values()),
            "unresolved_calls": self.unresolved_calls,
            "ambiguous_calls": self.ambiguous_calls,
            "address_alias_candidates": sum(
                relation.kind == "address-alias-candidate"
                for function in self.functions
                for relation in self.relations(function.identity)
            ),
            "truncated": self.truncated,
            "semantics": "candidate source structure; executable branch and value relations are not inferred",
        }

    @staticmethod
    def _expression_symbol(expression: Any) -> str:
        if not isinstance(expression, Mapping):
            return ""
        if expression.get("kind") == "variable":
            return str(expression.get("name", ""))
        if expression.get("kind") == "selector":
            base = SourceIndex._expression_symbol(expression.get("base"))
            return f"{base}.{expression.get('field', '')}" if base else ""
        return ""


class SQLiteSourceIndex:
    """Disk-backed, bounded source index for large multi-module dependency graphs."""

    SCHEMA_VERSION = "4"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        self._db.execute("PRAGMA query_only=ON")
        self.truncated, self.function_count, self.unresolved_calls, self.ambiguous_calls, self.edge_count = self._metadata()
        values = dict(self._db.execute("SELECT key, value FROM meta"))
        self.type_count = int(values.get("types", "0"))
        self.type_truncated = values.get("types_truncated") == "1"

    @classmethod
    def build(
        cls,
        source_path: str | Path,
        index_path: str | Path,
        *,
        max_records: int,
        max_bytes: int,
        max_line_bytes: int,
        types_path: str | Path | None = None,
        max_type_records: int = 200_000,
        max_type_bytes: int = 64 << 20,
        max_type_line_bytes: int = 64 << 10,
    ) -> "SQLiteSourceIndex":
        if min(max_records, max_bytes, max_line_bytes, max_type_records, max_type_bytes, max_type_line_bytes) <= 0:
            raise ValueError("source index limits must be positive")
        source = Path(source_path)
        type_source = Path(types_path) if types_path is not None else None
        destination = Path(index_path)
        stat = source.stat()
        type_stat = type_source.stat() if type_source is not None else None
        destination.parent.mkdir(parents=True, exist_ok=True)
        valid = False
        if destination.exists():
            try:
                with sqlite3.connect(f"file:{destination}?mode=ro", uri=True) as existing:
                    meta = dict(existing.execute("SELECT key, value FROM meta"))
                valid = (
                    meta.get("schema") == cls.SCHEMA_VERSION
                    and meta.get("source_size") == str(stat.st_size)
                    and meta.get("source_mtime_ns") == str(stat.st_mtime_ns)
                    and meta.get("types_size") == str(type_stat.st_size if type_stat else 0)
                    and meta.get("types_mtime_ns") == str(type_stat.st_mtime_ns if type_stat else 0)
                )
            except sqlite3.Error:
                valid = False
        if not valid:
            destination.unlink(missing_ok=True)
            destination.with_suffix(destination.suffix + "-journal").unlink(missing_ok=True)
            cls._build_database(
                source, destination, stat.st_size, stat.st_mtime_ns, max_records, max_bytes, max_line_bytes,
                type_source, type_stat.st_size if type_stat else 0, type_stat.st_mtime_ns if type_stat else 0,
                max_type_records, max_type_bytes, max_type_line_bytes,
            )
        return cls(destination)

    @classmethod
    def _build_database(
        cls,
        source: Path,
        destination: Path,
        source_size: int,
        source_mtime_ns: int,
        max_records: int,
        max_bytes: int,
        max_line_bytes: int,
        types_source: Path | None,
        types_size: int,
        types_mtime_ns: int,
        max_type_records: int,
        max_type_bytes: int,
        max_type_line_bytes: int,
    ) -> None:
        db = sqlite3.connect(destination)
        try:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute("PRAGMA cache_size=-8192")
            db.execute("PRAGMA temp_store=FILE")
            db.executescript(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "CREATE TABLE functions (identity TEXT PRIMARY KEY, package TEXT NOT NULL, "
                "symbol TEXT NOT NULL, short_symbol TEXT NOT NULL, receiver_name TEXT NOT NULL, payload TEXT NOT NULL);"
                "CREATE TABLE calls (caller TEXT NOT NULL, package TEXT NOT NULL, "
                "short_name TEXT NOT NULL, import_path TEXT NOT NULL, receiver_package TEXT NOT NULL, "
                "receiver_name TEXT NOT NULL, evidence TEXT NOT NULL);"
                "CREATE TABLE types (identity TEXT PRIMARY KEY, package TEXT NOT NULL, name TEXT NOT NULL, "
                "type_kind TEXT NOT NULL, type_expr TEXT NOT NULL, payload TEXT NOT NULL);"
                "CREATE TABLE type_fields (type_identity TEXT NOT NULL, ordinal INTEGER NOT NULL, "
                "name TEXT NOT NULL, type_expr TEXT NOT NULL, tag TEXT NOT NULL, embedded INTEGER NOT NULL, "
                "field_kind TEXT NOT NULL, line INTEGER NOT NULL, PRIMARY KEY(type_identity, ordinal));"
                "CREATE INDEX functions_short ON functions(short_symbol);"
                "CREATE INDEX functions_package_short ON functions(package, short_symbol);"
                "CREATE INDEX functions_receiver_method ON functions(receiver_name, short_symbol);"
                "CREATE INDEX types_package_name ON types(package, name);"
                "CREATE INDEX type_fields_name ON type_fields(type_identity, name);"
                "CREATE INDEX calls_short ON calls(short_name);"
                "CREATE INDEX calls_package_short ON calls(package, short_name);"
            )
            consumed = 0
            records = 0
            truncated = False
            pending_calls: list[tuple[str, str, str, str, str, str, str]] = []
            with source.open("rb") as stream, db:
                while True:
                    line = stream.readline(max_line_bytes + 1)
                    if not line:
                        break
                    consumed += len(line)
                    if len(line) > max_line_bytes or consumed > max_bytes:
                        truncated = True
                        break
                    fact = json.loads(line)
                    if fact.get("kind") == "source-facts.limit":
                        truncated = True
                        break
                    if fact.get("kind") != "function":
                        continue
                    records += 1
                    if records > max_records:
                        truncated = True
                        break
                    package = str(fact.get("package", ""))
                    symbol = str(fact.get("symbol", ""))
                    identity = f"{package}.{symbol}"
                    receiver_type = str(fact.get("receiver", {}).get("type", ""))
                    _, receiver_name = _receiver_identity(receiver_type, fact.get("imports", {}), package)
                    db.execute(
                        "INSERT OR REPLACE INTO functions VALUES (?, ?, ?, ?, ?, ?)",
                        (identity, package, symbol, symbol.rsplit(".", 1)[-1], receiver_name, line.decode("utf-8")),
                    )
                    for call in fact.get("calls", ()):
                        name = str(call)
                        qualifier = name.split(".", 1)[0]
                        receiver_type = str(fact.get("call_receiver_types", {}).get(name, ""))
                        import_path = "" if receiver_type else str(fact.get("imports", {}).get(qualifier, ""))
                        receiver_package, receiver_name = _receiver_identity(receiver_type, fact.get("imports", {}), package)
                        pending_calls.append((identity, package, name.rsplit(".", 1)[-1], import_path, receiver_package, receiver_name, name))
                    if len(pending_calls) >= 2000:
                        db.executemany("INSERT INTO calls VALUES (?, ?, ?, ?, ?, ?, ?)", pending_calls)
                        pending_calls.clear()
            if pending_calls:
                db.executemany("INSERT INTO calls VALUES (?, ?, ?, ?, ?, ?, ?)", pending_calls)
            db.execute("CREATE INDEX calls_caller ON calls(caller)")
            function_count = int(db.execute("SELECT COUNT(*) FROM functions").fetchone()[0])
            unresolved, ambiguous, edges = cls._call_stats(db)
            type_count, type_truncated = cls._ingest_types(
                db, types_source, max_type_records, max_type_bytes, max_type_line_bytes,
            )
            metadata = {
                "schema": cls.SCHEMA_VERSION,
                "source_size": str(source_size),
                "source_mtime_ns": str(source_mtime_ns),
                "source_path": str(source.resolve()),
                "types_path": str(types_source.resolve()) if types_source else "",
                "types_size": str(types_size),
                "types_mtime_ns": str(types_mtime_ns),
                "functions": str(function_count),
                "types": str(type_count),
                "types_truncated": "1" if type_truncated else "0",
                "unresolved_calls": str(unresolved),
                "ambiguous_calls": str(ambiguous),
                "edges": str(edges),
                "truncated": "1" if truncated else "0",
            }
            db.executemany("INSERT INTO meta VALUES (?, ?)", metadata.items())
            db.commit()
        finally:
            db.close()

    @staticmethod
    def _ingest_types(
        db: sqlite3.Connection, source: Path | None, max_records: int, max_bytes: int, max_line_bytes: int,
    ) -> tuple[int, bool]:
        if source is None:
            return 0, False
        consumed = 0
        records = 0
        truncated = False
        with source.open("rb") as stream, db:
            while True:
                line = stream.readline(max_line_bytes + 1)
                if not line:
                    break
                consumed += len(line)
                if len(line) > max_line_bytes or consumed > max_bytes:
                    truncated = True
                    break
                fact = json.loads(line)
                if fact.get("kind") == "source-types.limit":
                    truncated = True
                    break
                if fact.get("kind") != "type":
                    continue
                records += 1
                if records > max_records:
                    truncated = True
                    break
                package = str(fact.get("package", ""))
                name = str(fact.get("name", ""))
                identity = f"{package}.{name}"
                db.execute(
                    "INSERT OR REPLACE INTO types VALUES (?, ?, ?, ?, ?, ?)",
                    (identity, package, name, str(fact.get("type_kind", "unknown")),
                     str(fact.get("type_expr", "")), line.decode("utf-8")),
                )
                fields = fact.get("fields", ())
                db.executemany(
                    "INSERT OR REPLACE INTO type_fields VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        (identity, ordinal, str(item.get("name", "")), str(item.get("type", "")),
                         str(item.get("tag", "")), int(bool(item.get("embedded", False))),
                         str(item.get("kind", "unknown")), int(item.get("line", 0)))
                        for ordinal, item in enumerate(fields)
                    ),
                )
        return int(db.execute("SELECT COUNT(*) FROM types").fetchone()[0]), truncated

    @staticmethod
    def _resolve_rows(
        db: sqlite3.Connection, package: str, short_name: str, import_path: str = "",
        receiver_package: str = "", receiver_name: str = "",
    ) -> tuple[str, ...]:
        if import_path:
            return tuple(row[0] for row in db.execute(
                "SELECT identity FROM functions WHERE package=? AND short_symbol=? ORDER BY identity",
                (import_path, short_name),
            ))
        if receiver_name:
            query = "SELECT identity FROM functions WHERE receiver_name=? AND short_symbol=?"
            args: tuple[str, ...] = (receiver_name, short_name)
            if receiver_package:
                query += " AND package=?"
                args += (receiver_package,)
            return tuple(row[0] for row in db.execute(query + " ORDER BY identity", args))
        rows = tuple(row[0] for row in db.execute(
            "SELECT identity FROM functions WHERE package=? AND short_symbol=? ORDER BY identity",
            (package, short_name),
        ))
        if rows:
            return rows
        remote = tuple(row[0] for row in db.execute(
            "SELECT identity FROM functions WHERE short_symbol=? ORDER BY identity", (short_name,)
        ))
        return remote if len(remote) == 1 else ()

    @classmethod
    def _call_stats(cls, db: sqlite3.Connection) -> tuple[int, int, int]:
        unresolved = ambiguous = edges = 0
        for package, short_name, import_path, receiver_package, receiver_name in db.execute(
            "SELECT DISTINCT package, short_name, import_path, receiver_package, receiver_name FROM calls"
        ):
            candidates = cls._resolve_rows(db, package, short_name, import_path, receiver_package, receiver_name)
            count = int(db.execute(
                "SELECT COUNT(*) FROM calls WHERE package=? AND short_name=? AND import_path=? AND receiver_package=? AND receiver_name=?",
                (package, short_name, import_path, receiver_package, receiver_name),
            ).fetchone()[0])
            if not candidates:
                local = int(db.execute(
                    "SELECT COUNT(*) FROM functions WHERE package=? AND short_symbol=?", (package, short_name)
                ).fetchone()[0])
                remote = int(db.execute(
                    "SELECT COUNT(*) FROM functions WHERE short_symbol=?", (short_name,)
                ).fetchone()[0])
                if not import_path and not local and remote > 1:
                    ambiguous += count
                else:
                    unresolved += count
            elif len(candidates) > 1:
                ambiguous += count
                edges += count * len(candidates)
            else:
                edges += count
        return unresolved, ambiguous, edges

    def _metadata(self) -> tuple[bool, int, int, int, int]:
        values = dict(self._db.execute("SELECT key, value FROM meta"))
        if values.get("schema") != self.SCHEMA_VERSION:
            raise ValueError("unsupported SQLite source index schema")
        return (
            values.get("truncated") == "1",
            int(values.get("functions", "0")),
            int(values.get("unresolved_calls", "0")),
            int(values.get("ambiguous_calls", "0")),
            int(values.get("edges", "0")),
        )

    def function(self, identity: str) -> SourceFunction | None:
        row = self._db.execute("SELECT payload FROM functions WHERE identity=?", (identity,)).fetchone()
        if row is None:
            return None
        item = json.loads(row[0])
        return SourceFunction(
            package=str(item.get("package", "")), symbol=str(item.get("symbol", "")),
            file=str(item.get("file", "")), start_line=int(item.get("start_line", 0)),
            end_line=int(item.get("end_line", 0)), parameters=tuple(item.get("parameters", ())),
            calls=tuple(str(value) for value in item.get("calls", ())),
            conditions=tuple(item.get("conditions", ())), assignments=tuple(item.get("assignments", ())),
            returns=tuple(str(value) for value in item.get("returns", ())),
            imports=dict(item.get("imports", {})),
            receiver=dict(item.get("receiver", {})),
            call_receiver_types=dict(item.get("call_receiver_types", {})),
            return_sites=tuple(item.get("return_sites", ())),
            control_transfers=tuple(item.get("control_transfers", ())),
        )

    def source_type(self, identity: str) -> SourceType | None:
        row = self._db.execute("SELECT payload FROM types WHERE identity=?", (identity,)).fetchone()
        if row is None:
            return None
        item = json.loads(row[0])
        fields = tuple(
            SourceTypeField(str(name), str(type_expr), str(tag), bool(embedded), str(field_kind), int(line))
            for name, type_expr, tag, embedded, field_kind, line in self._db.execute(
                "SELECT name, type_expr, tag, embedded, field_kind, line FROM type_fields "
                "WHERE type_identity=? ORDER BY ordinal", (identity,),
            )
        )
        return SourceType(
            str(item.get("package", "")), str(item.get("name", "")),
            str(item.get("file", "")), int(item.get("line", 0)),
            str(item.get("type_kind", "unknown")), str(item.get("type_expr", "")),
            bool(item.get("alias", False)), dict(item.get("imports", {})), fields,
        )

    def types_for_package(self, package: str, *, limit: int = 1000) -> tuple[SourceType, ...]:
        if limit <= 0:
            raise ValueError("type query limit must be positive")
        identities = self._db.execute(
            "SELECT identity FROM types WHERE package=? ORDER BY name LIMIT ?", (package, limit)
        )
        return tuple(item for identity, in identities if (item := self.source_type(identity)) is not None)

    def field_path(self, type_identity: str, path: tuple[str, ...] | list[str]) -> FieldPathEvidence:
        requested = tuple(path)
        if not requested:
            return FieldPathEvidence(type_identity, requested, "invalid", reason="field path must not be empty")
        current = self.source_type(type_identity)
        if current is None:
            return FieldPathEvidence(type_identity, requested, "type-not-found", reason="source type declaration is absent")
        evidence: list[SourceTypeField] = []
        for index, field_name in enumerate(requested):
            field = next((item for item in current.fields if item.name == field_name), None)
            if field is None:
                return FieldPathEvidence(
                    type_identity, requested, "field-not-declared", tuple(evidence),
                    f"{current.identity} has no declared field {field_name!r}",
                )
            evidence.append(field)
            if index + 1 < len(requested):
                target = _named_type_identity(field.type_expr, current.imports, current.package)
                if target is None:
                    return FieldPathEvidence(
                        type_identity, requested, "nested-type-unresolved", tuple(evidence),
                        f"field {field_name!r} does not resolve to a named source type",
                    )
                nested = self.source_type(target)
                if nested is None:
                    return FieldPathEvidence(
                        type_identity, requested, "nested-type-not-indexed", tuple(evidence),
                        f"nested type declaration {target} is absent from this index",
                    )
                if nested.alias:
                    alias_target = _named_type_identity(nested.type_expr, nested.imports, nested.package)
                    nested = self.source_type(alias_target) if alias_target else None
                    if nested is None:
                        return FieldPathEvidence(
                            type_identity, requested, "alias-target-unresolved", tuple(evidence),
                            f"alias {target} does not resolve to an indexed named type",
                        )
                current = nested
        return FieldPathEvidence(type_identity, requested, "declared", tuple(evidence))

    def _resolve(self, caller: SourceFunction, call: str) -> tuple[str, ...]:
        qualifier = call.split(".", 1)[0]
        receiver_type = caller.call_receiver_types.get(call, "")
        return self._resolve_rows(
            self._db, caller.package, call.rsplit(".", 1)[-1],
            "" if receiver_type else caller.imports.get(qualifier, ""),
            *_receiver_identity(receiver_type, caller.imports, caller.package),
        )

    def callees(self, identity: str) -> tuple[SourceFunction, ...]:
        caller = self.function(identity)
        if caller is None:
            return ()
        targets = sorted({target for call in caller.calls for target in self._resolve(caller, call)})
        return tuple(item for target in targets if (item := self.function(target)) is not None)

    def callers(self, identity: str) -> tuple[SourceFunction, ...]:
        target = self.function(identity)
        if target is None:
            return ()
        candidates = self._db.execute(
            "SELECT DISTINCT caller, package, short_name, import_path, receiver_package, receiver_name FROM calls WHERE short_name=?",
            (target.symbol.rsplit(".", 1)[-1],),
        )
        callers = set()
        for caller_id, package, short_name, import_path, receiver_package, receiver_name in candidates:
            if identity in self._resolve_rows(self._db, package, short_name, import_path, receiver_package, receiver_name):
                callers.add(caller_id)
        return tuple(item for caller_id in sorted(callers) if (item := self.function(caller_id)) is not None)

    def relations(self, identity: str) -> tuple[SourceRelation, ...]:
        function = self.function(identity)
        if function is None:
            raise KeyError(f"source function not found: {identity}")
        relations = []
        for call in function.calls:
            candidates = self._resolve(function, call)
            status = "resolved" if len(candidates) == 1 else "ambiguous" if candidates else "unresolved"
            relations.extend(SourceRelation("call", identity, target, status, call) for target in candidates)
            if not candidates:
                relations.append(SourceRelation("call", identity, call, status, call))
        for assignment in function.assignments:
            expression = assignment.get("value")
            if not isinstance(expression, Mapping) or expression.get("kind") != "unary" or expression.get("operator") != "&":
                continue
            target = str(assignment.get("target", ""))
            source = SourceIndex._expression_symbol(expression.get("operand"))
            if target and source:
                relations.append(SourceRelation("address-alias-candidate", target, source, "candidate", f"{identity}:{assignment.get('line', 0)}"))
        return tuple(relations)

    def compile_conditions(self, identity: str, bindings: Mapping[str, tuple[Any, ...]]) -> tuple[CompiledFormula, ...]:
        function = self.function(identity)
        if function is None:
            raise KeyError(f"source function not found: {identity}")
        compiler = FormulaCompiler()
        return tuple(
            compiler.compile(condition["expr"], bindings) if isinstance(condition.get("expr"), Mapping)
            else CompiledFormula(None, False, ("condition has no normalized expression tree",))
            for condition in function.conditions
        )

    def compile_assignments(
        self, identity: str, bindings: Mapping[str, tuple[Any, ...]], targets: Mapping[str, str]
    ) -> tuple[CompiledAssignment, ...]:
        function = self.function(identity)
        if function is None:
            raise KeyError(f"source function not found: {identity}")
        compiler = FormulaCompiler()
        result = []
        for assignment in function.assignments:
            expression = assignment.get("value")
            formula = compiler.compile(expression, bindings) if isinstance(expression, Mapping) else CompiledFormula(
                None, False, ("assignment is not a supported single-value assignment",)
            )
            path = tuple(str(item) for item in assignment.get("path", ()))
            path_guards, path_limitations = _compile_path_guards(path, function.conditions, bindings)
            result.append(CompiledAssignment(
                targets.get(str(assignment.get("target", ""))), formula, int(assignment.get("line", 0)),
                path, path_guards, path_limitations,
            ))
        return tuple(result)

    def compile_returns(self, identity: str, bindings: Mapping[str, tuple[Any, ...]]) -> tuple[CompiledExit, ...]:
        function = self.function(identity)
        if function is None:
            raise KeyError(f"source function not found: {identity}")
        return _compile_return_sites(function, bindings)

    def paths(self, source: str, target: str, *, max_depth: int = 16, max_paths: int = 1000) -> tuple[tuple[str, ...], ...]:
        if max_depth < 0 or max_paths <= 0:
            raise ValueError("source path bounds must be non-negative depth and positive count")
        if self.function(source) is None or self.function(target) is None:
            return ()
        queue = deque([(source, (source,))])
        found = []
        frontier_limit = max_paths * max(1, max_depth)
        while queue and len(found) < max_paths:
            current, path = queue.popleft()
            if current == target:
                found.append(path)
                continue
            if len(path) - 1 >= max_depth:
                continue
            for following in (item.identity for item in self.callees(current)):
                if following not in path:
                    if len(queue) >= frontier_limit:
                        raise OverflowError("source route frontier exceeded its explicit bound")
                    queue.append((following, path + (following,)))
        return tuple(found)

    def summary(self) -> Mapping[str, Any]:
        packages = int(self._db.execute("SELECT COUNT(DISTINCT package) FROM functions").fetchone()[0])
        return {
            "status": "PARTIAL" if self.truncated or self.type_truncated or self.unresolved_calls or self.ambiguous_calls else "IMPLEMENTED",
            "functions": self.function_count,
            "packages": packages,
            "candidate_call_edges": self.edge_count,
            "unresolved_calls": self.unresolved_calls,
            "ambiguous_calls": self.ambiguous_calls,
            "truncated": self.truncated,
            "types": self.type_count,
            "types_truncated": self.type_truncated,
            "semantics": "candidate source structure; executable branch and value relations are not inferred",
            "storage": "sqlite-disk-backed",
        }

    def close(self) -> None:
        self._db.close()
