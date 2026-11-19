"""Z3-backed implementation of RSVE's small solver-neutral constraint subset."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Mapping

import z3

from .constraints import (
    AllOf,
    AnyOf,
    Arithmetic,
    Constraint,
    Equal,
    FiniteEnum,
    IntRange,
    Literal,
    NamedAssumption,
    Negate,
    Sort,
    StateRelation,
    Variable,
)
from .adapters import Capabilities
from .ir import ResultScope
from .results import SolverStatus
from .schema import SCHEMA_VERSION, encode


@dataclass(frozen=True)
class SolverLimits:
    timeout_ms: int | None = None
    memory_mb: int | None = None

    def __post_init__(self) -> None:
        if self.timeout_ms is not None and self.timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        if self.memory_mb is not None and self.memory_mb <= 0:
            raise ValueError("memory_mb must be positive")


@dataclass(frozen=True)
class ConstraintQuery:
    query_id: str
    formula: Constraint
    scope: ResultScope | None = None
    assumptions: tuple[str, ...] = ()
    limits: SolverLimits = field(default_factory=SolverLimits)

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "type": "ConstraintQuery",
            "payload": {
                "query_id": self.query_id,
                "formula": self.formula.to_record(),
                "scope": self.scope.to_record() if self.scope else None,
                "assumptions": list(self.assumptions),
                "limits": encode(self.limits),
            },
        }


@dataclass(frozen=True)
class SolverResult:
    status: SolverStatus
    query_id: str
    backend: str
    backend_version: str
    options: Mapping[str, Any]
    query: str
    assumptions: tuple[str, ...] = ()
    named_assertions: tuple[str, ...] = ()
    model: Mapping[str, Any] = field(default_factory=dict)
    unsat_core: tuple[str, ...] = ()
    proof_artifact: bytes | None = None
    unknown_reason: str | None = None
    scope: ResultScope | None = None

    @property
    def has_proof(self) -> bool:
        return self.proof_artifact is not None

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "type": "SolverResult",
            "payload": {
                "status": self.status.value,
                "query_id": self.query_id,
                "backend": self.backend,
                "backend_version": self.backend_version,
                "options": encode(dict(self.options)),
                "query": self.query,
                "assumptions": list(self.assumptions),
                "named_assertions": list(self.named_assertions),
                "model": encode(dict(self.model)),
                "unsat_core": list(self.unsat_core),
                "proof_artifact": encode(self.proof_artifact) if self.proof_artifact else None,
                "unknown_reason": self.unknown_reason,
                "scope": self.scope.to_record() if self.scope else None,
            },
        }


class UnsupportedConstraint(ValueError):
    """Raised internally when the selected backend cannot encode a node."""


class _Translator:
    def __init__(self) -> None:
        self.variables: dict[str, z3.ExprRef] = {}

    def variable(self, variable: Variable) -> z3.ExprRef:
        if variable.sort is Sort.BOOL:
            expr = z3.Bool(variable.name)
        elif variable.sort is Sort.INT:
            expr = z3.Int(variable.name)
        elif variable.sort is Sort.BITVECTOR:
            expr = z3.BitVec(variable.name, variable.width or 0)
        elif variable.sort is Sort.STRING:
            expr = z3.String(variable.name)
        else:
            raise UnsupportedConstraint(f"sort {variable.sort.value} is not supported by the Z3 adapter")
        self.variables[variable.name] = expr
        return expr

    def literal(self, literal: Literal, expected: z3.ExprRef | None = None) -> z3.ExprRef:
        if literal.sort is Sort.BOOL:
            return z3.BoolVal(bool(literal.value))
        if literal.sort is Sort.INT:
            return z3.IntVal(int(literal.value))
        if literal.sort is Sort.BITVECTOR:
            if expected is None or not z3.is_bv(expected):
                raise UnsupportedConstraint("bitvector literals require a bitvector variable context")
            return z3.BitVecVal(int(literal.value), expected.size())
        if literal.sort is Sort.STRING:
            return z3.StringVal(str(literal.value))
        raise UnsupportedConstraint(f"sort {literal.sort.value} is not supported by the Z3 adapter")

    def expr(self, node: Constraint) -> z3.ExprRef:
        if isinstance(node, Variable):
            return self.variable(node)
        if isinstance(node, Literal):
            return self.literal(node)
        if isinstance(node, Equal):
            if isinstance(node.left, Literal) and not isinstance(node.right, Literal):
                right = self.expr(node.right)
                left = self.literal(node.left, right)
            elif isinstance(node.right, Literal) and not isinstance(node.left, Literal):
                left = self.expr(node.left)
                right = self.literal(node.right, left)
            else:
                left = self.expr(node.left)
                right = self.expr(node.right)
            return left == right
        if isinstance(node, Arithmetic):
            left = self.expr(node.left)
            right = self.expr(node.right)
            if node.operator == "+":
                return left + right
            if node.operator == "-":
                return left - right
            if node.operator == "*":
                return left * right
            raise UnsupportedConstraint(f"arithmetic operator {node.operator!r} is unsupported")
        if isinstance(node, IntRange):
            value = self.expr(node.value)
            if z3.is_bv(value):
                return z3.And(z3.UGE(value, z3.BitVecVal(node.minimum, value.size())), z3.ULE(value, z3.BitVecVal(node.maximum, value.size())))
            return z3.And(value >= node.minimum, value <= node.maximum)
        if isinstance(node, FiniteEnum):
            value = self.expr(node.value)
            terms = []
            for item in node.values:
                if z3.is_bool(value):
                    literal = z3.BoolVal(bool(item))
                elif z3.is_int_value(value) or z3.is_int(value):
                    literal = z3.IntVal(int(item))
                elif z3.is_bv(value):
                    literal = z3.BitVecVal(int(item), value.size())
                elif z3.is_string(value):
                    literal = z3.StringVal(str(item))
                else:
                    raise UnsupportedConstraint("finite enum value has unsupported sort")
                terms.append(value == literal)
            return z3.Or(*terms)
        if isinstance(node, AllOf):
            return z3.And(*(self.expr(term) for term in node.terms))
        if isinstance(node, AnyOf):
            return z3.Or(*(self.expr(term) for term in node.terms))
        if isinstance(node, Negate):
            return z3.Not(self.expr(node.term))
        if isinstance(node, StateRelation):
            left = self.expr(node.left)
            right = self.expr(node.right)
            return {
                "=": left == right,
                "==": left == right,
                "!=": left != right,
                "<": left < right,
                "<=": left <= right,
                ">": left > right,
                ">=": left >= right,
            }.get(node.relation, self._unsupported_relation(node.relation))
        if isinstance(node, NamedAssumption):
            return self.expr(node.term)
        raise UnsupportedConstraint(f"constraint node {type(node).__name__} is unsupported")

    @staticmethod
    def _unsupported_relation(relation: str) -> z3.ExprRef:
        raise UnsupportedConstraint(f"relation {relation!r} is unsupported")


def _smt2(node: Constraint) -> str:
    """Stable human-readable query form; backend translation remains authoritative."""
    if isinstance(node, Variable):
        return node.name
    if isinstance(node, Literal):
        if node.sort is Sort.BOOL:
            return "true" if node.value else "false"
        if node.sort is Sort.STRING:
            return '"' + str(node.value).replace('"', '\\"') + '"'
        return str(node.value)
    if isinstance(node, Equal):
        return f"(= {_smt2(node.left)} {_smt2(node.right)})"
    if isinstance(node, Arithmetic):
        return f"({node.operator} {_smt2(node.left)} {_smt2(node.right)})"
    if isinstance(node, IntRange):
        return f"(and (>= {_smt2(node.value)} {node.minimum}) (<= {_smt2(node.value)} {node.maximum}))"
    if isinstance(node, FiniteEnum):
        return "(or " + " ".join(f"(= {_smt2(node.value)} {item!r})" for item in node.values) + ")"
    if isinstance(node, AllOf):
        return "(and " + " ".join(_smt2(term) for term in node.terms) + ")"
    if isinstance(node, AnyOf):
        return "(or " + " ".join(_smt2(term) for term in node.terms) + ")"
    if isinstance(node, Negate):
        return f"(not {_smt2(node.term)})"
    if isinstance(node, StateRelation):
        return f"({node.relation} {_smt2(node.left)} {_smt2(node.right)})"
    if isinstance(node, NamedAssumption):
        return f"(! {_smt2(node.term)} :named {node.name})"
    raise UnsupportedConstraint(type(node).__name__)


class Z3SolverAdapter:
    """Thin adapter; no Z3 objects escape through the result contract."""

    backend_name = "z3"

    def __init__(self, *, capture_proofs: bool = False) -> None:
        self.capture_proofs = capture_proofs

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(
            symbolize=True,
            prove=self.capture_proofs,
            models=True,
            unsat_cores=True,
            proof_artifacts=self.capture_proofs,
            incremental_scopes=True,
        )

    def solve(self, query: ConstraintQuery, *, timeout_ms: int | None = None) -> SolverResult:
        translator = _Translator()
        options: dict[str, Any] = {"timeout_ms": timeout_ms or query.limits.timeout_ms}
        solver = z3.Solver()
        if options["timeout_ms"] is not None:
            solver.set(timeout=int(options["timeout_ms"]))
        if query.limits.memory_mb is not None:
            solver.set(max_memory=int(query.limits.memory_mb))
        if self.capture_proofs:
            solver.set(proof=True)
        try:
            from .constraints import named_assertions

            named = named_assertions(query.formula)
            root_expression: z3.ExprRef | None = None
            if named and isinstance(query.formula, AllOf):
                unwrapped = tuple(term for term in query.formula.terms if not isinstance(term, NamedAssumption))
                if unwrapped:
                    root_expression = translator.expr(unwrapped[0] if len(unwrapped) == 1 else AllOf(unwrapped))
                    solver.add(root_expression)
            elif named and isinstance(query.formula, NamedAssumption):
                pass
            else:
                root_expression = translator.expr(query.formula)
                solver.add(root_expression)
            for name, assertion in named:
                solver.assert_and_track(translator.expr(assertion), name)
            for name in query.assumptions:
                solver.assert_and_track(z3.Bool(name), name)
            query_text = root_expression.sexpr() if root_expression is not None else _smt2(query.formula)
        except (UnsupportedConstraint, ValueError) as exc:
            return SolverResult(
                status=SolverStatus.UNKNOWN,
                query_id=query.query_id,
                backend=self.backend_name,
                backend_version=z3.get_version_string(),
                options=options,
                query=repr(query.formula),
                assumptions=query.assumptions,
                named_assertions=tuple(name for name, _ in named_assertions(query.formula)) if "named_assertions" in locals() else (),
                unknown_reason=f"UNSUPPORTED: {exc}",
                scope=query.scope,
            )

        status = solver.check()
        if status == z3.sat:
            model = solver.model()
            values = {
                name: _model_value(model.eval(variable, model_completion=True))
                for name, variable in sorted(translator.variables.items())
            }
            return SolverResult(
                status=SolverStatus.SAT,
                query_id=query.query_id,
                backend=self.backend_name,
                backend_version=z3.get_version_string(),
                options=options,
                query=query_text,
                assumptions=query.assumptions,
                named_assertions=tuple(name for name, _ in named),
                model=values,
                scope=query.scope,
            )
        if status == z3.unsat:
            proof = None
            if self.capture_proofs:
                try:
                    proof = str(solver.proof()).encode("utf-8")
                except z3.Z3Exception:
                    proof = None
            return SolverResult(
                status=SolverStatus.UNSAT_BOUNDED,
                query_id=query.query_id,
                backend=self.backend_name,
                backend_version=z3.get_version_string(),
                options=options,
                query=query_text,
                assumptions=query.assumptions,
                named_assertions=tuple(name for name, _ in named),
                unsat_core=tuple(sorted(str(item) for item in solver.unsat_core())),
                proof_artifact=proof,
                scope=query.scope,
            )
        return SolverResult(
            status=SolverStatus.UNKNOWN,
            query_id=query.query_id,
            backend=self.backend_name,
            backend_version=z3.get_version_string(),
            options=options,
            query=query_text,
            assumptions=query.assumptions,
            named_assertions=tuple(name for name, _ in named),
            unknown_reason=solver.reason_unknown(),
            scope=query.scope,
        )

    @contextmanager
    def incremental(self) -> Iterator["IncrementalZ3Session"]:
        session = IncrementalZ3Session(self)
        try:
            yield session
        finally:
            session.close()


class IncrementalZ3Session:
    def __init__(self, adapter: Z3SolverAdapter) -> None:
        self.adapter = adapter
        self._constraints: list[Constraint] = []
        self._scopes: list[int] = []

    def add(self, constraint: Constraint) -> None:
        self._constraints.append(constraint)

    def push(self) -> None:
        self._scopes.append(len(self._constraints))

    def pop(self) -> None:
        if not self._scopes:
            raise IndexError("incremental solver scope underflow")
        del self._constraints[self._scopes.pop():]

    def solve(self, query_id: str = "incremental", *, scope: ResultScope | None = None) -> SolverResult:
        if not self._constraints:
            raise ValueError("incremental query has no constraints")
        formula = AllOf(tuple(self._constraints)) if len(self._constraints) > 1 else self._constraints[0]
        return self.adapter.solve(ConstraintQuery(query_id, formula, scope=scope))

    def close(self) -> None:
        self._constraints.clear()
        self._scopes.clear()


def _model_value(value: z3.ExprRef) -> Any:
    if z3.is_bool(value):
        return z3.is_true(value)
    if z3.is_int_value(value):
        return value.as_long()
    if z3.is_bv_value(value):
        return value.as_long()
    if z3.is_string_value(value):
        return value.as_string()
    return str(value)
