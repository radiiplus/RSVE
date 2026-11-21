"""Lower explicitly bound source facts into executable RSVE operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .logic import Arithmetic, Constraint, Either, Equal, Every, Literal, Negate, Rel, Sort, Variable
from .model import Decision, Entry, Fidelity, Mode, Operation, Outcome, State
from .source import CompiledAssignment, CompiledFormula, SourceFunction
from .source_profile import BindingSpace, SourceFunctionProfile, SourceProfile
from .wp import Symbolic


@dataclass(frozen=True)
class LoweringResult:
    """Lowered source operation with completeness and limitation evidence."""

    function_identity: str
    operation: Operation | None
    complete: bool
    limitations: tuple[str, ...] = ()

    @property
    def supported(self) -> bool:
        return self.operation is not None


class SourceSemanticLowerer:
    """Build executable operations from explicitly mapped normalized facts.

    The source index supplies syntax facts. The profile supplies their meaning
    in request and state space. Supported inexact expressions execute as
    uncertain relations and never receive symbolic transitions. This lowerer
    does not infer either mapping.
    """

    def lower(
        self,
        source_index: Any,
        profile: SourceProfile | SourceFunctionProfile,
        function_identity: str | None = None,
    ) -> LoweringResult:
        if isinstance(profile, SourceProfile):
            identity = function_identity or ""
            try:
                binding = profile.function(identity)
            except KeyError as exc:
                return LoweringResult(identity, None, False, (str(exc),))
        else:
            binding = profile
            identity = function_identity or binding.function_identity
            if identity != binding.function_identity:
                return LoweringResult(identity, None, False, ("requested source identity does not match the profile binding",))

        function = source_index.function(identity)
        if function is None:
            return LoweringResult(identity, None, False, (f"source function is absent from index: {identity}",))
        limitations = list(binding.limitations)
        execution_limitations: list[str] = []
        try:
            binding.validate(function, require_all_assignments=True)
        except (TypeError, ValueError) as exc:
            limitations.append(str(exc))
        if not binding.complete:
            limitations.append("source profile marks this function incomplete")
        if function.calls:
            limitations.append("function calls require separately lowered dependency semantics")
        if function.returns or function.return_sites:
            limitations.append("return values and return-path effects are not lowered")
        if function.control_transfers:
            limitations.append("control transfers are not lowered")
        declared_assignment_lines = {int(item.get("line", 0)) for item in function.assignments}
        selected_assignment_lines = set(binding.assignment_lines)
        if declared_assignment_lines != selected_assignment_lines:
            limitations.append("profile must select every source assignment before this function can be lowered")
        if limitations:
            return LoweringResult(identity, None, False, tuple(dict.fromkeys(limitations)))

        compiled_conditions = source_index.compile_conditions(identity, binding.compiler_bindings())
        conditions_by_line: dict[int, list[CompiledFormula]] = {}
        for source_condition, compiled in zip(function.conditions, compiled_conditions):
            conditions_by_line.setdefault(int(source_condition.get("line", 0)), []).append(compiled)
        guards: list[tuple[CompiledFormula, bool]] = []
        guard_lines_by_id: dict[int, int] = {}
        guard_senses = getattr(binding, "guard_senses", {})
        for line in binding.guard_lines:
            matches = conditions_by_line.get(line, [])
            guard = matches[0] if len(matches) == 1 else None
            sense = guard_senses.get(line)
            if sense is None:
                limitations.append(f"guard at source line {line} has no explicit accepted branch sense")
            elif len(matches) != 1:
                limitations.append(f"guard at source line {line} does not uniquely identify one condition")
            elif guard is None or not guard.supported:
                limitations.append(f"guard at source line {line} has no executable expression")
            elif _constraint_type(guard.formula) != (Sort.BOOL, None, None):
                limitations.append(f"guard at source line {line} is not an explicitly boolean expression")
            else:
                guards.append((guard, bool(sense)))
                guard_lines_by_id[id(guard)] = line
                if not guard.exact:
                    execution_limitations.append(
                        f"guard at source line {line} executes concretely but has inexact symbolic semantics"
                    )

        assignments = source_index.compile_assignments(
            identity,
            binding.compiler_bindings(),
            binding.assignment_targets,
        )
        selected: list[CompiledAssignment] = []
        assignments_by_line: dict[int, int] = {}
        for item in function.assignments:
            line = int(item.get("line", 0))
            assignments_by_line[line] = assignments_by_line.get(line, 0) + 1
        for assignment in assignments:
            if assignment.line not in selected_assignment_lines:
                continue
            if not assignment.supported:
                limitations.append(f"assignment at source line {assignment.line} has no executable expression")
            elif assignment.path_limitations or len(assignment.path_guards) != len(assignment.path) or any(
                not item.supported for item in assignment.path_guards
            ):
                limitations.append(f"assignment path at source line {assignment.line} is incomplete")
            elif assignments_by_line.get(assignment.line, 0) > 1:
                limitations.append(f"multiple assignments on source line {assignment.line} have unresolved evaluation ordering")
            else:
                target_name = str(next(
                    item.get("target", "")
                    for item in function.assignments
                    if int(item.get("line", 0)) == assignment.line
                ))
                target_binding = binding.symbols.get(target_name)
                if target_binding is None:
                    limitations.append(f"assignment target {target_name} has no typed state binding")
                    continue
                if target_binding.space is not BindingSpace.STATE:
                    limitations.append(f"assignment target {target_name} is not bound to state")
                    continue
                if target_binding.field != assignment.target:
                    limitations.append(f"assignment target {target_name} binding disagrees with its declared state target")
                    continue
                if _constraint_type(assignment.formula.formula) != (
                    target_binding.sort,
                    target_binding.width,
                    target_binding.signed,
                ):
                    limitations.append(f"assignment at source line {assignment.line} has a different sort from its state target")
                    continue
                selected.append(assignment)
                if not assignment.formula.exact:
                    execution_limitations.append(
                        f"assignment at source line {assignment.line} executes concretely but has inexact symbolic semantics"
                    )
                if any(not item.exact for item in assignment.path_guards):
                    execution_limitations.append(
                        f"assignment path at source line {assignment.line} has inexact symbolic guards"
                    )
        if limitations:
            return LoweringResult(identity, None, False, tuple(dict.fromkeys(limitations)))

        selected.sort(key=lambda item: item.line)
        state_targets = tuple(binding.assignment_targets[str(item.get("target", ""))] for item in function.assignments)
        reads = frozenset(
            symbol.field
            for symbol in binding.symbols.values()
            if symbol.space is BindingSpace.STATE
        )
        guard_formula = _conjunction(tuple(
            item.formula if sense else Negate(item.formula)
            for item, sense in guards
            if item.formula is not None
        ))

        def source_values(
            state: Mapping[str, Any],
            request: Mapping[str, Any],
            formulas: tuple[CompiledFormula, ...],
        ) -> Mapping[str, Any]:
            names = {
                name
                for formula in formulas
                for name in _source_names(formula.expression)
            }
            values = {}
            for name in names:
                symbol = binding.symbols[name]
                source = request if symbol.space is BindingSpace.REQUEST else state
                values[name] = _resolve(source, symbol.field)
            return values

        def concrete_guard(state: State, request: Mapping[str, Any]) -> bool:
            values = source_values(state.as_dict(), request, tuple(item for item, _sense in guards))
            return all(bool(item.evaluate(values)) == sense for item, sense in guards)

        def apply(state: State, request: Mapping[str, Any]) -> State:
            values = state.as_dict()
            for assignment in selected:
                formulas = (assignment.formula,) + assignment.path_guards
                evaluation_values = source_values(values, request, formulas)
                if not all(bool(item.evaluate(evaluation_values)) for item in assignment.path_guards):
                    continue
                result = assignment.formula.evaluate(evaluation_values)
                values[assignment.target or ""] = result
            return State(values)

        def uncertain_relation(state: State, request: Mapping[str, Any]) -> tuple[Outcome, ...]:
            max_branches = 64
            guard_paths: list[tuple[bool, bool, tuple[str, ...]]] = [(True, False, ())]
            try:
                for guard, sense in guards:
                    guard_value = bool(guard.evaluate(source_values(
                        state.as_dict(), request, (guard,),
                    ))) == sense
                    choices = (False, True) if not guard.exact else (guard_value,)
                    guard_paths = [
                        (accepted and choice, uncertain or not guard.exact,
                         reasons + ((f"inexact guard at source line {guard_lines_by_id[id(guard)]}",) if not guard.exact else ()))
                        for accepted, uncertain, reasons in guard_paths
                        for choice in choices
                    ]
                    if len(guard_paths) > max_branches:
                        break
            except Exception as exc:
                return (Outcome(
                    Decision.UNKNOWN,
                    state,
                    fidelity=Fidelity.MODELED,
                    mode=Mode.ABSTRACT,
                    evidence=(f"source-profile:{identity}",),
                    unknown=frozenset(state_targets),
                    uncertainty=(f"source guard evaluation failed: {type(exc).__name__}",),
                ),)

            if len(guard_paths) > max_branches:
                return (Outcome(
                    Decision.UNKNOWN,
                    state,
                    fidelity=Fidelity.MODELED,
                    mode=Mode.ABSTRACT,
                    evidence=(f"source-profile:{identity}",),
                    unknown=frozenset(state_targets),
                    uncertainty=(f"inexact source guard branching exceeded {max_branches} outcomes",),
                ),)

            results: list[Outcome] = []
            for accepted, guard_uncertain, guard_reasons in guard_paths:
                if not accepted:
                    results.append(Outcome(
                        Decision.UNKNOWN if guard_uncertain else Decision.REJECT,
                        state,
                        guard=False,
                        fidelity=Fidelity.MODELED,
                        mode=Mode.ABSTRACT,
                        evidence=(f"source-profile:{identity}",),
                        uncertainty=guard_reasons,
                    ))
                    continue

                worlds: list[tuple[dict[str, Any], frozenset[str], bool, tuple[str, ...]]] = [
                    (state.as_dict(), frozenset(), guard_uncertain, guard_reasons)
                ]
                failed = False
                for assignment in selected:
                    next_worlds = []
                    for values, unknown, uncertain, reasons in worlds:
                        try:
                            path_values = tuple(
                                bool(item.evaluate(source_values(values, request, (item,))))
                                for item in assignment.path_guards
                            )
                        except Exception as exc:
                            failed = True
                            next_worlds.append((values, unknown, True, reasons + (
                                f"assignment path evaluation failed at source line {assignment.line}: {type(exc).__name__}",
                            )))
                            continue
                        path_uncertain = any(not item.exact for item in assignment.path_guards)
                        applies = all(path_values)
                        choices = (False, True) if path_uncertain else (applies,)
                        for apply_assignment in choices:
                            if not apply_assignment:
                                next_worlds.append((
                                    dict(values), unknown, uncertain or path_uncertain,
                                    reasons + ((f"inexact assignment path at source line {assignment.line}",) if path_uncertain else ()),
                                ))
                                continue
                            updated = dict(values)
                            try:
                                evaluation_values = source_values(updated, request, (assignment.formula,))
                                result = assignment.formula.evaluate(evaluation_values)
                            except Exception as exc:
                                failed = True
                                next_worlds.append((updated, unknown | {assignment.target or ""}, True, reasons + (
                                    f"assignment evaluation failed at source line {assignment.line}: {type(exc).__name__}",
                                )))
                                continue
                            target = assignment.target or ""
                            updated[target] = result
                            inexact = not assignment.formula.exact
                            next_worlds.append((
                                updated,
                                unknown | ({target} if inexact else set()),
                                uncertain or path_uncertain or inexact,
                                reasons + ((f"inexact assignment value at source line {assignment.line}",) if inexact else ()),
                            ))
                    worlds = next_worlds
                    if len(worlds) > max_branches:
                        return (Outcome(
                            Decision.UNKNOWN,
                            state,
                            fidelity=Fidelity.MODELED,
                            mode=Mode.ABSTRACT,
                            evidence=(f"source-profile:{identity}",),
                            unknown=frozenset(state_targets),
                            uncertainty=(f"inexact source assignment branching exceeded {max_branches} outcomes",),
                        ),)
                for values, unknown, uncertain, reasons in worlds:
                    results.append(Outcome(
                        Decision.UNKNOWN if uncertain or failed else Decision.ACCEPT,
                        State(values),
                        guard=True,
                        fidelity=Fidelity.MODELED,
                        mode=Mode.ABSTRACT if uncertain or failed else Mode.SYMBOLIC,
                        evidence=(f"source-profile:{identity}",),
                        writes=frozenset(state_targets),
                        unknown=unknown,
                        uncertainty=reasons,
                    ))
            return tuple(results)

        symbolic = None
        if not execution_limitations and all(not item.path for item in selected):
            symbolic_assignments: dict[str, Constraint] = {}
            for assignment in selected:
                target = f"state.{assignment.target}"
                expression = assignment.formula.formula
                assert expression is not None
                symbolic_assignments[target] = _substitute_state(expression, symbolic_assignments)
            symbolic = Symbolic(
                transition_id=binding.operation_name or identity,
                entry_point=binding.entry_point,
                guard=guard_formula,
                assignments=symbolic_assignments,
                semantics_ref=f"rsve.source.operation:{identity}",
                semantics_version="1",
            )
        else:
            limitations.append(
                "symbolic backward semantics are unavailable for inexact expressions or path-conditioned writes"
            )

        all_limitations = tuple(dict.fromkeys((*limitations, *execution_limitations)))

        evidence = f"{function.file}:{function.start_line}-{function.end_line}"
        operation = Operation(
            name=binding.operation_name or identity,
            entry_point=Entry(binding.entry_point),
            guard=concrete_guard,
            apply=apply,
            fidelity=Fidelity.MODELED,
            provenance=f"source-profile:{identity}",
            mode=Mode.SYMBOLIC if symbolic is not None else Mode.ABSTRACT,
            component=binding.component,
            symbolic_transition=symbolic,
            relation=uncertain_relation if execution_limitations else None,
            reads=reads,
            writes=frozenset(state_targets),
            provenance_inputs=(evidence,),
        )
        return LoweringResult(identity, operation, symbolic is not None, all_limitations)


def _conjunction(formulas: tuple[Constraint | None, ...]) -> Constraint:
    terms = tuple(item for item in formulas if item is not None)
    if not terms:
        return Literal(True, Sort.BOOL)
    return terms[0] if len(terms) == 1 else Every(terms)


def _constraint_type(node: Constraint | None) -> tuple[Sort, int | None, bool | None] | None:
    if isinstance(node, Variable):
        return node.sort, node.width, node.signed
    if isinstance(node, Literal):
        return node.sort, None, None
    if isinstance(node, Arithmetic):
        left = _constraint_type(node.left)
        right = _constraint_type(node.right)
        if left == right:
            return left
        if left is not None and left[0] is Sort.BITVECTOR and isinstance(node.right, Literal):
            return left
        if right is not None and right[0] is Sort.BITVECTOR and isinstance(node.left, Literal):
            return right
        return None
    if isinstance(node, (Equal, Rel, Every, Either, Negate)):
        return Sort.BOOL, None, None
    return None


def _source_names(expression: Any) -> frozenset[str]:
    if not isinstance(expression, Mapping):
        return frozenset()
    kind = expression.get("kind")
    if kind == "variable":
        name = str(expression.get("name", ""))
        return frozenset() if name in {"", "true", "false"} else frozenset({name})
    if kind == "selector":
        base = _source_name(expression.get("base"))
        return frozenset({f"{base}.{expression.get('field', '')}"}) if base else frozenset()
    return frozenset(
        name
        for value in expression.values()
        for name in _source_names(value)
    )


def _source_name(expression: Any) -> str:
    if not isinstance(expression, Mapping):
        return ""
    if expression.get("kind") == "variable":
        return str(expression.get("name", ""))
    if expression.get("kind") == "selector":
        base = _source_name(expression.get("base"))
        return f"{base}.{expression.get('field', '')}" if base else ""
    return ""


def _resolve(values: Mapping[str, Any], field_name: str) -> Any:
    if field_name in values:
        return values[field_name]
    current: Any = values
    for part in field_name.split("."):
        if not isinstance(current, Mapping) or part not in current:
            raise KeyError(f"profile field not present: {field_name}")
        current = current[part]
    return current


def _substitute_state(node: Constraint, assignments: Mapping[str, Constraint]) -> Constraint:
    """Compose sequential exact assignments into one pre-state relation."""
    if isinstance(node, Variable):
        return assignments.get(node.name, node)
    if isinstance(node, Literal):
        return node
    if isinstance(node, Arithmetic):
        return Arithmetic(node.operator, _substitute_state(node.left, assignments), _substitute_state(node.right, assignments))
    if isinstance(node, (Equal, Rel)):
        return type(node)(
            _substitute_state(node.left, assignments),
            _substitute_state(node.right, assignments),
        ) if isinstance(node, Equal) else Rel(
            _substitute_state(node.left, assignments),
            node.relation,
            _substitute_state(node.right, assignments),
        )
    if isinstance(node, Every):
        return Every(tuple(_substitute_state(item, assignments) for item in node.terms))
    if isinstance(node, Either):
        return Either(tuple(_substitute_state(item, assignments) for item in node.terms))
    if isinstance(node, Negate):
        return Negate(_substitute_state(node.term, assignments))
    raise TypeError(f"unsupported symbolic source expression: {type(node).__name__}")
