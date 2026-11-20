"""Bounded hybrid objective planning over the platform-neutral transition model."""

from __future__ import annotations

import heapq
import hashlib
import json
import time
from dataclasses import dataclass, fields, is_dataclass, replace
from itertools import product
from typing import Any, Callable, Mapping, Sequence

from .adapter import Target
from .logic import Axiom, Every, Constraint, Equal, Literal, Sort, Variable
from .diff import Analyzer
from .index import Index
from .model import Authorization, Decision, Operation, State, Event, Model
from .objective import All, Some, Objective, Same
from .result import (
    Report,
    Status,
    Divergence,
    Grade,
    Proof,
    Gap,
    Verdict,
    Witness,
    Reach,
)
from .solver import Answer, Query, Stack, Zed, Unknown
from .wp import Symbolic, WP, Truth, rename
from .workspace import Frame, Workspace


@dataclass(frozen=True)
class Plan:
    objective_id: str
    required_actions: tuple[tuple[str, Mapping[str, Any]], ...]
    method: str
    complete: bool
    uncertainty: tuple[str, ...] = ()
    required_traces: tuple[tuple[Mapping[str, Any], ...], ...] = ()
    cores: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class Attempt:
    interactions: tuple[Mapping[str, Any], ...]
    predicted_events: tuple[Event, ...]
    replayed: bool
    objective_observed: bool | None
    observed_events: tuple[Event, ...] = ()
    replay_stable: bool | None = None
    divergences: tuple[Divergence, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class Distance:
    """Explainable search priority; never a reachability proof."""

    unmet: int
    writers: int
    uncertainty: int
    cost: int

    @property
    def score(self) -> int:
        return self.unmet * 100 + self.uncertainty * 50 + self.cost + max(0, 10 - self.writers)


def _sort_for(value: Any) -> Sort | None:
    if isinstance(value, bool):
        return Sort.BOOL
    if isinstance(value, int):
        return Sort.INT
    if isinstance(value, str):
        return Sort.STRING
    return None


def _transform_is_lossy(transform: Any) -> bool:
    marker = getattr(transform, "information_loss", False)
    return marker.value != "none" if hasattr(marker, "value") else bool(marker)


def _symbolic_postcondition(objective: Objective) -> Constraint | None:
    constraints: list[Constraint] = []
    for predicate in objective.postconditions:
        if not isinstance(predicate, Same):
            return None
        sort = _sort_for(predicate.expected)
        if sort is None:
            return None
        constraints.append(
            Equal(
                Variable(f"state.{predicate.key}", sort),
                Literal(predicate.expected, sort),
            )
        )
    if not constraints:
        return None
    return constraints[0] if len(constraints) == 1 else Every(tuple(constraints))


def _initial_state_constraints(state: State) -> list[Constraint]:
    constraints: list[Constraint] = []
    for key, value in sorted(state.as_dict().items()):
        sort = _sort_for(value)
        if sort is not None:
            constraints.append(Axiom(
                f"state:{key}",
                Equal(Variable(f"state.{key}", sort), Literal(value, sort)),
            ))
    return constraints


def _mentions(node: Constraint, prefix: str) -> bool:
    if isinstance(node, Variable):
        return node.name.startswith(prefix)
    if is_dataclass(node):
        return any(_mentions_value(getattr(node, field.name), prefix) for field in fields(node))
    return False


def _mentions_value(value: Any, prefix: str) -> bool:
    if isinstance(value, Constraint):
        return _mentions(value, prefix)
    if isinstance(value, (tuple, list)):
        return any(_mentions_value(item, prefix) for item in value)
    return False


def _request_for_step(model: Mapping[str, Any], index: int) -> dict[str, Any]:
    request: dict[str, Any] = {}
    indexed_prefixes = (f"input.{index}.", f"request.{index}.")
    for name, value in model.items():
        for prefix in indexed_prefixes:
            if name.startswith(prefix):
                request[name[len(prefix):]] = value
    if request:
        return request
    for name, value in model.items():
        for prefix in ("input.", "request."):
            if name.startswith(prefix) and "." not in name[len(prefix):]:
                request[name[len(prefix):]] = value
    return request


class Regressor:
    """Derive bounded preimages for supported concrete operations.

    This deliberately reports bounded preimage enumeration as incomplete for
    opaque or information-losing operations; it never constructs an inverse.
    """

    def regress(
        self,
        model: Model,
        objective: Objective,
        *,
        solver: Zed | None = None,
        solver_timeout_ms: int | None = None,
        workspace: Workspace | None = None,
    ) -> Plan:
        actions: list[tuple[str, Mapping[str, Any]]] = []
        uncertainty: list[str] = []
        cores: list[tuple[str, ...]] = []
        workspace = workspace or Workspace.flat(model)
        index = Index.build(model)
        needed = self._keys(objective.postconditions)
        indexed = [item.operation for item in index.chain(needed)] if needed else []
        seen = {(item.entry_point.name, item.name) for item in indexed}
        operations = tuple(indexed) + tuple(
            item for item in model.ops()
            if (item.entry_point.name, item.name) not in seen
        )
        if needed and not indexed:
            uncertainty.append("no indexed writer was found for the objective state keys")
        for operation in operations:
            requests: list[Mapping[str, Any]] = []
            seen_requests: set[str] = set()
            try:
                probes = workspace.probes_for(operation.entry_point.name, objective.budget.max_states)
            except Exception as exc:
                probes = ()
                uncertainty.append(
                    f"probe expansion for {operation.entry_point.name} is unknown: {type(exc).__name__}"
                )
            for candidate in model.args() + probes:
                key = self._request_key(candidate)
                if key in seen_requests:
                    continue
                seen_requests.add(key)
                requests.append(candidate)
            if len(requests) > objective.budget.max_states:
                uncertainty.append(
                    f"bounded concrete preimage probes truncated to {objective.budget.max_states} requests"
                )
                requests = requests[:objective.budget.max_states]
            for request in requests:
                if self.preimage(operation, request, objective, workspace=workspace)(model.initial_state):
                    actions.append((operation.entry_point.name, dict(request)))
        backend = solver or Zed()
        with backend.incremental() as session:
            workspace_actions, workspace_uncertainty, workspace_cores = self._symbolic_workspace(
                model,
                objective,
                workspace=workspace,
                solver=session,
                solver_timeout_ms=solver_timeout_ms,
            )
            symbolic_actions, symbolic_uncertainty, action_cores = self._symbolic_actions(
                model,
                objective,
                solver=session,
                solver_timeout_ms=solver_timeout_ms,
            )
            symbolic_traces, sequence_uncertainty, trace_cores = self._symbolic_traces(
                model,
                objective,
                solver=session,
                solver_timeout_ms=solver_timeout_ms,
            )
            cores.extend(workspace_cores)
            cores.extend(action_cores)
            cores.extend(trace_cores)
        for action in workspace_actions + symbolic_actions:
            if (action[0], self._request_key(action[1])) not in {
                (entry, self._request_key(request)) for entry, request in actions
            }:
                actions.append(action)
        uncertainty.extend(workspace_uncertainty)
        uncertainty.extend(symbolic_uncertainty)
        uncertainty.extend(sequence_uncertainty)
        for trace in symbolic_traces:
            for interaction in trace:
                action = (interaction["entry_point"], dict(interaction.get("request", {})))
                if (action[0], self._request_key(action[1])) not in {
                    (entry, self._request_key(request)) for entry, request in actions
                }:
                    actions.append(action)
        if not actions:
            uncertainty.append("no one-step preimage was found; longer paths use forward bounded exploration")
        if any(operation.transforms and any(_transform_is_lossy(transform) for transform in operation.transforms) for operation in model.operations):
            uncertainty.append("information-losing transforms require bounded forward/preimage search")
        if workspace.probes or workspace.expanders:
            uncertainty.append("opaque or unenumerated workspace semantics were checked only against bounded probes")
        return Plan(
            objective_id=objective.objective_id,
            required_actions=tuple(actions),
            method=("workspace+preimage+solver+sequence+bounded_preimage"
                    if workspace_actions or symbolic_actions or symbolic_traces or any(
                        operation.symbolic_transition is not None
                        for operation in model.operations
                    ) else "workspace+bounded_preimage_enumeration"
                    if workspace is not None and workspace.graph is not None
                    else "bounded_preimage_enumeration"),
            complete=False,
            uncertainty=tuple(uncertainty),
            required_traces=tuple(symbolic_traces),
            cores=tuple(cores),
        )

    @staticmethod
    def _keys(predicates: Sequence[Any]) -> frozenset[str]:
        found: set[str] = set()
        for predicate in predicates:
            if isinstance(predicate, Same):
                found.add(predicate.key)
            elif isinstance(predicate, (All, Some)):
                found.update(Regressor._keys(predicate.predicates))
        return frozenset(found)

    def _symbolic_traces(
        self,
        model: Model,
        objective: Objective,
        *,
        solver: Zed | Stack,
        solver_timeout_ms: int | None,
    ) -> tuple[list[tuple[Mapping[str, Any], ...]], list[str], list[tuple[str, ...]]]:
        symbolic_operations = tuple(
            operation for operation in model.ops()
            if operation.symbolic_transition is not None
        )
        if len(symbolic_operations) < 1 or objective.budget.max_trace_length < 2:
            return [], [], []
        postcondition = _symbolic_postcondition(objective)
        if postcondition is None:
            return [], ["multi-step symbolic regression supports Same postconditions only"], []
        initial_constraints = _initial_state_constraints(model.initial_state)
        traces: list[tuple[Mapping[str, Any], ...]] = []
        uncertainty: list[str] = []
        cores: list[tuple[str, ...]] = []
        examined = 0
        for length in range(2, objective.budget.max_trace_length + 1):
            for sequence in product(symbolic_operations, repeat=length):
                examined += 1
                if examined > min(objective.budget.max_states, 256):
                    uncertainty.append("multi-step symbolic sequence bound reached")
                    return traces, uncertainty, cores
                transitions = tuple(operation.symbolic_transition for operation in sequence)
                result = WP().derive(postcondition, transitions)
                if result.status is not Truth.EXACT or result.precondition is None:
                    continue
                formula: Constraint = result.precondition
                if initial_constraints:
                    formula = Every(tuple(initial_constraints) + (Axiom(
                        f"route:{objective.objective_id}:{length}:{examined}",
                        formula,
                    ),))
                solved = _solve(
                    solver,
                    Query(
                        f"wp-sequence:{objective.objective_id}:{length}:{examined}",
                        formula,
                    ),
                    timeout_ms=solver_timeout_ms,
                )
                if solved.status is Verdict.UNKNOWN:
                    uncertainty.append(solved.unknown_reason or "multi-step symbolic query returned UNKNOWN")
                    continue
                if solved.status is not Verdict.SAT:
                    if solved.status is Verdict.UNSAT_BOUNDED and solved.unsat_core:
                        cores.append(solved.unsat_core)
                    continue
                interactions = tuple(
                    {
                        "entry_point": operation.entry_point.name,
                        "request": _request_for_step(solved.model, index),
                    }
                    for index, operation in enumerate(sequence)
                )
                if all(interaction["request"] or operation.symbolic_transition is not None for interaction, operation in zip(interactions, sequence)):
                    traces.append(interactions)
        return traces, uncertainty, cores

    def _symbolic_workspace(
        self,
        model: Model,
        objective: Objective,
        *,
        workspace: Workspace,
        solver: Zed | Stack,
        solver_timeout_ms: int | None,
    ) -> tuple[list[tuple[str, Mapping[str, Any]]], list[str], list[tuple[str, ...]]]:
        """Regress supported graph routes into their original entry request."""
        if workspace.graph is None and workspace.world is None and not workspace.aliases and not workspace.resources:
            return [], [], []
        postcondition = _symbolic_postcondition(objective)
        if postcondition is None:
            return [], ["workspace symbolic regression supports Same postconditions only"], []
        actions: list[tuple[str, Mapping[str, Any]]] = []
        uncertainty: list[str] = []
        cores: list[tuple[str, ...]] = []
        examined = 0
        model_operations = {(item.name, item.entry_point.name) for item in model.ops()}
        for operation in workspace.operations():
            symbolic = operation.symbolic_transition
            synthetic = (operation.name, operation.entry_point.name) not in model_operations
            if symbolic is None and not synthetic:
                continue
            routes = workspace.routes(operation) if workspace.graph is not None else (((), ()),)
            for transitions, connections in routes:
                examined += 1
                if examined > min(objective.budget.max_states, 256):
                    uncertainty.append("workspace symbolic route bound reached")
                    return actions, uncertainty, cores
                steps, stage, missing = self._route_symbols(workspace, transitions, connections)
                if missing:
                    uncertainty.append(
                        f"workspace symbolic route for {operation.entry_point.name} is unknown: {', '.join(missing)}"
                    )
                    continue
                if symbolic is None:
                    symbolic = Symbolic(
                        f"workspace-end:{operation.name}",
                        operation.entry_point.name,
                        Equal(Literal(True, Sort.BOOL), Literal(True, Sort.BOOL)),
                    )
                resource_reason = workspace.symbolic_resource_reason(operation, symbolic)
                if resource_reason is not None:
                    uncertainty.append(resource_reason)
                    continue
                steps.append(symbolic.scoped(f"route.{stage}.", f"route.{stage}."))
                world_id = self._world_symbolic_id(workspace, operation)
                if _mentions(postcondition, "state.env.") and world_id is not None:
                    environment = workspace.symbolics.get(world_id)
                    if environment is None:
                        missing.append(f"environment:{world_id}")
                    else:
                        steps.append(environment.scoped(f"route.{stage}.", f"route.{stage}."))
                if missing:
                    uncertainty.append(
                        f"workspace symbolic route for {operation.entry_point.name} is unknown: {', '.join(missing)}"
                    )
                    continue
                goal = self._alias_constraint(postcondition, workspace.aliases)
                steps = [self._alias_symbolic(step, workspace.aliases) for step in steps]
                result = WP().derive(goal, tuple(steps))
                if result.status is not Truth.EXACT or result.precondition is None:
                    uncertainty.append(
                        f"workspace symbolic route for {operation.entry_point.name} is unknown: "
                        f"{result.reason or 'unsupported semantics'}"
                    )
                    continue
                formula: Constraint = result.precondition
                initial = _initial_state_constraints(workspace.start().view())
                if initial:
                    formula = Every(tuple(initial) + (Axiom(
                        f"workspace:{objective.objective_id}:{examined}",
                        formula,
                    ),))
                solved = _solve(
                    solver,
                    Query(
                        f"workspace-wp:{objective.objective_id}:{examined}",
                        formula,
                    ),
                    timeout_ms=solver_timeout_ms,
                )
                if solved.status is Verdict.UNKNOWN:
                    uncertainty.append(
                        solved.unknown_reason or "workspace symbolic query returned UNKNOWN"
                    )
                    continue
                if solved.status is not Verdict.SAT:
                    if solved.status is Verdict.UNSAT_BOUNDED and solved.unsat_core:
                        cores.append(solved.unsat_core)
                    continue
                request = {
                    name[len("route.0."):]: value
                    for name, value in solved.model.items()
                    if name.startswith("route.0.")
                }
                if request:
                    actions.append((operation.entry_point.name, request))
        return actions, uncertainty, cores

    @staticmethod
    def _world_symbolic_id(workspace: Workspace, operation: Operation) -> str | None:
        if workspace.world is None:
            return None
        if operation.name in workspace.world.transitions:
            return operation.name
        if operation.entry_point.name in workspace.world.transitions:
            return operation.entry_point.name
        return None

    @staticmethod
    def _alias_name(name: str, aliases: tuple[tuple[str, ...], ...]) -> str:
        if name.startswith("state."):
            key = name[len("state."):]
            for group in aliases:
                if key in group:
                    return "state." + group[0]
        return name

    @classmethod
    def _alias_constraint(cls, node: Constraint, aliases: tuple[tuple[str, ...], ...]) -> Constraint:
        return rename(node, lambda name: cls._alias_name(name, aliases)) if aliases else node

    @classmethod
    def _alias_symbolic(cls, symbolic: Symbolic, aliases: tuple[tuple[str, ...], ...]) -> Symbolic:
        if not aliases:
            return symbolic
        mapper = lambda name: cls._alias_name(name, aliases)
        return replace(
            symbolic,
            guard=rename(symbolic.guard, mapper),
            assignments={mapper(key): rename(value, mapper) for key, value in symbolic.assignments.items()},
            alternatives=tuple(
                {mapper(key): rename(value, mapper) for key, value in branch.items()}
                for branch in symbolic.alternatives
            ),
        )

    @staticmethod
    def _route_symbols(
        workspace: Workspace,
        transitions: Sequence[Any],
        connections: Sequence[Any],
    ) -> tuple[list[Any], int, list[str]]:
        steps: list[Any] = []
        missing: list[str] = []
        stage = 0
        for index, transition in enumerate(transitions):
            for transform_id in transition.transform_ids:
                symbolic = workspace.symbolics.get(transform_id)
                if symbolic is None:
                    missing.append(f"transform:{transform_id}")
                else:
                    steps.append(symbolic.scoped(f"route.{stage}.", f"route.{stage + 1}."))
                stage += 1
            for recognizer_id in transition.recognizer_ids:
                symbolic = workspace.symbolics.get(recognizer_id)
                if symbolic is None:
                    missing.append(f"recognizer:{recognizer_id}")
                else:
                    steps.append(symbolic.scoped(f"route.{stage}.", f"route.{stage}."))
            for effect_id in transition.effect_ids:
                symbolic = workspace.symbolics.get(effect_id)
                if symbolic is None:
                    missing.append(f"effect:{effect_id}")
                else:
                    steps.append(symbolic.scoped(f"route.{stage}.", f"route.{stage}."))
            if index < len(connections):
                transform_id = connections[index].transform_id
                if transform_id is not None:
                    symbolic = workspace.symbolics.get(transform_id)
                    if symbolic is None:
                        missing.append(f"connection:{transform_id}")
                    else:
                        steps.append(symbolic.scoped(f"route.{stage}.", f"route.{stage + 1}."))
                    stage += 1
        return steps, stage, missing

    def _symbolic_actions(
        self,
        model: Model,
        objective: Objective,
        *,
        solver: Zed | Stack,
        solver_timeout_ms: int | None,
    ) -> tuple[list[tuple[str, Mapping[str, Any]]], list[str], list[tuple[str, ...]]]:
        if not any(operation.symbolic_transition is not None for operation in model.operations):
            return [], [], []
        postcondition = _symbolic_postcondition(objective)
        if postcondition is None:
            return [], ["symbolic backward planning supports Same postconditions only"], []
        actions: list[tuple[str, Mapping[str, Any]]] = []
        uncertainty: list[str] = []
        cores: list[tuple[str, ...]] = []
        wp_engine = WP()
        for operation in model.ops():
            transition = operation.symbolic_transition
            if transition is None:
                continue
            result = wp_engine.derive(postcondition, (transition,))
            if result.status is not Truth.EXACT or result.precondition is None:
                uncertainty.append(
                    f"symbolic preimage for {operation.entry_point.name} is unknown: {result.reason or 'unsupported semantics'}"
                )
                continue
            initial_constraints = [
                Equal(Variable(f"state.{key}", _sort_for(value)), Literal(value, _sort_for(value)))
                for key, value in sorted(model.initial_state.as_dict().items())
                if _sort_for(value) is not None
            ]
            formula: Constraint = result.precondition
            if initial_constraints:
                formula = Every(tuple(initial_constraints) + (Axiom(
                    f"pre:{objective.objective_id}:{operation.entry_point.name}",
                    formula,
                ),))
            solved = _solve(
                solver,
                Query(
                    f"wp:{objective.objective_id}:{operation.entry_point.name}",
                    formula,
                ),
                timeout_ms=solver_timeout_ms,
            )
            if solved.status is Verdict.UNKNOWN:
                uncertainty.append(
                    f"solver could not concretize symbolic preimage for {operation.entry_point.name}: {solved.unknown_reason or 'unknown'}"
                )
                continue
            if solved.status is not Verdict.SAT:
                if solved.status is Verdict.UNSAT_BOUNDED and solved.unsat_core:
                    cores.append(solved.unsat_core)
                continue
            request = {
                name.removeprefix("input.").removeprefix("request."): value
                for name, value in solved.model.items()
                if name.startswith(("input.", "request."))
            }
            if request:
                actions.append((operation.entry_point.name, request))
        return actions, uncertainty, cores

    @staticmethod
    def _request_key(request: Mapping[str, Any]) -> str:
        return json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)

    def preimage(
        self,
        operation: Operation,
        request: Mapping[str, Any],
        objective: Objective,
        *,
        workspace: Workspace | None = None,
    ) -> Callable[[State], bool]:
        """Return the exact concrete preimage predicate for a modeled relation.

        The returned predicate is exact only for the supplied modeled operation
        and request. It is intentionally a concrete relational preimage, not a
        claimed inverse for the underlying runtime transform.
        """
        if workspace is None:
            def precondition(state: State) -> bool:
                return any(
                    objective.evaluate(outcome.after, (outcome.event(
                        operation.name,
                        operation.entry_point.name,
                        request,
                        state,
                        component=operation.component,
                    ),))
                    for outcome in operation.branches(state, request)
                    if outcome.decision is not Decision.UNKNOWN
                )
            return precondition

        def precondition(state: State) -> bool:
            return any(
                objective.evaluate(move.after.view(), (move.event,))
                for move in workspace.moves(
                    Frame(
                        state,
                        workspace.start().environment,
                        regions=workspace.start().regions,
                        aliases=workspace.start().aliases,
                    ),
                    operation.entry_point.name,
                    request,
                    operation=operation,
                )
                if move.outcome.decision is not Decision.UNKNOWN and not move.after.uncertain
            )
        return precondition


def _solve(solver: Zed | Stack, query: Query, *, timeout_ms: int | None) -> Answer:
    """Run one query in a persistent session when one was supplied."""
    if not isinstance(solver, Stack):
        return solver.solve(query, timeout_ms=timeout_ms)
    solver.push()
    try:
        solver.add(query.formula)
        return solver.solve(query.query_id, timeout_ms=timeout_ms, scope=query.scope)
    except Unknown as exc:
        return Answer(
            status=Verdict.UNKNOWN,
            query_id=query.query_id,
            backend=solver.adapter.backend_name,
            backend_version="z3",
            options={"timeout_ms": timeout_ms},
            query=repr(query.formula),
            assumptions=query.assumptions,
            unknown_reason=f"UNSUPPORTED: {exc}",
            scope=query.scope,
        )
    finally:
        solver.pop()


class Planner:
    """Use backward action hints, then deterministic forward concretization."""

    def __init__(self, *, harness_sinks: set[str] | frozenset[str] = frozenset()) -> None:
        self.harness_sinks = frozenset(harness_sinks)

    def plan(
        self,
        model: Model,
        objective: Objective,
        authorization: Authorization,
        *,
        adapter: Target | None = None,
        environment: Mapping[str, str] | None = None,
        workspace: Workspace | None = None,
    ) -> Report:
        workspace = workspace or Workspace.flat(
            model,
            environment=State(dict(environment or {})),
        )
        validation = workspace.validate()
        if validation is not None and not validation.structural:
            raise ValueError(f"workspace topology is structurally invalid: {validation.errors}")
        if validation is not None and not validation.ready:
            raise ValueError(
                "workspace composition is not executable: "
                f"unverified={validation.unverified_connections}; missing={dict(validation.missing_capabilities)}"
            )
        adapter_environment = self._environment(adapter)
        execution_profile = self._analysis_profile(adapter)
        objective.validate(
            authorization,
            harness_sinks=self.harness_sinks,
            environment=environment or adapter_environment,
            execution_profile=execution_profile,
        )
        backward = Regressor().regress(
            model,
            objective,
            solver_timeout_ms=objective.budget.solver_timeout_ms,
            workspace=workspace,
        )
        phantom_attempt = self._probe_phantom_entries(adapter, objective, authorization)
        if phantom_attempt is not None and phantom_attempt.objective_observed and phantom_attempt.replay_stable:
            return self._report(
                Status.VALIDATED_WITNESS,
                model,
                objective,
                (),
                phantom_attempt,
                0,
                0,
                backward,
                environment or adapter_environment,
                reachability=Reach.POSSIBLE,
            )
        preferred = {(entry, self._request_key(request)) for entry, request in backward.required_actions}
        started = time.monotonic()
        budget = objective.budget
        queue: list[tuple[int, int, int, Frame, tuple[Event, ...], bool]] = []
        serial = 0
        heapq.heappush(queue, (0, serial, 0, workspace.start(), (), False))
        for interactions in backward.required_traces:
            for frame, trace, uncertain in self._model_traces(model, interactions, workspace=workspace):
                serial += 1
                heapq.heappush(queue, (-1, serial, len(trace), frame, trace, uncertain))
        input_candidates = list(model.args())
        for _entry, request in backward.required_actions:
            if self._request_key(request) not in {self._request_key(item) for item in input_candidates}:
                input_candidates.append(dict(request))
        input_candidates = sorted(input_candidates, key=self._request_key)
        visited: set[tuple[int, str, tuple[tuple[str, str], ...]]] = set()
        explored_states = 0
        explored_events = 0
        attempts: list[Attempt] = []
        budget_hit = False
        unknown_seen = any(item.startswith("probe expansion ") for item in backward.uncertainty)

        while queue:
            if (time.monotonic() - started) * 1000 > budget.max_time_ms:
                budget_hit = True
                break
            _, _, depth, frame, trace, uncertain = heapq.heappop(queue)
            state = frame.view()
            key = (
                depth,
                json.dumps(state.canonical(), sort_keys=True),
                json.dumps(frame.environment.canonical(), sort_keys=True),
                json.dumps(
                    {name: value.canonical() for name, value in sorted(frame.regions.items())},
                    sort_keys=True,
                ),
                uncertain,
                tuple(
                    (
                        event.operation,
                        event.entry_point,
                        repr(event.request),
                        event.decision.value,
                        event.guard_result,
                        event.terminal,
                        event.effects,
                        tuple(sorted(event.reads)),
                        tuple(sorted(event.writes)),
                        repr(event.reaction),
                        event.uncertainty,
                    )
                    for event in trace
                ),
            )
            if key in visited:
                continue
            visited.add(key)
            explored_states += 1

            if not uncertain and objective.evaluate(state, trace) and objective.satisfy(model.initial_state, trace):
                attempt = self._replay_candidate(
                    adapter,
                    objective,
                    model,
                    trace,
                    environment or adapter_environment,
                    authorization,
                )
                attempts.append(attempt)
                if attempt.replayed and attempt.objective_observed and self._stable(attempt, objective):
                    return self._report(
                        Status.VALIDATED_WITNESS,
                        model,
                        objective,
                        trace,
                        attempt,
                        explored_states,
                        explored_events,
                        backward,
                        environment or adapter_environment,
                        reachability=self._reachability(workspace, objective, trace),
                    )

                if not attempt.replayed:
                    return self._report(
                        Status.SAT_CANDIDATE,
                        model,
                        objective,
                        trace,
                        attempt,
                        explored_states,
                        explored_events,
                        backward,
                        environment or adapter_environment,
                        reachability=self._reachability(workspace, objective, trace),
                    )
                if attempt.divergences and attempt.objective_observed is not True:
                    return self._report(
                        Status.MODEL_DIVERGENCE,
                        model,
                        objective,
                        trace,
                        attempt,
                        explored_states,
                        explored_events,
                        backward,
                        environment or adapter_environment,
                        reachability=self._reachability(workspace, objective, trace),
                    )

            if trace and trace[-1].terminal:
                continue

            if depth >= budget.max_trace_length:
                continue
            for operation in workspace.operations():
                for request in input_candidates:
                    if explored_events >= budget.max_events:
                        budget_hit = True
                        break
                    if not model.allows(operation.entry_point.name, request):
                        continue
                    explored_events += 1
                    for move in workspace.moves(frame, operation.entry_point.name, request, operation=operation):
                        outcome = move.outcome
                        branch_unknown = move.after.uncertain
                        if branch_unknown and not uncertain:
                            unknown_seen = True
                        if explored_states + len(queue) >= budget.max_states:
                            budget_hit = True
                            continue
                        event = replace(move.event, ordering=len(trace))
                        next_trace = trace + (event,)
                        distance = self.distance(model, objective, move.after, next_trace)
                        preference = distance.score
                        if (operation.entry_point.name, self._request_key(request)) in preferred:
                            preference -= 25
                        serial += 1
                        heapq.heappush(queue, (preference, serial, depth + 1, move.after, next_trace, branch_unknown))
                if budget_hit:
                    break
            if budget_hit:
                break

        status = Status.BUDGET_EXHAUSTED if budget_hit else (Status.UNKNOWN if (attempts or unknown_seen) else Status.UNSAT_BOUNDED)
        gaps = [Gap(
            Grade.EVENT_BUDGET if budget_hit else (Grade.UNKNOWN if (attempts or unknown_seen) else Grade.BOUND),
            "bounded hybrid search exhausted its event/time/state budget" if budget_hit else ("candidate replay did not satisfy the objective or stability policy" if attempts else "an unresolved transition outcome may affect bounded reachability" if unknown_seen else "no witness exists in the encoded bounded model/surface"),
            {"max_trace_length": budget.max_trace_length, "attempts": len(attempts), "unknown_branches": unknown_seen},
        )]
        return self._report(
            status,
            model,
            objective,
            (),
            attempts[-1] if attempts else Attempt((), (), False, None),
            explored_states,
            explored_events,
            backward,
            environment or adapter_environment,
            gaps=gaps,
        )

    @staticmethod
    def distance(model: Model, objective: Objective, frame: Frame, trace: Sequence[Event]) -> Distance:
        unmet = sum(not predicate.evaluate(frame.view(), trace) for predicate in objective.postconditions)
        keys = Regressor._keys(objective.postconditions)
        writers = len(Index.build(model).chain(keys)) if keys else 0
        return Distance(unmet, writers, int(frame.uncertain), len(trace))

    def analyze(self, *args: Any, **kwargs: Any) -> Report:
        """Compatibility spelling for callers that use the engine's analyze API."""
        return self.plan(*args, **kwargs)

    def _replay_candidate(
        self,
        adapter: Target | None,
        objective: Objective,
        model: Model,
        predicted: Sequence[Event],
        environment: Mapping[str, str],
        authorization: Authorization,
    ) -> Attempt:
        interactions = tuple(
            {
                "entry_point": event.entry_point,
                "request": dict(event.source or event.request),
            }
            for event in predicted
        )
        if adapter is None:
            return Attempt(interactions, tuple(predicted), False, None, detail="candidate was not replayed by a target adapter")
        adapter.prepare()
        baseline = adapter.snapshot()
        all_runs: list[tuple[Event, ...]] = []
        outcomes: list[bool] = []
        signatures: list[str] = []
        first_divergences: tuple[Divergence, ...] = ()
        try:
            for _ in range(objective.budget.replay_runs):
                adapter.reset(baseline)
                observed = tuple(adapter.trace(interactions, authorization))
                all_runs.append(observed)
                final_state = observed[-1].after if observed else model.initial_state
                outcomes.append(objective.evaluate(final_state, observed) and objective.satisfy(model.initial_state, observed))
                signatures.append(hashlib.sha256(json.dumps({
                    "events": [self._semantic_event(event) for event in observed],
                    "output": self._semantic_output(getattr(adapter, "output", lambda: {})()),
                }, sort_keys=True, default=str).encode()).hexdigest())
                if not first_divergences:
                    first_divergences = Analyzer().compare(predicted, observed)
        finally:
            adapter.teardown()
        stable = len(set(outcomes)) == 1 and len(set(signatures)) == 1 and bool(outcomes)
        detail = "replay objective did not hold" if not all(outcomes) else ("replay was unstable" if not stable else "")
        return Attempt(
            interactions,
            tuple(predicted),
            True,
            all(outcomes) if outcomes else False,
            all_runs[0] if all_runs else (),
            stable,
            first_divergences,
            detail,
        )

    def _report(
        self,
        status: Status,
        model: Model,
        objective: Objective,
        predicted: Sequence[Event],
        attempt: Attempt,
        explored_states: int,
        explored_events: int,
        backward: Plan,
        environment: Mapping[str, str],
        *,
        gaps: Sequence[Gap] = (),
        reachability: Reach = Reach.UNKNOWN,
    ) -> Report:
        witness = None
        witness_events = attempt.observed_events if status is Status.VALIDATED_WITNESS and attempt.observed_events else tuple(predicted)
        model_aligned = (not bool(attempt.divergences)) if attempt.replayed and attempt.predicted_events else None
        if witness_events or attempt.interactions:
            final_state = witness_events[-1].after if witness_events else model.initial_state
            witness = Witness(
                objective=objective.objective_id,
                target_id=model.target_id,
                events=witness_events,
                final_state=final_state,
                validated=status is Status.VALIDATED_WITNESS,
                model_aligned=model_aligned,
                predicted_events=tuple(predicted),
                interactions=attempt.interactions,
                input_refs=tuple(ref for event in witness_events for ref in event.evidence_refs),
                state_checkpoints=tuple(event.after.canonical() for event in witness_events),
                environment=dict(environment),
                replay_result={"replayed": attempt.replayed, "objective_observed": attempt.objective_observed, "detail": attempt.detail},
                fidelity_scope={"mode": "concrete+instrumented", "model": "bounded", "backward": backward.method},
            )
        divergences = attempt.divergences
        proof_status = (
            Verdict.SAT
            if witness and status in {Status.VALIDATED_WITNESS, Status.SAT_CANDIDATE, Status.MODEL_DIVERGENCE}
            else Verdict.UNKNOWN
            if status in {Status.BUDGET_EXHAUSTED, Status.UNKNOWN, Status.MODEL_DIVERGENCE}
            else Verdict.UNSAT_BOUNDED
        )
        proof = Proof(
            status=proof_status,
            bound=objective.budget.max_trace_length,
            explored_states=explored_states,
            explored_events=explored_events,
            scope=objective.authorization_scope,
            query=json.dumps(objective.to_record(), sort_keys=True, default=str),
            assumptions=objective.assumptions + backward.uncertainty,
            named_core=tuple(sorted({name for core in backward.cores for name in core})),
            backend="bounded-hybrid-planner",
            options={"max_time_ms": objective.budget.max_time_ms, "max_events": objective.budget.max_events},
            fidelity_limitations=("bounded surface and trace length", "runtime replay depends on adapter capabilities"),
            execution_profile_id=environment.get("profile_id", "unknown"),
        )
        report_gaps = list(gaps)
        if attempt.detail:
            report_gaps.append(Gap(Grade.ASSUMPTION, attempt.detail, {"interactions": attempt.interactions}))
        return Report(
            status=status,
            target_id=model.target_id,
            objective=objective.objective_id,
            witness=witness,
            proof=proof,
            gaps=tuple(report_gaps),
            explored_states=explored_states,
            explored_events=explored_events,
            model_version=model.model_version,
            build_hash=model.build_hash,
            divergences=divergences,
            objective_version=objective.version,
            surface_scope=tuple(sorted({event.entry_point for event in tuple(predicted) + tuple(attempt.observed_events)})),
            environment=dict(environment),
            replay_runs=objective.budget.replay_runs if attempt.replayed else 0,
            replay_stable=(attempt.replay_stable if attempt.replayed else None),
            model_aligned=model_aligned,
            unresolved_uncertainty=backward.uncertainty,
            model_revision=model.model_version,
            execution_profile_id=environment.get("profile_id", "unknown"),
            reachability=reachability,
            solver_cores=backward.cores,
        )

    @classmethod
    def _reachability(
        cls,
        workspace: Workspace,
        objective: Objective,
        trace: Sequence[Event],
    ) -> Reach:
        """Classify all bounded modeled successors of one interaction trace.

        This is deliberately scoped to the workspace model and the exact
        interaction sequence. It does not claim that a concrete target will
        realize every modeled branch.
        """
        interactions = tuple(
            {"entry_point": event.entry_point, "request": dict(event.request)}
            for event in trace
        )
        alternatives = cls._model_traces(workspace.model, interactions, workspace=workspace)
        if not alternatives:
            return Reach.UNKNOWN
        if all(
            not uncertain
            and objective.evaluate(frame.view(), events)
            and objective.satisfy(workspace.model.initial_state, events)
            for frame, events, uncertain in alternatives
        ):
            return Reach.GUARANTEED
        return Reach.POSSIBLE

    @staticmethod
    def _request_key(request: Mapping[str, Any]) -> str:
        return json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def _model_traces(
        model: Model,
        interactions: Sequence[Mapping[str, Any]],
        *,
        workspace: Workspace | None = None,
    ) -> tuple[tuple[Frame, tuple[Event, ...], bool], ...]:
        workspace = workspace or Workspace.flat(model)
        frontier: list[tuple[Frame, tuple[Event, ...], bool]] = [(workspace.start(), (), False)]
        for index, interaction in enumerate(interactions):
            entry = str(interaction["entry_point"])
            request = dict(interaction.get("request", {}))
            operations = workspace.operations(entry)
            if not operations or not model.allows(entry, request):
                return ()
            next_frontier: list[tuple[Frame, tuple[Event, ...], bool]] = []
            for frame, events, uncertain in frontier:
                for operation in operations:
                    for move in workspace.moves(frame, entry, request, operation=operation):
                        if move.outcome.terminal and index != len(interactions) - 1:
                            continue
                        next_frontier.append((
                            move.after,
                            events + (replace(move.event, ordering=len(events)),),
                            uncertain or move.after.uncertain,
                        ))
            frontier = next_frontier
            if not frontier:
                return ()
        return tuple(frontier)

    @staticmethod
    def _probe_phantom_entries(
        adapter: Target | None,
        objective: Objective,
        authorization: Authorization,
    ) -> Attempt | None:
        if adapter is None:
            return None
        registry_factory = getattr(adapter, "surface", None)
        replay = getattr(adapter, "replay", None)
        if not callable(registry_factory) or not callable(replay):
            return None
        registry = registry_factory()
        for observed in registry.phantoms():
            interactions = ({"entry_point": observed.entry_point.name, "request": {}},)
            try:
                report = replay(interactions, runs=objective.budget.replay_runs, authorization=authorization)
            except (OSError, RuntimeError, TimeoutError, ValueError, PermissionError):
                continue
            if not report.runs:
                continue
            run = report.runs[0]
            observed_objective = bool(run.events) and objective.evaluate(run.events[-1].after, run.events)
            observed_objective = observed_objective and objective.satisfy(run.events[0].before, run.events)
            if observed_objective:
                return Attempt(
                    interactions,
                    (),
                    True,
                    True,
                    tuple(run.events),
                    bool(report.stable),
                    detail=f"phantom entry {observed.entry_point.name} was promoted from observed surface evidence",
                )
        return None

    @staticmethod
    def _semantic_event(event: Event) -> dict[str, Any]:
        return {
            "operation": event.operation,
            "entry_point": event.entry_point,
            "request": event.request,
            "before": event.before.canonical(),
            "after": event.after.canonical(),
            "observation": event.observation,
            "guard_result": event.guard_result,
            "decision": event.decision.value,
            "terminal": event.terminal,
            "effects": event.effects,
            "reaction": event.reaction,
        }

    @staticmethod
    def _semantic_output(output: Mapping[str, Any]) -> Any:
        if isinstance(output, Mapping) and "outcome" in output:
            return output["outcome"]
        return output

    @staticmethod
    def _environment(adapter: Target | None) -> Mapping[str, str]:
        observation = getattr(adapter, "observe", None)
        if observation is None:
            return {}
        result = observation()
        facts = dict(getattr(result, "facts", result))
        profile_factory = getattr(adapter, "profile", None)
        if callable(profile_factory):
            facts["profile_id"] = profile_factory().profile_id
        return facts

    @staticmethod
    def _analysis_profile(adapter: Target | None) -> Any | None:
        profile_factory = getattr(adapter, "profile", None)
        return profile_factory() if callable(profile_factory) else None

    @staticmethod
    def _stable(attempt: Attempt, objective: Objective) -> bool:
        return attempt.replayed and attempt.objective_observed is True and attempt.replay_stable is True and objective.budget.replay_runs >= 1
