"""Disk-backed, bounded call and callback candidate relations."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from .logic import Arithmetic, Constraint, Either, Every, Equal, Literal, Negate, Range, Rel, Set, Sort, Variable, Axiom


@dataclass(frozen=True)
class CallRelation:
    source: str
    target: str
    kind: str
    status: str
    evidence: tuple[str, ...]
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionContract:
    """Explicit summary over `arg.<name>` and `state.<path>` variables."""

    function: str
    parameters: tuple[str, ...] = ()
    preconditions: tuple[Constraint, ...] = ()
    state_updates: Mapping[str, Constraint] = field(default_factory=dict)
    effects: tuple[str, ...] = ()
    complete: bool = False
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.function:
            raise ValueError("contract function identity is required")
        if any(not item for item in self.parameters):
            raise ValueError("contract parameter names must be non-empty")


@dataclass(frozen=True)
class CallBinding:
    """Actual arguments and optional state remapping for one source call site."""

    caller: str
    callee: str
    callsite: str
    arguments: Mapping[str, Constraint]
    state: Mapping[str, Constraint] = field(default_factory=dict)
    order: int = 0
    complete: bool = False
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.caller or not self.callee or not self.callsite:
            raise ValueError("call binding requires caller, callee, and callsite identities")
        if self.order < 0:
            raise ValueError("call binding order must be non-negative")


@dataclass(frozen=True)
class ComposedContract:
    function: str
    preconditions: tuple[Constraint, ...]
    state_updates: Mapping[str, Constraint]
    effects: tuple[str, ...]
    functions: tuple[str, ...]
    evidence: tuple[str, ...]
    unresolved: tuple[CallRelation, ...]
    complete: bool
    limitations: tuple[str, ...] = ()
    runtime_observed: bool = False


class _RelationView:
    """A small, repeatable sequence facade that reads relation rows lazily."""

    def __init__(self, db: sqlite3.Connection, where: str = "", params: tuple[Any, ...] = ()) -> None:
        self._db = db
        self._where = where
        self._params = params

    def __iter__(self) -> Iterator[CallRelation]:
        query = "SELECT source,target,kind,status,evidence,limitations FROM relations"
        if self._where:
            query += " WHERE " + self._where
        query += " ORDER BY id"
        cursor = self._db.execute(query, self._params)
        for source, target, kind, status, evidence, limitations in cursor:
            yield CallRelation(source, target, kind, status, tuple(json.loads(evidence)), tuple(json.loads(limitations)))

    def __len__(self) -> int:
        query = "SELECT COUNT(*) FROM relations"
        if self._where:
            query += " WHERE " + self._where
        return int(self._db.execute(query, self._params).fetchone()[0])

    def __getitem__(self, index: int | slice) -> CallRelation | tuple[CallRelation, ...]:
        if isinstance(index, slice):
            if index.step not in (None, 1):
                raise ValueError("relation view slices support step 1 only")
            start = index.start or 0
            stop = index.stop
            if start < 0 or (stop is not None and stop < 0):
                raise IndexError("negative relation view indexes are unsupported")
            if stop is not None and stop - start > 100_000:
                raise OverflowError("relation view slice exceeds 100,000 records")
            limit = 100_000 if stop is None else max(0, stop - start)
            return self._read_page(start, limit)
        if index < 0:
            raise IndexError("negative relation view indexes are unsupported")
        rows = self._read_page(index, 1)
        if not rows:
            raise IndexError(index)
        return rows[0]

    def _read_page(self, offset: int, limit: int) -> tuple[CallRelation, ...]:
        query = "SELECT source,target,kind,status,evidence,limitations FROM relations"
        if self._where:
            query += " WHERE " + self._where
        query += " ORDER BY id LIMIT ? OFFSET ?"
        rows = self._db.execute(query, (*self._params, limit, offset))
        return tuple(
            CallRelation(source, target, kind, status, tuple(json.loads(evidence)), tuple(json.loads(limitations)))
            for source, target, kind, status, evidence, limitations in rows
        )


class CallGraph:
    """SQLite-backed graph. Iteration is bounded; close it when finished."""

    def __init__(self, directory: tempfile.TemporaryDirectory[str], db: sqlite3.Connection,
                 truncated: bool, truncation_reasons: tuple[str, ...]) -> None:
        self._directory = directory
        self._db = db
        self.truncated = truncated
        self.truncation_reasons = truncation_reasons
        self._closed = False

    @property
    def relations(self) -> _RelationView:
        self._ensure_open()
        return _RelationView(self._db)

    @property
    def summary(self) -> Mapping[str, int | bool | tuple[str, ...]]:
        self._ensure_open()
        counts = dict(self._db.execute("SELECT status,COUNT(*) FROM relations GROUP BY status"))
        return {
            "relations": int(sum(counts.values())),
            "resolved": int(counts.get("resolved", 0)),
            "candidate": int(counts.get("candidate", 0)),
            "unresolved": int(counts.get("unresolved", 0)),
            "truncated": self.truncated,
            "truncation_reasons": self.truncation_reasons,
        }

    def from_function(self, identity: str) -> _RelationView:
        self._ensure_open()
        return _RelationView(self._db, "source=?", (identity,))

    def close(self) -> None:
        if not self._closed:
            self._db.close()
            self._directory.cleanup()
            self._closed = True

    def __enter__(self) -> "CallGraph":
        self._ensure_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("call graph is closed")


class ContractComposer:
    """Compose explicit contracts across uniquely resolved direct calls.

    Contract variables use `arg.<formal>` and `state.<path>` names. A call
    binding supplies actual argument expressions and an order. Callee state
    transfers execute in binding order, then the caller's local transfer is
    applied. That ordering is a declared contract convention; callers must mark
    bindings complete only when source control-flow evidence supports it.
    """

    def __init__(self, *, max_contracts: int = 10_000, max_contract_bytes: int = 16 << 20,
                 max_binding_bytes: int = 16 << 20,
                 max_depth: int = 32, max_calls: int = 10_000, max_terms: int = 10_000) -> None:
        if min(max_contracts, max_contract_bytes, max_binding_bytes, max_depth, max_calls, max_terms) <= 0:
            raise ValueError("contract composition bounds must be positive")
        self.max_contracts = max_contracts
        self.max_contract_bytes = max_contract_bytes
        self.max_binding_bytes = max_binding_bytes
        self.max_depth = max_depth
        self.max_calls = max_calls
        self.max_terms = max_terms

    def compose(
        self,
        call_graph: CallGraph,
        root: str,
        contracts: Iterable[FunctionContract],
        bindings: Iterable[CallBinding],
    ) -> ComposedContract:
        contract_index: dict[str, FunctionContract] = {}
        bytes_used = 0
        issues: list[str] = []
        for contract in contracts:
            if len(contract_index) >= self.max_contracts:
                issues.append("function contract limit exceeded")
                break
            encoded_size = self._contract_size(contract)
            if encoded_size > self.max_contract_bytes or bytes_used + encoded_size > self.max_contract_bytes:
                issues.append("function contract byte limit exceeded")
                continue
            contract_index[contract.function] = contract
            bytes_used += encoded_size

        binding_index: dict[tuple[str, str, str], CallBinding] = {}
        binding_bytes = 0
        for index, binding in enumerate(bindings):
            if index >= self.max_calls:
                issues.append("call binding limit exceeded")
                break
            key = (binding.caller, binding.callee, binding.callsite)
            if key in binding_index:
                issues.append(f"duplicate call binding: {binding.callsite}")
                continue
            encoded_size = self._binding_size(binding)
            if encoded_size > self.max_binding_bytes or binding_bytes + encoded_size > self.max_binding_bytes:
                issues.append("call binding byte limit exceeded")
                continue
            binding_index[key] = binding
            binding_bytes += encoded_size

        call_count = 0

        def compose_function(identity: str, stack: tuple[str, ...], depth: int) -> ComposedContract | None:
            nonlocal call_count
            summary = contract_index.get(identity)
            if summary is None:
                issues.append(f"function contract unavailable: {identity}")
                return None
            if depth > self.max_depth:
                issues.append(f"call depth limit exceeded at {identity}")
                return ComposedContract(identity, (), {}, (), (identity,), summary.evidence, (), False,
                                        ("call depth limit exceeded",))

            preconditions = list(summary.preconditions)
            state_updates: dict[str, Constraint] = {}
            effects: list[str] = []
            functions_used = [identity]
            evidence = list(summary.evidence)
            gaps: list[CallRelation] = []
            limitations: list[str] = []
            complete = summary.complete

            caller_relations = []
            for relation in call_graph.from_function(identity):
                if len(caller_relations) >= self.max_calls:
                    limitations.append(f"call relation limit exceeded at {identity}")
                    complete = False
                    break
                caller_relations.append(relation)
            relation_positions = {id(relation): index for index, relation in enumerate(caller_relations)}
            def order_key(relation: CallRelation) -> tuple[int, int]:
                callsite_key = next((item for item in relation.evidence if item.startswith("call:")), "")
                binding = binding_index.get((identity, relation.target, callsite_key))
                return (binding.order if binding is not None else self.max_calls, relation_positions[id(relation)])
            caller_relations.sort(key=order_key)

            for relation in caller_relations:
                if relation.kind != "call":
                    gaps.append(relation)
                    limitations.append(f"non-synchronous relation is not composed: {relation.kind}:{relation.target}")
                    complete = False
                    continue
                if relation.status != "resolved":
                    gaps.append(relation)
                    limitations.append(f"call target is {relation.status}: {relation.target}")
                    complete = False
                    continue
                call_count += 1
                if call_count > self.max_calls:
                    limitations.append("composed call limit exceeded")
                    complete = False
                    break
                callsite = next((item for item in relation.evidence if item.startswith("call:")), "")
                binding = binding_index.get((identity, relation.target, callsite))
                if binding is None:
                    gaps.append(CallRelation(identity, relation.target, "call-binding", "unresolved",
                                             relation.evidence, ("actual argument/state binding is missing",)))
                    limitations.append(f"actual argument/state binding missing: {callsite or relation.target}")
                    complete = False
                    continue
                if not binding.complete:
                    gaps.append(CallRelation(identity, relation.target, "call-binding", "candidate",
                                             relation.evidence, ("call order/control-flow is not fully bound",)))
                    limitations.append(f"call order/control-flow evidence is incomplete: {callsite}")
                    complete = False
                    continue
                if relation.target in stack + (identity,):
                    gaps.append(CallRelation(identity, relation.target, "recursive-call", "unresolved",
                                             relation.evidence, ("recursive summary requires a fixed-point contract",)))
                    limitations.append(f"recursive call requires a fixed-point summary: {relation.target}")
                    complete = False
                    continue
                child = compose_function(relation.target, stack + (identity,), depth + 1)
                if child is None:
                    gaps.append(CallRelation(identity, relation.target, "call-contract", "unresolved",
                                             relation.evidence, ("callee contract is unavailable",)))
                    complete = False
                    continue

                mapping, missing = self._call_substitution(binding, contract_index[relation.target], state_updates)
                if missing:
                    limitations.extend(missing)
                    complete = False
                preconditions.extend(_substitute(term, mapping, f"frame::{callsite}::") for term in child.preconditions)
                for path, expression in child.state_updates.items():
                    state_updates[path] = _substitute(expression, mapping, f"frame::{callsite}::")
                effects.extend(child.effects)
                functions_used.extend(child.functions)
                evidence.extend(child.evidence)
                gaps.extend(child.unresolved)
                limitations.extend(child.limitations)
                complete = complete and child.complete

            # The contract's local transfer is defined to run after its callees.
            local_mapping = {f"state.{path}": expression for path, expression in state_updates.items()}
            for path, expression in summary.state_updates.items():
                state_updates[path] = _substitute(expression, local_mapping)
            effects.extend(summary.effects)
            complete = complete and not limitations and not gaps
            if len(preconditions) > self.max_terms or len(state_updates) > self.max_terms:
                limitations.append("composed contract term limit exceeded")
                preconditions = preconditions[:self.max_terms]
                complete = False
            return ComposedContract(
                identity, tuple(preconditions), state_updates, tuple(effects),
                tuple(dict.fromkeys(functions_used)), tuple(dict.fromkeys(evidence)),
                tuple(gaps), complete, tuple(dict.fromkeys(limitations)),
            )

        result = compose_function(root, (), 0)
        if result is None:
            return ComposedContract(root, (), {}, (), (), (), (), False,
                                    tuple(dict.fromkeys(issues + [f"root contract unavailable: {root}"])))
        if issues:
            return ComposedContract(
                result.function, result.preconditions, result.state_updates, result.effects,
                result.functions, result.evidence, result.unresolved, False,
                tuple(dict.fromkeys(result.limitations + tuple(issues))),
            )
        return result

    def _call_substitution(
        self, binding: CallBinding, callee: FunctionContract,
        current_state: Mapping[str, Constraint],
    ) -> tuple[dict[str, Constraint], tuple[str, ...]]:
        state_mapping = {f"state.{path}": value for path, value in current_state.items()}
        state_mapping.update({key if key.startswith("state.") else f"state.{key}": value
                              for key, value in binding.state.items()})
        mapping = dict(state_mapping)
        missing = []
        for parameter in callee.parameters:
            actual = binding.arguments.get(parameter, binding.arguments.get(f"arg.{parameter}"))
            if actual is None:
                missing.append(f"call argument binding missing for {callee.function}: {parameter}")
                continue
            actual_value = _substitute(actual, state_mapping)
            mapping[f"arg.{parameter}"] = actual_value
            mapping[parameter] = actual_value
        return mapping, tuple(missing)

    @staticmethod
    def _contract_size(contract: FunctionContract) -> int:
        record = {
            "function": contract.function,
            "parameters": contract.parameters,
            "preconditions": [item.to_record() for item in contract.preconditions],
            "state_updates": {key: value.to_record() for key, value in contract.state_updates.items()},
            "effects": contract.effects,
            "complete": contract.complete,
            "evidence": contract.evidence,
        }
        return len(json.dumps(record, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))

    @staticmethod
    def _binding_size(binding: CallBinding) -> int:
        record = {
            "caller": binding.caller,
            "callee": binding.callee,
            "callsite": binding.callsite,
            "arguments": {key: value.to_record() for key, value in binding.arguments.items()},
            "state": {key: value.to_record() for key, value in binding.state.items()},
            "evidence": binding.evidence,
        }
        return len(json.dumps(record, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def _substitute(node: Constraint, mapping: Mapping[str, Constraint], namespace: str = "") -> Constraint:
    if isinstance(node, Variable):
        replacement = mapping.get(node.name)
        if replacement is not None:
            return replacement
        if namespace and not node.name.startswith("state."):
            return Variable(namespace + node.name, node.sort, node.width, node.signed)
        return node
    if isinstance(node, Literal):
        return node
    if isinstance(node, Arithmetic):
        return Arithmetic(node.operator, _substitute(node.left, mapping, namespace),
                          _substitute(node.right, mapping, namespace))
    if isinstance(node, Equal):
        return Equal(_substitute(node.left, mapping, namespace), _substitute(node.right, mapping, namespace))
    if isinstance(node, Rel):
        return Rel(_substitute(node.left, mapping, namespace), node.relation,
                   _substitute(node.right, mapping, namespace))
    if isinstance(node, Range):
        return Range(_substitute(node.value, mapping, namespace), node.minimum, node.maximum)
    if isinstance(node, Set):
        return Set(_substitute(node.value, mapping, namespace), node.values)
    if isinstance(node, Every):
        return Every(tuple(_substitute(item, mapping, namespace) for item in node.terms))
    if isinstance(node, Either):
        return Either(tuple(_substitute(item, mapping, namespace) for item in node.terms))
    if isinstance(node, Negate):
        return Negate(_substitute(node.term, mapping, namespace))
    if isinstance(node, Axiom):
        return Axiom(node.name, _substitute(node.term, mapping, namespace))
    raise TypeError(f"unsupported contract constraint node: {type(node).__name__}")


class CallGraphBuilder:
    """Build call candidates with a disk index and bounded working memory.

    Source facts are serialized and indexed one at a time. SQLite cache is
    capped at 4 MiB; relation output is disk-backed and read through lazy views.
    One source record is capped at 1 MiB by default. Candidate expansion, input
    records, and total relation rows have explicit limits.
    """

    def __init__(self, *, max_functions: int = 500_000, max_relations: int = 2_000_000,
                 max_candidates_per_call: int = 256, max_fact_bytes: int = 1 << 20) -> None:
        if min(max_functions, max_relations, max_candidates_per_call, max_fact_bytes) <= 0:
            raise ValueError("call graph bounds must be positive")
        self.max_functions = max_functions
        self.max_relations = max_relations
        self.max_candidates_per_call = max_candidates_per_call
        self.max_fact_bytes = max_fact_bytes

    def build(
        self,
        functions: Iterable[Mapping[str, Any]],
        *,
        interface_implementations: Iterable[Mapping[str, Any]] = (),
        callback_registrations: Iterable[Mapping[str, Any]] = (),
        callback_invocations: Iterable[Mapping[str, Any]] = (),
        callback_registration_calls: Iterable[Mapping[str, Any]] = (),
        async_calls: Iterable[Mapping[str, Any]] = (),
    ) -> CallGraph:
        directory = tempfile.TemporaryDirectory(prefix="rsve-callgraph-")
        db = sqlite3.connect(Path(directory.name) / "callgraph.sqlite")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA cache_size=-4096")
        db.execute("PRAGMA temp_store=FILE")
        db.execute("PRAGMA mmap_size=0")
        db.executescript(
            "CREATE TABLE functions(identity TEXT PRIMARY KEY, package TEXT NOT NULL, symbol TEXT NOT NULL, "
            "short TEXT NOT NULL, receiver_type TEXT NOT NULL, payload TEXT NOT NULL);"
            "CREATE INDEX function_short ON functions(short);"
            "CREATE INDEX function_package_short ON functions(package,short);"
            "CREATE INDEX function_receiver_short ON functions(receiver_type,short);"
            "CREATE TABLE aliases(owner TEXT NOT NULL, target TEXT NOT NULL, name TEXT NOT NULL, evidence TEXT NOT NULL);"
            "CREATE INDEX alias_owner_target ON aliases(owner,target);"
            "CREATE TABLE function_values(owner TEXT NOT NULL, variable TEXT NOT NULL, target TEXT NOT NULL, evidence TEXT NOT NULL);"
            "CREATE INDEX function_value_owner_variable ON function_values(owner,variable);"
            "CREATE TABLE implementations(interface_type TEXT NOT NULL, concrete_type TEXT NOT NULL, evidence TEXT NOT NULL);"
            "CREATE INDEX implementations_interface ON implementations(interface_type);"
            "CREATE TABLE registrations(key TEXT NOT NULL, owner TEXT NOT NULL, target TEXT NOT NULL, evidence TEXT NOT NULL);"
            "CREATE INDEX registration_key ON registrations(key);"
            "CREATE TABLE relations(id INTEGER PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL, "
            "status TEXT NOT NULL, evidence TEXT NOT NULL, limitations TEXT NOT NULL);"
            "CREATE INDEX relation_source ON relations(source,id);"
        )
        truncated = False
        reasons: list[str] = []
        value_bindings_written = 0
        try:
            function_count = 0
            with db:
                for fact in functions:
                    if fact.get("kind") == "source-facts.limit":
                        truncated = True
                        reasons.append("source facts reported extraction truncation")
                        break
                    if function_count >= self.max_functions:
                        truncated = True
                        reasons.append("function record limit exceeded")
                        break
                    if fact.get("kind", "function") != "function":
                        continue
                    encoded = json.dumps(fact, separators=(",", ":"), ensure_ascii=True)
                    if len(encoded.encode("utf-8")) > self.max_fact_bytes:
                        truncated = True
                        reasons.append("source fact byte limit exceeded")
                        continue
                    identity = self._identity(fact)
                    if not identity or len(identity) > 8192:
                        truncated = True
                        reasons.append("function identity missing or too long")
                        continue
                    package = str(fact.get("package", ""))
                    symbol = str(fact.get("symbol", identity.rsplit(".", 1)[-1]))
                    receiver_type = self._type_name(
                        str(fact.get("receiver", {}).get("type", "")), {}, package,
                    ) if symbol.startswith("method.") else ""
                    db.execute(
                        "INSERT OR REPLACE INTO functions VALUES (?,?,?,?,?,?)",
                        (identity, package, symbol, symbol.rsplit(".", 1)[-1], receiver_type, encoded),
                    )
                    function_count += 1
                    for assignment in fact.get("assignments", ()):
                        variable, expression = str(assignment.get("target", "")), assignment.get("value")
                        if not variable or not isinstance(expression, Mapping):
                            continue
                        kind = str(expression.get("kind", ""))
                        assignment_evidence = self._evidence(fact, assignment)
                        if kind in {"variable", "selector"}:
                            name = self._expr_name(expression)
                            if name:
                                db.execute(
                                    "INSERT INTO aliases VALUES (?,?,?,?)",
                                    (identity, variable, name, json.dumps(assignment_evidence)),
                                )
                        elif kind in {"function", "function-value", "closure"}:
                            value_bindings_written, hit_limit = self._store_function_value(
                                db, identity, variable, expression, fact, assignment,
                                value_bindings_written,
                            )
                            if hit_limit:
                                truncated = True
                                reasons.append("function-value binding limit exceeded")

            for index, item in enumerate(interface_implementations):
                if index >= self.max_relations:
                    truncated = True
                    reasons.append("interface implementation record limit exceeded")
                    break
                item_package = str(item.get("package", ""))
                interface = self._type_name(str(item.get("interface", "")), item.get("imports", {}), item_package)
                concrete = self._type_name(str(item.get("concrete", "")), item.get("imports", {}), item_package)
                if interface and concrete:
                    db.execute("INSERT INTO implementations VALUES (?,?,?)", (interface, concrete, json.dumps(self._evidence(item))))

            relations_written = 0

            def append(relation: CallRelation) -> None:
                nonlocal relations_written, truncated
                if relations_written >= self.max_relations:
                    truncated = True
                    if "relation record limit exceeded" not in reasons:
                        reasons.append("relation record limit exceeded")
                    return
                db.execute(
                    "INSERT INTO relations(source,target,kind,status,evidence,limitations) VALUES (?,?,?,?,?,?)",
                    (relation.source, relation.target, relation.kind, relation.status,
                     json.dumps(relation.evidence), json.dumps(relation.limitations)),
                )
                relations_written += 1

            # Stream payloads from SQLite. Each cursor row contains one fact only.
            for identity, package, payload in db.execute("SELECT identity,package,payload FROM functions ORDER BY identity"):
                fact = json.loads(payload)
                receiver_types = fact.get("call_receiver_types", {})
                imports = fact.get("imports", {})
                async_names = set(str(value) for value in fact.get("async_calls", ()))
                for assignment in fact.get("assignments", ()):
                    variable = str(assignment.get("target", ""))
                    expression = assignment.get("value")
                    if not variable or not isinstance(expression, Mapping):
                        continue
                    if expression.get("kind") not in {"function", "function-value", "closure", "variable", "selector"}:
                        continue
                    targets, detail, cut = self._resolve_local_value(
                        db, identity, variable, self.max_candidates_per_call,
                    )
                    if cut:
                        truncated = True
                        reasons.append("function-value candidate limit exceeded")
                    evidence = self._evidence(fact, assignment)
                    if targets:
                        for target in targets:
                            append(CallRelation(
                                identity, target, "function-value-assignment", "candidate",
                                evidence + detail,
                                ("assignment identifies a function value; it does not prove use or invocation",),
                            ))
                    else:
                        value_kind = str(expression.get("kind", ""))
                        if value_kind in {"function", "function-value", "closure"}:
                            append(CallRelation(
                                identity, variable, "function-value-assignment", "unresolved", evidence,
                                ("function-value identity is missing or unsupported",),
                            ))
                for call_index, call in enumerate(fact.get("calls", ())):
                    if relations_written >= self.max_relations:
                        truncated = True
                        if "relation record limit exceeded" not in reasons:
                            reasons.append("relation record limit exceeded")
                        break
                    name = str(call)
                    receiver = str(receiver_types.get(name, ""))
                    targets, status, detail, cut = self._resolve(
                        db, identity, package, name, receiver, imports,
                    )
                    if cut:
                        truncated = True
                        reasons.append("per-call candidate limit exceeded")
                    kind = "goroutine" if name in async_names else "call"
                    callsite_id = f"call:{name}#{call_index}"
                    evidence = self._evidence(fact, {"evidence": callsite_id})
                    if not targets and not receiver:
                        targets, status, detail, cut = self._resolve_local_value(
                            db, identity, name, self.max_candidates_per_call,
                        )
                        if cut:
                            truncated = True
                            reasons.append("per-call candidate limit exceeded")
                    if not targets:
                        append(CallRelation(identity, name, kind, "unresolved", evidence,
                                            detail or ("no supported target evidence",)))
                    else:
                        for target in targets:
                            append(CallRelation(identity, target, kind, status, evidence + detail,
                                                detail + ("static relation does not prove runtime invocation",)))

            for index, registration in enumerate(callback_registrations):
                if index >= self.max_relations:
                    truncated = True
                    reasons.append("callback registration input limit exceeded")
                    break
                key = str(registration.get("key", ""))[:8192]
                owner = str(registration.get("owner", ""))[:8192]
                target = str(registration.get("target", ""))[:8192]
                if key and owner:
                    db.execute("INSERT INTO registrations VALUES (?,?,?,?)",
                               (key, owner, target, json.dumps(self._evidence(registration))))
                if owner and target:
                    append(CallRelation(owner, target, "callback-registration", "candidate",
                                        self._evidence(registration),
                                        ("registration evidence does not prove callback invocation",)))
                elif owner:
                    append(CallRelation(owner, key or "<missing-callback-key>", "callback-registration", "unresolved",
                                        self._evidence(registration), ("registration target identity is missing",)))

            for index, registration in enumerate(callback_registration_calls):
                if index >= self.max_relations:
                    truncated = True
                    reasons.append("callback registration call input limit exceeded")
                    break
                owner = str(registration.get("owner", ""))[:8192]
                key = str(registration.get("key", ""))[:8192]
                expression = registration.get("callback", registration.get("value"))
                targets: tuple[str, ...] = ()
                detail: tuple[str, ...] = ()
                cut = False
                if owner and isinstance(expression, Mapping):
                    targets, detail, cut = self._resolve_value_expression(
                        db, owner, expression, self.max_candidates_per_call,
                    )
                elif owner and isinstance(expression, str) and expression:
                    targets, detail, cut = self._resolve_local_value(
                        db, owner, expression, self.max_candidates_per_call,
                    )
                evidence = self._evidence(registration)
                callsite = str(registration.get("callsite", ""))
                if callsite:
                    evidence += ("registration-call:" + callsite[:4096],)
                if cut:
                    truncated = True
                    reasons.append("callback candidate limit exceeded")
                if not owner or not key:
                    append(CallRelation(owner or "<unbound-registration>", key or "<missing-callback-key>",
                                        "callback-registration", "unresolved", evidence,
                                        ("registration owner or key identity is missing",)))
                elif targets:
                    for target in targets:
                        db.execute("INSERT INTO registrations VALUES (?,?,?,?)",
                                   (key, owner, target, json.dumps(evidence + detail)))
                        append(CallRelation(owner, target, "callback-registration", "candidate",
                                            evidence + detail,
                                            ("registration call records a candidate callback value; invocation is separate",)))
                    if cut:
                        append(CallRelation(owner, key, "callback-registration", "unresolved", evidence,
                                            ("callback candidate bound exceeded",)))
                else:
                    append(CallRelation(owner, key, "callback-registration", "unresolved", evidence,
                                        detail or ("registration callback expression did not resolve statically",)))

            for index, invocation in enumerate(callback_invocations):
                if index >= self.max_relations:
                    truncated = True
                    reasons.append("callback invocation input limit exceeded")
                    break
                owner, key = str(invocation.get("owner", ""))[:8192], str(invocation.get("key", ""))[:8192]
                rows = db.execute("SELECT target,evidence FROM registrations WHERE key=? ORDER BY rowid LIMIT ?",
                                  (key, self.max_candidates_per_call + 1)).fetchall()
                if not owner or not rows:
                    append(CallRelation(owner or "<unbound-callback-invocation>", key or "<missing-callback-key>",
                                        "callback-invocation", "unresolved", self._evidence(invocation),
                                        ("no matching callback registration was supplied",)))
                    continue
                clipped = len(rows) > self.max_candidates_per_call
                if clipped:
                    truncated = True
                    reasons.append("callback candidate limit exceeded")
                    rows = rows[:self.max_candidates_per_call]
                for target, registration_evidence in rows:
                    if target:
                        append(CallRelation(owner, target, "callback-invocation", "candidate",
                                            self._evidence(invocation) + tuple(json.loads(registration_evidence)),
                                            ("callback key match is a candidate route, not observed dispatch",)))
                if clipped:
                    append(CallRelation(owner, key, "callback-invocation", "unresolved", self._evidence(invocation),
                                        ("callback candidate bound exceeded",)))

            for index, call in enumerate(async_calls):
                if index >= self.max_relations:
                    truncated = True
                    reasons.append("asynchronous call input limit exceeded")
                    break
                source, target = str(call.get("source", ""))[:8192], str(call.get("target", ""))[:8192]
                if source and target:
                    append(CallRelation(source, target, "goroutine", "candidate", self._evidence(call),
                                        ("asynchronous edge does not encode scheduler interleavings",)))
                else:
                    append(CallRelation(source or "<unbound-goroutine>", target or "<unresolved-target>",
                                        "goroutine", "unresolved", self._evidence(call),
                                        ("source or target identity is missing",)))

            db.commit()
            db.execute("PRAGMA optimize")
            return CallGraph(directory, db, truncated, tuple(dict.fromkeys(reasons)))
        except BaseException:
            db.close()
            directory.cleanup()
            raise

    def _resolve(
        self, db: sqlite3.Connection, caller: str, package: str, call: str,
        receiver_type: str, imports: Mapping[str, str],
    ) -> tuple[tuple[str, ...], str, tuple[str, ...], bool]:
        short = call.rsplit(".", 1)[-1]
        qualifier = call.split(".", 1)[0]
        if receiver_type:
            receiver = self._type_name(receiver_type, imports, package)
            rows = db.execute("SELECT identity FROM functions WHERE receiver_type=? AND short=? ORDER BY identity LIMIT ?",
                              (receiver, short, self.max_candidates_per_call + 1)).fetchall()
            if rows:
                cut = len(rows) > self.max_candidates_per_call
                targets = tuple(row[0] for row in rows[:self.max_candidates_per_call])
                return targets, "resolved" if len(rows) == 1 else "candidate", (("candidate bound exceeded",) if cut else ()), cut
            implementations = db.execute("SELECT concrete_type,evidence FROM implementations WHERE interface_type=? ORDER BY rowid LIMIT ?",
                                         (receiver, self.max_candidates_per_call + 1)).fetchall()
            targets: list[str] = []
            evidence: list[str] = []
            for concrete, implementation_evidence in implementations:
                evidence.extend(json.loads(implementation_evidence))
                remaining = self.max_candidates_per_call + 1 - len(targets)
                targets.extend(row[0] for row in db.execute(
                    "SELECT identity FROM functions WHERE receiver_type=? AND short=? ORDER BY identity LIMIT ?",
                    (concrete, short, remaining),
                ))
            unique = tuple(sorted(set(targets)))
            cut = len(unique) > self.max_candidates_per_call or len(implementations) > self.max_candidates_per_call
            if unique:
                detail = tuple(evidence) + (("candidate bound exceeded",) if cut else ())
                return unique[:self.max_candidates_per_call], "candidate", detail, cut
            return (), "unresolved", (f"receiver type has no indexed method evidence: {receiver}.{short}",), False

        import_path = str(imports.get(qualifier, ""))
        if import_path:
            rows = db.execute("SELECT identity FROM functions WHERE package=? AND short=? ORDER BY identity LIMIT ?",
                              (import_path, short, self.max_candidates_per_call + 1)).fetchall()
            return self._targets(rows, f"no declaration in imported package {import_path}")
        aliases = db.execute("SELECT name,evidence FROM aliases WHERE owner=? AND (target=? OR target LIKE ?) ORDER BY rowid LIMIT ?",
                             (caller, call, "%" + call, self.max_candidates_per_call + 1)).fetchall()
        alias_targets: set[str] = set()
        evidence: list[str] = []
        for name, item_evidence in aliases:
            evidence.extend(json.loads(item_evidence))
            direct_values = db.execute(
                "SELECT target,evidence FROM function_values WHERE owner=? AND variable=? ORDER BY rowid LIMIT ?",
                (caller, name, self.max_candidates_per_call + 1),
            ).fetchall()
            if direct_values:
                alias_targets.update(row[0] for row in direct_values)
                for _, value_evidence in direct_values:
                    evidence.extend(json.loads(value_evidence))
                continue
            alias_short = name.rsplit(".", 1)[-1]
            local_aliases = db.execute(
                "SELECT identity FROM functions WHERE package=? AND short=? ORDER BY identity LIMIT ?",
                (package, alias_short, self.max_candidates_per_call + 1),
            ).fetchall()
            rows_for_alias = local_aliases or db.execute(
                "SELECT identity FROM functions WHERE short=? ORDER BY identity LIMIT ?",
                (alias_short, self.max_candidates_per_call + 1),
            ).fetchall()
            alias_targets.update(row[0] for row in rows_for_alias)
        if alias_targets:
            cut = len(alias_targets) > self.max_candidates_per_call
            detail = ("function-value assignment alias",) + tuple(evidence)
            if cut:
                detail += ("candidate bound exceeded",)
            return tuple(sorted(alias_targets))[:self.max_candidates_per_call], "resolved" if len(alias_targets) == 1 else "candidate", detail, cut
        local_targets, local_detail, local_cut = self._resolve_local_value(
            db, caller, call, self.max_candidates_per_call,
        )
        if local_targets:
            return local_targets, "resolved" if len(local_targets) == 1 else "candidate", local_detail, local_cut
        local_rows = db.execute("SELECT identity FROM functions WHERE package=? AND short=? ORDER BY identity LIMIT ?",
                                (package, short, self.max_candidates_per_call + 1)).fetchall()
        if local_rows:
            return self._targets(local_rows, "same-package declaration candidate")
        rows = db.execute("SELECT identity FROM functions WHERE short=? ORDER BY identity LIMIT ?",
                          (short, self.max_candidates_per_call + 1)).fetchall()
        if len(rows) == 1:
            return (rows[0][0],), "resolved", (), False

        if rows:
            return self._targets(rows, "same-name target candidates; dispatch evidence is incomplete")
        return (), "unresolved", (), False

    def _store_function_value(
        self, db: sqlite3.Connection, owner: str, variable: str, expression: Mapping[str, Any],
        fact: Mapping[str, Any], assignment: Mapping[str, Any], written: int,
    ) -> tuple[int, bool]:
        if written >= self.max_relations:
            return written, True
        target = str(expression.get("identity", expression.get("target", expression.get("symbol", ""))))
        kind = str(expression.get("kind", ""))
        if kind == "closure" and not target:
            path = str(assignment.get("file", fact.get("file", "<unknown-file>")))[:4096]
            line = assignment.get("line", 0)
            target = f"{owner}.$closure@{path}:{line}"
        elif target and "." not in target and expression.get("package"):
            target = f"{expression['package']}.{target}"
        if not target:
            return written, False
        evidence = self._evidence(fact, assignment)
        evidence += (f"function-value:{kind}:{variable}",)
        db.execute("INSERT INTO function_values VALUES (?,?,?,?)",
                   (owner, variable[:8192], target[:8192], json.dumps(evidence)))
        return written + 1, False

    def _resolve_local_value(
        self, db: sqlite3.Connection, owner: str, variable: str, limit: int,
    ) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
        """Follow bounded local aliases to explicit function/closure values."""
        frontier = [variable]
        seen: set[str] = set()
        targets: set[str] = set()
        evidence: list[str] = []
        cut = False
        for _depth in range(16):
            next_frontier: list[str] = []
            for current in frontier:
                if current in seen:
                    continue
                seen.add(current)
                remaining = limit + 1 - len(targets)
                rows = db.execute(
                    "SELECT target,evidence FROM function_values WHERE owner=? AND variable=? ORDER BY rowid LIMIT ?",
                    (owner, current, max(1, remaining)),
                ).fetchall()
                for target, item_evidence in rows:
                    targets.add(target)
                    evidence.extend(json.loads(item_evidence))
                aliases = db.execute(
                    "SELECT name,evidence FROM aliases WHERE owner=? AND target=? ORDER BY rowid LIMIT ?",
                    (owner, current, limit + 1),
                ).fetchall()
                for alias, item_evidence in aliases:
                    next_frontier.append(alias)
                    evidence.extend(json.loads(item_evidence))
                if len(targets) > limit:
                    cut = True
                    break
            if cut or not next_frontier:
                break
            frontier = next_frontier
        else:
            if frontier:
                cut = True
        ordered = tuple(sorted(targets)[:limit])
        detail = ("local function-value assignment candidate",) + tuple(dict.fromkeys(evidence))
        if cut:
            detail += ("candidate or alias-depth bound exceeded",)
        return ordered, detail if ordered else (), cut

    def _resolve_value_expression(
        self, db: sqlite3.Connection, owner: str, expression: Mapping[str, Any], limit: int,
    ) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
        kind = str(expression.get("kind", ""))
        if kind in {"function", "function-value", "closure"}:
            target = str(expression.get("identity", expression.get("target", expression.get("symbol", ""))))
            if kind == "closure" and not target:
                path = str(expression.get("file", "<unknown-file>"))[:4096]
                line = expression.get("line", 0)
                target = f"{owner}.$closure@{path}:{line}"
            elif target and "." not in target and expression.get("package"):
                target = f"{expression['package']}.{target}"
            if target:
                return (target[:8192],), (f"registration function-value expression:{kind}",), False
        name = self._expr_name(expression)
        if name:
            return self._resolve_local_value(db, owner, name, limit)
        return (), (), False

    def _targets(self, rows: list[tuple[str]], reason: str) -> tuple[tuple[str, ...], str, tuple[str, ...], bool]:
        if not rows:
            return (), "unresolved", (reason,), False
        cut = len(rows) > self.max_candidates_per_call
        detail = (reason,) if len(rows) > 1 else ()
        if cut:
            detail += ("candidate bound exceeded",)
        status = "resolved" if len(rows) == 1 else "candidate"
        return tuple(row[0] for row in rows[:self.max_candidates_per_call]), status, detail, cut

    @staticmethod
    def _identity(fact: Mapping[str, Any]) -> str:
        identity = str(fact.get("identity", ""))
        if identity:
            return identity
        package, symbol = str(fact.get("package", "")), str(fact.get("symbol", ""))
        return f"{package}.{symbol}" if package and symbol else ""

    @staticmethod
    def _type_name(value: str, imports: Mapping[str, str] | None = None, default_package: str = "") -> str:
        normalized = value.strip().replace("*", "").replace("(", "").replace(")", "")
        if not normalized:
            return ""
        parts = normalized.split(".")
        if len(parts) > 1:
            package = str((imports or {}).get(parts[0], parts[0]))
            return package + "." + parts[-1]
        return (default_package + "." if default_package else "") + normalized

    @staticmethod
    def _expr_name(expression: Mapping[str, Any]) -> str:
        if expression.get("kind") == "variable":
            return str(expression.get("name", ""))
        if expression.get("kind") == "selector":
            base = CallGraphBuilder._expr_name(expression.get("base", {}))
            field = str(expression.get("field", ""))
            return f"{base}.{field}" if base and field else ""
        return ""

    @staticmethod
    def _evidence(*items: Mapping[str, Any]) -> tuple[str, ...]:
        evidence: list[str] = []
        for item in items:
            path = str(item.get("file", ""))[:4096]
            line = item.get("line", item.get("start_line", 0))
            symbol = str(item.get("symbol", item.get("function", "")))[:4096]
            if path or line or symbol:
                evidence.append(":".join(part for part in (path, str(line) if line else "", symbol) if part))
            extra = item.get("evidence")
            if isinstance(extra, str) and extra:
                evidence.append(extra[:4096])
            elif isinstance(extra, (tuple, list)):
                evidence.extend(str(value)[:4096] for value in extra if value)
        return tuple(dict.fromkeys(evidence))
