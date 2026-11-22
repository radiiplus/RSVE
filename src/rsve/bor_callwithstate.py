"""RSVE model for the non-CREATE2 Bor CallWithState nonce mutation path."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .bor_profile import BOR_COMMIT, BOR_TARGET
from .graph import Graph, Persona, Zone
from .model import Authorization, Decision, Entry, Fidelity, Model, Operation, Outcome, State
from .objective import Limits, Objective, Order, Same
from .workspace import Workspace


BOR_CALLWITHSTATE_SCOPE = "bor-callwithstate-readonly-mutation-analysis"
BOR_STATE_OVERRIDE_SCOPE = "bor-callwithstate-state-override-analysis"


@dataclass(frozen=True)
class BorCallWithStateProfile:
    target_id: str
    commit: str
    graph: Graph
    model: Model
    objective: Objective
    root_profile: Persona
    attached_regions: tuple[str, ...]
    unknown_regions: tuple[str, ...]
    source_refs: tuple[str, ...]

    def workspace(self) -> Workspace:
        # Keep the executable witness focused on the four production calls;
        # the graph carries the wider runtime and host attachments separately.
        return Workspace.flat(self.model)

    def authorization(self) -> Authorization:
        return Authorization(
            "rsve-bor-callwithstate-profile",
            frozenset({BOR_CALLWITHSTATE_SCOPE}),
            frozenset({self.target_id}),
        )

    def analyze(self):
        from .planner import Planner

        report = Planner().plan(
            self.model,
            self.objective,
            self.authorization(),
            workspace=self.workspace(),
        )
        return self.attach_unknown_regions(report)

    def attach_unknown_regions(self, report):
        unknowns = tuple(
            f"{region}: boundary is attached but not instrumented"
            for region in self.unknown_regions
        )
        return replace(
            report,
            unresolved_uncertainty=tuple(dict.fromkeys(report.unresolved_uncertainty + unknowns)),
        )

    def ingest_compiled_artifact(self, path):
        from .bor_evidence import BorCallWithStateIngest

        return BorCallWithStateIngest.load(path)

    def validate(self) -> tuple[str, ...]:
        return tuple(self.graph.validate().errors)


def _model() -> Model:
    initial = State({
        "call.requested": False,
        "live_state.supplied": False,
        "message.executed": False,
        "call.read_only": False,
        "account.nonce_before": 7,
        "account.nonce_after": 7,
        "state.mutated": False,
        "canonical.transaction": False,
        "receipt.created": False,
        "account.out_of_band": False,
    })

    def rejected(state: State, reason: str, source: str) -> Outcome:
        return Outcome(
            Decision.REJECT,
            state,
            observation={"reason": reason},
            guard=False,
            terminal=True,
            fidelity=Fidelity.MODELED,
            evidence=(source,),
        )

    def accepted(state: State, entry: str, source: str, writes: frozenset[str]) -> Outcome:
        return Outcome(
            Decision.ACCEPT,
            state,
            observation={"entry": entry},
            effects=(entry,),
            writes=writes,
            guard=True,
            fidelity=Fidelity.MODELED,
            evidence=(source,),
        )

    def rpc(state: State, request):
        source = "internal/ethapi/api.go:1043"
        if request.get("step") != "rpc":
            return (rejected(state, "eth_call entry required", source),)
        return (accepted(state.update(**{"call.requested": True}), "rpc.eth_call", source, frozenset({"call.requested"})),)

    def call_with_state(state: State, request):
        source = "internal/ethapi/api.go:1043"
        if not state.get("call.requested") or request.get("step") != "callwithstate":
            return (rejected(state, "CallWithState requires the RPC call", source),)
        if request.get("state_owner") != "caller-owned":
            return (rejected(state, "caller-owned StateDB is required", source),)
        return (accepted(state.update(**{"live_state.supplied": True, "call.read_only": True}), "internal.CallWithState", source, frozenset({"live_state.supplied", "call.read_only"})),)

    def apply_message(state: State, request):
        source = "core/state_transition.go:335"
        if not state.get("live_state.supplied") or request.get("step") != "applymessage":
            return (rejected(state, "ApplyMessage requires caller-owned state", source),)
        return (accepted(state.update(**{"message.executed": True}), "core.ApplyMessage", source, frozenset({"message.executed"})),)

    def set_nonce(state: State, request):
        source = "core/state_transition.go:571"
        if not state.get("message.executed") or request.get("step") != "setnonce":
            return (rejected(state, "SetNonce requires message execution", source),)
        return (accepted(
            state.update(**{
                "account.nonce_after": int(state.get("account.nonce_before", 7)) + 1,
                "state.mutated": True,
                "account.out_of_band": True,
            }),
            "state.SetNonce",
            source,
            frozenset({"account.nonce_after", "state.mutated", "account.out_of_band"}),
        ),)

    operations = (
        Operation("rpc.eth-call", Entry("rpc.eth_call"), relation=rpc, relation_complete=True, writes=frozenset({"call.requested"}), provenance="internal/ethapi/api.go:1043", component="bor.rpc.contract-call"),
        Operation("runtime.call-with-state", Entry("internal.CallWithState"), relation=call_with_state, relation_complete=True, writes=frozenset({"live_state.supplied", "call.read_only"}), provenance="internal/ethapi/api.go:1043", component="bor.runtime.message-conversion"),
        Operation("engine.apply-message", Entry("core.ApplyMessage"), relation=apply_message, relation_complete=True, writes=frozenset({"message.executed"}), provenance="core/state_transition.go:335", component="bor.runtime.serial-execute"),
        Operation("state.set-nonce", Entry("state.SetNonce"), relation=set_nonce, relation_complete=True, writes=frozenset({"account.nonce_after", "state.mutated", "account.out_of_band"}), provenance="core/state_transition.go:571", component="bor.state.serial-writes"),
    )
    inputs = (
        {"step": "rpc"},
        {"step": "callwithstate", "state_owner": "caller-owned"},
        {"step": "applymessage"},
        {"step": "setnonce"},
    )
    return Model.build(
        BOR_TARGET,
        initial,
        inputs,
        operations,
        build_hash=BOR_COMMIT,
        model_version="bor-callwithstate-readonly-mutation.v1",
        assumptions=(
            "the caller-owned StateDB is live across the internal CallWithState invocation",
            "the message uses zero value and zero gas price so the observed account change is nonce-only",
            "the public RPC wrapper normally supplies an isolated StateDB; this model targets internal callers of CallWithState",
        ),
    )


def bor_callwithstate_profile() -> BorCallWithStateProfile:
    from .bor_profile import bor_transaction_lifecycle_profile

    root = bor_transaction_lifecycle_profile()
    regions = (
        ("bor.rpc.contract-call", "RPC contract-call entry", "internal/ethapi/api.go:1043"),
        ("bor.runtime.message-conversion", "CallWithState message conversion", "internal/ethapi/api.go:1043"),
        ("bor.runtime.serial-execute", "ApplyMessage execution", "core/state_transition.go:335"),
        ("bor.state.serial-writes", "Account nonce write", "core/state_transition.go:571"),
        ("bor.persistence.state-root", "State-root persistence", "core/state/statedb.go:1819"),
        ("bor.runtime.process", "Runtime process boundary", "environment:process-identity"),
        ("bor.os.kernel", "OS and kernel boundary", "environment:namespace-seccomp"),
        ("bor.memory.cpu", "Memory and CPU telemetry", "environment:memory-cpu-telemetry"),
        ("bor.persistence.external", "External persistence boundary", "environment:database-filesystem"),
    )
    graph = root.graph
    known_regions = {region.region_id for region in graph.regions}
    for region_id, name, source in regions:
        if region_id in known_regions:
            continue
        graph = graph.zone(Zone(
            region_id,
            root.root_profile.profile_id,
            name,
            scope={"target_id": BOR_TARGET, "source": source, "status": "unknown" if region_id.startswith(("bor.runtime.process", "bor.os.", "bor.memory.", "bor.persistence.external")) else "attached"},
            provenance=root.graph.regions[0].provenance,
        ))
    unknown_regions = tuple(item[0] for item in regions if item[0].startswith(("bor.runtime.process", "bor.os.", "bor.memory.", "bor.persistence.external")))
    return BorCallWithStateProfile(
        BOR_TARGET,
        BOR_COMMIT,
        graph,
        _model(),
        Objective(
            "bor-callwithstate-readonly-account-mutation",
            BOR_TARGET,
            BOR_CALLWITHSTATE_SCOPE,
            (
                Same("call.read_only", True),
                Same("account.nonce_before", 7),
                Same("account.nonce_after", 8),
                Same("state.mutated", True),
                Same("canonical.transaction", False),
                Same("receipt.created", False),
                Same("account.out_of_band", True),
                Order(("rpc.eth_call", "internal.CallWithState", "core.ApplyMessage", "state.SetNonce")),
            ),
            state_keys=frozenset({"call.read_only", "account.nonce_before", "account.nonce_after", "state.mutated", "canonical.transaction", "receipt.created", "account.out_of_band"}),
            budget=Limits(max_trace_length=4, max_states=10_000, max_events=10_000, max_time_ms=60_000),
        ),
        root.root_profile,
        tuple(item[0] for item in regions),
        unknown_regions,
        tuple(item[2] for item in regions),
    )


@dataclass(frozen=True)
class BorStateOverrideProfile:
    """Focused model for overrides applied to a caller-owned live StateDB."""

    target_id: str
    commit: str
    graph: Graph
    model: Model
    objective: Objective
    root_profile: Persona
    attached_regions: tuple[str, ...]
    unknown_regions: tuple[str, ...]
    source_refs: tuple[str, ...]

    def workspace(self) -> Workspace:
        return Workspace.flat(self.model)

    def authorization(self) -> Authorization:
        return Authorization(
            "rsve-bor-state-override-profile",
            frozenset({BOR_STATE_OVERRIDE_SCOPE}),
            frozenset({self.target_id}),
        )

    def analyze(self):
        from .planner import Planner

        report = Planner().plan(
            self.model,
            self.objective,
            self.authorization(),
            workspace=self.workspace(),
        )
        unknowns = tuple(
            f"{region}: boundary is attached but not instrumented"
            for region in self.unknown_regions
        )
        return replace(
            report,
            unresolved_uncertainty=tuple(dict.fromkeys(report.unresolved_uncertainty + unknowns)),
        )

    def validate(self) -> tuple[str, ...]:
        return tuple(self.graph.validate().errors)


def _state_override_model() -> Model:
    initial = State({
        "call.requested": False,
        "live_state.supplied": False,
        "override.applied": False,
        "snapshot.created": False,
        "call.reverted": False,
        "account.balance_before": 100,
        "account.balance_after": 100,
        "account.storage_before": 0,
        "account.storage_after": 0,
        "state.mutated": False,
        "canonical.transaction": False,
        "receipt.created": False,
        "account.out_of_band": False,
        "state.persisted": False,
    })

    def reject(state: State, reason: str, source: str) -> Outcome:
        return Outcome(
            Decision.REJECT,
            state,
            observation={"reason": reason},
            guard=False,
            terminal=True,
            fidelity=Fidelity.MODELED,
            evidence=(source,),
        )

    def accept(state: State, entry: str, source: str, writes: frozenset[str]) -> Outcome:
        return Outcome(
            Decision.ACCEPT,
            state,
            observation={"entry": entry},
            effects=(entry,),
            writes=writes,
            guard=True,
            fidelity=Fidelity.MODELED,
            evidence=(source,),
        )

    def rpc(state: State, request):
        source = "internal/ethapi/api.go:1043"
        if request.get("step") != "rpc":
            return (reject(state, "eth_call entry required", source),)
        return (accept(state.update(**{"call.requested": True}), "rpc.eth_call", source, frozenset({"call.requested"})),)

    def call_with_state(state: State, request):
        source = "internal/ethapi/api.go:1052"
        if not state.get("call.requested") or request.get("step") != "callwithstate":
            return (reject(state, "CallWithState requires the RPC call", source),)
        if request.get("state_owner") != "caller-owned":
            return (reject(state, "caller-owned StateDB is required", source),)
        return (accept(state.update(**{"live_state.supplied": True}), "internal.CallWithState", source, frozenset({"live_state.supplied"})),)

    def apply_override(state: State, request):
        source = "internal/ethapi/api.go:911"
        if not state.get("live_state.supplied") or request.get("step") != "override":
            return (reject(state, "StateOverride.Apply requires caller-owned state", source),)
        if request.get("balance") != 1 or request.get("storage") != 99:
            return (reject(state, "synthetic balance/storage override required", source),)
        return (accept(state.update(**{
            "override.applied": True,
            "account.balance_after": 1,
            "account.storage_after": 99,
            "state.mutated": True,
            "account.out_of_band": True,
        }), "override.StateOverride.Apply", source, frozenset({"override.applied", "account.balance_after", "account.storage_after", "state.mutated", "account.out_of_band"})),)

    def reverted_call(state: State, request):
        source = "core/vm/evm.go:368"
        if not state.get("override.applied") or request.get("step") != "snapshot-revert":
            return (reject(state, "EVM snapshot must follow the override", source),)
        return (accept(state.update(**{"snapshot.created": True, "call.reverted": True}), "evm.Call.snapshot", source, frozenset({"snapshot.created", "call.reverted"})),)

    def commit(state: State, request):
        source = "core/state/statedb.go:2414"
        if not state.get("call.reverted") or request.get("step") != "commit":
            return (reject(state, "commit must follow the reverted call", source),)
        return (accept(state.update(**{"state.persisted": True}), "core.StateDB.Commit", source, frozenset({"state.persisted"})),)

    operations = (
        Operation("rpc.eth-call-override", Entry("rpc.eth_call"), relation=rpc, relation_complete=True, writes=frozenset({"call.requested"}), provenance="internal/ethapi/api.go:1043", component="bor.rpc.contract-call"),
        Operation("runtime.call-with-state-override", Entry("internal.CallWithState"), relation=call_with_state, relation_complete=True, writes=frozenset({"live_state.supplied"}), provenance="internal/ethapi/api.go:1052", component="bor.runtime.message-conversion"),
        Operation("runtime.state-override-apply", Entry("override.StateOverride.Apply"), relation=apply_override, relation_complete=True, writes=frozenset({"override.applied", "account.balance_after", "account.storage_after", "state.mutated", "account.out_of_band"}), provenance="internal/ethapi/api.go:911", component="bor.runtime.state-override"),
        Operation("contract.call-snapshot", Entry("evm.Call.snapshot"), relation=reverted_call, relation_complete=True, writes=frozenset({"snapshot.created", "call.reverted"}), provenance="core/vm/evm.go:368", component="bor.contract.evm-call"),
        Operation("persistence.commit", Entry("core.StateDB.Commit"), relation=commit, relation_complete=True, writes=frozenset({"state.persisted"}), provenance="core/state/statedb.go:2414", component="bor.persistence.state-root"),
    )
    inputs = (
        {"step": "rpc"},
        {"step": "callwithstate", "state_owner": "caller-owned"},
        {"step": "override", "balance": 1, "storage": 99},
        {"step": "snapshot-revert"},
        {"step": "commit"},
    )
    return Model.build(
        BOR_TARGET,
        initial,
        inputs,
        operations,
        build_hash=BOR_COMMIT,
        model_version="bor-callwithstate-state-override.v1",
        assumptions=(
            "StateOverride.Apply writes the supplied live StateDB before the EVM snapshot",
            "the reverted call restores only mutations made after the EVM snapshot",
            "a caller that commits or reuses the supplied StateDB can expose the override values to later state consumers",
        ),
    )


def bor_state_override_profile() -> BorStateOverrideProfile:
    root = bor_callwithstate_profile()
    regions = (
        ("bor.rpc.contract-call", "RPC contract-call entry", "internal/ethapi/api.go:1043"),
        ("bor.runtime.message-conversion", "CallWithState state selection", "internal/ethapi/api.go:1052"),
        ("bor.runtime.state-override", "StateOverride application", "internal/ethapi/api.go:911"),
        ("bor.contract.evm-call", "EVM snapshot boundary", "core/vm/evm.go:368"),
        ("bor.persistence.state-root", "State-root commit", "core/state/statedb.go:2414"),
        ("bor.runtime.process", "Runtime process boundary", "environment:process-identity"),
        ("bor.os.kernel", "OS and kernel boundary", "environment:namespace-seccomp"),
        ("bor.memory.cpu", "Memory and CPU telemetry", "environment:memory-cpu-telemetry"),
        ("bor.persistence.external", "External persistence boundary", "environment:database-filesystem"),
    )
    graph = root.graph
    known_regions = {region.region_id for region in graph.regions}
    for region_id, name, source in regions:
        if region_id in known_regions:
            continue
        graph = graph.zone(Zone(
            region_id,
            root.root_profile.profile_id,
            name,
            scope={"target_id": BOR_TARGET, "source": source, "status": "unknown" if region_id.startswith(("bor.runtime.process", "bor.os.", "bor.memory.", "bor.persistence.external")) else "attached"},
            provenance=root.graph.regions[0].provenance,
        ))
    unknown_regions = tuple(item[0] for item in regions if item[0].startswith(("bor.runtime.process", "bor.os.", "bor.memory.", "bor.persistence.external")))
    return BorStateOverrideProfile(
        BOR_TARGET,
        BOR_COMMIT,
        graph,
        _state_override_model(),
        Objective(
            "bor-callwithstate-state-override-balance-mutation",
            BOR_TARGET,
            BOR_STATE_OVERRIDE_SCOPE,
            (
                Same("account.balance_before", 100),
                Same("account.balance_after", 1),
                Same("account.storage_before", 0),
                Same("account.storage_after", 99),
                Same("state.mutated", True),
                Same("call.reverted", True),
                Same("canonical.transaction", False),
                Same("receipt.created", False),
                Same("account.out_of_band", True),
                Same("state.persisted", True),
                Order(("rpc.eth_call", "internal.CallWithState", "override.StateOverride.Apply", "evm.Call.snapshot", "core.StateDB.Commit")),
            ),
            state_keys=frozenset({"account.balance_before", "account.balance_after", "account.storage_before", "account.storage_after", "state.mutated", "call.reverted", "canonical.transaction", "receipt.created", "account.out_of_band", "state.persisted"}),
            budget=Limits(max_trace_length=5, max_states=10_000, max_events=10_000, max_time_ms=60_000),
        ),
        root.root_profile,
        tuple(item[0] for item in regions),
        unknown_regions,
        tuple(item[2] for item in regions),
    )


__all__ = [
    "BOR_CALLWITHSTATE_SCOPE",
    "BOR_STATE_OVERRIDE_SCOPE",
    "BorCallWithStateProfile",
    "BorStateOverrideProfile",
    "bor_callwithstate_profile",
    "bor_state_override_profile",
]
