"""Typed Bor top-level entry points and their dependency regions.

This module is intentionally disjoint from the transaction-lifecycle profile.
It describes where an analysis can enter Bor and which lower-level regions a
request can traverse.  The fixture values are explicitly synthetic; they are
useful for model construction but are not observations from a live node.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .graph import Direction, Graph, Manifest, Need, Persona, Port, Quality, Shape, Zone
from .ir import Representation
from .model import Authorization, Decision, Entry, Fidelity, Model, Operation, Outcome, Provenance, State
from .objective import Limits, Objective, Order, Same
from .workspace import Workspace


BOR_ENTRYPOINT_TARGET = "polygon-bor"
BOR_ENTRYPOINT_SCOPE = "bor-entrypoint-regions"
BOR_ENTRYPOINT_COMMIT = "c72e248587a19b1c93eda95871c46b53071e58fd"

# These values are deliberately fixture-only.  They make the model concrete
# without implying that an analysis observed a live account or block.
SYNTHETIC_VALUES: Mapping[str, str] = MappingProxyType({
    "chain_id": "80001",
    "block_number": "synthetic-0",
    "block_hash": "0x" + "11" * 32,
    "sender": "0x" + "22" * 20,
    "contract": "0x" + "33" * 20,
    "recipient": "0x" + "44" * 20,
    "transaction_hash": "0x" + "55" * 32,
    "state_root": "0x" + "66" * 32,
    "storage_key": "synthetic.slot.0",
})


@dataclass(frozen=True)
class BorEntryPoint:
    """One top-level RPC or contract-facing Bor entry point."""

    entry_point_id: str
    name: str
    kind: str
    region_id: str
    component: str
    profile: Persona
    need: Need
    manifest: Manifest
    input_representation: str
    output_representation: str
    source_refs: tuple[str, ...]
    validation_surface_ids: tuple[str, ...] = ()
    synthetic_values: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.entry_point_id or not self.name or not self.region_id:
            raise ValueError("entry point identity and region are required")
        if self.kind not in {"rpc", "contract", "internal"}:
            raise ValueError("entry point kind must be rpc, contract, or internal")


@dataclass(frozen=True)
class BorValidationSurface:
    """Checks that can accept, reject, or alter an entry-point request."""

    surface_id: str
    entry_point_id: str
    region_id: str
    name: str
    checks: tuple[str, ...]
    source_refs: tuple[str, ...]
    synthetic: bool = True

    def __post_init__(self) -> None:
        if not self.surface_id or not self.entry_point_id or not self.region_id:
            raise ValueError("validation surface identity and region are required")
        if not self.checks:
            raise ValueError("validation surfaces require at least one check")


@dataclass(frozen=True)
class BorUnknownRegion:
    """An attached dependency boundary whose behavior remains unresolved."""

    unknown_id: str
    region_id: str
    dependency: str
    reason: str
    observation_contract: str
    source_refs: tuple[str, ...]
    synthetic_values: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.unknown_id or not self.region_id or not self.dependency:
            raise ValueError("unknown region identity and dependency are required")
        if not self.observation_contract:
            raise ValueError("unknown regions require an observation contract")


@dataclass(frozen=True)
class BorEntrypointRegions:
    """Complete graph/model bundle returned by :func:`bor_entrypoint_regions`."""

    target_id: str
    commit: str
    graph: Graph
    model: Model
    objective: Objective
    entry_points: tuple[BorEntryPoint, ...]
    validation_surfaces: tuple[BorValidationSurface, ...]
    unknown_regions: tuple[BorUnknownRegion, ...]
    synthetic_values: Mapping[str, str]

    def workspace(self) -> Workspace:
        return Workspace.flat(
            self.model,
            graph=self.graph,
            environment=State(self.synthetic_values),
        )

    def authorization(self) -> Authorization:
        return Authorization(
            "rsve-bor-entrypoint-regions",
            frozenset({BOR_ENTRYPOINT_SCOPE}),
            frozenset({self.target_id}),
        )

    def analyze(self):
        """Run the bounded route model while retaining attached unknowns."""
        from .planner import Planner

        report = Planner().plan(
            self.model,
            self.objective,
            self.authorization(),
            environment=self.synthetic_values,
            workspace=self.workspace(),
        )
        if not self.unknown_regions:
            return report
        unknowns = tuple(
            f"{item.unknown_id}: {item.dependency} remains unresolved"
            for item in self.unknown_regions
        )
        from dataclasses import replace

        return replace(
            report,
            unresolved_uncertainty=tuple(dict.fromkeys(report.unresolved_uncertainty + unknowns)),
        )

    def validate(self) -> tuple[str, ...]:
        """Validate graph references and cross-reference all typed regions."""
        errors = list(self.graph.validate().errors)
        entry_ids = {item.entry_point_id for item in self.entry_points}
        region_ids = {item.region_id for item in self.graph.regions}
        errors.extend(
            f"entry point {item.entry_point_id} references unknown region {item.region_id}"
            for item in self.entry_points
            if item.region_id not in region_ids
        )
        errors.extend(
            f"validation surface {item.surface_id} references unknown entry point {item.entry_point_id}"
            for item in self.validation_surfaces
            if item.entry_point_id not in entry_ids
        )
        errors.extend(
            f"unknown region {item.unknown_id} references unknown graph region {item.region_id}"
            for item in self.unknown_regions
            if item.region_id not in region_ids
        )
        surface_ids = {item.surface_id for item in self.validation_surfaces}
        errors.extend(
            f"entry point {item.entry_point_id} references unknown validation surface {surface_id}"
            for item in self.entry_points
            for surface_id in item.validation_surface_ids
            if surface_id not in surface_ids
        )
        return tuple(errors)


def _profile(profile_id: str, component: str, region_id: str, source: str) -> Persona:
    return Persona(
        profile_id=profile_id,
        family="blockchain-client",
        component=component,
        implementation="github.com/0xPolygon/bor",
        version="develop",
        build_digest=BOR_ENTRYPOINT_COMMIT,
        execution_scope={
            "target_id": BOR_ENTRYPOINT_TARGET,
            "region": region_id,
            "source": source,
        },
        feature_set=frozenset({"rpc", "contract", "txpool", "evm", "state", "receipt", "persistence"}),
        provenance=Provenance("bor-source", "develop", (source,), Fidelity.ASSUMED),
    )


def _need(entry_point_id: str, component: str, region_id: str, source: str) -> Need:
    return Need(
        f"need.{entry_point_id}",
        "blockchain-layer",
        component,
        "github.com/0xPolygon/bor",
        "develop",
        build_digest=BOR_ENTRYPOINT_COMMIT,
        execution_scope={"target_id": BOR_ENTRYPOINT_TARGET, "region": region_id},
    )


def _manifest(entry_point_id: str, region_id: str, source: str) -> Manifest:
    return Manifest(
        f"rsve.bor.entrypoint.{entry_point_id}",
        f"rsve.bor/entrypoint/{entry_point_id}",
        "1",
        provides=frozenset({"entry.invoke", "validate", "trace", "reset"}),
        limitations=("runtime observations are not implied by this source model",),
        evidence_quality="source-modelled",
        scope={"target_id": BOR_ENTRYPOINT_TARGET, "region": region_id},
        provenance=Provenance("bor-source", "develop", (source,), Fidelity.ASSUMED),
    )


def _route_model(entry_points: tuple[BorEntryPoint, ...]) -> Model:
    initial = State({
        "rpc.transaction_submitted": False,
        "rpc.call_requested": False,
        "txpool.admitted": False,
        "state.transitioned": False,
        "evm.executed": False,
        "persistence.committed": False,
        "receipt.available": False,
    })

    def rejected(state: State, reason: str) -> Outcome:
        return Outcome(
            Decision.REJECT,
            state,
            observation={"accepted": False, "reason": reason},
            guard=False,
            terminal=True,
            fidelity=Fidelity.MODELED,
        )

    def accepted(state: State, stage: str, writes: frozenset[str]) -> Outcome:
        return Outcome(
            Decision.ACCEPT,
            state,
            observation={"accepted": True, "stage": stage},
            effects=(f"bor.{stage}",),
            writes=writes,
            guard=True,
            fidelity=Fidelity.MODELED,
        )

    def candidate(step: str, condition=lambda _state: True, **values):
        request = {"step": step, "tx_hash": SYNTHETIC_VALUES["transaction_hash"], "contract": SYNTHETIC_VALUES["contract"]}
        request.update(values)
        return lambda state, _objective: (request,) if condition(state) else ()

    def submit(state: State, request):
        if request.get("step") != "rpc.submit_transaction":
            return (rejected(state, "transaction submission step required"),)
        return (accepted(state.update(**{"rpc.transaction_submitted": True}), "rpc.submit_transaction", frozenset({"rpc.transaction_submitted"})),)

    def call(state: State, request):
        if request.get("step") != "rpc.eth_call":
            return (rejected(state, "eth_call step required"),)
        return (accepted(state.update(**{"rpc.call_requested": True}), "rpc.eth_call", frozenset({"rpc.call_requested"})),)

    def admit(state: State, request):
        if request.get("step") != "txpool.admission" or not state.get("rpc.transaction_submitted"):
            return (rejected(state, "submitted transaction required"),)
        return (accepted(state.update(**{"txpool.admitted": True}), "txpool.admission", frozenset({"txpool.admitted"})),)

    def transition(state: State, request):
        if request.get("step") != "state.transition" or not state.get("txpool.admitted"):
            return (rejected(state, "admitted transaction required"),)
        return (accepted(state.update(**{"state.transitioned": True}), "state.transition", frozenset({"state.transitioned"})),)

    def evm(state: State, request):
        if request.get("step") != "evm.call_create2":
            return (rejected(state, "EVM call/create2 step required"),)
        if not state.get("state.transitioned") and not state.get("rpc.call_requested"):
            return (rejected(state, "state transition or eth_call required"),)
        return (accepted(state.update(**{"evm.executed": True}), "evm.call_create2", frozenset({"evm.executed"})),)

    def persist(state: State, request):
        if request.get("step") != "persistence" or not state.get("evm.executed"):
            return (rejected(state, "executed EVM result required"),)
        return (accepted(state.update(**{"persistence.committed": True}), "persistence", frozenset({"persistence.committed"})),)

    def receipt(state: State, request):
        if request.get("step") != "rpc.receipt_query" or not state.get("persistence.committed"):
            return (rejected(state, "persisted receipt required"),)
        return (accepted(state.update(**{"receipt.available": True}), "rpc.receipt_query", frozenset({"receipt.available"})),)

    operations = (
        Operation("rpc.submit_transaction", Entry("rpc.submit_transaction", capabilities=frozenset({"rpc"})), relation=submit, relation_complete=True, request_candidates=candidate("rpc.submit_transaction", condition=lambda state: not state.get("rpc.transaction_submitted")), provenance="internal/ethapi/api.go", component="rpc.submit_transaction"),
        Operation("rpc.eth_call", Entry("rpc.eth_call", capabilities=frozenset({"rpc", "contract"})), relation=call, relation_complete=True, request_candidates=candidate("rpc.eth_call", condition=lambda state: not state.get("rpc.call_requested")), provenance="internal/ethapi/api.go", component="rpc.eth_call"),
        Operation("txpool.admission", Entry("txpool.admission", capabilities=frozenset({"txpool"})), relation=admit, relation_complete=True, request_candidates=candidate("txpool.admission", condition=lambda state: state.get("rpc.transaction_submitted") and not state.get("txpool.admitted")), provenance="core/txpool/validation.go", component="txpool.admission"),
        Operation("state.transition", Entry("state.transition", capabilities=frozenset({"state"})), relation=transition, relation_complete=True, request_candidates=candidate("state.transition", condition=lambda state: state.get("txpool.admitted") and not state.get("state.transitioned")), provenance="core/state_transition.go", component="state.transition"),
        Operation("evm.call_create2", Entry("evm.call_create2", capabilities=frozenset({"evm", "create2"})), relation=evm, relation_complete=True, request_candidates=candidate("evm.call_create2", condition=lambda state: (state.get("state.transitioned") or state.get("rpc.call_requested")) and not state.get("evm.executed"), create2=True, salt="synthetic-salt"), provenance="core/vm/evm.go", component="evm.call_create2"),
        Operation("persistence", Entry("persistence", capabilities=frozenset({"persistence"})), relation=persist, relation_complete=True, request_candidates=candidate("persistence", condition=lambda state: state.get("evm.executed") and not state.get("persistence.committed")), provenance="core/state/statedb.go", component="persistence"),
        Operation("rpc.receipt_query", Entry("rpc.receipt_query", capabilities=frozenset({"rpc", "receipt"})), relation=receipt, relation_complete=True, request_candidates=candidate("rpc.receipt_query", condition=lambda state: state.get("persistence.committed") and not state.get("receipt.available")), provenance="core/rawdb/bor_receipt.go", component="rpc.receipt_query"),
    )
    return Model(
        BOR_ENTRYPOINT_TARGET,
        initial,
        (),
        operations,
        build_hash=BOR_ENTRYPOINT_COMMIT,
        model_version="bor-entrypoint-regions.v1",
        assumptions=(
            "RPC transport, signatures, and contract calldata use explicit synthetic fixture values",
            "database, process, kernel, scheduler, and peer behavior remain attached unknown regions",
        ),
    )


def bor_entrypoint_regions() -> BorEntrypointRegions:
    """Build typed regions for Bor's RPC, contract, execution, and persistence paths."""
    definitions = (
        ("rpc.submit_transaction", "Transaction RPC submission", "rpc", "bor.rpc.submit", "rpc.transaction", "tx.signed", ("internal/ethapi/api.go:2117",), ("rpc.submit.validation",)),
        ("rpc.eth_call", "eth_call contract execution", "rpc", "bor.rpc.eth_call", "rpc.call", "evm.call.result", ("internal/ethapi/api.go", "core/ethapi/api.go"), ("rpc.call.validation",)),
        ("txpool.admission", "Txpool admission", "internal", "bor.txpool.admission", "tx.signed", "tx.admitted", ("core/txpool/validation.go:61",), ("txpool.stateless", "txpool.stateful")),
        ("state.transition", "State transition", "internal", "bor.state.transition", "tx.admitted", "evm.call.request", ("core/state_processor.go:335", "core/state_transition.go:390"), ("state.precheck", "state.fork_context")),
        ("evm.call_create2", "EVM call and CREATE2", "contract", "bor.evm.call_create2", "evm.call.request", "evm.result", ("core/vm/evm.go", "core/vm/interpreter.go"), ("evm.opcode", "evm.create2.address")),
        ("persistence", "State and receipt persistence", "internal", "bor.persistence", "receipt.internal", "receipt.storage", ("core/state/statedb.go", "core/rawdb/bor_receipt.go"), ("persistence.trie", "persistence.database")),
        ("rpc.receipt_query", "Receipt query", "rpc", "bor.rpc.receipt_query", "receipt.storage", "rpc.receipt", ("core/rawdb/bor_receipt.go:152",), ("rpc.receipt.lookup",)),
    )

    profiles: list[Persona] = []
    entry_points: list[BorEntryPoint] = []
    graph = Graph("bor-entrypoint-regions")
    for index, (entry_id, name, kind, region_id, input_rep, output_rep, sources, surfaces) in enumerate(definitions):
        profile = _profile(f"bor.entrypoint.profile.{index}", name.lower().replace(" ", "-"), region_id, sources[0])
        profiles.append(profile)
        if index == 0:
            graph = Graph.for_profile(profile, graph_id="bor-entrypoint-regions", region_id=region_id, region_name=name)
        else:
            graph = graph.persona(profile).zone(Zone(region_id, profile.profile_id, name, profile.execution_scope))
        manifest = _manifest(entry_id, region_id, sources[0])
        graph = graph.register(manifest)
        graph = graph.port(Port(f"{region_id}.input", region_id, "input", Direction.INPUT, input_rep, input_rep))
        graph = graph.port(Port(f"{region_id}.output", region_id, "output", Direction.OUTPUT, output_rep, output_rep))
        if entry_id == "rpc.eth_call":
            graph = graph.port(Port(f"{region_id}.invoke", region_id, "evm invoke", Direction.OUTPUT, "evm.call.request", "evm.call.request"))
            graph = graph.port(Port(f"{region_id}.result", region_id, "evm result", Direction.INPUT, "evm.result", "evm.result"))
        elif entry_id == "state.transition":
            graph = graph.port(Port(f"{region_id}.evm_result", region_id, "evm result", Direction.INPUT, "evm.result", "evm.result"))
            graph = graph.port(Port(f"{region_id}.receipt", region_id, "receipt", Direction.OUTPUT, "receipt.internal", "receipt.internal"))
        need = _need(entry_id, profile.component, region_id, sources[0])
        entry_points.append(BorEntryPoint(
            entry_id,
            name,
            kind,
            region_id,
            profile.component,
            profile,
            need,
            manifest,
            input_rep,
            output_rep,
            sources,
            surfaces,
            {"chain_id": SYNTHETIC_VALUES["chain_id"], "block_number": SYNTHETIC_VALUES["block_number"], "sender": SYNTHETIC_VALUES["sender"], "contract": SYNTHETIC_VALUES["contract"]},
        ))

    representations = {
        item
        for entry in entry_points
        for item in (
            Representation(entry.input_representation, entry.input_representation, "synthetic-typed-fixture"),
            Representation(entry.output_representation, entry.output_representation, "synthetic-typed-fixture"),
        )
    }
    for representation in sorted(representations, key=lambda item: item.representation_id):
        graph = graph.value(representation)

    def connect(source: str, destination: str, connection_id: str, correlation: str) -> None:
        nonlocal graph
        graph = graph.connect(
            source,
            destination,
            connection_id=connection_id,
            correlation_contract=correlation,
            correlation_quality=Quality.DETERMINISTIC_DERIVED,
            fidelity=Fidelity.MODELED,
            relationship_type=Shape.CAUSAL,
            scope={"target_id": BOR_ENTRYPOINT_TARGET},
        )

    connect("bor.rpc.submit.output", "bor.txpool.admission.input", "route.rpc-to-txpool", "tx.hash")
    connect("bor.txpool.admission.output", "bor.state.transition.input", "route.txpool-to-state", "tx.hash")
    connect("bor.state.transition.output", "bor.evm.call_create2.input", "route.state-to-evm", "execution.id")
    connect("bor.evm.call_create2.output", "bor.state.transition.evm_result", "route-evm-to-state", "execution.id")
    connect("bor.state.transition.receipt", "bor.persistence.input", "route-state-to-persistence", "state.root")
    connect("bor.persistence.output", "bor.rpc.receipt_query.input", "route-persistence-to-receipt", "tx.hash")
    connect("bor.rpc.eth_call.invoke", "bor.evm.call_create2.input", "route-call-to-evm", "call.id")
    connect("bor.evm.call_create2.output", "bor.rpc.eth_call.result", "route-evm-to-call", "call.id")

    surfaces = (
        BorValidationSurface("rpc.submit.validation", "rpc.submit_transaction", "bor.rpc.submit", "RPC request and signature checks", ("typed transaction", "chain id", "signature", "fee fields", "intrinsic gas"), ("internal/ethapi/api.go", "core/types/transaction.go")),
        BorValidationSurface("rpc.call.validation", "rpc.eth_call", "bor.rpc.eth_call", "eth_call context checks", ("block selector", "caller", "gas cap", "call data", "read-only execution"), ("internal/ethapi/api.go", "core/ethapi/api.go")),
        BorValidationSurface("txpool.stateless", "txpool.admission", "bor.txpool.admission", "Stateless txpool checks", ("transaction type", "size", "fork activation", "gas limit", "fee-cap ordering", "minimum tip"), ("core/txpool/validation.go:61",)),
        BorValidationSurface("txpool.stateful", "txpool.admission", "bor.txpool.admission", "Stateful txpool checks", ("nonce", "nonce gaps", "balance versus cost", "replacement cost"), ("core/txpool/validation.go:220",)),
        BorValidationSurface("state.precheck", "state.transition", "bor.state.transition", "State transition precheck", ("nonce", "upfront gas", "intrinsic gas", "balance", "authorization"), ("core/state_transition.go:390",)),
        BorValidationSurface("state.fork_context", "state.transition", "bor.state.transition", "Block and fork context", ("chain config", "block number", "base fee", "coinbase", "gas limit"), ("core/state_transition.go",)),
        BorValidationSurface("evm.opcode", "evm.call_create2", "bor.evm.call_create2", "EVM instruction validation", ("opcode dispatch", "stack height", "gas", "revert", "storage writes"), ("core/vm/interpreter.go",)),
        BorValidationSurface("evm.create2.address", "evm.call_create2", "bor.evm.call_create2", "CREATE2 address occupancy", ("nonce", "code hash", "storage root", "collision guard"), ("core/vm/evm.go", "core/state/parallel_statedb.go:1062")),
        BorValidationSurface("persistence.trie", "persistence", "bor.persistence", "Trie and state persistence", ("journal finalization", "account trie", "storage trie", "root reopen"), ("core/state/statedb.go",)),
        BorValidationSurface("persistence.database", "persistence", "bor.persistence", "Receipt/database persistence", ("receipt encoding", "storage key", "database write", "reopen"), ("core/rawdb/bor_receipt.go",)),
        BorValidationSurface("rpc.receipt.lookup", "rpc.receipt_query", "bor.rpc.receipt_query", "Receipt query", ("transaction hash", "block hash", "reorg visibility", "receipt fields"), ("core/rawdb/bor_receipt.go:152",)),
    )

    unknowns = (
        BorUnknownRegion("unknown.rpc.transport", "bor.rpc.submit", "HTTP/IPC/WebSocket transport and middleware", "Transport normalization, authentication, and request fan-out are outside this source model.", "capture request bytes, process identity, and response correlation", ("RPC boundary",), {"transport": "synthetic-local"}),
        BorUnknownRegion("unknown.rpc.call.snapshot", "bor.rpc.eth_call", "eth_call snapshot and historical-state selection", "The selected block state and snapshot lifetime are represented by synthetic values.", "capture block selector, state root, and snapshot lifetime", ("RPC boundary",), {"block_selector": SYNTHETIC_VALUES["block_number"], "state_root": SYNTHETIC_VALUES["state_root"]}),
        BorUnknownRegion("unknown.txpool.peers", "bor.txpool.admission", "peer gossip, replacement, and queue scheduling", "Peer-originated ordering and queue behavior are not inferred from local validation.", "capture peer id, queue transition, and replacement lineage", ("txpool boundary",), {"peer_id": "synthetic-peer-0"}),
        BorUnknownRegion("unknown.state.fork_config", "bor.state.transition", "chain configuration and fork activation", "Fork selection and configuration reload behavior need an observed block context.", "capture config digest and effective fork at block execution", ("core/state_transition.go",), {"fork_profile": "synthetic-bor-develop"}),
        BorUnknownRegion("unknown.evm.host", "bor.evm.call_create2", "precompiles, host calls, and runtime resource limits", "Host-provided EVM behavior is represented only by typed outcomes here.", "capture opcode trace, gas ledger, and host-call results", ("core/vm",), {"gas_limit": "synthetic-30000000"}),
        BorUnknownRegion("unknown.persistence.filesystem", "bor.persistence", "filesystem, database, process, and kernel persistence boundary", "The state model names the persistence seam but does not fabricate durable bytes or host events.", "capture database writes, fsync outcomes, process identity, and root reopen", ("core/state", "core/rawdb"), {"database": "synthetic-memory"}),
        BorUnknownRegion("unknown.receipt.reorg", "bor.rpc.receipt_query", "reorg and receipt visibility timing", "Receipt lookup semantics across competing heads require an observed chain history.", "capture canonical head, receipt key, and reorg event correlation", ("core/rawdb/bor_receipt.go",), {"canonical_head": SYNTHETIC_VALUES["block_hash"]}),
    )

    model = _route_model(tuple(entry_points))
    objective = Objective(
        "bor-entrypoint-route-coverage",
        BOR_ENTRYPOINT_TARGET,
        BOR_ENTRYPOINT_SCOPE,
        (
            Same("receipt.available", True),
            Same("evm.executed", True),
        ),
        environment_boundaries={"chain_id": SYNTHETIC_VALUES["chain_id"], "block_number": SYNTHETIC_VALUES["block_number"]},
        state_keys=frozenset({"rpc.transaction_submitted", "txpool.admitted", "state.transitioned", "evm.executed", "persistence.committed", "receipt.available"}),
        checkpoints=(Order(("rpc.submit_transaction", "txpool.admission", "state.transition", "evm.call_create2", "persistence", "rpc.receipt_query")),),
        assumptions=("synthetic request, account, block, and state-root values are explicit fixture inputs",),
        budget=Limits(max_trace_length=8),
    )
    return BorEntrypointRegions(
        BOR_ENTRYPOINT_TARGET,
        BOR_ENTRYPOINT_COMMIT,
        graph,
        model,
        objective,
        tuple(entry_points),
        surfaces,
        unknowns,
        SYNTHETIC_VALUES,
    )


__all__ = [
    "BOR_ENTRYPOINT_COMMIT",
    "BOR_ENTRYPOINT_SCOPE",
    "BOR_ENTRYPOINT_TARGET",
    "BorEntryPoint",
    "BorEntrypointRegions",
    "BorUnknownRegion",
    "BorValidationSurface",
    "SYNTHETIC_VALUES",
    "bor_entrypoint_regions",
]
