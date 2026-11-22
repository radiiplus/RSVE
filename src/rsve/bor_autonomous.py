"""End-to-end Bor region inventory and autonomous RSVE entry point.

The inventory is intentionally separate from the executable storage-root
model. It lets adapters bind RPC, contract, runtime, and host observations to
the same report without pretending that an uninstrumented boundary is safe.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .bor_callwithstate import bor_callwithstate_profile, bor_state_override_profile
from .bor_environment import EnvironmentObservation
from .bor_entrypoints import bor_entrypoint_regions
from .bor_profile import BorStorageRootRegressionProfile, bor_storage_root_regression_profile
from .graph import Graph, Zone


@dataclass(frozen=True)
class BorRegionSpec:
    region_id: str
    layer: str
    entry_points: tuple[str, ...]
    source_refs: tuple[str, ...]
    synthetic_fields: tuple[str, ...]
    unknown: bool = True


_REGIONS = (
    BorRegionSpec(
        "bor.rpc.transaction-submit",
        "rpc",
        ("eth_sendRawTransaction", "internal/ethapi.BlockChainAPI.SendTransaction"),
        ("internal/ethapi/api.go:2117", "internal/ethapi/transaction_args.go:404"),
        ("chain_id", "nonce", "gas", "fee_cap", "tip_cap", "to", "value", "data"),
    ),
    BorRegionSpec(
        "bor.rpc.contract-call",
        "rpc",
        ("eth_call", "internal/ethapi.BlockChainAPI.Call", "internal/ethapi.doCall"),
        ("internal/ethapi/api.go:902", "internal/ethapi/api.go:1039"),
        ("from", "to", "data", "gas", "value", "block_reference", "state_overrides"),
    ),
    BorRegionSpec(
        "bor.engine.txpool-admission",
        "engine",
        ("txpool.ValidateTransaction", "txpool.ValidateTransactionWithState"),
        ("core/txpool/validation.go:61", "core/txpool/validation.go:220"),
        ("sender_nonce", "sender_balance", "queued_cost", "fork_rules"),
    ),
    BorRegionSpec(
        "bor.engine.state-transition",
        "engine",
        ("core.ApplyMessage", "core.StateProcessor.Process"),
        ("core/state_transition.go:335", "core/state_processor.go:62"),
        ("pre_state_root", "message", "gas_pool", "block_context", "state_writes"),
    ),
    BorRegionSpec(
        "bor.contract.evm-call",
        "contract",
        ("core/vm.EVM.Call", "core/vm.EVM.StaticCall", "core/vm.EVM.DelegateCall"),
        ("core/vm/evm.go:350", "core/vm/evm.go:494", "core/vm/evm.go:540"),
        ("caller", "callee", "calldata", "value", "gas", "return_data", "revert"),
    ),
    BorRegionSpec(
        "bor.contract.create2",
        "contract",
        ("core/vm.EVM.Create2", "evm.CREATE2.collisionCheck"),
        ("core/vm/evm.go:640", "core/vm/evm.go:751"),
        ("creator", "salt", "init_code", "endowment", "derived_address", "collision_result"),
    ),
    BorRegionSpec(
        "bor.runtime.blockstm",
        "runtime",
        ("ParallelStateDB.FlushToMVStore", "ParallelStateDB.GetStorageRoot"),
        ("core/state/parallel_statedb.go:1076", "core/blockstm"),
        ("tx_index", "read_set", "write_set", "writer_index", "validation_result"),
    ),
    BorRegionSpec(
        "bor.runtime.process",
        "runtime",
        ("process.identity", "process.memory.snapshot", "process.signal"),
        ("environment:process-identity",),
        ("pid", "executable_hash", "maps_hash", "threads", "signals"),
    ),
    BorRegionSpec(
        "bor.persistence.state-root",
        "persistence",
        ("StateDB.IntermediateRoot", "StateDB.Commit"),
        ("core/state/statedb.go:1819", "core/state/statedb.go:2414"),
        ("account_before", "account_after", "storage_nodes", "post_state_root"),
    ),
    BorRegionSpec(
        "bor.persistence.receipt",
        "persistence",
        ("rawdb.WriteReceipts", "TransactionAPI.GetTransactionReceipt"),
        ("core/rawdb/bor_receipt.go:111", "internal/ethapi/api.go:1998"),
        ("tx_hash", "receipt_status", "gas_used", "logs", "storage_key"),
    ),
    BorRegionSpec(
        "bor.kernel.boundary",
        "kernel",
        ("syscall.audit", "seccomp.status", "namespace.status"),
        ("environment:kernel-syscall",),
        ("syscalls", "ptrace_state", "seccomp", "namespace", "signals"),
    ),
    BorRegionSpec(
        "bor.host.environment",
        "host",
        ("host.clock", "host.randomness", "host.disk", "host.cpu"),
        ("environment:host-state",),
        ("clock", "randomness", "disk_faults", "cpu_features", "cgroup"),
    ),
)


def bor_region_specs() -> tuple[BorRegionSpec, ...]:
    return _REGIONS


def bor_autonomous_profile() -> BorStorageRootRegressionProfile:
    """Attach the full region inventory to the executable Bor finding model."""
    base = bor_storage_root_regression_profile()
    graph: Graph = base.graph
    known = {region.region_id for region in graph.regions}
    for spec in _REGIONS:
        if spec.region_id in known:
            continue
        graph = graph.zone(Zone(
            spec.region_id,
            base.root_profile.profile_id,
            spec.region_id.removeprefix("bor.").replace(".", " "),
            scope={"target_id": base.target_id, "layer": spec.layer, "status": "unknown" if spec.unknown else "attached"},
            provenance=base.graph.regions[0].provenance,
        ))
    attached = tuple(dict.fromkeys(base.attached_regions + tuple(spec.region_id for spec in _REGIONS)))
    unknown = tuple(dict.fromkeys(base.unknown_regions + tuple(spec.region_id for spec in _REGIONS if spec.unknown)))
    return replace(base, graph=graph, attached_regions=attached, unknown_regions=unknown)


def autonomous_summary(profile: BorStorageRootRegressionProfile | None = None) -> dict[str, Any]:
    profile = profile or bor_autonomous_profile()
    report = profile.analyze()
    route = bor_entrypoint_regions()
    route_report = route.analyze()
    call_profile = bor_callwithstate_profile()
    call_report = call_profile.analyze()
    override_profile = bor_state_override_profile()
    override_report = override_profile.analyze()
    return {
        "status": report.status.value,
        "target": report.target_id,
        "build_hash": report.build_hash,
        "witness": tuple(event.entry_point for event in report.witness.events) if report.witness else (),
        "regions": profile.attached_regions,
        "unknown_regions": profile.unknown_regions,
        "unresolved_uncertainty": report.unresolved_uncertainty,
        "entrypoint_route": {
            "status": route_report.status.value,
            "witness": tuple(event.entry_point for event in route_report.witness.events) if route_report.witness else (),
            "unknown_regions": tuple(item.unknown_id for item in route.unknown_regions),
            "unresolved_uncertainty": route_report.unresolved_uncertainty,
        },
        "callwithstate": {
            "status": call_report.status.value,
            "witness": tuple(event.entry_point for event in call_report.witness.events) if call_report.witness else (),
            "regions": call_profile.attached_regions,
            "unknown_regions": call_profile.unknown_regions,
            "unresolved_uncertainty": call_report.unresolved_uncertainty,
        },
        "state_override": {
            "status": override_report.status.value,
            "witness": tuple(event.entry_point for event in override_report.witness.events) if override_report.witness else (),
            "regions": override_profile.attached_regions,
            "unknown_regions": override_profile.unknown_regions,
            "unresolved_uncertainty": override_report.unresolved_uncertainty,
        },
    }


def attach_environment_observation(report, observation: EnvironmentObservation):
    """Attach a strict runtime/host capture while retaining causal unknowns."""
    if report.target_id != observation.target or report.build_hash != observation.build_hash:
        raise ValueError("environment observation target or build does not match report")
    if report.witness is None:
        raise ValueError("environment observation requires a planner witness")
    evidence = observation.evidence()
    evidence_by_id = {item.evidence_id: item for item in report.evidence}
    evidence_by_id[evidence.evidence_id] = evidence
    witness_evidence = {item.evidence_id: item for item in report.witness.evidence}
    witness_evidence[evidence.evidence_id] = evidence
    unknowns = tuple(observation.unknowns)
    if observation.unmatched_engine_write_fields:
        unknowns += (
            "account change lacks an engine-write match; causal attribution remains unresolved",
        )
    witness = replace(
        report.witness,
        input_refs=tuple(dict.fromkeys(report.witness.input_refs + (observation.observation_ref,))),
        evidence=tuple(witness_evidence.values()),
        replay_result={
            **report.witness.replay_result,
            "environment_observation": observation.observation_ref,
            "unmatched_engine_write_fields": tuple(sorted(observation.unmatched_engine_write_fields)),
        },
    )
    return replace(
        report,
        witness=witness,
        evidence=tuple(evidence_by_id.values()),
        evidence_refs=tuple(dict.fromkeys(report.evidence_refs + (observation.observation_ref,))),
        unresolved_uncertainty=tuple(dict.fromkeys(report.unresolved_uncertainty + unknowns)),
    )


__all__ = [
    "BorRegionSpec",
    "attach_environment_observation",
    "autonomous_summary",
    "bor_autonomous_profile",
    "bor_region_specs",
]
