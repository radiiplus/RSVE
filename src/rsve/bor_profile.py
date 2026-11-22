"""Layered Polygon Bor transaction-lifecycle profile.

This module is deliberately data-first.  It records the boundaries below an
RPC transaction entry point and supplies a small executable model for the
admission, execution, receipt, persistence, and receipt-query path.  Values
which are not needed to exercise the contracts are explicit synthetic facts;
they are not presented as observations from a live Bor node.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Mapping

from .graph import (
    Binding,
    Direction,
    Extension,
    Graph,
    Manifest,
    Need,
    Persona,
    Port,
    Quality,
    Shape,
    Zone,
)
from .ir import (
    Contract,
    Effect,
    Evidence,
    Fact,
    Invertibility,
    Loss,
    Partiality,
    Recognizer,
    Relation,
    Representation,
    Transform,
    Transition,
)
from .model import (
    Authorization,
    Decision,
    Entry,
    Fidelity,
    Model,
    Operation,
    Outcome,
    Provenance,
    State,
)
from .objective import Limits, Objective, Order, Same
from .workspace import Workspace


BOR_COMMIT = "c72e248587a19b1c93eda95871c46b53071e58fd"
BOR_TARGET = "polygon-bor"
BOR_SCOPE = "bor-transaction-lifecycle-layered"
BOR_BALANCE_SCOPE = "bor-balance-integrity-analysis"
BOR_STORAGE_ROOT_SCOPE = "bor-parallel-storage-root-analysis"
BOR_RUNTIME_SCOPE = "bor-runtime-environment-integrity-analysis"


@dataclass(frozen=True)
class EnvironmentBinding:
    """One explicit value supplied to a modelled Bor execution environment."""

    binding_id: str
    need_id: str
    field: str
    value: str
    source: Provenance


@dataclass(frozen=True)
class BorLayer:
    """A dependency boundary represented by one graph profile and region."""

    layer_id: str
    name: str
    region_id: str
    profile: Persona
    need: Need
    manifest: Manifest
    contract_ids: tuple[str, ...]
    source: Provenance


@dataclass(frozen=True)
class ValidationSurface:
    """A concrete validation family that can affect balance observations."""

    surface_id: str
    layer_id: str
    entry_point: str
    checks: tuple[str, ...]
    source: Provenance
    compiled: bool


@dataclass(frozen=True)
class BorTransactionLifecycleProfile:
    """Complete layered profile and executable model for one Bor source batch."""

    target_id: str
    commit: str
    graph: Graph
    model: Model
    objective: Objective
    root_profile: Persona
    layers: tuple[BorLayer, ...]
    validation_surfaces: tuple[ValidationSurface, ...]
    contracts: tuple[Contract, ...]
    fixture: Fact
    environment_needs: tuple[Need, ...]
    environment_bindings: tuple[EnvironmentBinding, ...]
    provenance: tuple[Provenance, ...]

    def workspace(self) -> Workspace:
        """Return the resettable RSVE workspace for this profile."""
        environment = State(self.environment_values())
        return Workspace.flat(self.model, graph=self.graph, environment=environment)

    def environment_values(self) -> dict[str, str]:
        """Return the explicit environment bindings in planner-compatible form."""
        return {binding.field: binding.value for binding in self.environment_bindings}

    def analyze(self):
        """Run the bounded model analysis using this profile's own bindings."""
        from .planner import Planner

        return Planner().plan(
            self.model,
            self.objective,
            self.authorization(),
            environment=self.environment_values(),
            workspace=self.workspace(),
        )

    def analysis_feedback(self, report=None) -> dict[str, Any]:
        """Summarize what the current strapped profile still needs.

        This is intentionally diagnostic rather than prescriptive: unknowns and
        gaps are surfaced for the next dependency batch without turning them
        into assumed vulnerability classes.
        """
        report = report or self.analyze()
        gaps = tuple({"kind": gap.kind.value, "detail": gap.detail} for gap in report.gaps)
        next_tuning: list[str] = []
        if report.witness is None:
            next_tuning.append("inspect unresolved search gaps before adding another layer")
        if report.unresolved_uncertainty:
            next_tuning.append("bind or instrument the unresolved symbolic/runtime boundaries")
        if report.proof.status.value != "VALIDATED":
            next_tuning.append("attach the compiled runtime adapter before promoting the result")
        if report.replay_runs == 0:
            next_tuning.append("run the same fixture through the controlled Bor harness")
        return {
            "status": report.status.value,
            "reachability": report.reachability.value,
            "explored_states": report.explored_states,
            "explored_events": report.explored_events,
            "gaps": gaps,
            "unknowns": report.unresolved_uncertainty,
            "witness": tuple(event.entry_point for event in report.witness.events) if report.witness else (),
            "next_tuning": tuple(next_tuning),
        }

    def authorization(self) -> Authorization:
        return Authorization(
            "rsve-bor-layered-profile",
            frozenset({BOR_SCOPE, BOR_BALANCE_SCOPE}),
            frozenset({self.target_id}),
        )

    def ingest_compiled_artifact(self, path):
        """Load and reconcile a compiled Bor balance-analysis artifact."""
        from .bor_evidence import BorEvidenceIngest

        return BorEvidenceIngest.load(path)

    def validate(self) -> tuple[str, ...]:
        """Validate graph references and ensure every declared need is bound."""
        errors = list(item for item in self.graph.validate().errors)
        known_contracts = {item.contract_id for item in self.contracts}
        for layer in self.layers:
            missing = set(layer.contract_ids) - known_contracts
            errors.extend(f"{layer.layer_id}: missing contract {item}" for item in sorted(missing))
        known_layers = {layer.layer_id for layer in self.layers}
        errors.extend(
            f"{surface.surface_id}: unknown layer {surface.layer_id}"
            for surface in self.validation_surfaces
            if surface.layer_id not in known_layers
        )
        bound_needs = {item.need_id for item in self.environment_bindings}
        errors.extend(
            f"environment need is unbound: {need.requirement_id}"
            for need in self.environment_needs
            if need.requirement_id not in bound_needs
        )
        return tuple(errors)


@dataclass(frozen=True)
class BorStorageRootRegressionProfile:
    """Focused profile for the observed SELFDESTRUCT/recreation CREATE2 gap."""

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
        # The source graph records the attached regions; this focused model
        # executes the three production API calls directly so the lifecycle
        # graph does not add unrelated route interleavings to the witness.
        return Workspace.flat(self.model)

    def authorization(self) -> Authorization:
        return Authorization(
            "rsve-bor-storage-root-profile",
            frozenset({BOR_STORAGE_ROOT_SCOPE}),
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
        """Keep uninstrumented runtime boundaries attached to the report."""
        unknowns = tuple(
            f"{region}: boundary is attached but not instrumented"
            for region in self.unknown_regions
        )
        return replace(
            report,
            unresolved_uncertainty=tuple(dict.fromkeys(report.unresolved_uncertainty + unknowns)),
        )

    def ingest_compiled_artifact(self, path):
        from .bor_evidence import BorStorageRootIngest

        return BorStorageRootIngest.load(path)

    def validate(self) -> tuple[str, ...]:
        return tuple(self.graph.validate().errors)


def _evidence(evidence_id: str, source: str, reference: str) -> Evidence:
    return Evidence(evidence_id, Fidelity.MODELED, source, reference)


def _provenance(source: str, *references: str) -> Provenance:
    return Provenance(source, BOR_COMMIT, tuple(references), Fidelity.MODELED)


def _accepted(state: State, observation: Mapping[str, Any], *, effects: tuple[str, ...], writes: frozenset[str], source: str) -> Outcome:
    return Outcome(
        Decision.ACCEPT,
        state,
        observation=dict(observation),
        effects=effects,
        writes=writes,
        guard=True,
        fidelity=Fidelity.MODELED,
        evidence=(source,),
    )


def _rejected(state: State, reason: str, source: str) -> Outcome:
    return Outcome(
        Decision.REJECT,
        state,
        observation={"reason": reason},
        guard=False,
        terminal=True,
        fidelity=Fidelity.MODELED,
        evidence=(source,),
    )


def _errored(state: State, reason: str, source: str) -> Outcome:
    return Outcome(
        Decision.ERROR,
        state,
        observation={"reason": reason},
        terminal=True,
        fidelity=Fidelity.MODELED,
        evidence=(source,),
        uncertainty=(reason,),
    )


def _lifecycle_model() -> Model:
    initial = State({
        "rpc.accepted": False,
        "tx.hash": "",
        "tx.pending": False,
        "tx.rejection": "",
        "execution.available": False,
        "execution.outcome": "none",
        "execution.gas_used": 0,
        "balance.observed": False,
        "balance.status": "unknown",
        "balance.sender_delta": 0,
        "balance.recipient_delta": 0,
        "balance.fee_delta": 0,
        "balance.coinbase_delta": 0,
        "balance.burn_delta": 0,
        "balance.total_delta": 0,
        "balance.state_root_before": "",
        "balance.state_root_after": "",
        "balance.anomaly": False,
        "receipt.present": False,
        "receipt.status": "none",
        "receipt.tx_hash": "",
        "receipt.gas_used": 0,
        "receipt.cumulative_gas_used": 0,
        "receipt.persisted": False,
        "receipt.storage_key": "",
        "api.available": False,
        "api.tx_hash": "",
    })

    def ingress(state: State, request: Mapping[str, Any]) -> tuple[Outcome, ...]:
        source = "internal/ethapi/api.go:2117"
        if request.get("step") != "ingress":
            return (_rejected(state, "ingress step required", source),)
        if request.get("tx_case") not in {"success", "revert"}:
            return (_rejected(state.update(**{"tx.rejection": "malformed or policy-invalid request"}), "RPC request rejected", source),)
        return (_accepted(
            state.update(**{"rpc.accepted": True, "tx.hash": request["tx_hash"]}),
            {"stage": "rpc-ingress", "accepted": True},
            effects=("rpc.transaction.accepted",),
            writes=frozenset({"rpc.accepted", "tx.hash"}),
            source=source,
        ),)

    def admission(state: State, request: Mapping[str, Any]) -> tuple[Outcome, ...]:
        source = "core/txpool/validation.go:61"
        if not state.get("rpc.accepted") or request.get("tx_hash") != state.get("tx.hash"):
            return (_rejected(state, "transaction is not an admitted RPC request", source),)
        if request.get("step") != "admit":
            return (_rejected(state, "txpool admission step required", source),)
        if request.get("admission") != "valid":
            return (_rejected(state.update(**{"tx.rejection": "stateful validation rejected"}), "txpool validation rejected", source),)
        return (_accepted(
            state.update(**{"tx.pending": True}),
            {"stage": "txpool-admission", "accepted": True},
            effects=("txpool.admitted",),
            writes=frozenset({"tx.pending"}),
            source=source,
        ),)

    def execute(state: State, request: Mapping[str, Any]) -> tuple[Outcome, ...]:
        source = "core/state_processor.go:335"
        if not state.get("tx.pending") or request.get("tx_hash") != state.get("tx.hash"):
            return (_rejected(state, "transaction is not pending", source),)
        if request.get("step") != "execute":
            return (_rejected(state, "execution step required", source),)
        if request.get("execution") == "core-error":
            return (_errored(state, "execution core error", source),)
        if request.get("execution") not in {"success", "revert"}:
            return (_rejected(state, "execution result is not modelled", source),)
        return (_accepted(
            state.update(**{
                "execution.available": True,
                "execution.outcome": request["execution"],
                "execution.gas_used": request["gas_used"],
            }),
            {"stage": "execution", "outcome": request["execution"]},
            effects=("state.transition",),
            writes=frozenset({"execution.available", "execution.outcome", "execution.gas_used"}),
            source=source,
        ),)

    def receipt(state: State, request: Mapping[str, Any]) -> tuple[Outcome, ...]:
        source = "core/state_processor.go:298"
        if not state.get("execution.available") or request.get("tx_hash") != state.get("tx.hash"):
            return (_rejected(state, "execution result is unavailable", source),)
        if request.get("step") != "receipt":
            return (_rejected(state, "receipt derivation step required", source),)
        status = "failed" if state.get("execution.outcome") == "revert" else "success"
        gas_used = int(state.get("execution.gas_used", 0))
        return (_accepted(
            state.update(**{
                "receipt.present": True,
                "receipt.status": status,
                "receipt.tx_hash": state["tx.hash"],
                "receipt.gas_used": gas_used,
                "receipt.cumulative_gas_used": gas_used,
            }),
            {"stage": "receipt", "status": status, "tx_hash": state["tx.hash"]},
            effects=("receipt.created", "receipt.fields.derived"),
            writes=frozenset({"receipt.present", "receipt.status", "receipt.tx_hash", "receipt.gas_used", "receipt.cumulative_gas_used"}),
            source=source,
        ),)

    def reconcile_balance(state: State, request: Mapping[str, Any]) -> tuple[Outcome, ...]:
        source = "core/state_transition.go:633"
        if not state.get("execution.available") or request.get("tx_hash") != state.get("tx.hash"):
            return (_rejected(state, "execution result is unavailable", source),)
        if request.get("step") != "balance":
            return (_rejected(state, "balance observation step required", source),)
        status = request.get("balance_status", "unknown")
        if status not in {"consistent", "divergent", "unknown"}:
            return (_rejected(state, "balance observation status is not modelled", source),)
        return (_accepted(
            state.update(**{
                "balance.observed": True,
                "balance.status": status,
                "balance.sender_delta": request.get("sender_delta", 0),
                "balance.recipient_delta": request.get("recipient_delta", 0),
                "balance.fee_delta": request.get("fee_delta", 0),
                "balance.coinbase_delta": request.get("coinbase_delta", 0),
                "balance.burn_delta": request.get("burn_delta", 0),
                "balance.total_delta": request.get("total_delta", 0),
                "balance.state_root_before": request.get("state_root_before", ""),
                "balance.state_root_after": request.get("state_root_after", ""),
                "balance.anomaly": status == "divergent",
            }),
            {"stage": "balance-reconciliation", "status": status, "total_delta": request.get("total_delta", 0)},
            effects=("balance.observed", "balance.reconciled" if status == "consistent" else "balance.divergence-observed"),
            writes=frozenset({
                "balance.observed", "balance.status", "balance.sender_delta",
                "balance.recipient_delta", "balance.fee_delta", "balance.coinbase_delta",
                "balance.burn_delta", "balance.total_delta",
                "balance.state_root_before", "balance.state_root_after", "balance.anomaly",
            }),
            source=source,
        ),)

    def persist(state: State, request: Mapping[str, Any]) -> tuple[Outcome, ...]:
        source = "core/rawdb/bor_receipt.go:111"
        if not state.get("receipt.present") or request.get("tx_hash") != state.get("tx.hash"):
            return (_rejected(state, "receipt is unavailable", source),)
        if request.get("step") != "persist":
            return (_rejected(state, "receipt persistence step required", source),)
        return (_accepted(
            state.update(**{
                "receipt.persisted": True,
                "receipt.storage_key": request["storage_key"],
            }),
            {"stage": "persistence", "stored": True},
            effects=("receipt.persisted", "transaction.lookup-indexed"),
            writes=frozenset({"receipt.persisted", "receipt.storage_key"}),
            source=source,
        ),)

    def api(state: State, request: Mapping[str, Any]) -> tuple[Outcome, ...]:
        source = "core/rawdb/bor_receipt.go:152"
        if not state.get("receipt.persisted") or request.get("tx_hash") != state.get("tx.hash"):
            return (_rejected(state, "persisted receipt is unavailable", source),)
        if request.get("step") != "api":
            return (_rejected(state, "receipt API step required", source),)
        return (_accepted(
            state.update(**{"api.available": True, "api.tx_hash": state["tx.hash"]}),
            {"stage": "receipt-api", "returned": True, "status": state["receipt.status"]},
            effects=("rpc.receipt.returned",),
            writes=frozenset({"api.available", "api.tx_hash"}),
            source=source,
        ),)

    operations = (
        Operation("rpc.ingress", Entry("rpc.submitTransaction"), relation=ingress, relation_complete=True, writes=frozenset({"rpc.accepted", "tx.hash"}), provenance="internal/ethapi/api.go:2117", component="rpc.ingress"),
        Operation("txpool.admission", Entry("txpool.admit"), relation=admission, relation_complete=True, writes=frozenset({"tx.pending"}), provenance="core/txpool/validation.go:61", component="txpool.admission"),
        Operation("state.execution", Entry("core.applyTransaction"), relation=execute, relation_complete=True, writes=frozenset({"execution.available", "execution.outcome", "execution.gas_used"}), provenance="core/state_processor.go:335", component="state.execution"),
        Operation("balance.reconciliation", Entry("core.reconcileBalances"), relation=reconcile_balance, relation_complete=True, writes=frozenset({"balance.observed", "balance.status", "balance.sender_delta", "balance.recipient_delta", "balance.fee_delta", "balance.coinbase_delta", "balance.burn_delta", "balance.total_delta", "balance.state_root_before", "balance.state_root_after", "balance.anomaly"}), provenance="core/state_transition.go:633", component="balance.reconciliation"),
        Operation("receipt.derivation", Entry("core.makeReceipt"), relation=receipt, relation_complete=True, writes=frozenset({"receipt.present", "receipt.status", "receipt.tx_hash", "receipt.gas_used", "receipt.cumulative_gas_used"}), provenance="core/state_processor.go:298", component="receipt.derivation"),
        Operation("receipt.persistence", Entry("rawdb.writeBorReceipt"), relation=persist, relation_complete=True, writes=frozenset({"receipt.persisted", "receipt.storage_key"}), provenance="core/rawdb/bor_receipt.go:111", component="receipt.persistence"),
        Operation("receipt.api", Entry("rpc.getReceipt"), relation=api, relation_complete=True, writes=frozenset({"api.available", "api.tx_hash"}), provenance="core/rawdb/bor_receipt.go:152", component="receipt.api"),
    )
    success = {"tx_case": "success", "tx_hash": "0xsynthetic-success", "admission": "valid", "execution": "success", "gas_used": 21_000, "storage_key": "bor.receipt.synthetic-success"}
    revert = {"tx_case": "revert", "tx_hash": "0xsynthetic-revert", "admission": "valid", "execution": "revert", "gas_used": 24_000, "storage_key": "bor.receipt.synthetic-revert"}
    invalid = {"tx_case": "invalid", "tx_hash": "0xsynthetic-invalid", "admission": "insufficient-funds", "execution": "success", "gas_used": 21_000, "storage_key": "bor.receipt.synthetic-invalid"}
    # Keep the planner's default candidate surface small.  Revert and invalid
    # branches remain executable through Workspace.moves with explicit input.
    success.update({"balance_status": "consistent", "sender_delta": -42001, "recipient_delta": 1, "fee_delta": 21000, "coinbase_delta": 21000, "burn_delta": 21000, "total_delta": 0, "state_root_before": "0xsynthetic-state-before", "state_root_after": "0xsynthetic-state-after"})
    requests = [dict(success, step=step) for step in ("ingress", "admit", "execute", "balance", "receipt", "persist", "api")]
    return Model(
        BOR_TARGET,
        initial,
        tuple(requests),
        operations,
        build_hash=BOR_COMMIT,
        model_version="bor-balance-integrity-focused.v1",
        assumptions=(
            "RPC signing and fork selection are represented by the synthetic tx_case and environment bindings",
            "EVM execution is represented by success, revert, or core-error outcomes",
            "database bytes are represented by a deterministic synthetic storage key",
        ),
    )


def _graph_and_layers() -> tuple[Graph, tuple[BorLayer, ...], tuple[ValidationSurface, ...], tuple[Contract, ...], tuple[Need, ...], tuple[EnvironmentBinding, ...], tuple[Provenance, ...]]:
    root = Persona(
        "bor-develop:" + BOR_COMMIT[:12],
        "blockchain-client",
        "polygon-bor",
        "github.com/0xPolygon/bor",
        "develop",
        build_digest=BOR_COMMIT,
        execution_scope={"target_id": BOR_TARGET, "source_batch": "balance-integrity-focused"},
        feature_set=frozenset({"rpc", "txpool", "evm", "contract-bytecode", "balance-ledger", "state-root", "receipts", "rawdb"}),
        provenance=_provenance("bor-source", "go.mod", "core/txpool/validation.go", "core/state_processor.go"),
    )
    source_refs = (
        ("ingress", "RPC ingress", "rpc", "rpc.request", "tx.signed", "internal/ethapi/api.go:2117", "SubmitTransaction and transaction fee/protection checks"),
        ("admission", "Txpool admission", "txpool", "tx.signed", "tx.admitted", "core/txpool/validation.go:61", "ValidateTransaction and ValidateTransactionWithState"),
        ("execution", "State and EVM execution", "execution", "tx.admitted", "execution.result", "core/state_processor.go:335", "ApplyTransaction and ApplyTransactionWithEVM"),
        ("balance", "Balance reconciliation", "balance", "execution.result", "balance.ledger", "core/state_transition.go:633", "Fee settlement, gas refund, burn and coinbase balance effects"),
        ("receipt", "Receipt derivation", "receipt", "balance.ledger", "receipt.internal", "core/state_processor.go:298", "MakeReceipt"),
        ("persistence", "Receipt persistence", "persistence", "receipt.internal", "receipt.storage", "core/rawdb/bor_receipt.go:111", "WriteBorReceipt and lookup indexing"),
        ("api", "Receipt query/API", "api", "receipt.storage", "rpc.receipt", "core/rawdb/bor_receipt.go:152", "ReadBorTransaction and receipt lookup path"),
    )
    representations = (
        Representation("rpc.request", "TransactionRequest", "synthetic-json"),
        Representation("tx.signed", "SignedTransaction", "typed-envelope"),
        Representation("tx.admitted", "AdmittedTransaction", "pool-record"),
        Representation("execution.result", "ExecutionResult", "state-transition-result"),
        Representation("balance.ledger", "BalanceLedgerObservation", "state-and-account-delta"),
        Representation("receipt.internal", "Receipt", "in-memory-struct"),
        Representation("receipt.storage", "ReceiptForStorage", "rlp"),
        Representation("rpc.receipt", "ReceiptResponse", "synthetic-json"),
    )
    graph = Graph.for_profile(root, graph_id="bor-transaction-lifecycle-layered", region_id="bor.ingress", region_name="RPC transaction ingress")
    for representation in representations:
        graph = graph.value(representation)
    graph = graph.zone(Zone("bor.txpool", "bor-develop:" + BOR_COMMIT[:12], "Txpool admission"))
    graph = graph.zone(Zone("bor.execution", "bor-develop:" + BOR_COMMIT[:12], "State and EVM execution"))
    graph = graph.zone(Zone("bor.balance", "bor-develop:" + BOR_COMMIT[:12], "Balance reconciliation"))
    graph = graph.zone(Zone("bor.receipt", "bor-develop:" + BOR_COMMIT[:12], "Receipt derivation"))
    graph = graph.zone(Zone("bor.persistence", "bor-develop:" + BOR_COMMIT[:12], "Receipt persistence"))
    graph = graph.zone(Zone("bor.api", "bor-develop:" + BOR_COMMIT[:12], "Receipt query/API"))

    layers = []
    contracts = []
    needs = []
    bindings = []
    prev_output = None
    prev_region = None
    for index, (layer_id, name, short, input_rep, output_rep, source_ref, description) in enumerate(source_refs):
        region_id = "bor.ingress" if index == 0 else "bor." + short
        profile = root if index == 0 else Persona(
            "bor.layer." + short,
            "blockchain-layer",
            name.lower().replace(" ", "-"),
            "github.com/0xPolygon/bor",
            "develop",
            build_digest=BOR_COMMIT,
            execution_scope={"target_id": BOR_TARGET, "layer": layer_id, "source": source_ref},
            provenance=_provenance("bor-source", source_ref),
        )
        if index:
            graph = graph.persona(profile)
        manifest = Manifest(
            "rsve.bor." + short,
            "rsve.bor/" + layer_id,
            "1",
            provides=frozenset({"validate", "trace", "reset"}),
            limitations=("runtime replay is not attached in this source batch",),
            evidence_quality="source-modelled",
            scope={"target_id": BOR_TARGET, "layer": layer_id},
            provenance=_provenance("bor-source", source_ref),
        )
        graph = graph.register(manifest)
        extension_id = "bor-extension." + short
        graph = graph.extend(Extension(extension_id, manifest.extension_id, manifest.contract_id, {"source": source_ref}, {"target_id": BOR_TARGET, "layer": layer_id}, _provenance("bor-source", source_ref)))
        binding_id = "bor-binding." + short
        graph = graph.bind(Binding(binding_id, profile.profile_id, extension_id, "layer-observer", (region_id,), capabilities=frozenset({"validate", "trace", "reset"}), reset_participation="model-reset", evidence_scope=(source_ref,)))
        graph = graph.port(Port(region_id + ".input", region_id, "input", Direction.INPUT, input_rep, input_rep, provenance=_provenance("bor-source", source_ref)))
        graph = graph.port(Port(region_id + ".output", region_id, "output", Direction.OUTPUT, output_rep, output_rep, provenance=_provenance("bor-source", source_ref)))
        contract_id = "bor.contract." + layer_id
        evidence = (_evidence("bor-" + layer_id, "bor-source", source_ref),)
        contracts.append(Contract(contract_id, "bor.intended." + layer_id, "bor.enforced." + layer_id, region_id, evidence))
        recognizer_id = "bor.guard." + layer_id
        graph = graph.guard(Recognizer(recognizer_id, output_rep, "bor.enforced." + layer_id, "bor.intended." + layer_id, source_ref, ("env.chain_id",), True, evidence))
        effect_id = "bor.effect." + layer_id
        graph = graph.effect(Effect(effect_id, "bor." + layer_id, ("layer." + layer_id,), evidence, "bor.effect." + layer_id, "1", (input_rep,)))
        transform_id = "bor.transform." + layer_id
        graph = graph.transform(Transform(transform_id, input_rep, output_rep, "bor.transform." + layer_id, "1", Partiality.TOTAL, Relation.FUNCTION, Invertibility.UNKNOWN, Loss.POSSIBLE, evidence=evidence, complete=True, provenance="preserve", provenance_paths={output_rep: (input_rep,)}))
        graph = graph.transition(Transition("bor.transition." + layer_id, "bor." + layer_id, input_rep, output_rep, (transform_id,), (recognizer_id,), (effect_id,), contract_id, Partiality.TOTAL, Relation.FUNCTION, ("layer." + layer_id,), evidence, region_id))
        if prev_output is not None:
            # The destination transition owns its input-to-output transform;
            # this edge records the already-typed handoff between regions.
            graph = graph.connect(prev_output, region_id + ".input", connection_id="bor.connection." + prev_region + "-" + layer_id, correlation_contract="tx.hash", correlation_quality=Quality.DETERMINISTIC_DERIVED, fidelity=Fidelity.MODELED, provenance=_provenance("bor-source", source_ref), scope={"target_id": BOR_TARGET}, relationship_type=Shape.CAUSAL)
        layer_need = Need("bor-layer-" + layer_id, "blockchain-layer", name.lower().replace(" ", "-"), "github.com/0xPolygon/bor", "develop", build_digest=BOR_COMMIT, execution_scope={"target_id": BOR_TARGET, "layer": layer_id})
        needs.append(layer_need)
        layer_source = _provenance("bor-source", source_ref)
        layers.append(BorLayer(layer_id, name, region_id, profile, layer_need, manifest, (contract_id,), layer_source))
        prev_output = region_id + ".output"
        prev_region = short

    # The first layer's region was created by Graph.for_profile; its profile is the root.
    root_need = Need("bor-root", "blockchain-client", "polygon-bor", "github.com/0xPolygon/bor", "develop", build_digest=BOR_COMMIT, execution_scope={"target_id": BOR_TARGET})
    needs.append(root_need)
    validation_surfaces = (
        ValidationSurface("txpool.stateless", "admission", "txpool.ValidateTransaction", ("accepted transaction type", "transaction size", "fork activation", "gas limit", "fee-cap ordering", "signature", "intrinsic gas", "minimum tip"), _provenance("bor-source", "core/txpool/validation.go:61"), True),
        ValidationSurface("txpool.stateful", "admission", "txpool.ValidateTransactionWithState", ("nonce ordering", "nonce gaps", "balance versus transaction cost", "queued expenditure", "replacement cost"), _provenance("bor-source", "core/txpool/validation.go:220"), True),
        ValidationSurface("state.precheck", "execution", "core.stateTransition.preCheck", ("nonce", "upfront gas", "intrinsic gas", "balance", "authorization"), _provenance("bor-source", "core/state_transition.go:390"), True),
        ValidationSurface("evm.bytecode", "execution", "core/vm.Interpreter.Run", ("opcode dispatch", "stack validation", "gas accounting", "revert", "storage writes"), _provenance("bor-source", "core/vm/interpreter.go:218"), True),
        ValidationSurface("state.fees", "balance", "core.stateTransition.execute", ("gas refund", "base-fee burn destination", "coinbase tip", "fee-transfer log"), _provenance("bor-source", "core/state_transition.go:599"), True),
        ValidationSurface("state.trie", "balance", "core/state.StateDB.Commit", ("journal finalization", "account/storage trie commit", "root reopen"), _provenance("bor-source", "core/state/statedb.go:2414"), True),
        ValidationSurface("receipt.reconciliation", "receipt", "core/types.DeriveFields", ("gas used", "cumulative gas", "transaction count", "log indices", "receipt metadata"), _provenance("bor-source", "core/types/receipt.go:408"), True),
    )
    environment_needs = (
        root_need,
        Need("env-chain-config", "blockchain-environment", "chain-config", "synthetic", "bor-development", execution_scope={"target_id": BOR_TARGET}),
        Need("env-block-context", "blockchain-environment", "block-context", "synthetic", "block-0", execution_scope={"target_id": BOR_TARGET}),
        Need("env-state-db", "blockchain-environment", "state-db", "synthetic", "memory-v1", execution_scope={"target_id": BOR_TARGET}),
        Need("env-signer", "blockchain-environment", "signer", "synthetic", "secp256k1-fixture", execution_scope={"target_id": BOR_TARGET}),
        Need("env-vm", "blockchain-environment", "evm", "synthetic", "bor-evm-fixture", execution_scope={"target_id": BOR_TARGET}),
    )
    bindings.extend((
        EnvironmentBinding("env.root", "bor-root", "bor.target", BOR_TARGET, _provenance("synthetic-environment", "fixture")),
        EnvironmentBinding("env.chain-id", "env-chain-config", "env.chain_id", "80001", _provenance("synthetic-environment", "chain-config")),
        EnvironmentBinding("env.block-number", "env-block-context", "env.block_number", "synthetic-0", _provenance("synthetic-environment", "block-context")),
        EnvironmentBinding("env.state-db", "env-state-db", "env.state_db", "synthetic-memory", _provenance("synthetic-environment", "state-db")),
        EnvironmentBinding("env.signer", "env-signer", "env.signer", "synthetic-secp256k1", _provenance("synthetic-environment", "signer")),
        EnvironmentBinding("env.vm", "env-vm", "env.vm", "synthetic-bor-evm", _provenance("synthetic-environment", "evm")),
    ))
    return graph, tuple(layers), validation_surfaces, tuple(contracts), environment_needs, tuple(bindings), (_provenance("bor-source", "go.mod"), _provenance("synthetic-fixture", "fixture facts"))


def bor_transaction_lifecycle_profile() -> BorTransactionLifecycleProfile:
    """Build a fresh layered Bor profile with deterministic synthetic facts."""
    graph, layers, validation_surfaces, contracts, environment_needs, bindings, provenance = _graph_and_layers()
    model = _lifecycle_model()
    fixture = Fact(
        facts=MappingProxyType({
            "chain_id": "80001",
            "block_number": "synthetic-0",
            "block_hash": "0xsynthetic-block-hash",
            "sender": "0x1111111111111111111111111111111111111111",
            "recipient": "0x2222222222222222222222222222222222222222",
            "success_tx_hash": "0xsynthetic-success",
            "revert_tx_hash": "0xsynthetic-revert",
            "invalid_tx_hash": "0xsynthetic-invalid",
            "balance_model": "open-ledger-observation",
            "synthetic_burn_address": "0x000000000000000000000000000000000000dead",
            "success_receipt_storage_key": "bor.receipt.synthetic-success",
            "revert_receipt_storage_key": "bor.receipt.synthetic-revert",
        }),
        unknown=("live signer key", "live database bytes", "live scheduler", "live network peers"),
        profile_id="synthetic-bor-fixture",
        capabilities=frozenset({"transaction-ingress", "txpool-validation", "execution", "balance-observation", "state-root-observation", "receipt-derivation", "receipt-persistence", "receipt-api"}),
        execution_profile_id="bor-develop:" + BOR_COMMIT[:12],
    )
    objective = Objective(
        "bor-balance-integrity-observation",
        BOR_TARGET,
        BOR_BALANCE_SCOPE,
        (
            Same("api.available", True),
            Same("receipt.status", "success"),
            Same("receipt.tx_hash", "0xsynthetic-success"),
            Same("balance.observed", True),
            Same("balance.status", "consistent"),
            Same("balance.coinbase_delta", 21000),
            Same("balance.burn_delta", 21000),
            Same("balance.total_delta", 0),
            Order(("rpc.submitTransaction", "txpool.admit", "core.applyTransaction", "core.reconcileBalances", "core.makeReceipt", "rawdb.writeBorReceipt", "rpc.getReceipt")),
        ),
        environment_boundaries={"env.chain_id": "80001", "env.vm": "synthetic-bor-evm"},
        state_keys=frozenset({"api.available", "receipt.status", "receipt.tx_hash", "receipt.persisted", "balance.observed", "balance.status", "balance.total_delta"}),
        budget=Limits(max_trace_length=7, max_states=10_000_000, max_events=10_000_000, max_time_ms=60_000),
    )
    return BorTransactionLifecycleProfile(BOR_TARGET, BOR_COMMIT, graph, model, objective, graph.profiles[0], layers, validation_surfaces, contracts, fixture, environment_needs, bindings, provenance)


def _storage_root_model() -> Model:
    initial = State({
        "destructed": False,
        "recreated": False,
        "serial.storage_root_nonempty": False,
        "parallel.storage_root_nonempty": False,
        "serial.create2_admitted": True,
        "parallel.create2_admitted": True,
        "storage_root.divergence": False,
    })

    def step(request, expected):
        return request.get("step") == expected

    def destroy_guard(state, request):
        return step(request, "selfdestruct") and not state.get("destructed")

    def destroy_apply(state, _request):
        return state.update(destructed=True)

    def recreate_guard(state, request):
        return step(request, "recreate-with-storage") and state.get("destructed") is True and not state.get("recreated")

    def recreate_apply(state, _request):
        return state.update(
            recreated=True,
            **{
                "serial.storage_root_nonempty": True,
                "parallel.storage_root_nonempty": False,
            },
        )

    def create2_guard(state, request):
        return step(request, "create2-collision-check") and state.get("recreated") is True

    def create2_apply(state, _request):
        return state.update(
            **{
                "serial.create2_admitted": False,
                "parallel.create2_admitted": True,
                "storage_root.divergence": True,
            },
        )

    operations = (
        Operation(
            "bor.parallel.selfdestruct",
            Entry("parallel.SELFDESTRUCT"),
            guard=destroy_guard,
            apply=destroy_apply,
            provenance="core/state/parallel_statedb.go:594",
            component="bor.parallel.storage-root",
            effects=("publish SuicidePath",),
            writes=frozenset({"destructed"}),
        ),
        Operation(
            "bor.parallel.recreate-with-storage",
            Entry("parallel.CreateAccount+SetState"),
            guard=recreate_guard,
            apply=recreate_apply,
            provenance="core/state/parallel_statedb.go:623",
            component="bor.parallel.storage-root",
            effects=("publish CreatePath and storage write",),
            writes=frozenset({"recreated", "serial.storage_root_nonempty", "parallel.storage_root_nonempty"}),
        ),
        Operation(
            "bor.evm.create2-collision-check",
            Entry("evm.CREATE2.collisionCheck"),
            guard=create2_guard,
            apply=create2_apply,
            provenance="core/vm/evm.go:640",
            component="bor.evm.create2-guard",
            effects=("compare storage root against empty root",),
            writes=frozenset({"serial.create2_admitted", "parallel.create2_admitted", "storage_root.divergence"}),
            stop=True,
        ),
    )
    inputs = (
        {"step": "selfdestruct"},
        {"step": "recreate-with-storage"},
        {"step": "create2-collision-check"},
    )
    return Model.build(
        BOR_TARGET,
        initial,
        inputs,
        operations,
        build_hash=BOR_COMMIT,
        model_version="bor-storage-root-v1",
        assumptions=(
            "the compiled probe uses the same transaction order and state APIs as the production path",
            "the recreated account has a nonzero balance so EIP-161 empty-account deletion does not remove it",
        ),
    )


def bor_storage_root_regression_profile() -> BorStorageRootRegressionProfile:
    """Return the attached source regions and executable divergence model."""
    root = bor_transaction_lifecycle_profile()
    storage_region = "bor.parallel.storage-root"
    create2_region = "bor.evm.create2-guard"
    environment_regions = (
        ("bor.engine.state-write", "Engine state-write boundary", "core/state/state_object.go:301"),
        ("bor.runtime.process", "Runtime process boundary", "environment:process-identity"),
        ("bor.os.kernel", "OS and kernel isolation boundary", "environment:namespace-seccomp"),
        ("bor.memory.cpu", "Memory and CPU integrity boundary", "environment:memory-cpu-telemetry"),
        ("bor.persistence.external", "External persistence boundary", "environment:database-filesystem"),
    )
    graph = root.graph
    graph = graph.value(Representation("bor.storage-root.state", "StorageRootObservation", "serial-parallel-differential"))
    graph = graph.zone(Zone(storage_region, root.root_profile.profile_id, "Parallel storage-root read", scope={"target_id": BOR_TARGET, "source": "core/state/parallel_statedb.go:1076"}, provenance=_provenance("bor-source", "core/state/parallel_statedb.go:1076")))
    graph = graph.zone(Zone(create2_region, root.root_profile.profile_id, "CREATE2 collision guard", scope={"target_id": BOR_TARGET, "source": "core/vm/evm.go:640"}, provenance=_provenance("bor-source", "core/vm/evm.go:640")))
    for region_id, name, source in environment_regions:
        graph = graph.zone(Zone(region_id, root.root_profile.profile_id, name, scope={"target_id": BOR_TARGET, "source": source}, provenance=_provenance("environment-boundary", source)))
    unknown_regions = tuple(item[0] for item in environment_regions)
    return BorStorageRootRegressionProfile(
        BOR_TARGET,
        BOR_COMMIT,
        graph,
        _storage_root_model(),
        Objective(
            "bor-parallel-storage-root-recreation",
            BOR_TARGET,
            BOR_STORAGE_ROOT_SCOPE,
            (
                Same("serial.storage_root_nonempty", True),
                Same("parallel.storage_root_nonempty", False),
                Same("serial.create2_admitted", False),
                Same("parallel.create2_admitted", True),
                Same("storage_root.divergence", True),
                Order(("parallel.SELFDESTRUCT", "parallel.CreateAccount+SetState", "evm.CREATE2.collisionCheck")),
            ),
            state_keys=frozenset({"serial.storage_root_nonempty", "parallel.storage_root_nonempty", "serial.create2_admitted", "parallel.create2_admitted", "storage_root.divergence"}),
            budget=Limits(max_trace_length=3, max_states=10_000, max_events=10_000, max_time_ms=60_000),
        ),
        root.root_profile,
        (storage_region, create2_region) + unknown_regions,
        unknown_regions,
        ("core/state/parallel_statedb.go:1076", "core/vm/evm.go:640") + tuple(item[2] for item in environment_regions),
    )


__all__ = [
    "BOR_COMMIT",
    "BOR_SCOPE",
    "BOR_BALANCE_SCOPE",
    "BOR_STORAGE_ROOT_SCOPE",
    "BOR_RUNTIME_SCOPE",
    "BOR_TARGET",
    "BorLayer",
    "BorTransactionLifecycleProfile",
    "EnvironmentBinding",
    "ValidationSurface",
    "bor_transaction_lifecycle_profile",
    "BorStorageRootRegressionProfile",
    "bor_storage_root_regression_profile",
]
