"""Evidence ingestion for the focused compiled Bor balance harness."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .result import DiscoveryEvidence, Report, discovery_evidence, EvidenceLevel


_DECIMAL = re.compile(r"^-?(0|[1-9][0-9]*)$")


def _merge_evidence(*groups: tuple[DiscoveryEvidence, ...]) -> tuple[DiscoveryEvidence, ...]:
    merged: list[DiscoveryEvidence] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            if item.evidence_id not in seen:
                seen.add(item.evidence_id)
                merged.append(item)
    return tuple(merged)


def _integer(value: Any, field: str, *, optional: bool = False) -> int | None:
    if optional and value in (None, ""):
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field} must be a decimal integer")
    text = str(value)
    if not _DECIMAL.fullmatch(text):
        raise ValueError(f"{field} must be a decimal integer")
    return int(text)


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _string_list(value: Any, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value) or not all(isinstance(item, str) and item for item in value):
        qualifier = "string list" if allow_empty else "non-empty string list"
        raise ValueError(f"{field} must be a {qualifier}")
    return tuple(dict.fromkeys(value))


@dataclass(frozen=True)
class BorBalanceObservation:
    """One normalized observation from the compiled Bor probe matrix."""

    case: str
    admission: str
    execution: str
    receipt_status: str
    gas_used: int
    cumulative_gas_used: int
    sender_delta: int | None
    recipient_delta: int | None
    coinbase_delta: int | None
    burn_delta: int | None
    total_tracked_delta: int | None
    state_root_before: str
    state_root_after: str
    committed_state_root: str
    reopened: bool
    receipt_persisted: bool
    receipt_metadata_ready: bool
    findings: tuple[str, ...] = ()

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "BorBalanceObservation":
        required = ("case", "admission", "execution", "receipt_status")
        missing = [field for field in required if field not in record]
        if missing:
            raise ValueError(f"observation is missing {', '.join(missing)}")
        return cls(
            case=str(record["case"]),
            admission=str(record["admission"]),
            execution=str(record["execution"]),
            receipt_status=str(record["receipt_status"]),
            gas_used=_integer(record.get("gas_used", 0), "gas_used") or 0,
            cumulative_gas_used=_integer(record.get("cumulative_gas_used", 0), "cumulative_gas_used") or 0,
            sender_delta=_integer(record.get("sender_delta", ""), "sender_delta", optional=True),
            recipient_delta=_integer(record.get("recipient_delta", ""), "recipient_delta", optional=True),
            coinbase_delta=_integer(record.get("coinbase_delta", ""), "coinbase_delta", optional=True),
            burn_delta=_integer(record.get("burn_delta", ""), "burn_delta", optional=True),
            total_tracked_delta=_integer(record.get("total_tracked_delta", ""), "total_tracked_delta", optional=True),
            state_root_before=str(record.get("state_root_before", "")),
            state_root_after=str(record.get("state_root_after", "")),
            committed_state_root=str(record.get("committed_state_root", "")),
            reopened=_boolean(record.get("reopened", False), "reopened"),
            receipt_persisted=_boolean(record.get("receipt_persisted", False), "receipt_persisted"),
            receipt_metadata_ready=_boolean(record.get("receipt_metadata_ready", False), "receipt_metadata_ready"),
            findings=tuple(str(item) for item in record.get("findings", ())),
        )


@dataclass(frozen=True)
class BorBalanceReconciliation:
    case: str
    valid: bool
    tracked_delta: int | None
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class BorBalanceArtifact:
    """A validated, content-addressed Bor balance-analysis artifact."""

    target: str
    build_hash: str
    chain_id: str
    probe_count: int
    accepted: int
    rejected: int
    finding_count: int
    unknowns: tuple[str, ...]
    observations: tuple[BorBalanceObservation, ...]
    artifact_ref: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any], *, artifact_ref: str = "inline") -> "BorBalanceArtifact":
        observations = tuple(BorBalanceObservation.from_record(item) for item in payload.get("observations", ()))
        probe_count = _integer(payload.get("probe_count", len(observations)), "probe_count") or 0
        accepted = _integer(payload.get("accepted", 0), "accepted") or 0
        rejected = _integer(payload.get("rejected", 0), "rejected") or 0
        if probe_count != len(observations):
            raise ValueError("probe_count does not match observations")
        if accepted != sum(item.admission == "accepted" for item in observations):
            raise ValueError("accepted does not match observations")
        if rejected != sum(item.admission == "rejected" for item in observations):
            raise ValueError("rejected does not match observations")
        return cls(
            target=str(payload.get("target", "")),
            build_hash=str(payload.get("build_hash", "")),
            chain_id=str(payload.get("chain_id", "")),
            probe_count=probe_count,
            accepted=accepted,
            rejected=rejected,
            finding_count=_integer(payload.get("finding_count", 0), "finding_count") or 0,
            unknowns=tuple(str(item) for item in payload.get("unknowns", ())),
            observations=observations,
            artifact_ref=artifact_ref,
        )

    def observation(self, case: str) -> BorBalanceObservation:
        matches = tuple(item for item in self.observations if item.case == case)
        if len(matches) != 1:
            raise ValueError(f"artifact must contain exactly one observation for {case!r}")
        return matches[0]

    def reconcile(self, case: str | None = None) -> tuple[BorBalanceReconciliation, ...]:
        observations = (self.observation(case),) if case else self.observations
        results = []
        for item in observations:
            issues = list(item.findings)
            if item.admission == "accepted":
                deltas = (item.sender_delta, item.recipient_delta, item.coinbase_delta, item.burn_delta)
                if any(value is None for value in deltas) or item.total_tracked_delta is None:
                    issues.append("accepted observation has incomplete balance deltas")
                elif sum(deltas) != item.total_tracked_delta:
                    issues.append("tracked balance deltas do not reconcile")
                if not item.state_root_after:
                    issues.append("accepted observation has no post-state root")
                if item.committed_state_root != item.state_root_after:
                    issues.append("committed state root differs from observed post-state root")
                if not item.reopened:
                    issues.append("accepted observation did not reopen committed state")
                if not item.receipt_persisted or not item.receipt_metadata_ready:
                    issues.append("accepted observation did not verify receipt persistence metadata")
            elif item.admission == "rejected":
                if item.execution != "not-run" or item.receipt_status != "none":
                    issues.append("rejected observation reached execution or receipt construction")
                if item.receipt_persisted:
                    issues.append("rejected observation persisted a receipt")
            else:
                issues.append(f"unknown admission result {item.admission!r}")
            results.append(BorBalanceReconciliation(item.case, not issues, item.total_tracked_delta, tuple(dict.fromkeys(issues))))
        return tuple(results)

    def evidence(self, case: str | None = None) -> DiscoveryEvidence:
        reconciled = self.reconcile(case)
        if not reconciled or not all(item.valid for item in reconciled):
            raise ValueError("cannot create evidence for an unreconciled Bor artifact")
        cases = tuple(item.case for item in reconciled)
        claim = "compiled Bor harness observations reconcile tracked balances, state roots, and receipts"
        if case:
            claim += f" for {case}"
        return discovery_evidence(
            EvidenceLevel.IMPORTED_ARTIFACT,
            claim,
            "bor-compiled-harness",
            artifact_refs=(self.artifact_ref,),
            assumptions=self.unknowns,
            fidelity_scope={"target": self.target, "build_hash": self.build_hash, "chain_id": self.chain_id, "cases": cases},
            execution_profile_id=f"{self.target}:{self.build_hash[:12]}",
        )


@dataclass(frozen=True)
class BorEvidenceIngest:
    artifact: BorBalanceArtifact
    reconciliations: tuple[BorBalanceReconciliation, ...]

    @classmethod
    def load(cls, path: str | Path) -> "BorEvidenceIngest":
        source = Path(path)
        raw = source.read_bytes()
        payload = json.loads(raw)
        if not isinstance(payload, Mapping):
            raise ValueError("Bor artifact root must be an object")
        artifact_ref = "bor-artifact:" + hashlib.sha256(raw).hexdigest()[:20]
        artifact = BorBalanceArtifact.from_mapping(payload, artifact_ref=artifact_ref)
        return cls(artifact, artifact.reconcile())

    def attach_observation(self, report: Report, *, case: str = "transfer") -> Report:
        """Attach compiled evidence while preserving candidate status."""
        observation = self.artifact.observation(case)
        reconciliation = next(item for item in self.reconciliations if item.case == case)
        if not reconciliation.valid:
            raise ValueError(f"cannot attach unreconciled observation {case!r}: {reconciliation.issues}")
        if report.target_id != self.artifact.target or report.build_hash != self.artifact.build_hash:
            raise ValueError("compiled artifact target or build does not match report")
        if report.witness is None:
            raise ValueError("compiled observation requires a planner witness")
        expected = {
            "receipt.status": observation.receipt_status,
            "balance.sender_delta": observation.sender_delta,
            "balance.recipient_delta": observation.recipient_delta,
            "balance.coinbase_delta": observation.coinbase_delta,
            "balance.burn_delta": observation.burn_delta,
            "balance.total_delta": observation.total_tracked_delta,
        }
        actual = report.witness.final_state.as_dict()
        mismatches = [f"{key}: model={actual[key]!r}, artifact={value!r}" for key, value in expected.items() if key in actual and actual[key] != value]
        if mismatches:
            raise ValueError("compiled observation does not match planner witness: " + "; ".join(mismatches))
        evidence = self.artifact.evidence(case)
        witness = report.witness
        if witness is not None:
            witness = replace(
                witness,
                input_refs=tuple(dict.fromkeys(witness.input_refs + (self.artifact.artifact_ref,))),
                evidence=_merge_evidence(witness.evidence, (evidence,)),
                replay_result={**witness.replay_result, "compiled_artifact": self.artifact.artifact_ref, "observation": observation.case},
            )
        return replace(
            report,
            witness=witness,
            evidence=_merge_evidence(report.evidence, (evidence,)),
            evidence_refs=tuple(dict.fromkeys(report.evidence_refs + (self.artifact.artifact_ref,))),
            unresolved_uncertainty=tuple(dict.fromkeys(report.unresolved_uncertainty + self.artifact.unknowns)),
        )


@dataclass(frozen=True)
class BorStorageRootObservation:
    """One serial/parallel storage-root comparison from the Bor probe."""

    sequence: tuple[str, ...]
    serial_storage_root: str
    parallel_storage_root: str
    serial_nonempty: bool
    parallel_nonempty: bool
    serial_create2_admitted: bool
    parallel_create2_admitted: bool
    divergence: bool
    source_refs: tuple[str, ...]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "BorStorageRootObservation":
        sequence = payload.get("sequence", ())
        source_refs = payload.get("source_refs", ())
        if not isinstance(sequence, list) or not all(isinstance(item, str) for item in sequence):
            raise ValueError("storage-root sequence must be a string list")
        if not isinstance(source_refs, list) or not all(isinstance(item, str) for item in source_refs):
            raise ValueError("storage-root source_refs must be a string list")
        required = (
            "serial_storage_root", "parallel_storage_root", "serial_nonempty",
            "parallel_nonempty", "serial_create2_admitted", "parallel_create2_admitted",
            "divergence",
        )
        missing = [field for field in required if field not in payload]
        if missing:
            raise ValueError(f"storage-root observation is missing {', '.join(missing)}")
        return cls(
            tuple(sequence),
            str(payload["serial_storage_root"]),
            str(payload["parallel_storage_root"]),
            _boolean(payload["serial_nonempty"], "serial_nonempty"),
            _boolean(payload["parallel_nonempty"], "parallel_nonempty"),
            _boolean(payload["serial_create2_admitted"], "serial_create2_admitted"),
            _boolean(payload["parallel_create2_admitted"], "parallel_create2_admitted"),
            _boolean(payload["divergence"], "divergence"),
            tuple(source_refs),
        )


@dataclass(frozen=True)
class BorStorageRootArtifact:
    """Validated, content-addressed serial/parallel storage-root evidence."""

    target: str
    build_hash: str
    scope: str
    observation: BorStorageRootObservation
    artifact_ref: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any], *, artifact_ref: str = "inline") -> "BorStorageRootArtifact":
        observation = BorStorageRootObservation.from_mapping(payload)
        if observation.divergence != (
            observation.serial_nonempty != observation.parallel_nonempty
            or observation.serial_create2_admitted != observation.parallel_create2_admitted
            or observation.serial_storage_root != observation.parallel_storage_root
        ):
            raise ValueError("storage-root divergence flag does not match observations")
        if not observation.divergence:
            raise ValueError("storage-root artifact contains no serial/parallel divergence")
        if observation.sequence != ("selfdestruct", "recreate-with-storage", "create2-collision-check"):
            raise ValueError("storage-root artifact has an unsupported operation sequence")
        if observation.serial_create2_admitted or not observation.parallel_create2_admitted:
            raise ValueError("storage-root artifact does not show serial rejection and parallel admission")
        if observation.serial_nonempty is not True or observation.parallel_nonempty is not False:
            raise ValueError("storage-root artifact does not show the expected non-empty-root mismatch")
        return cls(
            target=str(payload.get("target", "")),
            build_hash=str(payload.get("build_hash", "")),
            scope=str(payload.get("scope", "")),
            observation=observation,
            artifact_ref=artifact_ref,
        )

    def evidence(self) -> DiscoveryEvidence:
        return discovery_evidence(
            EvidenceLevel.IMPORTED_ARTIFACT,
            "Bor serial and parallel state disagree on a recreated account's storage root and CREATE2 collision admission",
            "bor-storage-root-probe",
            artifact_refs=(self.artifact_ref,),
            fidelity_scope={
                "target": self.target,
                "build_hash": self.build_hash,
                "scope": self.scope,
                "sequence": self.observation.sequence,
                "source_refs": self.observation.source_refs,
            },
            execution_profile_id=f"{self.target}:{self.build_hash[:12]}",
            divergence_refs=(self.artifact_ref,),
        )


@dataclass(frozen=True)
class BorStorageRootIngest:
    artifact: BorStorageRootArtifact

    @classmethod
    def load(cls, path: str | Path) -> "BorStorageRootIngest":
        source = Path(path)
        raw = source.read_bytes()
        payload = json.loads(raw)
        if not isinstance(payload, Mapping):
            raise ValueError("storage-root artifact root must be an object")
        artifact_ref = "bor-storage-root-artifact:" + hashlib.sha256(raw).hexdigest()[:20]
        return cls(BorStorageRootArtifact.from_mapping(payload, artifact_ref=artifact_ref))

    def attach_observation(self, report: Report) -> Report:
        """Attach the production differential while preserving candidate status."""
        if report.target_id != self.artifact.target or report.build_hash != self.artifact.build_hash:
            raise ValueError("storage-root artifact target or build does not match report")
        if report.witness is None:
            raise ValueError("storage-root observation requires a planner witness")
        observation = self.artifact.observation
        expected = {
            "serial.storage_root_nonempty": observation.serial_nonempty,
            "parallel.storage_root_nonempty": observation.parallel_nonempty,
            "serial.create2_admitted": observation.serial_create2_admitted,
            "parallel.create2_admitted": observation.parallel_create2_admitted,
            "storage_root.divergence": observation.divergence,
        }
        actual = report.witness.final_state.as_dict()
        missing = [key for key in expected if key not in actual]
        if missing:
            raise ValueError("storage-root witness is missing fields: " + ", ".join(missing))
        mismatches = [
            f"{key}: model={actual[key]!r}, artifact={value!r}"
            for key, value in expected.items()
            if actual[key] != value
        ]
        if mismatches:
            raise ValueError("storage-root observation does not match planner witness: " + "; ".join(mismatches))
        evidence = self.artifact.evidence()
        witness = replace(
            report.witness,
            input_refs=tuple(dict.fromkeys(report.witness.input_refs + (self.artifact.artifact_ref,))),
            evidence=_merge_evidence(report.witness.evidence, (evidence,)),
            replay_result={
                **report.witness.replay_result,
                "compiled_artifact": self.artifact.artifact_ref,
                "observation": self.artifact.scope,
            },
        )
        return replace(
            report,
            witness=witness,
            evidence=_merge_evidence(report.evidence, (evidence,)),
            evidence_refs=tuple(dict.fromkeys(report.evidence_refs + (self.artifact.artifact_ref,))),
        )


@dataclass(frozen=True)
class BorAccountTuple:
    """The account fields whose change can affect committed blockchain state."""

    balance: int
    nonce: int
    code_hash: str
    storage_root: str

    @classmethod
    def from_mapping(cls, value: Any, field: str) -> "BorAccountTuple":
        if not isinstance(value, Mapping):
            raise ValueError(f"{field} must be an object")
        required = ("balance", "nonce", "code_hash", "storage_root")
        missing = [item for item in required if item not in value]
        if missing:
            raise ValueError(f"{field} is missing {', '.join(missing)}")
        balance = _integer(value["balance"], f"{field}.balance")
        nonce = _integer(value["nonce"], f"{field}.nonce")
        return cls(balance or 0, nonce or 0, str(value["code_hash"]), str(value["storage_root"]))

    def changed_fields(self, other: "BorAccountTuple") -> frozenset[str]:
        fields = ("balance", "nonce", "code_hash", "storage_root")
        return frozenset(field for field in fields if getattr(self, field) != getattr(other, field))


@dataclass(frozen=True)
class BorRuntimeObservation:
    """A runtime/host adapter observation around one account transition."""

    regions: tuple[str, ...]
    account_before: BorAccountTuple
    account_after: BorAccountTuple
    engine_writes: frozenset[str]
    environment_events: tuple[str, ...]
    unknowns: tuple[str, ...]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "BorRuntimeObservation":
        regions = _string_list(payload.get("regions", []), "regions")
        engine_writes = _string_list(payload.get("engine_writes", []), "engine_writes", allow_empty=True)
        events = payload.get("environment_events", [])
        if not isinstance(events, list) or not all(isinstance(item, str) for item in events):
            raise ValueError("environment_events must be a string list")
        unknowns = payload.get("unknowns", [])
        if not isinstance(unknowns, list) or not all(isinstance(item, str) for item in unknowns):
            raise ValueError("unknowns must be a string list")
        return cls(
            regions,
            BorAccountTuple.from_mapping(payload.get("account_before"), "account_before"),
            BorAccountTuple.from_mapping(payload.get("account_after"), "account_after"),
            frozenset(engine_writes),
            tuple(events),
            tuple(dict.fromkeys(unknowns)),
        )

    @property
    def changed_fields(self) -> frozenset[str]:
        return self.account_before.changed_fields(self.account_after)

    @property
    def unaccounted_fields(self) -> frozenset[str]:
        return self.changed_fields - self.engine_writes

    @property
    def out_of_band(self) -> bool:
        return bool(self.unaccounted_fields)


@dataclass(frozen=True)
class BorRuntimeArtifact:
    """Content-addressed evidence from the runtime and host boundary."""

    target: str
    build_hash: str
    scope: str
    observation: BorRuntimeObservation
    artifact_ref: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any], *, artifact_ref: str = "inline") -> "BorRuntimeArtifact":
        return cls(
            target=str(payload.get("target", "")),
            build_hash=str(payload.get("build_hash", "")),
            scope=str(payload.get("scope", "")),
            observation=BorRuntimeObservation.from_mapping(payload),
            artifact_ref=artifact_ref,
        )

    def evidence(self) -> DiscoveryEvidence:
        if self.observation.out_of_band:
            claim = "runtime observation found account fields changing without matching declared engine writes"
        else:
            claim = "runtime observation reconciled account fields with declared engine writes"
        return discovery_evidence(
            EvidenceLevel.IMPORTED_ARTIFACT,
            claim,
            "bor-runtime-environment-adapter",
            artifact_refs=(self.artifact_ref,),
            assumptions=self.observation.unknowns,
            fidelity_scope={
                "target": self.target,
                "build_hash": self.build_hash,
                "scope": self.scope,
                "regions": self.observation.regions,
                "changed_fields": tuple(sorted(self.observation.changed_fields)),
                "unaccounted_fields": tuple(sorted(self.observation.unaccounted_fields)),
                "environment_events": self.observation.environment_events,
            },
            execution_profile_id=f"{self.target}:{self.build_hash[:12]}",
            divergence_refs=(self.artifact_ref,) if self.observation.out_of_band else (),
        )


@dataclass(frozen=True)
class BorRuntimeIngest:
    artifact: BorRuntimeArtifact

    @classmethod
    def load(cls, path: str | Path) -> "BorRuntimeIngest":
        source = Path(path)
        raw = source.read_bytes()
        payload = json.loads(raw)
        if not isinstance(payload, Mapping):
            raise ValueError("runtime artifact root must be an object")
        artifact_ref = "bor-runtime-artifact:" + hashlib.sha256(raw).hexdigest()[:20]
        return cls(BorRuntimeArtifact.from_mapping(payload, artifact_ref=artifact_ref))

    def attach_observation(self, report: Report) -> Report:
        if report.target_id != self.artifact.target or report.build_hash != self.artifact.build_hash:
            raise ValueError("runtime artifact target or build does not match report")
        if report.witness is None:
            raise ValueError("runtime observation requires a planner witness")
        evidence = self.artifact.evidence()
        witness = replace(
            report.witness,
            input_refs=tuple(dict.fromkeys(report.witness.input_refs + (self.artifact.artifact_ref,))),
            evidence=_merge_evidence(report.witness.evidence, (evidence,)),
            replay_result={
                **report.witness.replay_result,
                "runtime_artifact": self.artifact.artifact_ref,
                "runtime_regions": self.artifact.observation.regions,
                "out_of_band_fields": tuple(sorted(self.artifact.observation.unaccounted_fields)),
            },
        )
        unknowns = self.artifact.observation.unknowns
        if self.artifact.observation.out_of_band:
            unknowns = unknowns + (
                "runtime observation requires causal attribution to process, kernel, persistence, or engine",
            )
        return replace(
            report,
            witness=witness,
            evidence=_merge_evidence(report.evidence, (evidence,)),
            evidence_refs=tuple(dict.fromkeys(report.evidence_refs + (self.artifact.artifact_ref,))),
            unresolved_uncertainty=tuple(dict.fromkeys(report.unresolved_uncertainty + unknowns)),
        )


@dataclass(frozen=True)
class BorCallWithStateObservation:
    """A production observation for the non-canonical CallWithState path."""

    sequence: tuple[str, ...]
    nonce_before: int
    nonce_after: int
    state_mutated: bool
    canonical_transaction: bool
    receipt_created: bool
    out_of_band: bool
    source_refs: tuple[str, ...]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "BorCallWithStateObservation":
        sequence = _string_list(payload.get("sequence", []), "sequence")
        expected = ("rpc.eth_call", "internal.CallWithState", "core.ApplyMessage", "state.SetNonce")
        if sequence != expected:
            raise ValueError("sequence does not match the CallWithState nonce path")
        source_refs = _string_list(payload.get("source_refs", []), "source_refs")
        nonce_before = _integer(payload.get("nonce_before"), "nonce_before") or 0
        nonce_after = _integer(payload.get("nonce_after"), "nonce_after") or 0
        if nonce_after != nonce_before + 1:
            raise ValueError("nonce_after must be nonce_before + 1")
        state_mutated = _boolean(payload.get("state_mutated"), "state_mutated")
        canonical_transaction = _boolean(payload.get("canonical_transaction"), "canonical_transaction")
        receipt_created = _boolean(payload.get("receipt_created"), "receipt_created")
        out_of_band = _boolean(payload.get("out_of_band"), "out_of_band")
        if not state_mutated or canonical_transaction or receipt_created or not out_of_band:
            raise ValueError("artifact does not describe a non-canonical out-of-band mutation")
        return cls(sequence, nonce_before, nonce_after, state_mutated, canonical_transaction, receipt_created, out_of_band, source_refs)


@dataclass(frozen=True)
class BorCallWithStateArtifact:
    target: str
    build_hash: str
    scope: str
    observation: BorCallWithStateObservation
    artifact_ref: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any], *, artifact_ref: str = "inline") -> "BorCallWithStateArtifact":
        return cls(
            target=str(payload.get("target", "")),
            build_hash=str(payload.get("build_hash", "")),
            scope=str(payload.get("scope", "")),
            observation=BorCallWithStateObservation.from_mapping(payload),
            artifact_ref=artifact_ref,
        )

    def evidence(self) -> DiscoveryEvidence:
        return discovery_evidence(
            EvidenceLevel.IMPORTED_ARTIFACT,
            "read-only CallWithState advanced the supplied account nonce outside a canonical transaction",
            "bor-callwithstate-probe",
            artifact_refs=(self.artifact_ref,),
            assumptions=("the probe uses a caller-owned live StateDB, matching the internal API contract",),
            fidelity_scope={
                "target": self.target,
                "build_hash": self.build_hash,
                "scope": self.scope,
                "sequence": self.observation.sequence,
                "nonce_before": self.observation.nonce_before,
                "nonce_after": self.observation.nonce_after,
                "source_refs": self.observation.source_refs,
            },
            execution_profile_id=f"{self.target}:{self.build_hash[:12]}",
            divergence_refs=(self.artifact_ref,),
        )


@dataclass(frozen=True)
class BorCallWithStateIngest:
    artifact: BorCallWithStateArtifact

    @classmethod
    def load(cls, path: str | Path) -> "BorCallWithStateIngest":
        source = Path(path)
        raw = source.read_bytes()
        payload = json.loads(raw)
        if not isinstance(payload, Mapping):
            raise ValueError("CallWithState artifact root must be an object")
        artifact_ref = "bor-callwithstate-artifact:" + hashlib.sha256(raw).hexdigest()[:20]
        return cls(BorCallWithStateArtifact.from_mapping(payload, artifact_ref=artifact_ref))

    def attach_observation(self, report: Report) -> Report:
        if report.target_id != self.artifact.target or report.build_hash != self.artifact.build_hash:
            raise ValueError("CallWithState artifact target or build does not match report")
        if report.witness is None:
            raise ValueError("CallWithState observation requires a planner witness")
        observation = self.artifact.observation
        expected = {
            "call.read_only": True,
            "account.nonce_before": observation.nonce_before,
            "account.nonce_after": observation.nonce_after,
            "state.mutated": observation.state_mutated,
            "canonical.transaction": observation.canonical_transaction,
            "receipt.created": observation.receipt_created,
            "account.out_of_band": observation.out_of_band,
        }
        actual = report.witness.final_state.as_dict()
        missing = [key for key in expected if key not in actual]
        if missing:
            raise ValueError("CallWithState witness is missing fields: " + ", ".join(missing))
        mismatches = [
            f"{key}: model={actual[key]!r}, artifact={value!r}"
            for key, value in expected.items()
            if actual[key] != value
        ]
        if mismatches:
            raise ValueError("CallWithState observation does not match planner witness: " + "; ".join(mismatches))
        evidence = self.artifact.evidence()
        witness = replace(
            report.witness,
            input_refs=tuple(dict.fromkeys(report.witness.input_refs + (self.artifact.artifact_ref,))),
            evidence=_merge_evidence(report.witness.evidence, (evidence,)),
            replay_result={
                **report.witness.replay_result,
                "compiled_artifact": self.artifact.artifact_ref,
                "observation": self.artifact.scope,
            },
        )
        return replace(
            report,
            witness=witness,
            evidence=_merge_evidence(report.evidence, (evidence,)),
            evidence_refs=tuple(dict.fromkeys(report.evidence_refs + (self.artifact.artifact_ref,))),
        )


__all__ = [
    "BorBalanceArtifact", "BorBalanceObservation", "BorBalanceReconciliation", "BorEvidenceIngest",
    "BorStorageRootArtifact", "BorStorageRootIngest", "BorStorageRootObservation",
    "BorAccountTuple", "BorRuntimeArtifact", "BorRuntimeIngest", "BorRuntimeObservation",
    "BorCallWithStateArtifact", "BorCallWithStateIngest", "BorCallWithStateObservation",
]
