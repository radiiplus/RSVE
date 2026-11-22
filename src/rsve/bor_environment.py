"""Strict runtime and host-boundary observations for Bor.

This module is deliberately observation-only.  It records the process,
runtime, persistence, kernel, and host-fault context surrounding an account
transition, then compares the account tuple with declared engine writes.  An
unmatched field is an integrity observation with unresolved attribution; it
is not a vulnerability verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .result import DiscoveryEvidence, EvidenceLevel, discovery_evidence


ACCOUNT_FIELDS = ("balance", "nonce", "code_hash", "storage_root")


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: tuple[str, ...], field: str) -> None:
    actual = set(value)
    required = set(expected)
    missing = sorted(required - actual)
    unknown = sorted(actual - required)
    if missing or unknown:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise ValueError(f"{field} has invalid fields: {'; '.join(details)}")


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _optional_string(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _string(value, field)


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value and value.isdecimal() and (value == "0" or not value.startswith("0")):
        result = int(value)
    else:
        raise ValueError(f"{field} must be a decimal integer")
    if result < minimum:
        raise ValueError(f"{field} must be at least {minimum}")
    return result


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _string_list(value: Any, field: str, *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a string list")
    if not allow_empty and not value:
        raise ValueError(f"{field} must not be empty")
    if not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{field} must contain only non-empty strings")
    if len(set(value)) != len(value):
        raise ValueError(f"{field} must not contain duplicates")
    return tuple(value)


def _tuple_strings(value: Any, field: str, *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise TypeError(f"{field} must be a tuple when constructed directly")
    if not allow_empty and not value:
        raise ValueError(f"{field} must not be empty")
    if not all(isinstance(item, str) and item for item in value):
        raise TypeError(f"{field} must contain only non-empty strings")
    if len(set(value)) != len(value):
        raise ValueError(f"{field} must not contain duplicates")
    return value


@dataclass(frozen=True)
class ProcessIdentity:
    """Identity of the Bor process that produced the observation."""

    pid: int
    parent_pid: int
    executable: str
    executable_hash: str
    argv: tuple[str, ...]
    uid: int
    gid: int
    start_time_ns: int

    def __post_init__(self) -> None:
        _integer(self.pid, "process.pid", minimum=1)
        _integer(self.parent_pid, "process.parent_pid")
        _string(self.executable, "process.executable")
        _string(self.executable_hash, "process.executable_hash")
        _tuple_strings(self.argv, "process.argv", allow_empty=False)
        _integer(self.uid, "process.uid")
        _integer(self.gid, "process.gid")
        _integer(self.start_time_ns, "process.start_time_ns", minimum=1)

    @classmethod
    def from_mapping(cls, value: Any, *, field: str = "process_identity") -> "ProcessIdentity":
        payload = _mapping(value, field)
        expected = ("pid", "parent_pid", "executable", "executable_hash", "argv", "uid", "gid", "start_time_ns")
        _exact_keys(payload, expected, field)
        return cls(
            _integer(payload["pid"], f"{field}.pid", minimum=1),
            _integer(payload["parent_pid"], f"{field}.parent_pid"),
            _string(payload["executable"], f"{field}.executable"),
            _string(payload["executable_hash"], f"{field}.executable_hash"),
            _string_list(payload["argv"], f"{field}.argv", allow_empty=False),
            _integer(payload["uid"], f"{field}.uid"),
            _integer(payload["gid"], f"{field}.gid"),
            _integer(payload["start_time_ns"], f"{field}.start_time_ns", minimum=1),
        )


@dataclass(frozen=True)
class RuntimeState:
    """Runtime counters captured at the account transition boundary."""

    runtime_name: str
    runtime_version: str
    scheduler: str
    cpu_time_ns: int
    rss_bytes: int
    virtual_memory_bytes: int
    thread_count: int
    open_fd_count: int
    gc_pause_ns: int

    def __post_init__(self) -> None:
        _string(self.runtime_name, "runtime.runtime_name")
        _string(self.runtime_version, "runtime.runtime_version")
        _string(self.scheduler, "runtime.scheduler")
        for name in ("cpu_time_ns", "rss_bytes", "virtual_memory_bytes", "gc_pause_ns"):
            _integer(getattr(self, name), f"runtime.{name}")
        _integer(self.thread_count, "runtime.thread_count", minimum=1)
        _integer(self.open_fd_count, "runtime.open_fd_count")

    @classmethod
    def from_mapping(cls, value: Any, *, field: str = "runtime_state") -> "RuntimeState":
        payload = _mapping(value, field)
        expected = (
            "runtime_name", "runtime_version", "scheduler", "cpu_time_ns", "rss_bytes",
            "virtual_memory_bytes", "thread_count", "open_fd_count", "gc_pause_ns",
        )
        _exact_keys(payload, expected, field)
        return cls(
            _string(payload["runtime_name"], f"{field}.runtime_name"),
            _string(payload["runtime_version"], f"{field}.runtime_version"),
            _string(payload["scheduler"], f"{field}.scheduler"),
            _integer(payload["cpu_time_ns"], f"{field}.cpu_time_ns"),
            _integer(payload["rss_bytes"], f"{field}.rss_bytes"),
            _integer(payload["virtual_memory_bytes"], f"{field}.virtual_memory_bytes"),
            _integer(payload["thread_count"], f"{field}.thread_count", minimum=1),
            _integer(payload["open_fd_count"], f"{field}.open_fd_count"),
            _integer(payload["gc_pause_ns"], f"{field}.gc_pause_ns"),
        )


@dataclass(frozen=True)
class PersistenceState:
    """Persistence boundary state surrounding the account observation."""

    backend: str
    database_path: str
    pre_state_root: str
    post_state_root: str
    journal_mode: str
    database_files: tuple[str, ...]
    flushed: bool
    fsync_count: int
    reopened: bool

    def __post_init__(self) -> None:
        _string(self.backend, "persistence.backend")
        _string(self.database_path, "persistence.database_path")
        _string(self.pre_state_root, "persistence.pre_state_root")
        _string(self.post_state_root, "persistence.post_state_root")
        _string(self.journal_mode, "persistence.journal_mode")
        _tuple_strings(self.database_files, "persistence.database_files", allow_empty=False)
        _boolean(self.flushed, "persistence.flushed")
        _integer(self.fsync_count, "persistence.fsync_count")
        _boolean(self.reopened, "persistence.reopened")

    @classmethod
    def from_mapping(cls, value: Any, *, field: str = "persistence_state") -> "PersistenceState":
        payload = _mapping(value, field)
        expected = (
            "backend", "database_path", "pre_state_root", "post_state_root", "journal_mode",
            "database_files", "flushed", "fsync_count", "reopened",
        )
        _exact_keys(payload, expected, field)
        return cls(
            _string(payload["backend"], f"{field}.backend"),
            _string(payload["database_path"], f"{field}.database_path"),
            _string(payload["pre_state_root"], f"{field}.pre_state_root"),
            _string(payload["post_state_root"], f"{field}.post_state_root"),
            _string(payload["journal_mode"], f"{field}.journal_mode"),
            _string_list(payload["database_files"], f"{field}.database_files", allow_empty=False),
            _boolean(payload["flushed"], f"{field}.flushed"),
            _integer(payload["fsync_count"], f"{field}.fsync_count"),
            _boolean(payload["reopened"], f"{field}.reopened"),
        )


@dataclass(frozen=True)
class KernelOSState:
    """Kernel and operating-system context, without causal interpretation."""

    os_name: str
    kernel_release: str
    architecture: str
    containerized: bool
    cgroup: str
    syscall_trace_id: str
    memory_pressure: str

    def __post_init__(self) -> None:
        _string(self.os_name, "kernel.os_name")
        _string(self.kernel_release, "kernel.kernel_release")
        _string(self.architecture, "kernel.architecture")
        _boolean(self.containerized, "kernel.containerized")
        _string(self.cgroup, "kernel.cgroup")
        _string(self.syscall_trace_id, "kernel.syscall_trace_id")
        _string(self.memory_pressure, "kernel.memory_pressure")

    @classmethod
    def from_mapping(cls, value: Any, *, field: str = "kernel_os_state") -> "KernelOSState":
        payload = _mapping(value, field)
        expected = ("os_name", "kernel_release", "architecture", "containerized", "cgroup", "syscall_trace_id", "memory_pressure")
        _exact_keys(payload, expected, field)
        return cls(
            _string(payload["os_name"], f"{field}.os_name"),
            _string(payload["kernel_release"], f"{field}.kernel_release"),
            _string(payload["architecture"], f"{field}.architecture"),
            _boolean(payload["containerized"], f"{field}.containerized"),
            _string(payload["cgroup"], f"{field}.cgroup"),
            _string(payload["syscall_trace_id"], f"{field}.syscall_trace_id"),
            _string(payload["memory_pressure"], f"{field}.memory_pressure"),
        )


@dataclass(frozen=True)
class HostFault:
    """One captured host fault; its presence does not establish causation."""

    kind: str
    source: str
    detail: str
    timestamp_ns: int
    fatal: bool
    signal: str | None
    address: str | None

    def __post_init__(self) -> None:
        _string(self.kind, "host_fault.kind")
        _string(self.source, "host_fault.source")
        _string(self.detail, "host_fault.detail")
        _integer(self.timestamp_ns, "host_fault.timestamp_ns")
        _boolean(self.fatal, "host_fault.fatal")
        _optional_string(self.signal, "host_fault.signal")
        _optional_string(self.address, "host_fault.address")

    @classmethod
    def from_mapping(cls, value: Any, *, field: str = "host_fault") -> "HostFault":
        payload = _mapping(value, field)
        expected = ("kind", "source", "detail", "timestamp_ns", "fatal", "signal", "address")
        _exact_keys(payload, expected, field)
        return cls(
            _string(payload["kind"], f"{field}.kind"),
            _string(payload["source"], f"{field}.source"),
            _string(payload["detail"], f"{field}.detail"),
            _integer(payload["timestamp_ns"], f"{field}.timestamp_ns"),
            _boolean(payload["fatal"], f"{field}.fatal"),
            _optional_string(payload["signal"], f"{field}.signal"),
            _optional_string(payload["address"], f"{field}.address"),
        )


@dataclass(frozen=True)
class AccountTuple:
    """The account fields that can change committed blockchain state."""

    balance: int
    nonce: int
    code_hash: str
    storage_root: str

    def __post_init__(self) -> None:
        _integer(self.balance, "account.balance")
        _integer(self.nonce, "account.nonce")
        _string(self.code_hash, "account.code_hash")
        _string(self.storage_root, "account.storage_root")

    @classmethod
    def from_mapping(cls, value: Any, *, field: str) -> "AccountTuple":
        payload = _mapping(value, field)
        _exact_keys(payload, ACCOUNT_FIELDS, field)
        return cls(
            _integer(payload["balance"], f"{field}.balance"),
            _integer(payload["nonce"], f"{field}.nonce"),
            _string(payload["code_hash"], f"{field}.code_hash"),
            _string(payload["storage_root"], f"{field}.storage_root"),
        )

    def changed_fields(self, after: "AccountTuple") -> frozenset[str]:
        return frozenset(field for field in ACCOUNT_FIELDS if getattr(self, field) != getattr(after, field))


@dataclass(frozen=True)
class EnvironmentObservation:
    """A complete, observation-only runtime/environment capture."""

    target: str
    build_hash: str
    scope: str
    regions: tuple[str, ...]
    process_identity: ProcessIdentity
    runtime_state: RuntimeState
    persistence_state: PersistenceState
    kernel_os_state: KernelOSState
    host_faults: tuple[HostFault, ...]
    account_before: AccountTuple
    account_after: AccountTuple
    declared_engine_writes: frozenset[str]
    environment_events: tuple[str, ...]
    unknowns: tuple[str, ...]

    def __post_init__(self) -> None:
        _string(self.target, "target")
        _string(self.build_hash, "build_hash")
        _string(self.scope, "scope")
        _tuple_strings(self.regions, "regions", allow_empty=False)
        if not isinstance(self.process_identity, ProcessIdentity):
            raise TypeError("process_identity must be ProcessIdentity")
        if not isinstance(self.runtime_state, RuntimeState):
            raise TypeError("runtime_state must be RuntimeState")
        if not isinstance(self.persistence_state, PersistenceState):
            raise TypeError("persistence_state must be PersistenceState")
        if not isinstance(self.kernel_os_state, KernelOSState):
            raise TypeError("kernel_os_state must be KernelOSState")
        if not isinstance(self.account_before, AccountTuple) or not isinstance(self.account_after, AccountTuple):
            raise TypeError("account tuples must be AccountTuple values")
        if not isinstance(self.host_faults, tuple) or not all(isinstance(item, HostFault) for item in self.host_faults):
            raise TypeError("host_faults must be a tuple of HostFault values")
        if not isinstance(self.declared_engine_writes, frozenset):
            raise TypeError("declared_engine_writes must be a frozenset")
        if not self.declared_engine_writes <= set(ACCOUNT_FIELDS):
            raise ValueError("declared_engine_writes contains an unknown account field")
        _tuple_strings(self.environment_events, "environment_events", allow_empty=True)
        _tuple_strings(self.unknowns, "unknowns", allow_empty=True)

    @classmethod
    def from_mapping(cls, value: Any) -> "EnvironmentObservation":
        payload = _mapping(value, "environment_observation")
        expected = (
            "target", "build_hash", "scope", "regions", "process_identity", "runtime_state",
            "persistence_state", "kernel_os_state", "host_faults", "account_before",
            "account_after", "declared_engine_writes", "environment_events", "unknowns",
        )
        _exact_keys(payload, expected, "environment_observation")
        faults = payload["host_faults"]
        if not isinstance(faults, list):
            raise ValueError("host_faults must be an object list")
        return cls(
            _string(payload["target"], "target"),
            _string(payload["build_hash"], "build_hash"),
            _string(payload["scope"], "scope"),
            _string_list(payload["regions"], "regions", allow_empty=False),
            ProcessIdentity.from_mapping(payload["process_identity"]),
            RuntimeState.from_mapping(payload["runtime_state"]),
            PersistenceState.from_mapping(payload["persistence_state"]),
            KernelOSState.from_mapping(payload["kernel_os_state"]),
            tuple(HostFault.from_mapping(item, field=f"host_faults[{index}]") for index, item in enumerate(faults)),
            AccountTuple.from_mapping(payload["account_before"], field="account_before"),
            AccountTuple.from_mapping(payload["account_after"], field="account_after"),
            frozenset(_string_list(payload["declared_engine_writes"], "declared_engine_writes", allow_empty=True)),
            _string_list(payload["environment_events"], "environment_events", allow_empty=True),
            _string_list(payload["unknowns"], "unknowns", allow_empty=True),
        )

    @classmethod
    def from_json(cls, value: str | bytes | bytearray) -> "EnvironmentObservation":
        if not isinstance(value, (str, bytes, bytearray)):
            raise TypeError("JSON input must be text or bytes")
        try:
            payload = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("environment observation is not valid JSON") from exc
        return cls.from_mapping(payload)

    @classmethod
    def from_file(cls, path: str | Path) -> "EnvironmentObservation":
        return cls.from_json(Path(path).read_bytes())

    @property
    def changed_fields(self) -> frozenset[str]:
        return self.account_before.changed_fields(self.account_after)

    @property
    def unmatched_engine_write_fields(self) -> frozenset[str]:
        """Changed account fields not covered by declared engine writes."""
        return self.changed_fields - self.declared_engine_writes

    @property
    def reconciled(self) -> bool:
        return not self.unmatched_engine_write_fields

    @property
    def observation_ref(self) -> str:
        """Stable identity for this capture, independent of Python object identity."""
        encoded = json.dumps(self.to_record(), sort_keys=True, separators=(",", ":")).encode()
        return "bor-environment:" + hashlib.sha256(encoded).hexdigest()[:20]

    def evidence(self, *, artifact_ref: str | None = None) -> DiscoveryEvidence:
        """Return observation evidence without assigning a vulnerability verdict."""
        reference = artifact_ref or self.observation_ref
        unmatched = tuple(sorted(self.unmatched_engine_write_fields))
        if unmatched:
            claim = "runtime/environment observation recorded account-field changes without matching declared engine writes"
            divergence_refs = (reference,)
        else:
            claim = "runtime/environment observation reconciled changed account fields with declared engine writes"
            divergence_refs = ()
        return discovery_evidence(
            EvidenceLevel.IMPORTED_ARTIFACT,
            claim,
            "bor-runtime-environment-observation",
            artifact_refs=(reference,),
            assumptions=self.unknowns,
            fidelity_scope={
                "target": self.target,
                "build_hash": self.build_hash,
                "scope": self.scope,
                "regions": self.regions,
                "changed_fields": tuple(sorted(self.changed_fields)),
                "unmatched_engine_write_fields": unmatched,
                "environment_events": self.environment_events,
                "host_fault_count": len(self.host_faults),
            },
            execution_profile_id=f"{self.target}:{self.build_hash[:12]}",
            divergence_refs=divergence_refs,
        )

    def to_record(self) -> dict[str, Any]:
        """Return a JSON-compatible record using the strict parser's field names."""
        return {
            "target": self.target,
            "build_hash": self.build_hash,
            "scope": self.scope,
            "regions": list(self.regions),
            "process_identity": {
                "pid": self.process_identity.pid,
                "parent_pid": self.process_identity.parent_pid,
                "executable": self.process_identity.executable,
                "executable_hash": self.process_identity.executable_hash,
                "argv": list(self.process_identity.argv),
                "uid": self.process_identity.uid,
                "gid": self.process_identity.gid,
                "start_time_ns": self.process_identity.start_time_ns,
            },
            "runtime_state": {
                "runtime_name": self.runtime_state.runtime_name,
                "runtime_version": self.runtime_state.runtime_version,
                "scheduler": self.runtime_state.scheduler,
                "cpu_time_ns": self.runtime_state.cpu_time_ns,
                "rss_bytes": self.runtime_state.rss_bytes,
                "virtual_memory_bytes": self.runtime_state.virtual_memory_bytes,
                "thread_count": self.runtime_state.thread_count,
                "open_fd_count": self.runtime_state.open_fd_count,
                "gc_pause_ns": self.runtime_state.gc_pause_ns,
            },
            "persistence_state": {
                "backend": self.persistence_state.backend,
                "database_path": self.persistence_state.database_path,
                "pre_state_root": self.persistence_state.pre_state_root,
                "post_state_root": self.persistence_state.post_state_root,
                "journal_mode": self.persistence_state.journal_mode,
                "database_files": list(self.persistence_state.database_files),
                "flushed": self.persistence_state.flushed,
                "fsync_count": self.persistence_state.fsync_count,
                "reopened": self.persistence_state.reopened,
            },
            "kernel_os_state": {
                "os_name": self.kernel_os_state.os_name,
                "kernel_release": self.kernel_os_state.kernel_release,
                "architecture": self.kernel_os_state.architecture,
                "containerized": self.kernel_os_state.containerized,
                "cgroup": self.kernel_os_state.cgroup,
                "syscall_trace_id": self.kernel_os_state.syscall_trace_id,
                "memory_pressure": self.kernel_os_state.memory_pressure,
            },
            "host_faults": [
                {
                    "kind": fault.kind,
                    "source": fault.source,
                    "detail": fault.detail,
                    "timestamp_ns": fault.timestamp_ns,
                    "fatal": fault.fatal,
                    "signal": fault.signal,
                    "address": fault.address,
                }
                for fault in self.host_faults
            ],
            "account_before": {
                "balance": self.account_before.balance,
                "nonce": self.account_before.nonce,
                "code_hash": self.account_before.code_hash,
                "storage_root": self.account_before.storage_root,
            },
            "account_after": {
                "balance": self.account_after.balance,
                "nonce": self.account_after.nonce,
                "code_hash": self.account_after.code_hash,
                "storage_root": self.account_after.storage_root,
            },
            "declared_engine_writes": sorted(self.declared_engine_writes),
            "environment_events": list(self.environment_events),
            "unknowns": list(self.unknowns),
        }


__all__ = [
    "ACCOUNT_FIELDS",
    "AccountTuple",
    "EnvironmentObservation",
    "HostFault",
    "KernelOSState",
    "PersistenceState",
    "ProcessIdentity",
    "RuntimeState",
]
