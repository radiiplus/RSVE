"""Execution-driven Bor investigation.

This module deliberately does not import a Bor vulnerability profile. It runs a
target command, records its raw output, derives integrity hypotheses from the
observed fields, and repeats the same command only when an anomaly is found.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
from typing import Any, Mapping, Sequence


DEFAULT_TARGET = "polygon-bor"
DEFAULT_BUILD = "c72e248587a19b1c93eda95871c46b53071e58fd"
DEFAULT_COMMAND = ("go", "run", "./cmd/bor-balance-analysis")


def _integer(value: Any) -> int | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:20]


@dataclass(frozen=True)
class RuntimeCommand:
    argv: tuple[str, ...]
    cwd: str
    timeout_seconds: float

    def record(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "display": shlex.join(self.argv),
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class RuntimeExecution:
    command: RuntimeCommand
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    source_revision: str | None
    target_revision_available: bool
    toolchain: str | None
    payload: Mapping[str, Any] | None
    parse_error: str | None = None

    def record(self) -> dict[str, Any]:
        return {
            "classification": "RUNTIME_OBSERVATION",
            "command": self.command.record(),
            "returncode": self.returncode,
            "duration_ms": self.duration_ms,
            "source_revision": self.source_revision,
            "target_revision_available": self.target_revision_available,
            "toolchain": self.toolchain,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "payload": _canonical(self.payload) if self.payload is not None else None,
            "parse_error": self.parse_error,
        }


def _run_metadata(cwd: Path, revision: str) -> tuple[str | None, bool, str | None]:
    def command(*argv: str) -> str | None:
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.stdout.strip() or None

    source_revision = command("git", "rev-parse", "HEAD")
    available = command("git", "cat-file", "-t", f"{revision}^{{commit}}") == "commit"
    toolchain = command("go", "version")
    return source_revision, available, toolchain


def execute_target(
    argv: Sequence[str] = DEFAULT_COMMAND,
    *,
    cwd: str | Path | None = None,
    timeout_seconds: float = 120,
    revision: str = DEFAULT_BUILD,
) -> RuntimeExecution:
    workdir = Path(cwd or os.environ.get("BOR_SOURCE_ROOT", "/home/codespace/bor/bor-source")).resolve()
    command = RuntimeCommand(tuple(argv), str(workdir), timeout_seconds)
    source_revision, available, toolchain = _run_metadata(workdir, revision)
    started = time.monotonic()
    try:
        result = subprocess.run(
            tuple(argv),
            cwd=workdir,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        returncode = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as error:
        returncode = 124
        stdout = error.stdout or ""
        stderr = (error.stderr or "") + "target command timed out"
    except OSError as error:
        returncode = 127
        stdout = ""
        stderr = str(error)
    duration_ms = int((time.monotonic() - started) * 1000)
    payload = None
    parse_error = None
    if returncode == 0:
        try:
            decoded = json.loads(stdout)
            if not isinstance(decoded, Mapping):
                raise ValueError("target JSON root must be an object")
            payload = decoded
        except (json.JSONDecodeError, ValueError) as error:
            parse_error = str(error)
    return RuntimeExecution(
        command,
        returncode,
        stdout,
        stderr,
        duration_ms,
        source_revision,
        available,
        toolchain,
        payload,
        parse_error,
    )


def _observation_hypotheses(observation: Mapping[str, Any], index: int) -> list[dict[str, Any]]:
    """Derive hypotheses only from observed invariant violations."""
    case = str(observation.get("case", f"observation-{index}"))
    hypotheses: list[dict[str, Any]] = []

    deltas = tuple(_integer(observation.get(field)) for field in (
        "sender_delta", "recipient_delta", "coinbase_delta", "burn_delta",
    ))
    tracked = _integer(observation.get("total_tracked_delta"))
    if all(value is not None for value in deltas) and tracked is not None:
        derived = sum(value for value in deltas if value is not None)
        if derived != tracked:
            hypotheses.append({
                "kind": "balance_conservation_violation",
                "case": case,
                "difference": {"derived_total": derived, "reported_total": tracked},
                "source_fields": ["sender_delta", "recipient_delta", "coinbase_delta", "burn_delta", "total_tracked_delta"],
            })

    admission = observation.get("admission")
    execution = observation.get("execution")
    receipt = observation.get("receipt_status")
    if admission == "accepted" and execution != "completed":
        hypotheses.append({
            "kind": "accepted_execution_gap",
            "case": case,
            "difference": {"admission": admission, "execution": execution},
            "source_fields": ["admission", "execution"],
        })
    if admission == "rejected" and (execution != "not-run" or receipt != "none"):
        hypotheses.append({
            "kind": "rejected_execution_or_receipt",
            "case": case,
            "difference": {"admission": admission, "execution": execution, "receipt_status": receipt},
            "source_fields": ["admission", "execution", "receipt_status"],
        })

    post_root = observation.get("state_root_after")
    committed_root = observation.get("committed_state_root")
    if post_root and committed_root and post_root != committed_root:
        hypotheses.append({
            "kind": "commit_root_mismatch",
            "case": case,
            "difference": {"state_root_after": post_root, "committed_state_root": committed_root},
            "source_fields": ["state_root_after", "committed_state_root"],
        })

    unexpected = observation.get("unexpected_writes")
    if isinstance(unexpected, list) and unexpected:
        hypotheses.append({
            "kind": "unexpected_database_write",
            "case": case,
            "difference": {"count": len(unexpected), "writes": unexpected},
            "source_fields": ["unexpected_writes"],
        })

    if admission == "accepted" and execution == "completed":
        if observation.get("reopened") is False:
            hypotheses.append({
                "kind": "committed_state_not_reopened",
                "case": case,
                "difference": {"reopened": False},
                "source_fields": ["reopened"],
            })
        if observation.get("receipt_persisted") is False:
            hypotheses.append({
                "kind": "receipt_not_persisted",
                "case": case,
                "difference": {"receipt_persisted": False},
                "source_fields": ["receipt_persisted"],
            })

    for hypothesis in hypotheses:
        hypothesis["hypothesis_id"] = "hypothesis:" + _fingerprint(hypothesis)
        hypothesis["classification"] = "UNRESOLVED"
    return hypotheses


def derive_hypotheses(payload: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    observations = payload.get("observations", ())
    if not isinstance(observations, list):
        return ({
            "hypothesis_id": "hypothesis:invalid-observations",
            "kind": "invalid_runtime_observations",
            "classification": "UNRESOLVED",
            "difference": {"observations": type(observations).__name__},
        },)
    derived: list[dict[str, Any]] = []
    for index, observation in enumerate(observations):
        if isinstance(observation, Mapping):
            derived.extend(_observation_hypotheses(observation, index))
        else:
            derived.append({
                "hypothesis_id": f"hypothesis:invalid-observation-{index}",
                "kind": "invalid_runtime_observation",
                "classification": "UNRESOLVED",
                "difference": {"type": type(observation).__name__},
            })
    return tuple(derived)


def _hypothesis_key(hypothesis: Mapping[str, Any]) -> tuple[Any, ...]:
    return (hypothesis.get("kind"), hypothesis.get("case"), _canonical(hypothesis.get("difference")))


def investigate(
    argv: Sequence[str] = DEFAULT_COMMAND,
    *,
    cwd: str | Path | None = None,
    timeout_seconds: float = 120,
    revision: str = DEFAULT_BUILD,
    verify_argv: Sequence[str] | None = None,
) -> dict[str, Any]:
    first = execute_target(argv, cwd=cwd, timeout_seconds=timeout_seconds, revision=revision)
    hypotheses = list(derive_hypotheses(first.payload)) if first.payload is not None else []
    second: RuntimeExecution | None = None
    if hypotheses:
        second = execute_target(argv, cwd=cwd, timeout_seconds=timeout_seconds, revision=revision)
        reproduced = {
            _hypothesis_key(item)
            for item in (derive_hypotheses(second.payload) if second.payload is not None else ())
        }
        for item in hypotheses:
            if _hypothesis_key(item) in reproduced:
                item["classification"] = "REPRODUCED_RUNTIME_OBSERVATION"
            elif second.returncode != 0 or second.payload is None:
                item["classification"] = "UNRESOLVED"
            else:
                item["classification"] = "REJECTED_HYPOTHESIS"

    independent: dict[str, Any] = {"classification": "NOT_RUN"}
    if verify_argv is not None:
        verification = execute_target(verify_argv, cwd=cwd, timeout_seconds=timeout_seconds, revision=revision)
        if verification.returncode != 0:
            verification_classification = "UNRESOLVED"
        elif verification.payload is not None:
            verification_classification = "INDEPENDENTLY_VERIFIED_RESULT"
        else:
            # A successful command without structured evidence is useful as a
            # verifier execution record, but cannot verify the target result.
            verification_classification = "INDEPENDENT_VERIFICATION_SUCCEEDED"
        independent = {
            "classification": verification_classification,
            "execution": verification.record(),
        }

    result = {
        "investigation": "bor-execution-driven",
        "target": first.payload.get("target", DEFAULT_TARGET) if first.payload else DEFAULT_TARGET,
        "build_hash": first.payload.get("build_hash", revision) if first.payload else revision,
        "classification": "RUNTIME_OBSERVATION" if first.returncode == 0 and first.payload is not None else "UNRESOLVED",
        "execution": first.record(),
        "hypotheses": hypotheses,
        "reproduction": second.record() if second is not None else {"classification": "NOT_REQUIRED"},
        "independent_verification": independent,
    }
    if not hypotheses and result["classification"] == "RUNTIME_OBSERVATION":
        result["conclusion"] = "consistent_observation_set"
    elif not hypotheses:
        result["conclusion"] = "runtime_execution_unavailable"
    else:
        result["conclusion"] = "hypotheses_require_review"
    return result


def imported_artifact(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    raw = source.read_bytes()
    payload = json.loads(raw)
    return {
        "classification": "IMPORTED_ARTIFACT",
        "path": str(source),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "payload": _canonical(payload),
    }


__all__ = [
    "DEFAULT_BUILD",
    "DEFAULT_COMMAND",
    "DEFAULT_TARGET",
    "RuntimeCommand",
    "RuntimeExecution",
    "derive_hypotheses",
    "execute_target",
    "imported_artifact",
    "investigate",
]
