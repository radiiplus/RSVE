"""Small JSONL artifact store for local deterministic experiments."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .results import AnalysisReport


class JsonlArtifactStore:
    """Append-only store with stable IDs and conservative default redaction.

    The store is intentionally a local baseline, not a replacement for a
    production artifact service. Payloads are normalized before hashing so the
    same evidence receives the same ID across replay runs.
    """

    def __init__(self, path: str | Path, *, redact_keys: frozenset[str] | None = None) -> None:
        self.path = Path(path)
        self.redact_keys = redact_keys or frozenset({"secret", "token", "password", "private_key"})

    def _redact(self, value: Any, key: str | None = None) -> Any:
        if key is not None and key.lower() in self.redact_keys:
            return "[REDACTED]"
        if isinstance(value, Mapping):
            return {str(item_key): self._redact(item_value, str(item_key)) for item_key, item_value in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._redact(item) for item in value]
        return value

    def put(self, kind: str, payload: Mapping[str, Any]) -> str:
        normalized = self._redact({"kind": kind, "payload": payload})
        encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str)
        artifact_id = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        record = {"id": artifact_id, **normalized}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":"), default=str) + "\n")
        return artifact_id

    def get(self, artifact_id: str) -> Mapping[str, Any] | None:
        if not self.path.exists():
            return None
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                if record.get("id") == artifact_id:
                    return record
        return None

    def record_report(self, report: AnalysisReport) -> str:
        return self.put("analysis_report", report.canonical())

    def record_solver_result(self, result: Any) -> str:
        return self.put("solver_result", result.to_record())
