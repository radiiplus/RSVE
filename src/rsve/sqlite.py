"""Transactional SQLite evidence store for RSVE artifacts and solver results."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .result import Report


Store = 1


class Sqlite:
    """Local transactional artifact ledger with explicit stale-query tracking."""

    def __init__(self, path: str | Path, *, redact_keys: frozenset[str] | None = None) -> None:
        self.path = Path(path)
        if str(self.path) == ":memory:":
            raise ValueError("Sqlite requires a file path for durable transactions")
        self.redact_keys = redact_keys or frozenset({"secret", "token", "password", "private_key"})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @property
    def schema_version(self) -> int:
        with self._session() as connection:
            row = connection.execute("SELECT value FROM metadata WHERE key = 'schema_version'").fetchone()
            return int(row[0]) if row else 0

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def put(self, kind: str, payload: Mapping[str, Any]) -> str:
        with self.transaction() as connection:
            return self._put_connection(connection, kind, payload)

    def get(self, artifact_id: str) -> Mapping[str, Any] | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT id, kind, payload, schema_version FROM artifacts WHERE id = ?",
                (artifact_id,),
            ).fetchone()
        if row is None:
            return None
        return {"id": row[0], "kind": row[1], "payload": json.loads(row[2]), "schema_version": row[3]}

    def report(self, report: Report) -> str:
        return self.put("analysis_report", report.canonical())

    def solve(self, result: Any) -> str:
        payload = result.to_record()
        query_id = str(getattr(result, "query_id", "unknown"))
        scope = getattr(result, "scope", None)
        model_revision = str(getattr(scope, "model_revision_id", "unknown"))
        profile_id = str(getattr(scope, "execution_profile_id", "unknown"))
        with self.transaction() as connection:
            artifact_id = self._put_connection(connection, "solver_result", payload)
            stale = connection.execute(
                "SELECT 1 FROM query_invalidations WHERE query_id = ? LIMIT 1",
                (query_id,),
            ).fetchone() is not None
            connection.execute(
                "INSERT OR REPLACE INTO solver_results "
                "(artifact_id, query_id, model_revision, execution_profile_id, valid, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (artifact_id, query_id, model_revision, profile_id, 0 if stale else 1, time.time()),
            )
        return artifact_id

    def record_snapshot(
        self,
        snapshot_id: str,
        *,
        target_id: str,
        build_hash: str,
        scope: str,
        payload: Mapping[str, Any],
    ) -> str:
        """Persist snapshot metadata; external snapshot bytes remain adapter-owned."""
        return self.put("snapshot", {
            "snapshot_id": snapshot_id,
            "target_id": target_id,
            "build_hash": build_hash,
            "scope": scope,
            "payload": dict(payload),
            "external_bytes": True,
        })

    def delta(self, delta: Any) -> str:
        payload = {
            "delta_id": delta.delta_id,
            "parent_revision": delta.parent_revision,
            "revision": delta.revision,
            "kind": delta.kind.value if hasattr(delta.kind, "value") else str(delta.kind),
            "description": delta.description,
            "added_constraints": list(delta.added_constraints),
            "demoted_assumptions": list(delta.demoted_assumptions),
            "promoted_evidence": list(delta.promoted_evidence),
            "observed_entries": list(delta.observed_entries),
            "invalidated_queries": list(delta.invalidated_queries),
            "evidence_refs": list(delta.evidence_refs),
        }
        with self.transaction() as connection:
            artifact_id = self._put_connection(connection, "model_delta", payload)
            self._invalidate_connection(
                connection,
                delta.invalidated_queries,
                reason=f"model revision changed: {delta.description}",
                model_revision=delta.revision,
                delta_id=delta.delta_id,
                artifact_id=artifact_id,
            )
        return artifact_id

    def invalidate(
        self,
        query_ids: Sequence[str],
        *,
        reason: str,
        model_revision: str = "unknown",
        execution_profile_id: str = "unknown",
        delta_id: str = "",
    ) -> int:
        with self.transaction() as connection:
            return self._invalidate_connection(
                connection,
                query_ids,
                reason=reason,
                model_revision=model_revision,
                execution_profile_id=execution_profile_id,
                delta_id=delta_id,
            )

    def answer(
        self,
        query_id: str,
        *,
        model_revision: str | None = None,
        execution_profile_id: str | None = None,
        include_stale: bool = False,
    ) -> Mapping[str, Any] | None:
        with self._session() as connection:
            row = connection.execute(
                "SELECT artifact_id, model_revision, execution_profile_id, valid "
                "FROM solver_results WHERE query_id = ? ORDER BY created_at DESC LIMIT 1",
                (query_id,),
            ).fetchone()
            if row is None:
                return None
            invalidations = connection.execute(
                "SELECT reason FROM query_invalidations WHERE query_id = ? ORDER BY created_at",
                (query_id,),
            ).fetchall()
        scope_mismatch = (
            (model_revision is not None and row[1] != model_revision)
            or (execution_profile_id is not None and row[2] != execution_profile_id)
        )
        if (not row[3] or scope_mismatch) and not include_stale:
            return None
        artifact = self.get(str(row[0]))
        if artifact is None:
            return None
        return {
            **artifact,
            "valid": bool(row[3]) and not scope_mismatch,
            "model_revision": row[1],
            "execution_profile_id": row[2],
            "stale_reasons": tuple(item[0] for item in invalidations) + tuple(
                reason for reason in (
                    "model revision mismatch" if model_revision is not None and row[1] != model_revision else "",
                    "execution profile mismatch" if execution_profile_id is not None and row[2] != execution_profile_id else "",
                ) if reason
            ),
        }

    def valid(self, query_id: str, *, model_revision: str, execution_profile_id: str) -> bool:
        with self._session() as connection:
            row = connection.execute(
                "SELECT valid, model_revision, execution_profile_id FROM solver_results "
                "WHERE query_id = ? ORDER BY created_at DESC LIMIT 1",
                (query_id,),
            ).fetchone()
        return bool(row and row[0] and row[1] == model_revision and row[2] == execution_profile_id)

    def _put_connection(self, connection: sqlite3.Connection, kind: str, payload: Mapping[str, Any]) -> str:
        normalized = self._redact({"kind": kind, "payload": payload})
        encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str)
        artifact_id = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        connection.execute(
            "INSERT OR IGNORE INTO artifacts (id, kind, payload, schema_version) VALUES (?, ?, ?, ?)",
            (artifact_id, kind, json.dumps(normalized["payload"], sort_keys=True, separators=(",", ":"), default=str), Store),
        )
        return artifact_id

    def _invalidate_connection(
        self,
        connection: sqlite3.Connection,
        query_ids: Sequence[str],
        *,
        reason: str,
        model_revision: str,
        execution_profile_id: str = "unknown",
        delta_id: str = "",
        artifact_id: str = "",
    ) -> int:
        count = 0
        for query_id in sorted(set(query_ids)):
            connection.execute(
                "INSERT INTO query_invalidations "
                "(query_id, reason, model_revision, execution_profile_id, delta_id, artifact_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (query_id, reason, model_revision, execution_profile_id, delta_id, artifact_id, time.time()),
            )
            cursor = connection.execute("UPDATE solver_results SET valid = 0 WHERE query_id = ?", (query_id,))
            count += cursor.rowcount
        return count

    def _migrate(self) -> None:
        with self._session() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            current = connection.execute("SELECT value FROM metadata WHERE key = 'schema_version'").fetchone()
            if current is not None and int(current[0]) != Store:
                raise RuntimeError(f"unsupported artifact store schema: {current[0]}")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    schema_version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS solver_results (
                    artifact_id TEXT PRIMARY KEY REFERENCES artifacts(id),
                    query_id TEXT NOT NULL,
                    model_revision TEXT NOT NULL,
                    execution_profile_id TEXT NOT NULL,
                    valid INTEGER NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS solver_results_query_idx ON solver_results(query_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS query_invalidations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    model_revision TEXT NOT NULL,
                    execution_profile_id TEXT NOT NULL,
                    delta_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS query_invalidations_query_idx ON query_invalidations(query_id, created_at);
                """
            )
            if current is None:
                connection.execute(
                    "INSERT INTO metadata (key, value) VALUES ('schema_version', ?)",
                    (str(Store),),
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _redact(self, value: Any, key: str | None = None) -> Any:
        if key is not None and key.lower() in self.redact_keys:
            return "[REDACTED]"
        if isinstance(value, Mapping):
            return {str(item_key): self._redact(item_value, str(item_key)) for item_key, item_value in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._redact(item) for item in value]
        return value
