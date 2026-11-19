import tempfile
import unittest
from pathlib import Path

from rsve import Scope, Sqlite
from rsve.diff import Kind, Delta
from rsve.result import Verdict
from rsve.solver import Answer


class Suite(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = Sqlite(Path(self.directory.name) / "evidence.sqlite3")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def solver_result(self, query_id: str = "q-1") -> Answer:
        return Answer(
            status=Verdict.SAT,
            query_id=query_id,
            backend="test",
            backend_version="1",
            options={"timeout_ms": 100},
            query="(= x 1)",
            scope=Scope("target", "build", "revision-1", 2, 10, execution_profile_id="profile-1"),
        )

    def test_schema_redaction_stable_ids_and_snapshot_metadata(self):
        self.assertEqual(self.store.schema_version, 1)
        first = self.store.put("trace", {"token": "secret", "count": 1})
        second = self.store.put("trace", {"token": "secret", "count": 1})
        self.assertEqual(first, second)
        record = self.store.get(first)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["payload"]["token"], "[REDACTED]")
        snapshot = self.store.record_snapshot(
            "snapshot-1", target_id="target", build_hash="build", scope="process-local", payload={"path": "/tmp/overlay"}
        )
        self.assertEqual(self.store.get(snapshot)["payload"]["external_bytes"], True)

    def test_transaction_rolls_back(self):
        with self.assertRaisesRegex(RuntimeError, "abort"):
            with self.store.transaction() as connection:
                connection.execute(
                    "INSERT INTO artifacts (id, kind, payload, schema_version) VALUES (?, ?, ?, ?)",
                    ("rollback", "test", "{}", 1),
                )
                raise RuntimeError("abort")
        self.assertIsNone(self.store.get("rollback"))

    def test_solver_results_are_scoped_and_invalidated(self):
        artifact_id = self.store.solve(self.solver_result())
        current = self.store.answer("q-1")
        self.assertEqual(current["id"], artifact_id)
        self.assertTrue(current["valid"])
        self.assertTrue(self.store.valid("q-1", model_revision="revision-1", execution_profile_id="profile-1"))
        self.assertFalse(self.store.valid("q-1", model_revision="revision-2", execution_profile_id="profile-1"))
        self.assertIsNone(self.store.answer("q-1", model_revision="revision-2", execution_profile_id="profile-1"))
        stale_scope = self.store.answer("q-1", model_revision="revision-2", execution_profile_id="profile-1", include_stale=True)
        self.assertFalse(stale_scope["valid"])
        self.assertIn("model revision mismatch", stale_scope["stale_reasons"])

        self.assertEqual(self.store.invalidate(("q-1",), reason="guard refinement", model_revision="revision-2", delta_id="delta-1"), 1)
        self.assertIsNone(self.store.answer("q-1"))
        stale = self.store.answer("q-1", include_stale=True)
        self.assertFalse(stale["valid"])
        self.assertEqual(stale["stale_reasons"], ("guard refinement",))

    def test_model_delta_invalidates_dependent_queries_atomically(self):
        self.store.solve(self.solver_result("q-2"))
        delta = Delta(
            delta_id="delta-2",
            parent_revision="revision-1",
            revision="revision-2",
            kind=Kind.MODEL_TOO_LOOSE,
            description="runtime rejected the candidate",
            invalidated_queries=("q-2",),
        )
        artifact_id = self.store.delta(delta)
        self.assertIsNotNone(self.store.get(artifact_id))
        self.assertIsNone(self.store.answer("q-2"))


if __name__ == "__main__":
    unittest.main()
