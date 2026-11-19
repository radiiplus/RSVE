import unittest
from pathlib import Path
import tempfile

from rsve import Authorization, Fidelity, JsonlArtifactStore, OpenTelemetryAdapter
from rsve.extensions import NodeTargetAdapter


FIXTURE = Path(__file__).parent / "fixtures" / "node" / "fixture.mjs"


class NodeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture")
        self.auth = Authorization("test-runner", frozenset({"node-lab"}), frozenset({"node-fixture"}))

    def tearDown(self) -> None:
        self.adapter.teardown()

    def test_capabilities_and_surface_preserve_phantom_evidence(self) -> None:
        environment = self.adapter.environment_observation()
        self.assertTrue(environment.profile_id.startswith("linux-"))
        self.assertIn("memory_model", environment.facts)
        report = self.adapter.capability_report()
        self.assertIn("async.correlation", report.supported_event_hooks)
        self.assertFalse(report.deterministic_replay)
        self.assertTrue(any("universal" in item.lower() for item in report.limitations))
        registry = self.adapter.surface_registry()
        self.assertEqual([item.entry_point.name for item in registry.phantom_entries()], ["dynamic_debug"])
        self.assertTrue(registry.phantom_entries()[0].evidence)

        profile = self.adapter.analysis_profile()
        self.assertEqual(profile.execution_scope["target_id"], "node-fixture")
        self.assertEqual(profile.component, "node.js")

    def test_stateful_async_trace_and_clean_replay(self) -> None:
        self.adapter.prepare()
        initial = self.adapter.snapshot()
        first = self.adapter.invoke("increment", {"amount": 1}, self.auth)
        second = self.adapter.invoke("async_increment", {"amount": 2}, self.auth)
        self.assertEqual(first[-1].after["count"], 1)
        self.assertEqual(second[-1].after["count"], 3)
        self.assertTrue(any(event.operation == "async.schedule" for event in second))
        self.assertTrue(all(event.fidelity is Fidelity.OBSERVED for event in first + second))
        self.assertTrue(all(event.event_id and event.trace_id and event.state_after_id for event in second))
        self.adapter.reset(initial)
        self.assertEqual(self.adapter.snapshot()["state"]["count"], 0)

        replay = self.adapter.replay(
            ({"entry_point": "increment", "request": {"amount": 1}},
             {"entry_point": "async_increment", "request": {"amount": 2}},
             {"entry_point": "read", "request": {}}),
            runs=3,
        )
        self.assertTrue(replay.stable)
        self.assertEqual(replay.replayability, "partially_replayable")
        self.assertEqual(len(replay.runs), 3)
        self.assertTrue(all(run.events for run in replay.runs))
        self.assertTrue(all(len({event.run_id for event in run.events}) == 1 for run in replay.runs))
        self.assertTrue(all(len({event.trace_id for event in run.events}) == 1 for run in replay.runs))
        flaky = self.adapter.replay(
            ({"entry_point": "increment", "request": {"amount": 1, "flaky": True}},),
            runs=3,
        )
        self.assertFalse(flaky.stable)
        self.assertEqual(len({run.outcome_hash for run in flaky.runs}), 2)

    def test_guard_rejection_and_authorization_are_explicit(self) -> None:
        rejected = self.adapter.invoke("increment", {"amount": -1}, self.auth)
        self.assertTrue(any(event.guard_result is False for event in rejected))
        with self.assertRaises(PermissionError):
            self.adapter.invoke("increment", {"amount": 1}, Authorization("denied", frozenset()))
        with self.assertRaises(PermissionError):
            self.adapter.execute_trace(
                ({"entry_point": "increment", "request": {"amount": 1}},),
                Authorization("denied", frozenset()),
            )

    def test_payload_evidence_is_hashed_and_redacted_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JsonlArtifactStore(Path(directory) / "evidence.jsonl")
            adapter = NodeTargetAdapter(FIXTURE, target_id="node-fixture", artifact_store=store)
            try:
                events = adapter.invoke("increment", {"amount": 1, "token": "canary-secret"}, self.auth)
                reference = events[0].evidence_refs[0]
                record = store.get(reference)
                self.assertIsNotNone(record)
                assert record is not None
                payload = record["payload"]
                self.assertEqual(payload["redacted"]["token"], "[REDACTED]")
                self.assertNotIn("raw_bytes_hex", payload)
            finally:
                adapter.teardown()

    def test_trace_codec_preserves_rsve_fields_without_otel_dependency(self) -> None:
        events = self.adapter.invoke("increment", {"amount": 1}, self.auth)
        exported = OpenTelemetryAdapter().export(events, target=self.adapter.identity())
        imported = OpenTelemetryAdapter().import_events(exported)
        self.assertEqual(len(imported), len(events))
        self.assertEqual(imported[0].operation, events[0].operation)
        self.assertEqual(imported[0].state_after_id, events[0].state_after_id)
        self.assertEqual(imported[0].evidence_source, events[0].evidence_source)


if __name__ == "__main__":
    unittest.main()
