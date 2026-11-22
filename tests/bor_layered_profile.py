import json
import unittest
from tempfile import NamedTemporaryFile

from rsve import Decision, EvidenceLevel, Status
from rsve.bor_profile import bor_transaction_lifecycle_profile


class BorLayeredProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = bor_transaction_lifecycle_profile()
        self.workspace = self.profile.workspace()

    def test_graph_covers_each_boundary_and_is_structurally_ready(self):
        self.assertEqual(self.profile.validate(), ())
        validation = self.profile.graph.validate()
        self.assertTrue(validation.structural)
        self.assertTrue(validation.ready)
        self.assertEqual(
            [layer.layer_id for layer in self.profile.layers],
            ["ingress", "admission", "execution", "balance", "receipt", "persistence", "api"],
        )
        self.assertEqual(len(self.profile.graph.transitions), 7)
        self.assertEqual(len(self.profile.graph.connections), 6)
        self.assertEqual(
            [surface.surface_id for surface in self.profile.validation_surfaces],
            [
                "txpool.stateless", "txpool.stateful", "state.precheck",
                "evm.bytecode", "state.fees", "state.trie", "receipt.reconciliation",
            ],
        )
        self.assertTrue(all(surface.compiled for surface in self.profile.validation_surfaces))

    def test_fixture_environment_and_provenance_are_explicit(self):
        self.assertEqual(self.profile.fixture.facts["sender"], "0x1111111111111111111111111111111111111111")
        self.assertIn("live signer key", self.profile.fixture.unknown)
        self.assertEqual(len(self.profile.environment_needs), len(self.profile.environment_bindings))
        self.assertTrue(all(item.source.fidelity.value == "modeled" for item in self.profile.environment_bindings))
        self.assertTrue(all(layer.source.evidence for layer in self.profile.layers))
        self.assertTrue(all(contract.evidence for contract in self.profile.contracts))

    def test_planner_finds_complete_success_lifecycle(self):
        report = self.profile.analyze()
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.witness.final_state["receipt.status"], "success")
        self.assertEqual(
            [event.entry_point for event in report.witness.events],
            ["rpc.submitTransaction", "txpool.admit", "core.applyTransaction", "core.reconcileBalances", "core.makeReceipt", "rawdb.writeBorReceipt", "rpc.getReceipt"],
        )

    def test_compiled_artifact_is_reconciled_as_observed_evidence(self):
        payload = {
            "target": self.profile.target_id,
            "build_hash": self.profile.commit,
            "chain_id": "137",
            "probe_count": 1,
            "accepted": 1,
            "rejected": 0,
            "finding_count": 0,
            "unknowns": ["RPC transport is outside the harness"],
            "observations": [{
                "case": "transfer", "admission": "accepted", "execution": "completed", "receipt_status": "success",
                "gas_used": 21000, "cumulative_gas_used": 21000,
                "sender_delta": "-42001", "recipient_delta": "1", "coinbase_delta": "21000", "burn_delta": "21000", "total_tracked_delta": "0",
                "state_root_before": "0xbefore", "state_root_after": "0xafter", "committed_state_root": "0xafter",
                "reopened": True, "receipt_persisted": True, "receipt_metadata_ready": True,
            }],
        }
        with NamedTemporaryFile(mode="w", suffix=".json") as artifact:
            json.dump(payload, artifact)
            artifact.flush()
            ingest = self.profile.ingest_compiled_artifact(artifact.name)
        self.assertEqual(ingest.reconciliations[0].issues, ())
        report = ingest.attach_observation(self.profile.analyze())
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.replay_runs, 0)
        self.assertTrue(any(item.level is EvidenceLevel.OBSERVED for item in report.evidence))
        self.assertIn(ingest.artifact.artifact_ref, report.evidence_refs)

    def test_compiled_artifact_rejects_unreconciled_balance(self):
        payload = {
            "target": self.profile.target_id, "build_hash": self.profile.commit,
            "probe_count": 1, "accepted": 1, "rejected": 0,
            "observations": [{
                "case": "transfer", "admission": "accepted", "execution": "completed", "receipt_status": "success",
                "sender_delta": "-1", "recipient_delta": "1", "coinbase_delta": "0", "burn_delta": "0", "total_tracked_delta": "1",
                "state_root_after": "0xafter", "committed_state_root": "0xafter", "reopened": True,
                "receipt_persisted": True, "receipt_metadata_ready": True,
            }],
        }
        with NamedTemporaryFile(mode="w", suffix=".json") as artifact:
            json.dump(payload, artifact)
            artifact.flush()
            ingest = self.profile.ingest_compiled_artifact(artifact.name)
        self.assertFalse(ingest.reconciliations[0].valid)
        with self.assertRaises(ValueError):
            ingest.attach_observation(self.profile.analyze())

    def test_analysis_feedback_surfaces_current_unknowns(self):
        feedback = self.profile.analysis_feedback()
        self.assertEqual(feedback["status"], Status.SAT_CANDIDATE.value)
        self.assertEqual(feedback["reachability"], "GUARANTEED")
        self.assertTrue(feedback["witness"])
        self.assertTrue(any("runtime adapter" in item for item in feedback["next_tuning"]))

    def test_balance_divergence_is_observed_without_preclassifying_it(self):
        request = {
            "step": "ingress",
            "tx_case": "success",
            "tx_hash": "0xsynthetic-success",
            "admission": "valid",
            "execution": "success",
            "gas_used": 21_000,
            "balance_status": "divergent",
            "sender_delta": -20_000,
            "recipient_delta": 1,
            "fee_delta": 20_000,
            "total_delta": 1,
        }
        state = self.workspace.start()
        for entry, step in (
            ("rpc.submitTransaction", "ingress"),
            ("txpool.admit", "admit"),
            ("core.applyTransaction", "execute"),
            ("core.reconcileBalances", "balance"),
        ):
            move = self.workspace.moves(state, entry, dict(request, step=step))[0]
            self.assertEqual(move.outcome.decision, Decision.ACCEPT)
            state = move.after
        self.assertEqual(state.target.get("balance.status"), "divergent")
        self.assertTrue(state.target.get("balance.anomaly"))
        self.assertEqual(state.target.get("balance.total_delta"), 1)

    def test_revert_receipt_and_admission_rejection_are_distinct(self):
        revert = {"step": "ingress", "tx_case": "revert", "tx_hash": "0xsynthetic-revert", "admission": "valid", "execution": "revert", "gas_used": 24_000, "storage_key": "bor.receipt.synthetic-revert"}
        state = self.workspace.start()
        for entry, step in (
            ("rpc.submitTransaction", "ingress"),
            ("txpool.admit", "admit"),
            ("core.applyTransaction", "execute"),
            ("core.makeReceipt", "receipt"),
        ):
            request = dict(revert, step=step)
            move = self.workspace.moves(state, entry, request)[0]
            self.assertEqual(move.outcome.decision, Decision.ACCEPT)
            state = move.after
        self.assertEqual(state.target.get("receipt.status"), "failed")

        ingress = self.workspace.moves(
            self.workspace.start(),
            "rpc.submitTransaction",
            {"step": "ingress", "tx_case": "success", "tx_hash": "0xsynthetic-invalid"},
        )[0]
        invalid = self.workspace.moves(
            ingress.after,
            "txpool.admit",
            {"step": "admit", "tx_case": "success", "tx_hash": "0xsynthetic-invalid", "admission": "insufficient-funds"},
        )[0]
        self.assertEqual(invalid.outcome.decision, Decision.REJECT)
        self.assertFalse(invalid.after.target.get("receipt.present"))


if __name__ == "__main__":
    unittest.main()
