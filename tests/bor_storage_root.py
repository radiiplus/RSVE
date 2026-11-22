import json
import unittest
from tempfile import NamedTemporaryFile

from rsve import EvidenceLevel, Status
from rsve.bor_evidence import BorRuntimeArtifact, BorRuntimeIngest, BorStorageRootIngest
from rsve.bor_profile import bor_storage_root_regression_profile


class BorStorageRootTests(unittest.TestCase):
    def test_compiled_differential_attaches_to_the_three_step_witness(self):
        profile = bor_storage_root_regression_profile()
        payload = {
            "target": profile.target_id,
            "build_hash": profile.commit,
            "scope": "bor-parallel-storage-root-recreation",
            "sequence": ["selfdestruct", "recreate-with-storage", "create2-collision-check"],
            "serial_storage_root": "0x9d7bbe35dc5044f7e5a75c01412f8939d00ceae1f6187655dc8d80237724a66b",
            "parallel_storage_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "serial_nonempty": True,
            "parallel_nonempty": False,
            "serial_create2_admitted": False,
            "parallel_create2_admitted": True,
            "divergence": True,
            "source_refs": ["core/state/parallel_statedb.go:1076", "core/vm/evm.go:640"],
        }
        with NamedTemporaryFile(mode="w", suffix=".json") as artifact:
            json.dump(payload, artifact)
            artifact.flush()
            report = BorStorageRootIngest.load(artifact.name).attach_observation(profile.analyze())

        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(
            [event.entry_point for event in report.witness.events],
            ["parallel.SELFDESTRUCT", "parallel.CreateAccount+SetState", "evm.CREATE2.collisionCheck"],
        )
        self.assertTrue(any(item.level is EvidenceLevel.IMPORTED_ARTIFACT for item in report.evidence))
        self.assertEqual(
            profile.attached_regions,
            (
                "bor.parallel.storage-root", "bor.evm.create2-guard",
                "bor.engine.state-write", "bor.runtime.process", "bor.os.kernel",
                "bor.memory.cpu", "bor.persistence.external",
            ),
        )
        self.assertIn("bor.runtime.process", profile.unknown_regions)
        self.assertTrue(any("bor.os.kernel" in item for item in report.unresolved_uncertainty))

    def test_opposite_admission_direction_is_not_attached(self):
        profile = bor_storage_root_regression_profile()
        payload = {
            "target": profile.target_id,
            "build_hash": profile.commit,
            "scope": "bor-parallel-storage-root-recreation",
            "sequence": ["selfdestruct", "recreate-with-storage", "create2-collision-check"],
            "serial_storage_root": "0x01",
            "parallel_storage_root": "0x00",
            "serial_nonempty": False,
            "parallel_nonempty": True,
            "serial_create2_admitted": True,
            "parallel_create2_admitted": False,
            "divergence": True,
            "source_refs": [],
        }
        with NamedTemporaryFile(mode="w", suffix=".json") as artifact:
            json.dump(payload, artifact)
            artifact.flush()
            with self.assertRaises(ValueError):
                BorStorageRootIngest.load(artifact.name)

    def test_runtime_boundary_keeps_out_of_band_account_change_unresolved(self):
        profile = bor_storage_root_regression_profile()
        runtime = BorRuntimeArtifact.from_mapping({
            "target": profile.target_id,
            "build_hash": profile.commit,
            "scope": "runtime-account-integrity",
            "regions": ["bor.runtime.process", "bor.os.kernel", "bor.persistence.external"],
            "account_before": {"balance": "100", "nonce": "0", "code_hash": "0x00", "storage_root": "0x00"},
            "account_after": {"balance": "99", "nonce": "0", "code_hash": "0x00", "storage_root": "0x00"},
            "engine_writes": [],
            "environment_events": ["account delta observed after process boundary"],
            "unknowns": ["causal attribution unavailable"],
        }, artifact_ref="inline-runtime")
        report = BorRuntimeIngest(runtime).attach_observation(profile.analyze())

        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertIn("balance", report.witness.replay_result["out_of_band_fields"])
        self.assertIn("causal attribution unavailable", report.unresolved_uncertainty)
        self.assertTrue(any(item.level is EvidenceLevel.IMPORTED_ARTIFACT for item in report.evidence))
