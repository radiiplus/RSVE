import unittest
from pathlib import Path

from rsve.extensions import QemuLinuxSubstrate


IMAGE = Path("/home/codespace/.cache/rsve/qemu/ubuntu-26.04/ubuntu-26.04-server-cloudimg-amd64.img")
QEMU_AVAILABLE = all(Path(f"/usr/bin/{tool}").exists() for tool in ("qemu-system-x86_64", "qemu-img"))


@unittest.skipUnless(QEMU_AVAILABLE and IMAGE.is_file(), "QEMU tools and the pinned Ubuntu image are required")
class QemuLinuxSubstrateTests(unittest.TestCase):
    def test_boot_observe_snapshot_reset_and_execute(self):
        substrate = QemuLinuxSubstrate(boot_timeout_s=30)
        try:
            substrate.prepare()
            snapshot = substrate.snapshot()
            identity = substrate.identity()
            observation = substrate.environment_observation()

            self.assertEqual(identity["platform"], "qemu-tcg")
            self.assertIn("Ubuntu", observation.facts["distribution"])
            self.assertTrue(substrate.serial_output())
            with self.assertRaisesRegex(RuntimeError, "no guest command channel"):
                substrate.execute("printf canary")

            substrate.reset(snapshot)
            self.assertTrue(substrate.serial_output())
        finally:
            substrate.teardown()


if __name__ == "__main__":
    unittest.main()
