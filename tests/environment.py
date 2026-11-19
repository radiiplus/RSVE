import platform
import unittest

from rsve.extensions import Linux, Host


class Suite(unittest.TestCase):
    def test_default_profile_is_explicit_and_round_trips(self):
        if platform.system().lower() != "linux":
            self.skipTest("Linux default profile is only collected on Linux")
        adapter = Linux("tests/fixtures")
        profile = adapter.profile
        self.assertEqual(profile.os_name, "linux")
        self.assertTrue(profile.profile_id.startswith("linux-"))
        self.assertIn("memory_model", profile.facts())
        self.assertIn("scheduler", profile.observation().unknown)
        self.assertEqual(Host.from_record(profile.to_record()), profile)

    def test_requirements_are_explicitly_checked(self):
        adapter = Linux("tests/fixtures")
        self.assertTrue(adapter.satisfies({"os": "linux"}))
        self.assertFalse(adapter.satisfies({"os": "not-linux"}))


if __name__ == "__main__":
    unittest.main()
