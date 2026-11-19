import unittest

from rsve import ExecutionProfile, LayerPin, ProfileStatus


class ExecutionProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = ExecutionProfile(
            pins=(
                LayerPin("runtime", "node", "24.21.0", source="runtime.version"),
                LayerPin("os", "linux", "6.8", "image-hash", "image.manifest"),
            )
        )

    def test_profile_round_trips_and_matches_observation(self):
        record = self.profile.to_record()
        self.assertEqual(ExecutionProfile.from_record(record), self.profile)
        result = self.profile.verify(self.profile.pins)
        self.assertEqual(result.status, ProfileStatus.MATCH)
        self.assertEqual(result.drifted, ())

    def test_drift_and_unknown_are_distinct(self):
        drift = self.profile.verify((LayerPin("runtime", "node", "25.0.0"), LayerPin("os", "linux", "6.8")))
        self.assertEqual(drift.status, ProfileStatus.DRIFT)
        self.assertIn("runtime:node", drift.drifted)

        unknown = self.profile.verify((LayerPin("runtime", "node", "24.21.0"),))
        self.assertEqual(unknown.status, ProfileStatus.UNKNOWN)
        self.assertIn("os:linux", unknown.unknown)


if __name__ == "__main__":
    unittest.main()
