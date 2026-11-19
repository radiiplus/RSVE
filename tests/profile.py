import unittest

from rsve import Persona, Match, Need


class Suite(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = Persona(
            "node-a",
            "runtime",
            "node.js",
            "rsve.node",
            "24.21.0",
            build_digest="build",
            execution_scope={"target_id": "fixture", "os": "linux"},
        )

    def test_requirement_round_trips_and_matches_scoped_profile(self):
        requirement = Need(
            "node-runtime",
            "runtime",
            "node.js",
            "rsve.node",
            "24.21.0",
            execution_scope={"target_id": "fixture"},
        )
        self.assertEqual(Need.from_record(requirement.to_record()), requirement)
        self.assertEqual(requirement.verify(self.profile).status, Match.MATCH)

    def test_drift_and_unknown_are_distinct(self):
        drift = Need("node-runtime", "runtime", "node.js", "rsve.node", "25.0").verify(self.profile)
        self.assertEqual(drift.status, Match.DRIFT)
        unknown = Need("node-runtime", "runtime", "node.js", "rsve.node", "unknown", execution_scope={"kernel": "6"}).verify(self.profile)
        self.assertEqual(unknown.status, Match.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
