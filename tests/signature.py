import unittest

from rsve import Archive, Decision, Event, Level, Signature, State


class Suite(unittest.TestCase):
    def event(self, amount, *, decision=Decision.ACCEPT):
        before = State({"count": 0})
        after = State({"count": amount})
        return Event(
            operation="update",
            entry_point="update",
            request={"amount": amount},
            before=before,
            after=after,
            component="fixture.state",
            guard_result=decision is Decision.ACCEPT,
            decision=decision,
            writes=frozenset({"count"}),
        )

    def test_input_values_do_not_define_behavior_identity(self):
        first = Signature.make((self.event(1),), State({"count": 1}), target="fixture", profile="profile-a", keys={"count"})
        second = Signature.make((self.event(1),), State({"count": 1}), target="fixture", profile="profile-a", keys={"count"})
        self.assertEqual(first.path["coarse"], second.path["coarse"])
        self.assertEqual(first.path["exact"], second.path["exact"])

    def test_behavior_change_is_novel_at_multiple_resolutions(self):
        archive = Archive()
        first = Signature.make((self.event(1),), State({"count": 1}), target="fixture", profile="profile-a", keys={"count"})
        archive, novelty = archive.offer(first)
        self.assertEqual(novelty.score, 3)
        archive, novelty = archive.offer(first)
        self.assertEqual(novelty.score, 0)
        self.assertTrue(archive.seen(first))
        self.assertTrue(archive.seen(first, Level.EXACT))
        changed = Signature.make((self.event(2),), State({"count": 2}), target="fixture", profile="profile-a", keys={"count"})
        _, novelty = archive.offer(changed)
        self.assertEqual(novelty.score, 3)

    def test_profiles_partition_behavior_archives(self):
        archive = Archive()
        first = Signature.make((self.event(1),), State({"count": 1}), target="fixture", profile="profile-a")
        second = Signature.make((self.event(1),), State({"count": 1}), target="fixture", profile="profile-b")
        archive, first_novelty = archive.offer(first)
        archive, second_novelty = archive.offer(second)
        self.assertEqual(first_novelty.score, 3)
        self.assertEqual(second_novelty.score, 3)

    def test_coarse_state_can_match_while_exact_state_refines(self):
        first = Signature.make((self.event(1),), State({"count": 1, "mode": "a"}), target="fixture", profile="profile-a")
        second = Signature.make((self.event(1),), State({"count": 1, "mode": "b"}), target="fixture", profile="profile-a")
        self.assertEqual(first.state["coarse"], second.state["coarse"])
        self.assertNotEqual(first.state["exact"], second.state["exact"])


if __name__ == "__main__":
    unittest.main()
