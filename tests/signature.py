import unittest

from rsve import Archive, Decision, Event, Level, Signature, State


class Suite(unittest.TestCase):
    def event(self, amount, *, request_amount=None, decision=Decision.ACCEPT, ordering=0, parent=None):
        before = State({"count": 0})
        after = State({"count": amount})
        return Event(
            operation="update",
            entry_point="update",
            request={"amount": amount if request_amount is None else request_amount},
            before=before,
            after=after,
            component="fixture.state",
            guard_result=decision is Decision.ACCEPT,
            decision=decision,
            writes=frozenset({"count"}),
            ordering=ordering,
            parent_event_id=parent,
        )

    def test_input_values_do_not_define_behavior_identity(self):
        first = Signature.make((self.event(1, request_amount=1),), State({"count": 1}), target="fixture", profile="profile-a", keys={"count"})
        second = Signature.make((self.event(1, request_amount=99),), State({"count": 1}), target="fixture", profile="profile-a", keys={"count"})
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

    def test_archive_refines_coarse_state_after_distinct_continuations(self):
        def signature(mode, continuation):
            intermediate = State({"count": 1, "mode": mode})
            final = State({"count": 1, "mode": mode, "done": True})
            first = Event(
                operation="prepare",
                entry_point="prepare",
                request={},
                before=State({"count": 0}),
                after=intermediate,
                component="fixture.state",
                guard_result=True,
                decision=Decision.ACCEPT,
                writes=frozenset({"count", "mode"}),
                ordering=0,
            )
            second = Event(
                operation=continuation,
                entry_point=continuation,
                request={},
                before=intermediate,
                after=final,
                component="fixture.state",
                guard_result=True,
                decision=Decision.ACCEPT,
                reads=frozenset({"mode"}),
                writes=frozenset({"done"}),
                ordering=1,
            )
            return Signature.make((first, second), final, target="fixture", profile="profile-a", keys={"count"})

        first = signature("a", "continue-a")
        second = signature("b", "continue-b")
        self.assertEqual(first.state_continuations[0][0], second.state_continuations[0][0])

        archive, _ = Archive().offer(first)
        archive, novelty = archive.offer(second)
        self.assertTrue(novelty.state)
        self.assertEqual(len(archive.refinements), 2)
        self.assertFalse(archive.offer(first)[1].state)

    def test_scope_partitions_behavior_archives(self):
        first = Signature.make((self.event(1),), State({"count": 1}), target="fixture", profile="profile-a", scope={"chain": 1})
        second = Signature.make((self.event(1),), State({"count": 1}), target="fixture", profile="profile-a", scope={"chain": 2})
        archive, first_novelty = Archive().offer(first)
        _, second_novelty = archive.offer(second)
        self.assertEqual(first_novelty.score, 3)
        self.assertEqual(second_novelty.score, 3)

    def test_causal_order_is_signature_input(self):
        first = Signature.make((self.event(1, ordering=1, parent="a"),), State({"count": 1}), target="fixture", profile="profile-a")
        second = Signature.make((self.event(1, ordering=2, parent="b"),), State({"count": 1}), target="fixture", profile="profile-a")
        self.assertNotEqual(first.path["coarse"], second.path["coarse"])
        self.assertNotEqual(first.path["exact"], second.path["exact"])


if __name__ == "__main__":
    unittest.main()
