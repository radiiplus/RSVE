import unittest

from rsve import (
    Signal,
    World,
    Context,
    State,
)


class Suite(unittest.TestCase):
    def test_environment_reaction_influences_next_state_and_divergence_is_targeted(self):
        model = World(
            Context(State({"count": 0}), State({"quota": 1})),
            {
                "write": lambda state, request: (
                    state.target.update(count=state.target["count"] + request["amount"]),
                    state.environment.update(quota=state.environment["quota"] - request["amount"]),
                    {"accepted": True},
                ),
            },
        )
        predicted = model.predict("write", model.initial, {"amount": 1})
        self.assertEqual(predicted.status, Signal.PREDICTED)
        self.assertEqual(predicted.after.environment["quota"], 0)
        observed = model.observe("write", model.initial, Context(State({"count": 1}), State({"quota": 1})), {"accepted": True})
        divergence = model.reconcile(predicted, observed)
        self.assertIsNotNone(divergence)
        assert divergence is not None
        self.assertEqual(divergence.differing_target_keys, ())
        self.assertEqual(divergence.differing_environment_keys, ("quota",))

    def test_missing_environment_semantics_is_unknown(self):
        state = Context(State({}), State({}))
        step = World(state, {}).predict("missing", state, {})
        self.assertEqual(step.status, Signal.UNKNOWN)

    def test_options_preserve_possible_environmental_successors(self):
        state = Context(State({"count": 0}), State({"quota": 1}))
        world = World(
            state,
            {
                "roll": lambda _state, _request: (
                    (State({"count": 1}), State({"quota": 0}), {"branch": "a"}),
                    (State({"count": 2}), State({"quota": 0}), {"branch": "b"}),
                ),
            },
            nondeterministic=frozenset({"roll"}),
        )
        self.assertEqual(len(world.options("roll", state, {})), 2)
        self.assertEqual(world.predict("roll", state, {}).status, Signal.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
