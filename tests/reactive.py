import unittest

from rsve import (
    EnvironmentResultStatus,
    ReactiveEnvironment,
    ReactiveEnvironmentState,
    State,
)


class ReactiveEnvironmentTests(unittest.TestCase):
    def test_environment_reaction_influences_next_state_and_divergence_is_targeted(self):
        model = ReactiveEnvironment(
            ReactiveEnvironmentState(State({"count": 0}), State({"quota": 1})),
            {
                "write": lambda state, request: (
                    state.target.with_updates(count=state.target["count"] + request["amount"]),
                    state.environment.with_updates(quota=state.environment["quota"] - request["amount"]),
                    {"accepted": True},
                ),
            },
        )
        predicted = model.predict("write", model.initial, {"amount": 1})
        self.assertEqual(predicted.status, EnvironmentResultStatus.PREDICTED)
        self.assertEqual(predicted.after.environment["quota"], 0)
        observed = model.observe("write", model.initial, ReactiveEnvironmentState(State({"count": 1}), State({"quota": 1})), {"accepted": True})
        divergence = model.reconcile(predicted, observed)
        self.assertIsNotNone(divergence)
        assert divergence is not None
        self.assertEqual(divergence.differing_target_keys, ())
        self.assertEqual(divergence.differing_environment_keys, ("quota",))

    def test_missing_environment_semantics_is_unknown(self):
        state = ReactiveEnvironmentState(State({}), State({}))
        step = ReactiveEnvironment(state, {}).predict("missing", state, {})
        self.assertEqual(step.status, EnvironmentResultStatus.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
