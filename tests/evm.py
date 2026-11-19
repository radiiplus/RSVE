import unittest
from pathlib import Path

from rsve import (
    Authorization,
    EntryPoint,
    FlowToSink,
    GuardInvariant,
    HybridPlanner,
    ObjectiveBudget,
    ObjectiveDefinition,
    Operation,
    State,
    StateEquals,
    TransitionModel,
)
from rsve.extensions import EvmTargetAdapter
from rsve.result import AnalysisStatus


FIXTURE = Path(__file__).parent / "fixtures" / "evm" / "src" / "Counter.sol"
ANVIL = Path("/home/codespace/.foundry/bin/anvil")


def model() -> TransitionModel:
    return TransitionModel(
        target_id="evm-fixture",
        initial_state=State({"count": 0}),
        inputs=({"amount": 1, "canary": "RSVE-CANARY"},),
        operations=(Operation(
            name="state.mutation",
            entry_point=EntryPoint("increment"),
            guard=lambda _state, request: 0 < request["amount"] <= 10,
            apply=lambda state, request: state.with_updates(count=state["count"] + request["amount"]),
            observe=lambda _before, _request, after: {"count": after["count"]},
            component="evm.fixture.state",
        ),),
    )


@unittest.skipUnless(ANVIL.exists(), "Foundry/Anvil is required for the EVM vertical slice")
class EvmAdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapter = EvmTargetAdapter(FIXTURE, target_id="evm-fixture", port=18547)
        self.auth = Authorization("evm-tests", frozenset({"evm-lab"}), frozenset({"evm-fixture"}))

    def tearDown(self):
        self.adapter.teardown()

    def test_chain_entries_revert_and_replay(self):
        self.assertTrue(self.adapter.evm_capabilities.local_chain)
        self.assertTrue(self.adapter.evm_capabilities.storage_state)
        good = self.adapter.invoke("increment", {"amount": 1, "canary": "RSVE-CANARY"}, self.auth)
        self.assertEqual(good[0].operation, "state.mutation")
        self.assertEqual(good[0].after["count"], 1)
        rejected = self.adapter.invoke("increment", {"amount": 11, "canary": "RSVE-CANARY"}, self.auth)
        self.assertEqual(rejected[0].operation, "guard.decision")
        self.assertFalse(rejected[0].guard_result)
        replay = self.adapter.replay(
            ({"entry_point": "increment", "request": {"amount": 1, "canary": "RSVE-CANARY"}},),
            runs=2,
            authorization=self.auth,
        )
        self.assertTrue(replay.stable)
        self.assertEqual(len(replay.runs), 2)

    def test_shared_objective_planner_validates_on_evm(self):
        objective = ObjectiveDefinition(
            "evm-reach-one",
            "evm-fixture",
            "evm-lab",
            (StateEquals("count", 1), FlowToSink("increment", "RSVE-CANARY", "evm.fixture.state"), GuardInvariant()),
            permitted_sinks=frozenset({"evm.fixture.state"}),
            budget=ObjectiveBudget(max_trace_length=1, replay_runs=2),
        )
        report = HybridPlanner(harness_sinks={"evm.fixture.state"}).plan(
            model(), objective, self.auth, adapter=self.adapter,
        )
        self.assertEqual(report.status, AnalysisStatus.VALIDATED_WITNESS)
        self.assertTrue(report.witness.validated)
        self.assertEqual(report.witness.final_state["count"], 1)


if __name__ == "__main__":
    unittest.main()
