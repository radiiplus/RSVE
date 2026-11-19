import json
import unittest
from pathlib import Path

from rsve import (
    Authorization,
    EntryPoint,
    FlowToSink,
    GuardInvariant,
    HybridPlanner,
    ObjectiveDefinition,
    Operation,
    State,
    StateEquals,
    TransitionModel,
)
from rsve.extensions import NodeTargetAdapter
from rsve.semantics import compare_acceptance
from rsve.results import AnalysisStatus


FIXTURE = Path(__file__).parent / "fixtures" / "node" / "blackbox_lab.mjs"
MANIFEST = Path(__file__).parent / "fixtures" / "node" / "blackbox_manifest.json"
UNAUTHORIZED = {"role": "analyst", "token": "RSVE-CANARY"}
AUTHORIZED = {"role": "admin", "token": "RSVE-CANARY"}


class BlackboxDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = NodeTargetAdapter(FIXTURE, manifest=MANIFEST, target_id="blackbox-lab", scope="blackbox-lab")
        self.authorization = Authorization("blackbox-test", frozenset({"blackbox-lab"}), frozenset({"blackbox-lab"}))

    def tearDown(self) -> None:
        self.adapter.teardown()

    def _actual_accepts(self, encoded: str) -> bool:
        request = json.loads(encoded)
        replay = self.adapter.replay(
            (({"entry_point": "submit", "request": request}),),
            runs=1,
            authorization=self.authorization,
        )
        return any(
            event.operation == "guard.decision" and event.guard_result is True
            for event in replay.runs[0].events
        )

    def test_blackbox_over_acceptance_reaches_controlled_sink(self) -> None:
        domain = tuple(json.dumps(value, sort_keys=True) for value in (UNAUTHORIZED, AUTHORIZED))
        residual = compare_acceptance(
            actual=self._actual_accepts,
            intended=lambda encoded: json.loads(encoded).get("role") == "admin",
            domain=domain,
        )
        self.assertEqual(residual.over_acceptance, frozenset({json.dumps(UNAUTHORIZED, sort_keys=True)}))
        self.adapter.teardown()

        model = TransitionModel(
            target_id="blackbox-lab",
            initial_state=State({"delivered": 0, "sinkValues": []}),
            inputs=(UNAUTHORIZED,),
            operations=(Operation(
                name="state.mutation",
                entry_point=EntryPoint("submit"),
                guard=lambda _state, request: request.get("role") == "admin" or request.get("token") == "RSVE-CANARY",
                apply=lambda state, request: state.with_updates(
                    delivered=state["delivered"] + 1,
                    sinkValues=list(state["sinkValues"]) + [request.get("token", "")],
                ),
                observe=lambda _before, _request, _after: {"sink": "controlled.local.sink", "canary": True},
                component="controlled.local.sink",
            ),),
            build_hash="blackbox-model",
        )
        objective = ObjectiveDefinition(
            "canary-reaches-controlled-sink",
            "blackbox-lab",
            "blackbox-lab",
            (
                StateEquals("delivered", 1),
                FlowToSink("submit", "RSVE-CANARY", "controlled.local.sink"),
                GuardInvariant("submit"),
            ),
            permitted_sinks=frozenset({"controlled.local.sink"}),
        )
        report = HybridPlanner(harness_sinks={"controlled.local.sink"}).plan(
            model, objective, self.authorization, adapter=self.adapter,
        )
        self.assertEqual(report.status, AnalysisStatus.VALIDATED_WITNESS)
        self.assertEqual(report.witness.interactions[0]["request"], UNAUTHORIZED)
        self.assertEqual(report.witness.final_state["delivered"], 1)


if __name__ == "__main__":
    unittest.main()
