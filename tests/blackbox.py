import json
import unittest
from pathlib import Path

from rsve import (
    Authorization,
    Entry,
    Flow,
    Guard,
    Planner,
    Objective,
    Operation,
    State,
    Same,
    Model,
)
from rsve.extensions import Node
from rsve.acceptance import compare
from rsve.result import Status


FIXTURE = Path(__file__).parent / "fixtures" / "node" / "blackbox.mjs"
MANIFEST = Path(__file__).parent / "fixtures" / "node" / "blackbox.json"
UNAUTHORIZED = {"role": "analyst", "token": "RSVE-CANARY"}
AUTHORIZED = {"role": "admin", "token": "RSVE-CANARY"}


class Suite(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = Node(FIXTURE, manifest=MANIFEST, target_id="blackbox-lab", scope="blackbox-lab")
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
        residual = compare(
            actual=self._actual_accepts,
            intended=lambda encoded: json.loads(encoded).get("role") == "admin",
            domain=domain,
        )
        self.assertEqual(residual.over_acceptance, frozenset({json.dumps(UNAUTHORIZED, sort_keys=True)}))
        self.adapter.teardown()

        model = Model(
            target_id="blackbox-lab",
            initial_state=State({"delivered": 0, "sinkValues": []}),
            inputs=(UNAUTHORIZED,),
            operations=(Operation(
                name="state.mutation",
                entry_point=Entry("submit"),
                guard=lambda _state, request: request.get("role") == "admin" or request.get("token") == "RSVE-CANARY",
                apply=lambda state, request: state.update(
                    delivered=state["delivered"] + 1,
                    sinkValues=list(state["sinkValues"]) + [request.get("token", "")],
                ),
                observe=lambda _before, _request, _after: {"sink": "controlled.local.sink", "canary": True},
                component="controlled.local.sink",
            ),),
            build_hash="blackbox-model",
        )
        objective = Objective(
            "canary-reaches-controlled-sink",
            "blackbox-lab",
            "blackbox-lab",
            (
                Same("delivered", 1),
                Flow("submit", "RSVE-CANARY", "controlled.local.sink"),
                Guard("submit"),
            ),
            permitted_sinks=frozenset({"controlled.local.sink"}),
        )
        report = Planner(harness_sinks={"controlled.local.sink"}).plan(
            model, objective, self.authorization, adapter=self.adapter,
        )
        self.assertEqual(report.status, Status.VALIDATED_WITNESS)
        self.assertEqual(report.witness.interactions[0]["request"], UNAUTHORIZED)
        self.assertEqual(report.witness.final_state["delivered"], 1)


if __name__ == "__main__":
    unittest.main()
