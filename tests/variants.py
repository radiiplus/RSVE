import json
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from rsve import (
    Authorization,
    Entry,
    Flow,
    Guard,
    Planner,
    Limits,
    Objective,
    Operation,
    State,
    Same,
    Model,
)
from rsve.extensions import Node
from rsve.result import Status
from rsve.acceptance import compare


FIXTURE = Path(__file__).parent / "fixtures" / "node" / "variant.mjs"
MANIFEST = Path(__file__).parent / "fixtures" / "node" / "variant.json"
SINK = "controlled.local.sink"


@dataclass(frozen=True)
class Case:
    name: str
    probe: dict[str, Any]
    interactions: tuple[dict[str, Any], ...]
    intended: Callable[[dict[str, Any]], bool]


CASES = (
    Case(
        "decode-boundary",
        {"variant": "decode", "value": "RSVE-%43ANARY", "token": "RSVE-CANARY"},
        ({"entry_point": "submit", "request": {"variant": "decode", "value": "RSVE-%43ANARY", "token": "RSVE-CANARY"}},),
        lambda request: request["value"] == "RSVE-CANARY",
    ),
    Case(
        "coercion-boundary",
        {"variant": "coerce", "role": ["admin"], "token": "RSVE-CANARY"},
        ({"entry_point": "submit", "request": {"variant": "coerce", "role": ["admin"], "token": "RSVE-CANARY"}},),
        lambda request: isinstance(request["role"], str) and request["role"] == "admin",
    ),
    Case(
        "duplicate-field-boundary",
        {"variant": "duplicate", "fields": [["role", "viewer"], ["role", "admin"]], "token": "RSVE-CANARY"},
        ({"entry_point": "submit", "request": {"variant": "duplicate", "fields": [["role", "viewer"], ["role", "admin"]], "token": "RSVE-CANARY"}},),
        lambda request: len(request["fields"]) == 1 and request["fields"][0] == ["role", "admin"],
    ),
    Case(
        "state-sequence-boundary",
        {"variant": "sequence", "action": "prepare", "mode": "review", "token": "RSVE-CANARY"},
        (
            {"entry_point": "prepare", "request": {"variant": "sequence", "action": "prepare", "mode": "review", "token": "RSVE-CANARY"}},
            {"entry_point": "commit", "request": {"variant": "sequence", "action": "commit", "token": "RSVE-CANARY"}},
        ),
        lambda request: request.get("mode") == "admin",
    ),
)


class Suite(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = Node(FIXTURE, manifest=MANIFEST, target_id="variant-lab", scope="variant-lab")
        self.authorization = Authorization("variant-tests", frozenset({"variant-lab"}), frozenset({"variant-lab"}))

    def tearDown(self) -> None:
        self.adapter.teardown()

    def actual_accepts(self, request: dict[str, Any]) -> bool:
        replay = self.adapter.replay(({"entry_point": request.get("action", "submit"), "request": request},), runs=1, authorization=self.authorization)
        return any(event.operation == "guard.decision" and event.guard_result is True for event in replay.runs[0].events)

    def model_for(self, case: Case) -> Model:
        if case.name == "state-sequence-boundary":
            operations = (
                Operation("prepare", Entry("prepare"), guard=lambda state, request: request.get("action") == "prepare" and request.get("mode") == "review", apply=lambda state, _request: state.update(pending=True), component="variant.pending"),
                Operation("state.mutation", Entry("commit"), guard=lambda state, request: request.get("action") == "commit" and state.get("pending") is True, apply=lambda state, _request: state.update(pending=False, delivered=state["delivered"] + 1), observe=lambda _before, _request, _after: {"sink": SINK, "canary": True, "variant": "sequence"}, component=SINK),
            )
            inputs = tuple(item["request"] for item in case.interactions)
        else:
            request = case.probe
            operations = (Operation("state.mutation", Entry("submit"), guard=lambda _state, _request: True, apply=lambda state, _request: state.update(delivered=state["delivered"] + 1), observe=lambda _before, _request, _after: {"sink": SINK, "canary": True, "variant": request["variant"]}, component=SINK),)
            inputs = (request,)
        return Model("variant-lab", State({"pending": False, "delivered": 0}), inputs, operations, build_hash="variant-model")

    def test_variants_detect_residual_and_reachability(self) -> None:
        detected = []
        for case in CASES:
            encoded = json.dumps(case.probe, sort_keys=True)
            residual = compare(
                actual=lambda candidate: self.actual_accepts(json.loads(candidate)),
                intended=lambda candidate: case.intended(json.loads(candidate)),
                domain=(encoded,),
            )
            self.assertEqual(len(residual.over_acceptance), 1, case.name)
            model = self.model_for(case)
            objective = Objective(
                f"reach-{case.name}",
                "variant-lab",
                "variant-lab",
                (Same("delivered", 1), Flow(case.interactions[-1]["entry_point"], "RSVE-CANARY", SINK), Guard()),
                permitted_sinks=frozenset({SINK}),
                budget=Limits(max_trace_length=2),
            )
            self.adapter.teardown()
            report = Planner(harness_sinks={SINK}).plan(model, objective, self.authorization, adapter=self.adapter)
            self.assertEqual(report.status, Status.VALIDATED_WITNESS, case.name)
            detected.append(case.name)
        self.assertEqual(tuple(detected), tuple(case.name for case in CASES))


if __name__ == "__main__":
    unittest.main()
