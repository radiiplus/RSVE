"""Small repeatable benchmark for modeled and instrumented fixture paths."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rsve import (  # noqa: E402
    Authorization,
    Budget,
    Engine,
    Entry,
    Node,
    Objective,
    Operation,
    State,
    Model,
)


def modeled_fixture() -> Model:
    operation = Operation(
        name="increment",
        entry_point=Entry("bench.increment"),
        guard=lambda _state, request: request["amount"] > 0,
        apply=lambda state, request: state.update(count=state["count"] + request["amount"]),
    )
    return Model("bench", State({"count": 0}), ({"amount": 1}, {"amount": 2}), (operation,))


def measure(rounds: int, function) -> float:
    started = time.perf_counter()
    for _ in range(rounds):
        function()
    return (time.perf_counter() - started) * 1000 / rounds


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=20)
    args = parser.parse_args()
    if args.rounds <= 0:
        raise SystemExit("--rounds must be positive")

    model = modeled_fixture()
    objective = Objective("bench", "bench-lab", lambda state, _trace: state["count"] == 2)
    authorization = Authorization("benchmark", frozenset({"bench-lab"}))
    modeled_ms = measure(args.rounds, lambda: Engine().analyze(model, objective, authorization, Budget(max_depth=1)))

    adapter = Node(ROOT / "tests/fixtures/node/fixture.mjs", target_id="node-fixture")
    adapter.prepare()
    baseline = adapter.snapshot()
    observed_events = 0

    def instrumented_run() -> None:
        nonlocal observed_events
        adapter.reset(baseline)
        events = adapter.trace(({"entry_point": "increment", "request": {"amount": 1}},))
        observed_events = len(events)

    try:
        instrumented_ms = measure(args.rounds, instrumented_run)
        profile_id = adapter.execution_profile().profile_id
    finally:
        adapter.teardown()
    print(json.dumps({
        "rounds": args.rounds,
        "modeled_bounded_ms_per_run": round(modeled_ms, 4),
        "node_instrumented_ms_per_run": round(instrumented_ms, 4),
        "node_events_per_run": observed_events,
        "profile_id_prefix": profile_id[:16],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
