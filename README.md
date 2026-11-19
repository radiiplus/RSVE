# RSVE

RSVE is a deterministic, bounded program-analysis core for building an evidence-backed model of reachable target behavior. The core is platform-neutral; the first solver backend is an isolated, pinned Z3 adapter. It provides:

- typed target and transition models;
- deterministic bounded forward exploration with optional input constraints;
- authorized objectives and validated witnesses;
- bounded proof results with explicit residual gaps;
- model/reality trace divergence localization; and
- JSON Lines artifact persistence with default secret redaction.

The core deliberately does not claim global completeness. Every result carries its search budget, model provenance, and fidelity boundary. Runtime, instrumentation, solver, environment, and storage integrations implement the protocols in `rsve.adapter`.

## Quick start

```python
from rsve import (
    Status, Authorization, Budget, Engine, Entry, Goal, Operation,
    State, Model,
)

model = Model(
    target_id="fixture",
    initial_state=State({"count": 0}),
    inputs=({"amount": 1}, {"amount": 2}),
    operations=(Operation(
        name="increment",
        entry_point=Entry("lab.increment", declared=True),
        guard=lambda state, request: request["amount"] > 0,
        apply=lambda state, request: state.update(
            count=state["count"] + request["amount"]
        ),
    ),),
)

report = Engine().analyze(
    model,
    Goal(
        name="reach-two",
        scope="fixture-lab",
        postcondition=lambda state, trace: state["count"] == 2,
    ),
    Authorization(subject="test-runner", scopes=frozenset({"fixture-lab"})),
    Budget(max_depth=2),
)
assert report.witness is not None
assert report.status is Status.MODEL_SAT
```

`Engine` evaluates only the supplied transition model, so `MODEL_SAT` is not a runtime validation claim. Use `Planner` with a target adapter when the result must be replay-confirmed against a real controlled fixture.

Run the tests with:

```bash
python -m unittest discover -s tests -p "*.py" -v
```

The first solver backend is pinned as `z3-solver==4.12.6.0`. The adapter records its version, options, query, model, unsat core, optional proof bytes, and limitations in the artifact ledger; unsupported theories remain `UNKNOWN`.

For release checks, run `python scripts/check.py`, `python -m unittest discover -s tests -p "*.py" -v`, and `python scripts/benchmark.py --rounds 20`. Optional Foundry and QEMU integrations are capability-gated and are not installed by the Python package. Layered execution profiles pin observed target, runtime, OS/ISA, toolchain, image, and adapter identities; objective `profile_pins` are checked before planning.
