# RSVE Release Report

Release scope: repository state after BATCH 10 and the BATCH 11 readiness pass.

## Working capabilities

- Platform-neutral typed IR, evidence/fidelity axes, surface registries, and schema round-trips.
- Bounded Z3 solving, residual queries, named cores, explicit UNKNOWN handling, and exact supported weakest-precondition rules.
- Node and EVM controlled fixtures with replay, state reset, observed traces, and objective validation.
- Graph-owned profile instances and requirements with target, runtime, platform, OS/ISA, adapter, toolchain, image, configuration, and execution-scope fields.
- Composable workspace graph with typed bindings, representations, transforms, recognizers, state slots, correlation evidence, nested graphs, capability resolution, composite snapshot contracts, and budgets.
- Executable semantic graph traversal and reactive environment prediction/reconciliation.
- Minimal QEMU/Ubuntu Linux substrate with verified image, TCG launch, serial evidence, and qcow2 reset.
- Optional bounded realization optimization over caller-supplied candidates.
- Transactional SQLite evidence storage with schema versioning and stale solver-query invalidation.
- Synthetic black-box over-acceptance detection with a replay-validated controlled-sink witness.
- Four black-box behavior variants covering representation and state-boundary reachability.
- A real loopback HTTP fixture with deterministic open interaction-domain expansion, residual measurement, stable two-request replay, and explicit budget exhaustion.

## Verification

The complete suite passes with 68 tests. `python -m unittest discover -s tests -p 'test_*.py' -v` passes, including the QEMU serial/snapshot lifecycle. `python -m compileall -q src tests` and `git diff --check` pass. The focused graph, semantic interpreter, reactive environment, profile requirement, persistent solver, Node, EVM, planner, optimizer, and artifact tests pass. CI is intentionally excluded and no new dependency was added.

## Current benchmark

The benchmark reports modeled bounded analysis and Node fixture instrumentation separately. It records event count and profile ID prefix. It does not claim cross-host comparability, and QEMU is not included in the default timing loop because guest boot cost would dominate the application-runtime measurement.

Measured in this workspace with 20 rounds on Python 3.14.2: modeled bounded analysis averaged `0.0502 ms/run`; Node instrumented fixture execution averaged `2.488 ms/run` and emitted 4 events per run. The current built wheel is `67,277` bytes.

## Dependency footprint and platforms

The Python package has one direct dependency: `z3-solver==4.12.6.0`. Supported development baseline is Python 3.11+ on Linux; Node 24 is used by the local fixture suite. Foundry and QEMU are optional external tools. The QEMU image is an external verified artifact from the [Ubuntu Server 26.04 release](https://cloud-images.ubuntu.com/releases/server/server/26.04/release/), not part of the wheel. CI configuration is intentionally excluded from this repository snapshot.

## Limits and safety

Results remain bounded by target/build, workspace graph, surface, state, trace, environment, profile, solver, and replay budgets. UNSAT is never a global target proof. QEMU TCG is an OS/ISA substrate boundary, not exact hardware or scheduler replay, and the current substrate intentionally has no guest command channel. Fixtures are local and synthetic; payloads are redacted by default. No automatic unauthorized execution, secret extraction, or external exfiltration path is provided.

## Next highest-value work

Expand package/framework/loader pin discovery only where an adapter can observe it, add richer artifact retention/query tooling, and keep missing observations as UNKNOWN.
