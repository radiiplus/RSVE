# RSVE Release Report

Release scope: repository state after BATCH 10 and the BATCH 11 readiness pass.

## Working capabilities

- Platform-neutral typed IR, evidence/fidelity axes, surface registries, and schema round-trips.
- Bounded Z3 solving, residual queries, named cores, explicit UNKNOWN handling, and exact supported weakest-precondition rules.
- Node and EVM controlled fixtures with replay, state reset, observed traces, and objective validation.
- Layered execution profiles with target, runtime, platform, OS/ISA, adapter, toolchain, and image pins.
- Minimal QEMU/Ubuntu Linux substrate with verified image, TCG launch, serial evidence, and qcow2 reset.
- Optional bounded realization optimization over caller-supplied candidates.
- Transactional SQLite evidence storage with schema versioning and stale solver-query invalidation.
- Synthetic black-box over-acceptance detection with a replay-validated controlled-sink witness.
- Four black-box behavior variants covering representation and state-boundary reachability.
- A real loopback HTTP fixture with deterministic open interaction-domain expansion, residual measurement, stable two-request replay, and explicit budget exhaustion.

## Verification

The complete suite passes with 53 tests. `python -m unittest discover -s tests -v` passes, including the QEMU guest lifecycle. `python -m pip check`, bytecode compilation, dependency-lock verification, wheel build, SQLite artifact tests, optimizer fixture, black-box detection regression, HTTP open-domain replay, symbolic planner guidance, canonical transform bridging, authorization enforcement, and variant coverage pass. `pip-audit==2.9.0 --requirement requirements.lock` reports no known vulnerabilities. Run `python scripts/benchmark.py --rounds 20` for local measurements; benchmark values are host-dependent and are not proof artifacts.

## Current benchmark

The benchmark reports modeled bounded analysis and Node fixture instrumentation separately. It records event count and profile ID prefix. It does not claim cross-host comparability, and QEMU is not included in the default timing loop because guest boot cost would dominate the application-runtime measurement.

Measured in this workspace with 20 rounds on Python 3.14.2: modeled bounded analysis averaged `0.0502 ms/run`; Node instrumented fixture execution averaged `2.488 ms/run` and emitted 4 events per run. The current built wheel is `67,277` bytes.

## Dependency footprint and platforms

The Python package has one direct dependency: `z3-solver==4.12.6.0`. Supported development baseline is Python 3.11+ on Linux; Node 24 is used by the local fixture suite. Foundry and QEMU are optional external tools. The QEMU image is an external verified artifact from the [Ubuntu Server 26.04 release](https://cloud-images.ubuntu.com/releases/server/server/26.04/release/), not part of the wheel. CI configuration is intentionally excluded from this repository snapshot.

## Limits and safety

Results remain bounded by target/build, surface, state, trace, environment, profile pins, solver, and replay budgets. UNSAT is never a global target proof. QEMU TCG is an OS/ISA substrate boundary, not exact hardware or scheduler replay. Fixtures are local and synthetic; payloads are redacted by default. No automatic unauthorized execution, secret extraction, or external exfiltration path is provided.

## Next highest-value work

Expand package/framework/loader pin discovery only where an adapter can observe it, add richer artifact retention/query tooling, and keep missing observations as UNKNOWN.
