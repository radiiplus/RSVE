# RSVE Roadmap

This roadmap is grounded in the current paths. Planned paths are named explicitly; they do not exist yet.

## Dependency order

`canonical IR` -> `workspace graph and bindings` -> `semantic interpreter` -> `solver/residual contract` -> `reactive environment model` -> `trace/replay harness` -> `objective/planner` -> `differential refinement` -> optional extensions (Node/EVM/Linux/QEMU) -> realization optimization -> durable artifacts/release.

## Batches

| Batch | Scope | Actual paths | New dependencies | Exit gate |
| --- | --- | --- | --- | --- |
| 0 | Repository reconnaissance and feasibility audit | `docs/rsve/audit.md`, `docs/rsve/decisions.md`, `docs/rsve/roadmap.md`, `docs/rsve/deps.md` | None | Facts, gaps, risks, and unknowns are evidenced; no engine/dependency changes |
| 1 | Library/dependency architecture | `docs/rsve/deps.md`, `pyproject.toml`, `lock` | `z3-solver==4.12.6.0` only | Every adopted dependency has a role, pin, license/maintenance decision, and adapter boundary |
| 2 | Typed Transform/Transition IR | `src/rsve/schema.py`, `ir.py`, `logic.py`, `registry.py`, `tests/core.py` | None | Versioned records, execution/fidelity separation, objective AST, and evidence-backed surfaces round-trip and reject invalid input |
| 3 | Solver-aided bounded residuals | `src/rsve/logic.py`, `src/rsve/solver.py`, `src/rsve/residual.py`, `tests/core.py` | `z3-solver==4.12.6.0` | SAT/model, bounded UNSAT/core, UNKNOWN, incremental scopes, residual queries, and bounded scope are tested |
| 4 | Node target extension | `src/rsve/adapter.py`, `src/rsve/extensions/node.py`, `tests/node.py`, `tests/fixtures/node/` | Node built-ins `node:diagnostics_channel`, `node:async_hooks` | Declared/observed entries, authorization, traces, state checkpoints, reset/replay limits, phantom evidence, and semantic replay work on an owned fixture |
| 5 | Trace schema and deterministic harness | `src/rsve/model.py`, `src/rsve/ir.py`, `src/rsve/trace.py`, `src/rsve/extensions/node.py`, `tests/node.py` | No OpenTelemetry dependency | Stable IDs/causal links, environment facts/unknowns, bounded redacted artifacts, k-of-n runs, partial replay, and OTel-shaped import/export are tested |
| 6 | Objective language and hybrid witness planner | `src/rsve/objective.py`, `src/rsve/planner.py`, `src/rsve/search.py`, `src/rsve/result.py`, `tests/planner.py`, `tests/search.py`, `tests/http.py` | Reuse existing model and adapter contracts | Authorized extensional objectives, bounded preimage/forward search, deterministic open interaction-domain expansion, single and multi-entry candidates, replay validation, and truthful candidate/UNSAT/budget semantics pass |
| 7 | Differential refinement and result semantics | `src/rsve/diff.py`, `src/rsve/model.py`, `src/rsve/result.py`, `tests/planner.py` | None | First divergence classification, immutable deltas/experiments, counterexample exclusions, stale-query invalidation, and model/reality scope are evidenced |
| 8 | Cross-runtime extension design and portability proof | `src/rsve/extensions/contract.py`, `src/rsve/extensions/node.py`, `src/rsve/extensions/linux.py`, `src/rsve/graph.py`, `tests/fixtures/evm/`, `tests/evm.py`, `tests/environment.py`, `tests/profile.py`, `docs/rsve/adapter.md` | Foundry v1.9.0 (`anvil`, `forge`, `cast`) installed outside the Python package; JDK APIs remain optional roadmap contracts | The same objective/planner/trace/result workflow validates Node and EVM fixtures through optional extensions and graph-owned profile requirements |
| 9 | Minimal QEMU Linux substrate and native gate | `src/rsve/adapter.py`, `src/rsve/extensions/node.py`, `src/rsve/extensions/linux.py`, `tests/qemu.py`, `docs/rsve/adapter.md` | System QEMU 8.2.2 and `qemu-img`; official Ubuntu Server 26.04 amd64 cloud image pinned by SHA256 | Boot, capture serial evidence, snapshot/reset, and report guest environment scope through an optional substrate extension; guest command execution requires a separate guest-agent extension |
| 10 | Optional realization optimization | `src/rsve/optimize.py`, `tests/optimize.py`, `docs/rsve/objective.md` | No new dependency; reuse adapter replay and existing objective semantics | Equivalent caller-supplied realizations replay successfully from the same clean snapshot, cost improvement is measured, and the original witness/equivalence evidence are preserved |
| 11 | Consolidation and release readiness | `scripts/check.py`, `scripts/benchmark.py`, `NOTICE.md`, `docs/rsve/release.md`, `README.md` | No package dependency change; CI intentionally excluded | Clean build, lock/security checks, schema/tests, fixture replay, benchmark, notices, safety boundaries, and documented limitations pass when run by maintainers or an external pipeline |
| 12 | Future artifact query/retention improvements | `src/rsve/sqlite.py` and deployment-specific tooling | No dependency selected | Add retention, backup, richer query/reporting, and external snapshot lifecycle only when operational requirements are demonstrated |

## Immediate next implementation gate

The QEMU Linux substrate is implemented as the explicit OS/ISA boundary for controlled fixtures, realization optimization is replay-gated over finite candidates, and SQLite provides the durable artifact/query ledger. Native instrumentation, symbolic binaries, S2E, and whole-system selective symbolic execution remain gated on a reproducible divergence that requires them. The next work should improve artifact queries and adapter coverage without changing the canonical trace or objective contract.
