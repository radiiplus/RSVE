# RSVE Repository Audit

Audit date: 2026-11-19. Repository root: `/home/codespace/smt`.

## Scope and evidence

The repository contains a small Python package and a fixture-driven unittest suite. Git metadata now exists with a single local/root history; broader ownership and review history remain UNKNOWN. The editable install generated `src/rsve.egg-info/` and Python cache directories; these are environment artifacts, not source capabilities.

Observed facts:

| Area | Status | Evidence |
| --- | --- | --- |
| Language and build | EXISTS | `pyproject.toml`; setuptools build; Python `>=3.11` |
| Package | EXISTS | `src/rsve/`; package version `0.1.0` |
| Dependencies | EXISTS (one pinned backend) | `[project].dependencies` contains `z3-solver==4.12.6.0` |
| Lockfile/reproducibility | PARTIAL | `requirements.lock` pins the runtime backend; build-system pinning and CI verification are still missing |
| Tests | EXISTS | `tests/test_core.py`, `tests/test_node_adapter.py`, `tests/test_planner.py`, `tests/test_symbolic.py`, `tests/test_evm_adapter.py`, `tests/test_environment.py`, `tests/test_qemu_adapter.py`; core and adapter tests include the QEMU guest lifecycle when the pinned image/tools are present |
| CI | MISSING | No `.github`, `tox.ini`, `noxfile.py`, Makefile, or CI configuration |
| Documentation | PARTIAL | `README.md` and `docs/rsve/` document the current core, adapter, decisions, and gaps |
| VCS metadata | PARTIAL | Local Git history and `origin` exist; broader branch/review history is not represented in the initial snapshot |
| Runtime evidence | EXISTS for three slices | Current environment has Node `v24.21.0`, Java `25.0.4.1`, SQLite library `3.45.1`, Foundry v1.9.0, QEMU `8.2.2`, and Ubuntu Server 26.04 amd64 cloud image; Node, EVM, and QEMU guest lifecycle are exercised |
| Solver backend | EXISTS | `src/rsve/solver.py` uses declared `z3-solver==4.12.6.0`; SAT/model, bounded UNSAT/core, UNKNOWN, timeout, and incremental tests pass |

## RSVE capability map

Status meanings: EXISTS is implemented and tested; PARTIAL is an explicit contract or narrow implementation without the full capability; MISSING has no repository implementation; CONFLICTS means current behavior violates the contract; UNKNOWN means repository evidence is insufficient.

| RSVE component or milestone capability | Status | File/test evidence and gap |
| --- | --- | --- |
| Typed state and transition model | PARTIAL | `src/rsve/model.py`: `State`, `Operation`, `TransitionModel`, `TraceEvent`; graph is implicit in operations and not a persisted component graph |
| Entry-point registry/discovery | PARTIAL | `EntryPoint`, `SurfaceRegistry`, and `NodeTargetAdapter.discover_entries()` exist; framework-wide discovery is intentionally unsupported |
| Transducers and representation semantics | EXISTS within supported semantics | `ir.Transform` is canonical; `SemanticInterpreter` composes supported transforms and recognizers, preserves representation lineage, and returns UNKNOWN for opaque semantics. General runtime semantics remain extension-provided |
| Recognizers and intended contracts | PARTIAL | Canonical `ir.Recognizer`, `SemanticInterpreter`, and `semantics.py` finite-domain residual helpers exist; enforcement trace, dominance analysis, and independent contract source remain partial |
| Transform/domain mismatch | PARTIAL | `transform_domain_mismatch()` computes finite `Image(T) - D`; reachable-image evidence is not connected to runtime traces |
| Over- and under-acceptance | PARTIAL | `compare_acceptance()` names both directions; only finite supplied domains are supported |
| Effect lemmas/checkpoints | PARTIAL | `EffectLemma` is checked against trace prefixes by `Engine`; no backward derivation or persisted checkpoint evidence |
| Target extension | PARTIAL | `src/rsve/extensions/node_adapter.py` and `src/rsve/extensions/evm_adapter.py` launch explicit local fixtures; JVM/native adapters remain contracts or roadmap work |
| Instrumentation adapter | PARTIAL | Node fixture uses `diagnostics_channel` and `AsyncLocalStorage`; generic runtime instrumentation remains a protocol |
| Semantic model adapter | PARTIAL | Versioned `Transform`/`Transition` records and exact supported symbolic transitions exist; no complete runtime semantics registry |
| Solver adapter | EXISTS within supported subset | `src/rsve/solver.py` translates the typed constraint subset to Z3; unsupported theories return UNKNOWN; proof capture remains optional |
| Reactive environment model | EXISTS within core scope | `src/rsve/environment_model.py` models target/environment state together, predicts reactions, and reconciles observed reactions; concrete Linux facts remain extension-provided |
| Composable workspace graph | EXISTS within tested graph scope | `src/rsve/graph.py` provides profiles, extension instances, bindings, typed regions/ports/connections, nested graphs, capability resolution, correlation evidence, composite snapshots, budgets, and cycle-safe traversal |
| Layer/profile identity | EXISTS within graph scope | `ProfileInstance` and `ProfileRequirement` in `src/rsve/graph.py` support multiple implementations, versions, configurations, execution scopes, and shared-dependency comparisons |
| Realization optimization | EXISTS within bounded candidate scope | `src/rsve/optimizer.py` replays caller-supplied alternatives from one clean snapshot and compares explicit costs; it does not synthesize new primitives or replace the planner |
| Black-box vulnerability-style detection | EXISTS in synthetic lab scope | `tests/test_blackbox_detection.py`, `tests/test_blackbox_variants.py`, and `tests/test_http_open_domain.py` observe canary-only controlled sinks, compute actual-minus-intended acceptance, expand an HTTP interaction domain, and replay-validate objectives without relying on source-location disclosure |
| Black-box variant coverage | EXISTS in bounded fixture scope | `tests/test_blackbox_variants.py` covers decoding, coercion, duplicate-field parsing, and stateful sequence boundaries; variants remain synthetic, local-only, finite, and independently specified |
| QEMU OS/ISA substrate | EXISTS within controlled guest scope | `src/rsve/extensions/qemu_adapter.py` boots the SHA256-pinned Ubuntu Server 26.04 amd64 image with QEMU TCG, captures serial boot evidence, and recreates qcow2 overlays for reset; guest command execution requires a separate guest-agent extension, while host hardware, scheduler, entropy, clock, external services, and exact whole-system replay remain unknown |
| Artifact store | EXISTS within local SQLite scope | `src/rsve/artifacts_sqlite.py` adds content-addressed redacted artifacts, WAL-backed transactions, schema versioning, solver-result indexes, snapshot metadata, and model/profile-aware stale-query invalidation; JSONL remains the lightweight export/debug store |
| Deterministic bounded planning | EXISTS | `Engine.analyze()` performs canonical-order breadth-first search with depth, state, and event budgets; `src/rsve/domain_search.py` expands an open interaction frontier under explicit candidate/time/trace budgets and reports budget exhaustion |
| Backward planning | PARTIAL | `src/rsve/weakest_precondition.py` is exact for deterministic guarded assignments and `HybridPlanner` now consumes supported WP/Z3 assignments; multi-step symbolic sequence regression and runtime-specific relations remain incomplete |
| Forward/concolic execution | PARTIAL | Forward model execution exists; no concrete target execution, symbolic values, or concolic feedback |
| Validated witness | PARTIAL | `HybridPlanner` requires adapter replay and objective observation before `VALIDATED_WITNESS`; the legacy `Engine` now returns `MODEL_SAT` with `Witness.validated=False` |
| Bounded proof result | PARTIAL | `UNSAT_BOUNDED`, `UNKNOWN`, models, and cores are explicit and tested; solver proof bytes are optional and there is no fidelity proof |
| Model/reality divergence | PARTIAL | `DifferentialAnalyzer` aligns semantic events, classifies first divergence, and emits immutable refinement deltas; broader correlation and model mutation remain limited |
| Authorization and lab scope | PARTIAL | `Authorization` is enforced at Node/EVM invoke, replay, and ordered execution boundaries; target isolation, policy store, and deployment audit identity remain unavailable |
| Phantom entry detection | EXISTS within registry | `src/rsve/registry.py` requires observed evidence and retains conditions; no runtime discovery implementation |
| Replay and snapshot/reset | PARTIAL | Node and EVM fixtures support clean reset, ordered replay, k-of-n semantic stability, and authorization; exact host/environment replay is explicitly unavailable |
| Standard trace interchange | PARTIAL | `TraceEvent` has IDs, causal links, representations, states, environment, ordering, and evidence; `OpenTelemetryAdapter` maps these without an OTel dependency |
| Cross-runtime portability | EXISTS within two fixtures | `tests/test_node_adapter.py` and `tests/test_evm_adapter.py` run the same planner/objective/result workflow; JVM/native capability contracts are documented without claiming implementation |
| Security/redaction | PARTIAL | JSONL redacts a small key set by default; no structured secret classification, trace redaction policy, or sink isolation |

## Architectural risks

1. **Execution versus fidelity.** `Operation.fidelity` separates a modeled event from an observed one, `HybridPlanner` requires replay evidence for `VALIDATED_WITNESS`, and `Engine` reports model-only success as `MODEL_SAT`; neither model execution nor replay alone proves full runtime fidelity.

2. **Residual-set scope.** The helpers operate over caller-supplied finite domains. They must never be presented as global accepted sets. `Image(T) - D`, over-acceptance, and under-acceptance must remain separate report fields and carry domain/provenance evidence.

3. **Solver proof scope.** `UNSAT_BOUNDED` currently means bounded exhaustive exploration of the finite model/input set. A future solver result must preserve the exact query, assumptions, abstraction, solver/version/options, core/proof artifact, and the independent model-fidelity limitation. An UNSAT core is not a real-target proof.

4. **State and snapshot semantics.** `State` is immutable modeled data. An adapter snapshot may include processes, files, handles, clocks, random state, threads, or external services. Treating those as interchangeable would make replay unsound.

5. **Platform independence.** Node and EVM fixtures now demonstrate the same core workflow. JVM and native behavior remains behind explicit capability contracts; the core must not silently collapse unobserved semantics into safe or impossible.

6. **Determinism.** Linux environment identity and layered execution profile scope are now recorded, and QEMU provides a portable guest OS/ISA boundary. Clock/randomness, scheduler behavior, hardware memory ordering, adapter versions, and solver settings remain partly uncontrolled; TCG is an emulation boundary, not a deterministic replay oracle.

7. **Repository governance.** Local Git metadata and a lockfile exist, but CI is intentionally excluded from this repository snapshot. Build, test, and advisory checks must therefore be run explicitly by maintainers or an external pipeline.

8. **Dependency drift.** The environment contains packages not declared by the project. Import success is not evidence that a dependency is available to a clean build.

9. **Optimization scope.** Realization optimization is intentionally finite and replay-gated. It cannot discover a better realization outside the supplied candidate set, and unknown resource metrics remain explicit rather than estimated as zero.

10. **Artifact durability.** SQLite provides local transactional durability and query invalidation, but external snapshot bytes remain adapter-owned and filesystem permissions/backup/retention policy are deployment responsibilities.

## Audit conclusion

The repository now supports a graph-centered Python core with canonical semantic interpretation, reactive environment state, persistent bounded Z3 sessions, a Node/EVM extension slice, a QEMU-backed Ubuntu Linux substrate, exact symbolic weakest-precondition rules for a small deterministic assignment subset, replay-gated bounded realization optimization, and a transactional SQLite evidence ledger with stale-query invalidation. Native symbolic, syscall-boundary, and whole-system selective analysis remain extension contracts; none of these capabilities imply global reachability or exact environment replay.
