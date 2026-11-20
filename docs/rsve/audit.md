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
| Lockfile/reproducibility | PARTIAL | `lock` pins the runtime backend; build-system pinning and CI verification are still missing |
| Tests | EXISTS | `tests/core.py`, `tests/node.py`, `tests/planner.py`, `tests/symbolic.py`, `tests/evm.py`, `tests/environment.py`, `tests/qemu.py`; core and adapter tests include the QEMU guest lifecycle when the pinned image/tools are present |
| CI | MISSING | No `.github`, `tox.ini`, `noxfile.py`, Makefile, or CI configuration |
| Documentation | PARTIAL | `README.md` and `docs/rsve/` document the current core, adapter, decisions, and gaps |
| VCS metadata | PARTIAL | Local Git history and `origin` exist; broader branch/review history is not represented in the initial snapshot |
| Runtime evidence | EXISTS for three slices | Current environment has Node `v24.21.0`, Java `25.0.4.1`, SQLite library `3.45.1`, Foundry v1.9.0, QEMU `8.2.2`, and Ubuntu Server 26.04 amd64 cloud image; Node, EVM, and QEMU guest lifecycle are exercised |
| Solver backend | EXISTS | `src/rsve/solver.py` uses declared `z3-solver==4.12.6.0`; SAT/model, bounded UNSAT/core, UNKNOWN, timeout, and incremental tests pass |

## RSVE capability map

Status meanings: EXISTS is implemented and tested; PARTIAL is an explicit contract or narrow implementation without the full capability; MISSING has no repository implementation; CONFLICTS means current behavior violates the contract; UNKNOWN means repository evidence is insufficient.

| RSVE component or milestone capability | Status | File/test evidence and gap |
| --- | --- | --- |
| Typed state and transition model | PARTIAL | `src/rsve/model.py`: `State`, `Operation`, `Outcome`, `Model`, `Event`; rejection, partial, error and unknown branches are explicit, and `src/rsve/workspace.py` composes target/environment and owner-aware region frames with qualified predicate views; connected graph routes now carry destination-region effects, but arbitrary aliasing and dependency semantics remain bounded |
| Entry-point registry/discovery | PARTIAL | `Entry`, `Surface`, and `Node.discover()` exist; framework-wide discovery is intentionally unsupported |
| Transducers and representation semantics | EXISTS within supported semantics | `ir.Transform` is canonical; `Interpreter` composes supported transforms and recognizers, preserves representation lineage, and returns UNKNOWN for opaque semantics. General runtime semantics remain extension-provided |
| Recognizers and intended contracts | PARTIAL | Canonical `ir.Recognizer`, `Interpreter`, and `acceptance.py` finite-domain residual helpers exist; enforcement trace, dominance analysis, and independent contract source remain partial |
| Transform/domain mismatch | PARTIAL | `gap()` computes finite `Image(T) - D`; reachable-image evidence is not connected to runtime traces |
| Over- and under-acceptance | PARTIAL | `compare()` names both directions; only finite supplied domains are supported |
| Effect lemmas/checkpoints | PARTIAL | `Lemma` is checked against trace prefixes by `Engine`; no backward derivation or persisted checkpoint evidence |
| Target extension | PARTIAL | `src/rsve/extensions/node.py` and `src/rsve/extensions/node.py` launch explicit local fixtures; JVM/native adapters remain contracts or roadmap work |
| Instrumentation adapter | PARTIAL | Node fixture uses `diagnostics_channel` and `AsyncLocalStorage`; generic runtime instrumentation remains a protocol |
| Semantic model adapter | PARTIAL | Versioned `Transform`/`Transition` records and exact supported symbolic transitions exist; finite explicitly enumerated relational successors are now supported by WP/Z3, but no complete runtime semantics registry exists |
| Solver adapter | EXISTS within supported subset | `src/rsve/solver.py` translates the typed constraint subset to Z3; unsupported theories return UNKNOWN; proof capture remains optional |
| Reactive environment model | PARTIAL | `src/rsve/environment.py` models target/environment state together, exposes multiple predicted successors through `World.options()`, marks declared uncontrolled transitions UNKNOWN, distinguishes incomplete empty relations from complete empty relations, and reconciles observed reactions; `Workspace` expands those successors during planner search and reports model-scoped POSSIBLE versus GUARANTEED reachability, while concrete Linux facts remain extension-provided |
| Composable workspace graph | PARTIAL | `src/rsve/graph.py` provides profiles, extension instances, bindings, typed regions/ports/connections, nested graphs, capability resolution, correlation evidence, composite snapshots, budgets, and cycle-safe traversal; `Workspace` validates topology, traverses bounded verified connections, executes graph transforms before operations, carries initialized region state through routes, applies registered effects, requires explicit scalar request mappers, and exposes graph-only routes, while full cross-region dependency semantics remain incomplete |
| Layer/profile identity | EXISTS within graph scope | `Persona` and `Need` in `src/rsve/graph.py` support multiple implementations, versions, configurations, execution scopes, and shared-dependency comparisons |
| Realization optimization | EXISTS within bounded candidate scope | `src/rsve/optimize.py` replays caller-supplied alternatives from one clean snapshot and compares explicit costs; it does not synthesize new primitives or replace the planner |
| Black-box vulnerability-style detection | EXISTS in synthetic lab scope | `tests/blackbox.py`, `tests/variants.py`, and `tests/web.py` observe canary-only controlled sinks, compute actual-minus-intended acceptance, expand an HTTP interaction domain, and replay-validate objectives without relying on source-location disclosure |
| Black-box variant coverage | EXISTS in bounded fixture scope | `tests/variants.py` covers decoding, coercion, duplicate-field parsing, and stateful sequence boundaries; variants remain synthetic, local-only, finite, and independently specified |
| QEMU OS/ISA substrate | EXISTS within controlled guest scope | `src/rsve/extensions/qemu.py` boots the SHA256-pinned Ubuntu Server 26.04 amd64 image with QEMU TCG, captures serial boot evidence, and recreates qcow2 overlays for reset; guest command execution requires a separate guest-agent extension, while host hardware, scheduler, entropy, clock, external services, and exact whole-system replay remain unknown |
| Artifact store | EXISTS within local SQLite scope | `src/rsve/sqlite.py` adds content-addressed redacted artifacts, WAL-backed transactions, schema versioning, solver-result indexes, snapshot metadata, and model/profile-aware stale-query invalidation; JSONL remains the lightweight export/debug store |
| Deterministic bounded planning | EXISTS | `Engine.analyze()` performs canonical-order breadth-first search with depth, state, and event budgets; `src/rsve/search.py` expands an open interaction frontier under explicit candidate/time/trace budgets and reports budget exhaustion |
| Backward planning | PARTIAL | `src/rsve/wp.py` is exact for deterministic guarded assignments and finite explicit relational alternatives, `Planner` consumes supported WP/Z3 assignments, and `Index.chain()` follows bounded accepted/rejected read/write writer closure; concrete preimage checks and explicitly bound symbolic graph routes now execute through the supplied `Workspace`, including graph-only region effects, while opaque runtime transforms, unenumerated relational routes, and cross-region aliasing remain incomplete |
| Objective distance | EXISTS within planner heuristic scope | `Planner.distance()` scores unmet predicates, causal writers, uncertainty, and route cost for ordering only; it is not an admissible proof or reachability claim |
| Forward/concolic execution | PARTIAL | Forward model execution exists; no concrete target execution, symbolic values, or concolic feedback |
| Validated witness | PARTIAL | `Planner` requires adapter replay and objective observation before `VALIDATED_WITNESS`; the legacy `Engine` now returns `MODEL_SAT` with `Witness.validated=False` |
| Bounded proof result | PARTIAL | `UNSAT_BOUNDED`, `UNKNOWN`, models, and cores are explicit and tested; solver proof bytes are optional and there is no fidelity proof |
| Model/reality divergence | PARTIAL | `Analyzer` aligns semantic events, classifies first divergence, and emits immutable refinement deltas; broader correlation and model mutation remain limited |
| Authorization and lab scope | PARTIAL | `Authorization` is enforced at Node/EVM invoke, replay, and ordered execution boundaries; target isolation, policy store, and deployment audit identity remain unavailable |
| Phantom entry detection | EXISTS within registry | `src/rsve/registry.py` requires observed evidence and retains conditions; no runtime discovery implementation |
| Replay and snapshot/reset | PARTIAL | Node and EVM fixtures support clean reset, ordered replay, k-of-n semantic stability, and authorization; exact host/environment replay is explicitly unavailable |
| Standard trace interchange | PARTIAL | `Event` has IDs, causal links, representations, states, environment, ordering, and evidence; `Otel` maps these without an OTel dependency |
| Cross-runtime portability | EXISTS within two fixtures | `tests/node.py` and `tests/evm.py` run the same planner/objective/result workflow; JVM/native capability contracts are documented without claiming implementation |
| Security/redaction | PARTIAL | JSONL redacts a small key set by default; no structured secret classification, trace redaction policy, or sink isolation |

## Architectural risks

1. **Execution versus fidelity.** `Operation.fidelity` separates a modeled event from an observed one, `Planner` requires replay evidence for `VALIDATED_WITNESS`, and `Engine` reports model-only success as `MODEL_SAT`; neither model execution nor replay alone proves full runtime fidelity.

2. **Residual-set scope.** The helpers operate over caller-supplied finite domains. They must never be presented as global accepted sets. `Image(T) - D`, over-acceptance, and under-acceptance must remain separate report fields and carry domain/provenance evidence.

3. **Solver proof scope.** `UNSAT_BOUNDED` currently means bounded exhaustive exploration of the finite model/input set. A future solver result must preserve the exact query, assumptions, abstraction, solver/version/options, core/proof artifact, and the independent model-fidelity limitation. An UNSAT core is not a real-target proof.

4. **State and snapshot semantics.** `State` is immutable modeled data. An adapter snapshot may include processes, files, handles, clocks, random state, threads, or external services. Treating those as interchangeable would make replay unsound.

5. **Platform independence.** Node and EVM fixtures now demonstrate the same core workflow. JVM and native behavior remains behind explicit capability contracts; the core must not silently collapse unobserved semantics into safe or impossible.

6. **Determinism.** Linux environment identity and layered execution profile scope are now recorded, and QEMU provides a portable guest OS/ISA boundary. Clock/randomness, scheduler behavior, hardware memory ordering, adapter versions, and solver settings remain partly uncontrolled; TCG is an emulation boundary, not a deterministic replay oracle.

7. **Repository governance.** Local Git metadata and a lockfile exist, but CI is intentionally excluded from this repository snapshot. Build, test, and advisory checks must therefore be run explicitly by maintainers or an external pipeline.

8. **Unknown transition branches.** Unknown outcomes are retained as uncertain trace branches and force `UNKNOWN` when they can affect the bounded conclusion; missing graph effect semantics, dependent recognizers, opaque seams, and declared uncontrolled environment transitions are also marked UNKNOWN. None is treated as rejection, identity, or bounded UNSAT.

9. **Dependency drift.** The environment contains packages not declared by the project. Import success is not evidence that a dependency is available to a clean build.

10. **Optimization scope.** Realization optimization is intentionally finite and replay-gated. It cannot discover a better realization outside the supplied candidate set, and unknown resource metrics remain explicit rather than estimated as zero.

11. **Artifact durability.** SQLite provides local transactional durability and query invalidation, but external snapshot bytes remain adapter-owned and filesystem permissions/backup/retention policy are deployment responsibilities.

## Audit conclusion

The repository now supports a graph-centered Python core with canonical semantic interpretation, pre-operation graph transformation lowering, missing-semantics uncertainty preservation, bounded verified graph-connection routes including graph-only entries, explicit scalar request mappers, owner-aware region state and qualified predicate views, reactive environment state with explicit uncontrolled and incomplete outcomes, persistent bounded Z3 sessions with retained named cores, model-scoped possible/guaranteed reachability classification, explicitly bound symbolic regression through supported graph routes and graph-only region effects, finite explicit relational preimages, a Node/EVM extension slice, a QEMU-backed Ubuntu Linux substrate, exact symbolic weakest-precondition rules for supported deterministic and finite relational subsets, replay-gated bounded realization optimization, and a transactional SQLite evidence ledger with stale-query invalidation. Full cross-region dependency and alias semantics, opaque runtime transform regression, unenumerated relational graph regression, native symbolic, syscall-boundary, and whole-system selective analysis remain incomplete or extension contracts; none of these capabilities imply global reachability or exact environment replay.
