# RSVE Decisions

## ADR-0001: Keep the current Python core and add only documented adapters

**Decision:** Keep `src/rsve` as the engine-owned, platform-neutral package. Add runtime-specific code under explicit adapter modules and keep the existing `Target`, `Probe`, `Solve`, `Env`, and `Vault` boundaries.

**Reason:** The repository has one coherent Python package and no evidence supporting a language/runtime migration. Renaming or restructuring would add risk without improving the next milestone.

**Rejected:** Making Node/V8, LLVM, Rosette, or a binary-analysis framework the core IR. Those are adapter/substrate concerns.

## ADR-0002: Keep runtime dependencies minimal and pin the first solver

**Decision:** Use Python `ast` and `sqlite3` where their standard-library capabilities fit. Use Node's built-in `node:inspector` and `node:diagnostics_channel` for the first Node adapter. Add only `z3-solver==4.12.6.0` for Batch 3 and record the same pin in `lock`.

**Reason:** Batch 2 needs no external package. Batch 3 requires a real backend for model extraction, incremental solving, timeout/unknown handling, and unsat cores. The exact Z3 package is already available and verified in the environment; the pin prevents an undeclared ambient import from becoming the implementation contract.

**Constraint:** A clean environment must provide the declared Python version and, for Node tests, an explicitly checked Node runtime. Z3 proof artifacts remain optional and are never inferred from an unsat core.

**Rejected/deferred:** cvc5, Tree-sitter, OpenTelemetry SDKs, Frida, angr, and an orchestration framework remain deferred because they are not needed by the current core and adapter milestones.

## ADR-0003: Preserve separate execution-mode and evidence-fidelity axes

**Decision:** Keep modeled, observed, assumed, and substrate evidence distinct from concrete, instrumented, concolic, symbolic, and abstract execution modes. Add a fidelity ledger before calling a witness validated against a target.

**Reason:** A concrete modeled execution is not runtime observation; a symbolic result is not evidence that the real target has the modeled semantics.

## ADR-0004: Treat bounded results as scope-relative

**Decision:** Continue emitting `SAT`, `UNSAT_BOUNDED`, and `UNKNOWN`/budget results with explicit depth, state, event, environment, and model scope. Never rename bounded absence to global unreachability.

**Reason:** The current engine is finite and bounded. A solver adapter must preserve the same limitation plus its query and proof metadata.

## ADR-0005: Keep RSVE's canonical trace schema and map standards at the boundary

**Decision:** RSVE owns the canonical event/state/checkpoint schema. Add optional OpenTelemetry/OTLP import/export only as an adapter, preserving RSVE fields that OTel does not express.

**Reason:** OTel provides useful span/event conventions and interoperability, but it is an observability interchange model, not a complete program-state or solver-evidence schema.

## ADR-0006: Make authorization a hard precondition

**Decision:** Authorization failure remains a rejection, not a search penalty or residual gap. Concrete adapters must receive authorization context and independently enforce target/scope/isolation policy.

**Reason:** Authorized lab use is a safety invariant. The current `Authorization` object is necessary but not sufficient for isolation.

## ADR-0007: Use Z3 behind a solver-neutral query boundary

**Decision:** Keep `Solve` abstract and implement `Zed` in `src/rsve/solver.py`. Translate only the supported constraint subset. Preserve SMT-like query text, backend/version/options, model, named unsat core, unknown reason, and optional proof bytes. Keep cvc5 as a conformance alternative, not a second dependency.

**Reason:** Batch 2 now provides a typed constraint AST and result scope. Z3 satisfies the first real backend gate with a thin adapter; unsupported theories return UNKNOWN. A core is stored separately and is never relabeled as a proof.

## ADR-0008: Keep objectives extensional and replay-gated

**Decision:** Represent the first objective language with `Objective` and small predicates for state equality, canary flow, allowed state changes, entry sequences, and guard invariants. Require target/scope authorization, controlled sinks, environment boundaries, and explicit budgets. A model candidate is `SAT_CANDIDATE` until the adapter observes the postcondition after clean replay; only then is it `VALIDATED_WITNESS`.

**Reason:** The planner needs observable postconditions without encoding a prescribed command or exploit sequence. Keeping predicates extensional makes the language small, serializable, and runtime-independent.

**Rejected:** A general-purpose objective programming language and treating modeled execution as real-target validation.

## ADR-0009: Refine through immutable counterexample deltas

**Decision:** `Analyzer` aligns semantic events while preserving adapter-only events as correlation context. Runtime rejection can add an explicit interaction exclusion to a new model revision; every delta records its parent, evidence, and invalidated query IDs.

**Reason:** Counterexamples must change the model/query scope without mutating prior experiment records or turning instrumentation gaps into safety claims.

**Rejected:** In-place model mutation, silently retrying failed candidates, and treating an UNSAT core or an observed event as a global proof.

## ADR-0010: Make symbolic weakest preconditions explicit and bounded by semantics

**Decision:** Add `Symbolic` and `WP` for deterministic guarded assignments over booleans, bounded integers/bit-vectors, equality, ranges, finite enums, boolean connectives, state relations, named assumptions, and `+`, `-`, `*` expressions. Compose transitions backwards by substitution. Nondeterministic, relational, opaque, or unsupported nodes return `UNKNOWN`.

**Reason:** This provides a genuinely exact weakest-precondition result relative to an explicit semantic relation without pretending that Python callables or arbitrary runtime behavior are symbolically understood.

**Rejected:** Inferring inverses from observed traces or treating unknown runtime operations as identity.

## ADR-0011: Use Foundry as the controlled EVM adapter substrate

**Decision:** Install and pin Foundry v1.9.0 outside the Python dependency graph. Use Anvil for local chain state and snapshots, Forge for fixture compilation, and Cast for ABI encoding. Keep the EVM integration behind `Evm` and preserve canonical RSVE events/results.

**Reason:** The environment lacked a local EVM runtime, while the official toolchain supplies the distinct execution, state, receipt, revert, log, and replay capabilities required by BATCH 8. The fixture is local and synthetic.

**Rejected:** Adding a Python Web3 stack, treating Forge fuzzing as RSVE planning, or installing Slither as a general runtime observer.

## ADR-0012: Use QEMU as the Linux substrate boundary

**Decision:** Use the installed QEMU 8.2.2 and implement `Qemu` as an optional adapter. Boot the official Ubuntu Server 26.04 amd64 cloud image with TCG, a q35 machine, and a temporary qcow2 overlay while capturing serial evidence. Keep cloud-init, SSH, guest agents, S2E, and native symbolic backends outside this minimal substrate.

**Reason:** Higher runtime stacks depend on an explicit Linux kernel, syscall, ABI, filesystem, virtual-memory, network, and scheduler boundary. QEMU supplies a portable guest boundary using an existing emulator without making those observations look like exact host replay or a target-level proof.

**Scope:** The pinned cloud image is verified before boot. Snapshot/reset is overlay recreation from the verified base image. Guest entropy, wall clock, scheduler interleavings, external services, and host hardware ordering remain explicit unknowns.

**Rejected/deferred:** KVM as the portable default, S2E as a full selective-symbolic substrate, and native backends without a measured requirement. TCG is slower but available without host virtualization assumptions.

## ADR-0013: Use an explicit Linux environment profile by default

**Decision:** Host-local Unix fixtures use `LinuxEnv` as the default environment boundary. It records observed Linux/kernel/ABI facts and labels scheduler, entropy, hardware memory ordering, network, external services, and exact snapshot scope as unknown or limited. QEMU can provide a guest profile later through the same boundary.

**Reason:** Node and EVM fixtures already execute on Linux and higher runtime behavior can depend on syscalls, ABI, virtual memory, filesystem, clocks, scheduling, and resource limits. Omitting that context would make the evidence scope ambiguous.

**Rejected:** Making Linux assumptions global in core schemas/planning, or treating host-local execution as exact OS replay.

## ADR-0014: Pin the guest artifact separately from Python dependencies

**Decision:** Keep the Ubuntu cloud image outside the Python package and pin its SHA256 in `src/rsve/extensions/node.py` and the dependency record. Do not add a large guest image to the source distribution.

**Reason:** The guest is a reproducible fixture artifact, not a Python library. Separating it keeps package installs small while allowing the adapter to reject an altered image before execution.

## ADR-0015: Scope solver evidence with a layered execution profile

**Decision:** Use graph-owned `Profile` and `Need` records for independently scoped target, runtime, platform, OS, ISA, adapter, tool, image, configuration, and execution-context identities. Multiple profiles may coexist. `Check` reports `MATCH`, `DRIFT`, or `UNKNOWN`; missing or unobserved fields never match by assumption. Runtime implementations are optional extensions and contribute profiles through workspace bindings.

**Reason:** A target build hash alone does not identify the runtime stack that produced an observation. The solver and planner need a stable scope identifier so a bounded result is not reused across Node, kernel, ABI, emulator, toolchain, or image drift.

**Rejected:** One global version string, treating package manifests as proof of loaded code, or making every external dependency a mandatory core schema field. Layer-specific pins remain optional and evidence-backed.

## ADR-0016: Optimize only replay-validated equivalent realizations

**Decision:** `Optimizer` accepts a validated original witness and a finite caller/model-supplied candidate set. It replays every candidate from one clean snapshot, applies the unchanged objective/checkpoints/stability policy, computes explicit costs, and retains the original witness plus equivalence evidence.

**Rejected:** Optimizing before correctness, inventing runtime primitives, dropping guards or authorization, treating missing resource metrics as zero, or replacing the bounded planner with a general optimizer.

## ADR-0017: Use SQLite for the local transactional evidence ledger

**Decision:** Add `Sqlite` using Python `sqlite3`, WAL mode, content-addressed redacted payloads, schema version `1`, solver-result indexes, snapshot metadata, and explicit query invalidation records. Keep `Jsonl` for small append-only export/debug use.

Solver results are valid only within their recorded model revision and execution profile. A refinement delta can invalidate dependent query IDs in the same transaction as its artifact record; callers may retrieve stale records only by explicitly requesting them.

**Rejected:** An ORM, server database, bespoke graph store, or treating external snapshot bytes as if SQLite owned their lifecycle.

## ADR-0018: Lower supported graph semantics through the workspace boundary

**Decision:** Keep `Graph` responsible for topology and use `Workspace` as the executable composition boundary. Supported graph transforms and recognizers are evaluated by `Interpreter.outcomes()` and lowered into canonical `Outcome` branches; operation and environment branches remain explicit. Unsupported graph semantics become `UNKNOWN` rather than identity.

**Reason:** This connects topology to planner execution without creating a second transition vocabulary or making graph metadata look like runtime evidence. The lowering is intentionally scoped until graph effects have executable state semantics.

## ADR-0019: Separate bounded possible and guaranteed reachability

**Decision:** `Report.reachability` records `POSSIBLE`, `GUARANTEED`, or `UNKNOWN` over the exact bounded interaction sequence and workspace model. `GUARANTEED` requires every enumerated modeled successor to satisfy the objective; it does not claim concrete-target or global guarantee.

**Reason:** A successful branch of a nondeterministic operation establishes possibility only. Keeping this classification separate from `Status` preserves replay and fidelity semantics.

## ADR-0020: Reuse persistent solver sessions for symbolic regression

**Decision:** `Regressor` runs symbolic action and sequence queries through one `Stack` session, using push/pop per query, stable named assertions, and retained UNSAT cores on `Plan` and `Report`.

**Reason:** This makes incremental solving operational in the planner and gives conflict-directed search evidence without treating a core as blame or proof. Unsupported theories remain `UNKNOWN`.

## ADR-0021: Execute graph semantics before operation semantics

**Decision:** `Workspace` evaluates matching graph transforms and recognizers first, maps accepted transformed values into operation requests, applies registered graph effects, and preserves rejection, unknown, and empty-relation outcomes without falling back to the original operation.

**Reason:** A graph connection is part of execution only when its representation change affects the operation input. Graph metadata must not become a post-hoc annotation or an identity fallback.

## ADR-0022: Mark declared uncontrolled environment outcomes as unknown

**Decision:** `World.options()` marks every branch of a transition declared nondeterministic as `UNKNOWN`. Explicit alternative branches without that declaration remain modelled alternatives and support bounded POSSIBLE/GUARANTEED classification.

**Reason:** An uncontrolled environment transition cannot support a guarantee merely because one predicted successor reaches the objective.

## ADR-0023: Use workspace semantics for concrete backward preimages

**Decision:** `Regressor` accepts an optional `Workspace`; concrete preimage checks execute through that workspace, including graph lowering and environment reactions. Symbolic WP remains limited to explicit symbolic relations and does not infer inverses for runtime callables.

**Reason:** Forward and concrete backward checks must evaluate the same composed semantics. Full graph-level symbolic regression remains an explicit limitation until those relations have symbolic contracts.

## ADR-0024: Missing graph effects preserve uncertainty

**Decision:** A declared graph effect without a registered evaluator produces an `UNKNOWN` semantic branch. Recognizers preserve that uncertainty and cannot turn it into `REJECT`; effect metadata is not treated as an identity operation.

**Reason:** Skipping an effect can make later state and objective conclusions unsound. Effect execution is only modeled when its evaluator is explicitly registered.

## ADR-0025: Use owner-aware region state

**Decision:** `Frame.regions` is an optional map of independently owned states. An operation with a matching component executes against its owner state and updates that region; global state remains a separate projection. Predicate views expose qualified keys such as `region.key`.

**Reason:** A region map is useful only if it affects execution, not merely visited-state identity. Full aliasing, cross-region read/write declarations, and resource ownership remain future semantic extensions.

## ADR-0026: Traverse bounded verified graph routes

**Decision:** `Workspace` follows compatible graph connections lazily, applies connection transforms, evaluates destination transitions, and exposes graph-only declared entries as synthetic operations. Traversal is cycle-safe and bounded by graph depth. Entry allowlists can restrict which graph entries are planner-visible.

**Reason:** Typed topology must influence reachability. Structural graph connectivity is not treated as execution evidence, and unsupported or uncorrelated seams remain explicit uncertainty.

## ADR-0027: Require explicit scalar request mapping

**Decision:** A scalar graph output requires a registered workspace mapper before it can become an operation request. Mapping outputs that are already mappings remain directly representable; there is no multi-field heuristic fallback.

**Reason:** Representation conversion does not determine operation request shape by itself. Explicit mapping preserves semantics and provenance across a seam.

## ADR-0028: Declare environment relation completeness

**Decision:** An empty environment relation is `UNKNOWN` unless its transition ID is declared complete. A complete empty relation is an exhaustive no-successor result. Declared uncontrolled transitions remain UNKNOWN even when alternatives are enumerated.

**Reason:** Empty enumeration and proven absence are different evidence states.

## Unresolved items

- Exact target/runtime identity and build-hash source are not defined.
- Snapshot scope for process, filesystem, clock, randomness, scheduler, network namespace, and external services is unresolved.
- The canonical trace needs correlation IDs and time semantics before asynchronous Node evidence is trusted.
- The intended contract source and policy language for recognizers are unresolved.
- A solver proof format and independent checker strategy are unresolved.
- CI host matrix and supported Node/JVM/EVM versions are unresolved because no CI exists.

## ADR-0029: Bind symbolic graph semantics explicitly

**Decision:** `Workspace.symbolics` provides explicit `Symbolic` contracts for graph transforms, recognizers, effects, and connection bridges. `Regressor` enumerates bounded graph routes, scopes their representation variables by route stage, composes them with the endpoint operation relation, and solves the resulting preimage with the existing WP/Z3 session. Forward execution continues to use the registered concrete evaluators.

**Reason:** A callable transform cannot be inverted soundly by inspection. Explicit symbolic bindings let backward regression and forward execution share a route while preserving `UNKNOWN` for opaque or relational semantics. The original source request is retained separately from the transformed operation request for replay.

**Rejected:** Treating runtime callables as identity or automatically deriving inverses, making graph metadata solver semantics, or reporting a model-solved transformed request as the original interaction.

## ADR-0030: Carry owned region state through graph routes

**Decision:** Graph route evaluation carries both the global target state and initialized owner-region states. A transition reads and writes its owner when that region is present in the frame; otherwise it uses the legacy global projection. Destination-region effects survive into the endpoint operation and objective view. Graph-only routes may be regressed when their transforms, recognizers, and effects have explicit symbolic bindings.

**Reason:** A region map that only affects visited-state keys is not executable composition. The compatibility fallback keeps existing graphs valid while making independently initialized regions semantically meaningful.

**Rejected:** Copying the entire target state into every region, treating region IDs as proof of ownership without frame state, or merging region effects into global state without an explicit projection.
