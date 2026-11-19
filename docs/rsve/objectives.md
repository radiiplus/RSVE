# Objective and Refinement Slice

`ObjectiveDefinition` is the versioned, extensional objective boundary. It names the target and authorization scope, limits permitted sinks and environment facts, and carries trace/state/replay budgets. Predicates currently cover:

An objective may also carry graph-owned `profile_requirements` for hard scoped requirements such as runtime version, OS/kernel, ISA/ABI, framework, toolchain, image, or application build. The planner verifies them against the extension's observed `ProfileInstance` before backward or forward search begins. A mismatch or missing observation rejects the objective; it never becomes a successful or silently broadened analysis.

- state equality and the existing typed constraint subset;
- synthetic-canary flow to a named controlled sink;
- allowed state changes;
- ordered entry sequences;
- along-trace guard invariants;
- conjunction, disjunction, and negation of those predicates.

`HybridPlanner` combines exact weakest-precondition regression for operations that expose a `SymbolicTransition`, Z3 model extraction, bounded concrete preimage enumeration, and deterministic forward exploration over `(entry, state)` candidates. It does not construct inverses for opaque or information-losing transforms. A model-only candidate is `SAT_CANDIDATE`; adapter replay from a clean snapshot must observe the objective and satisfy the stability policy before `VALIDATED_WITNESS` is returned. `Witness.model_aligned` separately records whether differential comparison found a model/reality mismatch.

`DifferentialAnalyzer` aligns semantic operation/entry events while tolerating known adapter-only events, but reports unexpected semantic events instead of skipping them. It reports the first justified divergence, then can create an immutable `ModelDelta`, including explicit assumption demotions for unresolved model/environment gaps. A runtime guard rejection adds an explicit interaction exclusion to a new `TransitionModel` revision and records invalidated query IDs. Prior experiments remain unchanged.

`RealizationOptimizer` is optional and runs only after a validated witness exists. It compares a finite set of caller/model-supplied realizations, replays each from one clean snapshot, applies the fixed objective and stability policy, and records interaction, trace, timing, dependency, resource, instrumentation, and reproducibility costs. The original witness and equivalence evidence are retained.

The black-box lab regression in `tests/test_blackbox_detection.py` probes a synthetic Node target with a canary-only local sink. It compares observed finite acceptance with an independent intended predicate, then requires a clean replay-validated witness for the sink postcondition. The test reports the residual direction and validation status without exposing implementation location details.

`tests/test_blackbox_variants.py` broadens that regression across decoding/canonicalization, type coercion, duplicate-field parsing, and a stateful prepare/commit sequence. These are behavior-level variants with local canary data, not operational exploit payloads or claims of universal vulnerability coverage.

`tests/test_http_open_domain.py` exercises the same workflow through a real loopback HTTP service. It first measures an independently specified admin-only acceptance policy, then expands a deterministic interaction domain across the discovered HTTP entries and validates the first two-request canary flow by clean replay. This is an open-ended search strategy with explicit candidate, trace, and time budgets; budget exhaustion is reported rather than treated as global UNSAT.

All negative results are bounded by the objective's surface, state, trace, time, replay, and environment scope. Unsupported semantics and incomplete replay remain explicit uncertainty.
