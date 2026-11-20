# Objective and Refinement Slice

`Objective` is the versioned, extensional objective boundary. It names the target and authorization scope, limits permitted sinks and environment facts, and carries trace/state/replay budgets. Predicates currently cover:

An objective may also carry graph-owned `profile_requirements` for hard scoped requirements such as runtime version, OS/kernel, ISA/ABI, framework, toolchain, image, or application build. The planner verifies them against the extension's observed `Profile` before backward or forward search begins. A mismatch or missing observation rejects the objective; it never becomes a successful or silently broadened analysis.

- state equality and the existing typed constraint subset;
- synthetic-canary flow to a named controlled sink;
- allowed state changes;
- ordered entry sequences;
- along-trace guard invariants;
- conjunction, disjunction, and negation of those predicates.

With `require_lineage=True`, `Flow` requires sink evidence linking the event
to the declared source entry; literal canary presence alone is not enough.
The workspace carries this evidence as `data_lineage` on event observations.
Graph transforms declare provenance modes (`preserve`, `duplicate`, `combine`,
`discard`, or `unknown`). Unknown transfer remains explicit uncertainty rather
than becoming identity or loss, so a lineage-requiring Flow objective cannot
pass through it.

Symbolic regression compiles state predicates through the existing constraint
AST. `Same`, `Test`, `Changes`, `All`, `Some`, and `Not` are supported when
their child constraints and value sorts are supported. `Flow`, `Order`, and
`Guard` remain trace predicates evaluated by bounded forward or replay
execution; they are not represented as final-state equalities.

`Planner` combines exact weakest-precondition regression for operations that expose a `Symbolic`, Z3 model extraction, bounded concrete preimage enumeration, and deterministic forward exploration over `(entry, state)` candidates. `Workspace.contracts()` distinguishes exact forward/backward semantic bindings from forward-only or probe-bounded bindings. The planner does not construct inverses for opaque or information-losing transforms. A model-only candidate is `SAT_CANDIDATE`; adapter replay from a clean snapshot must observe the objective and satisfy the stability policy before `VALIDATED_WITNESS` is returned. `Witness.model_aligned` separately records whether differential comparison found a model/reality mismatch.

`Analyzer` aligns semantic operation/entry events while tolerating known adapter-only events, but reports unexpected semantic events instead of skipping them. It reports the first justified divergence, then can create an immutable `Delta`, including explicit assumption demotions for unresolved model/environment gaps. A runtime guard rejection adds an explicit interaction exclusion to a new `Model` revision and records invalidated query IDs. Prior experiments remain unchanged.

`Optimizer` is optional and runs only after a validated witness exists. It compares a finite set of caller/model-supplied realizations, replays each from one clean snapshot, applies the fixed objective and stability policy, and records interaction, trace, timing, dependency, resource, instrumentation, and reproducibility costs. The original witness and equivalence evidence are retained.

The black-box lab regression in `tests/blackbox.py` probes a synthetic Node target with a canary-only local sink. It compares observed finite acceptance with an independent intended predicate, then requires a clean replay-validated witness for the sink postcondition. The test reports the residual direction and validation status without exposing implementation location details.

`tests/variants.py` broadens that regression across decoding/canonicalization, type coercion, duplicate-field parsing, and a stateful prepare/commit sequence. These are behavior-level variants with local canary data, not operational exploit payloads or claims of universal vulnerability coverage.

`tests/http.py` exercises the same workflow through a real loopback HTTP service. It first measures an independently specified admin-only acceptance policy, then expands a deterministic interaction domain across the discovered HTTP entries and validates the first two-request canary flow by clean replay. This is an open-ended search strategy with explicit candidate, trace, and time budgets; budget exhaustion is reported rather than treated as global UNSAT.

All negative results are bounded by the objective's surface, state, trace, time, replay, and environment scope. Unsupported semantics and incomplete replay remain explicit uncertainty.
