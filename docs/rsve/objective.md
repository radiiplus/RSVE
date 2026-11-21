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

Graph transform chains are composed in declared order. Validation checks that
each output representation feeds the next transform input and that the final
representation matches the transition output. Concrete execution and symbolic
route synthesis reject incompatible chains. Exact weakest-precondition
regression composes the bound symbolic relations and recognizers across the
intermediate representation stages.

Transitions may operate directly on a semantic representation such as text or
a typed object; they do not need an intermediate byte representation. Execution
records the input and each produced representation. Changing representation
requires an explicit transform with declared semantics, so RSVE does not infer
a universal binary-to-text or opcode pipeline. The built-in strict UTF-8
decoder has concrete forward semantics and an exact backward preimage for a
concrete text objective; malformed byte sequences raise a decode error, and
replacement/normalization policies require separate semantics. The decoder
defaults to a 1 MiB input/preimage limit, which callers can lower or raise.

`ObservedTransformModel` stores observed input/state/output tuples for opaque
transforms. It answers only for an exact recorded input and state; unseen
contexts remain `UNKNOWN`, conflicting outputs remain separate alternatives,
and repeated samples never imply a complete relation. Observed first-stage
inputs seed the existing bounded probe search. Resulting routes remain
uncertain until an exact semantic contract or controlled runtime replay
resolves them.

Symbolic regression compiles state predicates through the existing constraint
AST. `Same`, `Test`, `Changes`, `All`, `Some`, and `Not` are supported when
their child constraints and value sorts are supported. `Flow`, `Order`, and
`Guard` remain trace predicates evaluated by bounded forward or replay
execution; they are not represented as final-state equalities.

`Planner` combines exact weakest-precondition regression for operations that expose a `Symbolic`, Z3 model extraction, bounded concrete preimage enumeration, and deterministic forward exploration over `(entry, state)` candidates. `Workspace.contracts()` distinguishes exact forward/backward semantic bindings from forward-only or probe-bounded bindings. The planner does not construct inverses for opaque or information-losing transforms. A model-only candidate is `SAT_CANDIDATE`; adapter replay from a clean snapshot must observe the objective and satisfy the stability policy before `VALIDATED_WITNESS` is returned. `Witness.model_aligned` separately records whether differential comparison found a model/reality mismatch.

Operations may also expose `request_candidates(state, objective)`, a lazy candidate source for state-dependent and objective-directed exploration. The planner and `Guide` consult it at reached states, merge its requests with solver-derived, planned, probe, and model requests, deduplicate them, and bound consumption by the state budget. A provider exception or a domain that exceeds the bound is retained as uncertainty; a negative search with truncated semantic candidates or successor branches is reported as `UNKNOWN`, not exhaustive. This lets an adapter or semantic model derive new requests from the current capability state instead of relying only on a static input list. It does not infer request semantics from arbitrary source code or traces: a target integration must provide a candidate source and executable transition semantics. Every composed candidate is executed through the workspace model, and replay is still needed to validate a concrete witness.

After each modeled move, the planner feeds the move's declared writes into the capability index. Moves that write objective state, or write state read by a transition in the objective's causal writer closure, receive higher queue priority. This is a search heuristic: it advances likely consequences and newly enabled operations without treating declared read/write edges as proof that a guard passes. Runtime and branch evidence still controls the report status.

Novelty strategies use the shared `CandidatePriority` signal. Objective progress and newly addressed postconditions carry the strongest weights; objective-relevant readers exposed by changed state, distinct transitions, and explicitly reported uncertainty resolution add bounded bonuses. State/transition/path novelty contributes a smaller bonus, while measured candidate-assessment time is a small cost penalty. `Guide` derives progress and route potential from modeled frames and the causal index; an event contributes uncertainty resolution only when its observation explicitly names the resolved item. These weights order work, not confidence or reachability, and can be inspected through `Trial.priority()`.

When replay diverges, `Guide` records an `Analyzer` refinement and invalidates the affected guide-plan and route query identities. Observed-fidelity events are added to the model as exact request/pre-state facts, scoped by component and any captured environment/client context; the causal index and backward plan are rebuilt before expansion continues. The observed successor can feed later route exploration, but remains uncertain because one observed outcome does not establish the complete transition relation. Unprobed counterexamples are not generalized into request-wide exclusions.

Forward search also triggers bounded online backward replanning from the current composed frame. The resulting suffix actions and requests are merged into that frame's next expansion and prioritized alongside the original plan; alternative forward states remain in the queue. Replanning is capped at 64 frontier frames (or the smaller state budget), with bound exhaustion and failures reported as uncertainty. Thus later state changes can alter which suffix RSVE pursues while earlier branches remain available for reconsideration. Runtime observations that contradict the model still require replay analysis/refinement; they are not silently promoted to new semantics.

For Go targets, `SourceIndex` consumes bounded normalized source facts. `SourceProfile` explicitly binds each source symbol to a typed request/state field, each assignment target to a state key, and each selected guard to its accepted branch sense. `SourceSemanticLowerer` composes supported expressions into concrete operations even when their symbolic encoding is inexact. Such operations emit uncertain accept/reject branches, carry candidate writes marked unknown, and have no symbolic transition; exact expressions can also compose sequential writes symbolically. Unsupported syntax, calls without call-site argument/return facts, returns, control transfers, and ambiguous source lines remain limitations. `Guide(..., source_index=index, source_profile=profile)` adds executable operations to its workspace before regression and strategy search. Missing exact backward semantics or uncertain branches makes a negative search incomplete. Source facts and generated candidates are model evidence; controlled adapter replay is still required for target-runtime validation.

`RelaxationAnalyzer` uses an UNSAT core to try bounded, one-at-a-time removal of named top-level `Axiom` constraints or named query assumptions. A SAT result after removal is `COUNTERFACTUAL`; it only becomes `MODEL_CONFIRMED` when every solver-model variable is explicitly bound to a matching request field and an authorized trace reaches the objective through certain `Workspace.moves` outcomes. This confirms the route in the executable model, not the target runtime. Nested/unnamed constraints are retained, duplicate relaxation identifiers are rejected, and bounds are reported explicitly.

`Analyzer` aligns semantic operation/entry events while tolerating known adapter-only events, but reports unexpected semantic events instead of skipping them. It reports the first justified divergence, then can create an immutable `Delta`, including explicit assumption demotions for unresolved model/environment gaps. A runtime guard rejection adds an explicit interaction exclusion to a new `Model` revision and records invalidated query IDs. Prior experiments remain unchanged.

An operation's rejection is nonterminal by default, so denial effects and subsequent operations remain searchable. Set `stop=True` when rejection really ends that modeled route. Exceptions produce `ERROR` outcomes; `error_handler` can model partial state changes, while `error_effects`, `error_writes`, and `stop_on_error` describe the failure branch. Without a handler, the branch remains traversable but marks `error-aftermath` unmodeled, so later success is only a candidate until that state is resolved.

`World` may schedule delayed environment transitions with `Schedule`; `Workspace` carries their pending queue and logical step in each `Frame`, then applies due callbacks as later modeled operations advance time. Callback branching and event limits are retained in the successor frame and event evidence. These are logical model steps, not measurements of OS timers or real scheduler interleavings.

An `Operation` may declare `client_id`. Client-scoped operations receive that client's local fields plus shared target fields under `shared.*`. Their updates to unqualified keys stay in that client's state; `shared.*` updates modify common target state. Frames and event records retain the client identity, and objectives can inspect client-local state through `client.<id>.<field>`. This supports bounded sequential cross-client plans, not concurrent race execution or automatic discovery of real clients.

`Optimizer` is optional and runs only after a validated witness exists. It compares a finite set of caller/model-supplied realizations, replays each from one clean snapshot, applies the fixed objective and stability policy, and records interaction, trace, timing, dependency, resource, instrumentation, and reproducibility costs. The original witness and equivalence evidence are retained.

The black-box lab regression in `tests/blackbox.py` probes a synthetic Node target with a canary-only local sink. It compares observed finite acceptance with an independent intended predicate, then requires a clean replay-validated witness for the sink postcondition. The test reports the residual direction and validation status without exposing implementation location details.

`tests/variants.py` broadens that regression across decoding/canonicalization, type coercion, duplicate-field parsing, and a stateful prepare/commit sequence. These are behavior-level variants with local canary data, not operational exploit payloads or claims of universal vulnerability coverage.

`tests/http.py` exercises the same workflow through a real loopback HTTP service. It first measures an independently specified admin-only acceptance policy, then expands a deterministic interaction domain across the discovered HTTP entries and validates the first two-request canary flow by clean replay. This is an open-ended search strategy with explicit candidate, trace, and time budgets; budget exhaustion is reported rather than treated as global UNSAT.

All negative results are bounded by the objective's surface, state, trace, time, replay, and environment scope. Unsupported semantics and incomplete replay remain explicit uncertainty.
