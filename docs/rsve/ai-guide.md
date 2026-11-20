# RSVE Guide for AI Investigators

This guide explains how an AI model should use RSVE to investigate an
authorized target, synthesize candidate realizations, verify them, and report
uncertainty honestly. It describes the executable behavior currently present
in the repository. It is not a claim that RSVE can analyze arbitrary software
or prove global reachability.

## 1. Operating model

Treat RSVE as a bounded causal-analysis engine with five cooperating parts:

1. A model describes states, entry points, operations, guards, effects, and
   possible transition outcomes.
2. A workspace composes that model with graph regions, transformations,
   recognizers, environments, probes, and symbolic relations.
3. An objective describes an observable postcondition without prescribing an
   implementation route.
4. The regressor works backward through supported symbolic relations and
   bounded concrete probes to propose inputs and traces.
5. The planner executes candidates forward, then replays them against an
   authorized target when an adapter is available.

The central rule for an AI investigator is:

> Use backward reasoning to prioritize candidates, forward execution to test
> them, and evidence from replay to decide what actually happened.

Do not treat a model-satisfiable candidate as a real-world witness. Do not
treat an incomplete bounded search as proof that the target cannot satisfy an
objective.

## 2. Capability truth table

Before asking RSVE to do work, classify the available evidence.

| Capability | Current status | Meaning |
| --- | --- | --- |
| Flat modeled operations | Implemented | Deterministic and relational bounded outcomes can be explored. |
| Z3-backed state synthesis | Implemented for supported constraints | Exact only for the represented symbolic subset. |
| Weakest-precondition regression | Implemented for supported functional relations and explicit finite alternatives | Unknown relations do not become identity transforms. |
| Graph execution | Implemented within bounded supported routes | Only declared and executable graph semantics participate. |
| Reactive environment | Implemented within supplied `World` semantics | Multiple outcomes are possible; uncontrolled outcomes are unknown. |
| Flow validation | Implemented with explicit lineage and sink-consumption contracts | Literal canary presence alone is insufficient when lineage is required. |
| Symbolic Flow regression | Bounded and partial | Requires complete symbolic contracts and explicit provenance paths. |
| Runtime replay | Adapter-dependent | A replay-confirmed result requires a real controlled adapter. |
| Arbitrary runtime discovery | Not implemented by core | Use an extension that supplies the needed observations. |
| Global completeness | Not implemented | All negative results are scoped to explicit bounds and model fidelity. |

When a required capability is missing, report `UNKNOWN` or
`UNSUPPORTED_CAPABILITY`. Never silently replace it with an identity
operation, an empty environment, or a presumed causal connection.

## 3. The AI investigation loop

Use this loop for every investigation.

### Step 1: Establish authorization

Authorization is a hard precondition. Create it before constructing an
objective or invoking a target adapter.

```python
from rsve import Authorization

authorization = Authorization(
    subject="analysis-agent",
    scopes=frozenset({"fixture-lab"}),
    target_ids=frozenset({"fixture"}),
)
```

Use only local fixtures, explicitly authorized targets, controlled sinks,
and isolated environments. A sink name in a `Flow` objective must also be in
the planner's controlled `harness_sinks` set.

### Step 2: Inspect before modeling

Collect the target identity, build or version digest, execution scope,
available entry points, state schema, environment facts, adapter manifest,
and observation limits.

The AI should produce a short inventory before searching:

```text
target: fixture
scope: fixture-lab
entries: increment, reset
state: count:int, quota:int
environment: local-only, resettable
symbolic relations: increment-v1
replay: available, 2 runs
known gaps: scheduler and external services unobserved
```

Do not infer an entry point from a name alone. Confirm it through a declared
model, observed surface, or adapter evidence. Preserve the source and scope
of every observation.

### Step 3: Build the smallest faithful model

Start with the state and transitions that can affect the objective. Add a
transition outcome for every behavior that matters, including rejection,
undefined behavior, errors, partial effects, and unknown semantics.

```python
from rsve import Entry, Model, Operation, Outcome, State, Decision

def update(state, request):
    return state.update(count=state.get("count", 0) + request["amount"])

operation = Operation(
    name="increment",
    entry_point=Entry("increment"),
    guard=lambda state, request: isinstance(request.get("amount"), int),
    apply=update,
    writes=frozenset({"count"}),
)

model = Model(
    target_id="fixture",
    initial_state=State({"count": 0}),
    inputs=({"amount": 1}, {"amount": 2}),
    operations=(operation,),
)
```

For behavior that is not a simple guard/apply pair, use `relation` and
return one or more `Outcome` objects. A rejected outcome is still a real
transition if the model says it changes state, emits an event, changes the
environment, or enables later work.

```python
def relation(state, request):
    if request.get("mode") == "prepare":
        return (Outcome(
            Decision.REJECT,
            state.update(armed=True),
            guard=False,
            terminal=False,
        ),)
    return (Outcome(Decision.UNKNOWN, state, uncertainty=("mode semantics unavailable",)),)
```

Do not use `None` to represent rejection. Do not return `ACCEPT` with
`guard=False`. Keep `UNKNOWN` branches in the search because they can affect
reachability conclusions.

### Step 4: Express the objective as an observable result

The objective should state what must be observed, not the command sequence
the AI expects to work.

```python
from rsve import Limits, Objective, Same

objective = Objective(
    objective_id="count-reaches-two",
    target_id="fixture",
    authorization_scope="fixture-lab",
    postconditions=(Same("count", 2),),
    state_keys=frozenset({"count"}),
    budget=Limits(
        max_trace_length=2,
        max_states=500,
        max_events=2_000,
        solver_timeout_ms=1_000,
        replay_runs=2,
    ),
)
```

Useful predicates include:

- `Same(key, value)` for direct state equality.
- `Test(constraint)` for supported typed constraints.
- `Changes(keys)` to constrain allowed state changes.
- `Flow(source, canary, sink, require_lineage=True)` for a controlled
  source-to-sink objective.
- `Guard(expected=...)` for trace guard invariants.
- `Order(entries)` for an observed ordering requirement.
- `All`, `Some`, and `Not` for Boolean composition.

`Flow`, `Order`, and `Guard` are trace predicates. They are evaluated from
events and are not reduced to final-state equalities. A `Flow` with
`require_lineage=True` requires explicit origin transfer and sink consumption;
the same string merely appearing at the sink is not sufficient.

For source-to-sink tests, use a controlled sink:

```python
objective = Objective(
    objective_id="canary-reaches-sink",
    target_id="fixture",
    authorization_scope="fixture-lab",
    postconditions=(
        Flow("source", "RSVE-CANARY", "controlled.sink", require_lineage=True),
    ),
    permitted_sinks=frozenset({"controlled.sink"}),
    budget=Limits(max_trace_length=2, replay_runs=2),
)
```

### Step 5: Validate the objective before planning

```python
objective.validate(
    authorization,
    harness_sinks={"controlled.sink"},
)
```

If this raises `Invalid`, stop. Do not broaden the authorization scope or
remove the sink restriction to make a search proceed.

### Step 6: Compose a workspace when the target has multiple regions

Use `Workspace.flat(model)` for a single modeled region. Use a `Graph` and
`Workspace.flat(..., graph=...)` when data, state, control, or environment
crosses region boundaries.

```python
from rsve import State, Workspace

workspace = Workspace.flat(
    model,
    regions={
        "parser": State({"parsed": False}),
        "worker": State({"done": False}),
    },
    transforms={
        "decode": lambda value, state: {"amount": int(value["amount"])},
    },
    effects={
        "finish": lambda state, value: state.update(done=True),
    },
)
```

Region state must be initialized explicitly when a transition owns a region.
Missing owned state yields `UNKNOWN`; it never falls back to the global target
state.

Use typed graph connections deliberately:

- `DATA` carries a representation value.
- `CONTROL` describes control dependence.
- `STATE` describes state dependence.
- `CAUSAL` describes a causal relationship.
- `OWNERSHIP`, `RESOURCE`, `ALIAS`, and `LIFETIME` are not data routes.

Only verified or explicitly transformed `DATA` connections should be used as
value routes. A connection with `Quality.UNCORRELATED` can remain in the
topology, but it cannot establish lineage-dependent causality.

### Step 7: Inspect semantic contracts before relying on synthesis

```python
for contract in workspace.contracts():
    print(
        contract.semantic_id,
        contract.forward,
        contract.backward,
        contract.complete,
        contract.limitations,
    )
```

For symbolic synthesis, a transform, recognizer, effect, or endpoint needs a
complete compatible contract. A concrete evaluator alone supports forward
execution but not exact symbolic regression. A probe or expander supports
bounded exploration but is not a complete semantic contract.

When a contract is incomplete, the AI should say:

```text
The candidate was not synthesized from an exact relation. The affected route
is UNKNOWN or bounded by concrete probes: <limitation>.
```

### Step 8: Run backward regression first

```python
from rsve import Regressor

plan = Regressor().regress(model, objective, workspace=workspace)

print(plan.method)
print(plan.required_actions)
print(plan.required_traces)
print(plan.uncertainty)
print(plan.cores)
```

Interpret the plan as search guidance, not proof:

- `required_actions` are inputs or entry actions worth trying.
- `required_traces` are bounded solver-generated interaction sequences.
- `uncertainty` lists unsupported semantics, probe limits, route limits, and
  unresolved branches.
- `cores` are conflicting constraint subsets, not proof of blame.

The regressor uses, in order of strength:

1. Exact symbolic transition relations and weakest-precondition regression.
2. Explicit finite relational alternatives.
3. Graph-route symbolic transforms and effects with complete contracts.
4. Bounded concrete probes and expanders.
5. Unknown when the available information cannot establish a preimage.

Never describe a probe-derived candidate as an exact inverse. Never describe
an unsupported transform as identity.

### Step 9: Run forward planning

```python
from rsve import Planner

report = Planner(harness_sinks={"controlled.sink"}).plan(
    model,
    objective,
    authorization,
    workspace=workspace,
)
```

With an adapter, pass it explicitly:

```python
report = Planner(harness_sinks={"controlled.sink"}).plan(
    model,
    objective,
    authorization,
    adapter=target_adapter,
    workspace=workspace,
)
```

The planner combines backward hints with bounded forward exploration. It
tracks target state, region state, environment state, uncertainty, event
history, graph outcomes, and budget consumption. It does not assume that the
apparent validation stack is the only route.

## 4. Read results correctly

Always inspect all of these fields:

```python
print(report.status)
print(report.reachability)
print(report.witness)
print(report.gaps)
print(report.unresolved_uncertainty)
print(report.divergences)
print(report.solver_cores)
```

| Status | Correct AI interpretation |
| --- | --- |
| `VALIDATED_WITNESS` | A controlled adapter replay observed the objective and met the stability policy. |
| `SAT_CANDIDATE` | The bounded model produced a candidate, but no replay confirmation exists. |
| `MODEL_SAT` | A model-only path satisfies the encoded objective; it is not target evidence. |
| `MODEL_DIVERGENCE` | Execution produced relevant evidence that differs from the model. Preserve both facts. |
| `UNSAT_BOUNDED` | No route was found in the encoded finite model and stated bounds. Not global impossibility. |
| `BUDGET_EXHAUSTED` | Search stopped because a declared resource bound was reached. Not unreachable. |
| `UNKNOWN` | Missing, opaque, uncorrelated, nondeterministic, or otherwise unresolved semantics may affect the result. |

`Reach.POSSIBLE` means at least one modeled branch reaches the objective.
`Reach.GUARANTEED` requires all modeled branches in the analyzed bounded
scope to satisfy it. An uncontrolled or unknown branch prevents a guaranteed
claim. `Reach.UNKNOWN` means the workspace cannot establish either claim.

A correct AI report includes the scope:

```text
Result: SAT_CANDIDATE
Reachability: POSSIBLE
Scope: bounded workspace model, max_trace_length=2, max_states=500
Replay: not performed
Unknowns: graph seam correlation unavailable
```

## 5. Provenance-aware Flow use

Value lineage must be explicit at every boundary.

### Operation-level transfer

`Operation.provenance_paths` maps output paths to input paths. The sink's
`provenance_inputs` declares which output paths it actually consumes.

```python
sink = Operation(
    "store",
    Entry("store"),
    component="controlled.sink",
    provenance_paths={"payload": ("proof",)},
    provenance_inputs=("payload",),
)
```

This says that `payload` derives from `proof` and that the sink consumes
`payload`. Omitting `provenance_inputs` means a lineage-aware Flow objective
cannot claim that the sink used the value.

### Graph-level transfer

Graph transforms use `provenance` plus `provenance_paths`:

```python
Transform(
    "encode",
    "raw",
    "wire",
    "fixture.encode",
    "1",
    Partiality.TOTAL,
    Relation.FUNCTION,
    Invertibility.UNKNOWN,
    Loss.NONE,
    provenance="preserve",
    provenance_paths={"payload": ("proof",)},
)
```

The modes mean:

- `preserve`: the specified source paths remain available.
- `duplicate`: multiple outputs may use the specified source origins.
- `combine`: the output depends on all declared source paths.
- `discard`: the declared source origins are removed.
- `unknown`: no lineage claim is allowed.

An explicit path mapping does not override `provenance="unknown"`. A graph
connection with uncorrelated evidence also cannot establish a lineage-aware
Flow. Use `Quality.DIRECT` or `Quality.DETERMINISTIC_DERIVED` only when the
correlation contract supports that claim.

### What Flow proves

With `require_lineage=True`, a passing Flow requires:

1. The source event contains the canary at a tracked source path.
2. The source origin survives the declared transformations.
3. The sink is reached.
4. The sink consumes a path carrying that origin.
5. The relevant event correlation is not marked uncertain.

It does not prove that every possible branch carries the value, that an
unobserved runtime consumed it, or that a literal value was not independently
recreated.

## 6. Reactive environments

Use `World` when target behavior depends on environment state, resource
availability, clocks, quotas, filesystem state, or other modeled reactions.

```python
from rsve import Context, State, World

def react(context, request):
    quota = context.environment.get("quota", 0)
    if quota <= 0:
        return (context.target, context.environment, {"accepted": False})
    return (
        context.target.update(done=True),
        context.environment.update(quota=quota - 1),
        {"accepted": True},
    )

world = World(
    Context(State({"done": False}), State({"quota": 1})),
    {"submit": react},
)
workspace = Workspace.flat(model, world=world)
```

For multiple possible reactions, return an iterable of successor triples.
Mark the transition nondeterministic unless every permitted outcome is fully
controlled and understood. An empty result is only exhaustive when the
transition ID is in `World.complete`; otherwise it becomes `UNKNOWN`.

The AI must distinguish:

- `POSSIBLE`: one modeled environment branch reaches the objective.
- `GUARANTEED`: every modeled branch reaches the objective.
- `UNKNOWN`: at least one relevant reaction is uncontrolled or incomplete.

## 7. Runtime adapters and replay

Use core APIs for semantics and extension APIs for observation/execution.
The current optional extensions include Node, EVM, Linux, and QEMU support.
Do not import or assume an adapter until its manifest and capability report
show that it covers the required path.

The adapter workflow is:

```text
prepare -> snapshot -> invoke/trace -> collect events -> reset -> replay
```

For every replay candidate:

1. Start from a clean snapshot.
2. Execute only interactions inside the authorization scope.
3. Preserve every observed event, including rejection and error events.
4. Compare the observed objective with the predicted objective.
5. Repeat according to `Limits.replay_runs`.
6. Treat instability as evidence, not as a successful witness.

`VALIDATED_WITNESS` requires actual adapter replay. If no adapter is passed,
the strongest normal result is a model candidate, not a validated witness.

## 8. Differential refinement

When observed execution differs from prediction, do not discard the model or
silently widen it. Use the differential result to localize the affected
transition, assumption, graph seam, environment reaction, or profile.

The AI should record:

```text
model revision before divergence
predicted event and state
observed event and state
correlation evidence
affected assumption or contract
whether the divergence is model-too-strict, model-too-loose,
instrumentation-gap, environment-difference, or unsupported semantics
proposed revision and its evidence scope
queries invalidated by the revision
```

A single accepted or rejected input does not justify a global domain rule.
Generalize only after probing additional points or obtaining a semantic
contract. Preserve the original trace and revision history.

## 9. Search strategy for AI models

Use a staged search policy that spends expensive work where it can answer the
objective.

### Fast pass

- Validate authorization and controlled sinks.
- Inspect profiles and workspace contracts.
- Run `Regressor` with the smallest useful trace and solver budgets.
- Execute exact symbolic candidates first.

### Causal expansion

- Read `plan.uncertainty` and `plan.cores`.
- Identify the unresolved region or dependency named by the result.
- Add only the missing symbolic relation, probe, effect, or correlation
  evidence needed for that dependency.
- Re-run regression with a new model revision.

### Forward confirmation

- Run candidates through `Workspace.moves` before using a target adapter.
- Reject candidates whose route is uncertain when the objective requires
  confirmed lineage or causal correlation.
- Replay only candidates that satisfy the authorization and sink policy.

### Alternative routes

- Do not remove a guard because a route is UNSAT.
- Look for explicit alternative transitions, non-adjacent writers, rejected
  branches with modeled effects, or environment-mediated routes.
- Treat a hypothetical relaxation as counterfactual, never as an executable
  witness.

### Cost and optimization

Run `Optimizer` only after a validated witness exists. Keep the objective,
authorization, replay policy, and evidence requirements fixed. Optimization
chooses among supplied equivalent realizations; it does not establish that a
new realization is equivalent merely because it is cheaper.

## 10. Behavior signatures and novelty

Use behavior signatures to prioritize exploration after the semantic model
and objective are established. Signatures are derived from existing `Event`,
`State`, and workspace frame records; they do not replace execution semantics
and they are not equivalence proofs.

```python
from rsve import Archive, Signature

signature = Signature.make(
    observed_events,
    final_frame,
    target="fixture",
    profile="node-profile-1",
    keys={"count", "done"},
)

archive, novelty = Archive().offer(signature)
print(novelty.score, novelty.state, novelty.transition, novelty.path)
```

The signature has three behavior levels:

- `state`: target, region, and environment configuration.
- `transition`: decision, termination, guard, read/write footprint, effects,
  state delta, representations, uncertainty, and reaction shape.
- `path`: ordered transition composition plus resulting state/environment.

Each level has `coarse` and `exact` digests. Coarse signatures preserve
structure and selected objective-relevant values while abstracting other
values by shape. Exact signatures include full state values and hashed
observations/reactions. The `keys` argument defines the values that matter to
the current objective; it is not a hardcoded universal state taxonomy.

`Archive` keeps separate state, transition, and path sets, each partitioned
by target and profile. A new request with the same behavior is not novel just
because its input bytes differ. A new state, effect, or causal path can be
novel independently. Call `seen(signature, Level.EXACT)` when a coarse match
needs exact refinement.

Use the archive as a ranking signal only:

1. Execute or model a candidate using the normal workspace/planner path.
2. Build a signature from its actual events and resulting frame.
3. Offer it to the profile-partitioned archive.
4. Prioritize candidates with useful novelty and objective progress.
5. Keep the exact trace and evidence separately.

Do not use a novel signature as proof of a vulnerability, reachability, or
semantic difference. If two candidates share a coarse signature but later
diverge, retain the counterexample and refine the selected keys or archive
resolution.

RSVE provides five bounded novelty-driven strategies. All require an
assessment callback that returns a `Trial`; the callback is responsible for
executing or modeling the candidate and deciding whether the objective was
actually satisfied. A boolean acceptance result is not enough to claim a
validated witness: the assessor must provide an explicit result status.

```python
from rsve import Bounds, Mcts, Signature, Status, Trial

def assess(candidate):
    events, frame, accepted = run_authorized_workspace(candidate)
    replayed = accepted  # replace with the controlled replay result
    stable = replayed      # replace with the configured stability check
    signature = Signature.make(
        events,
        frame,
        target="fixture",
        profile="profile-1",
        keys={"done", "quota"},
    )
    return Trial(
        accepted,
        signature,
        status=Status.VALIDATED_WITNESS if replayed and stable else Status.SAT_CANDIDATE,
        replayed=replayed,
        stable=stable,
    )

result = Mcts().search(
    seeds,
    expand,
    assess,
    budget=Bounds(max_candidates=500, max_trace_length=4, max_time_ms=5_000),
    archive=archive,
)
```

`Trial(status=Status.MODEL_SAT)` or `Trial(status=Status.SAT_CANDIDATE)` keeps
model-only evidence separate from replay-confirmed evidence. The
`VALIDATED_WITNESS` status is accepted only when the trial is accepted and has
stable replay evidence. Every novelty strategy returns the archive accumulated
during its run as `Found.archive`; pass that archive to a later search to avoid
rediscovering the same behavior. Archive partitions include target, profile
and execution scope.

`Mcts` uses deterministic UCB selection over expanded candidate traces and
back-propagates objective acceptance plus behavior novelty. `Evolve` evaluates
a bounded population, retains the most novel candidates, and calls the
supplied mutation function to create the next population. Both deduplicate
candidate traces, enforce the same explicit bounds, and return
`BUDGET_EXHAUSTED` when a budget stops exploration.

For an end-to-end RSVE search, use `Guide`. It connects the objective to the
existing regressor and workspace instead of requiring the caller to invent
seeds, expansion, and assessment callbacks:

```python
from rsve import Authorization, Guide, Workspace

guide = Guide(
    workspace,
    objective,
    Authorization("investigator", frozenset({"lab"}), frozenset({"fixture"})),
    harness_sinks={"controlled.sink"},
)
result = guide.search("frontier", archive=archive)
```

`Guide` obtains seeds from `Regressor.required_actions` and
`required_traces`, expands entries using the workspace's operations and
bounded probes, executes every candidate through `Workspace.moves`, and
builds signatures from the resulting events and frames. Without an adapter,
successful results are `MODEL_SAT`. Passing an authorized target adapter adds
controlled replay; only accepted, stable replay results can be
`VALIDATED_WITNESS`. The guide closes the adapter after the search.

The complementary strategies are:

- `Beam` evaluates a layer at a time and retains only the most novel bounded
  population.
- `Frontier` performs deterministic best-first expansion, prioritizing the
  children of candidates that produced novel behavior.
- `Anneal` mutates one current candidate, accepts improvements immediately,
  and can accept lower-novelty moves according to a deterministic seeded
  cooling schedule to escape a local behavior plateau.

The callback should return `accepted=True` only for an objective result
established within the declared model or replay scope. A missing signature is
recorded as a limitation and contributes no novelty; it never becomes a
synthetic signature. These strategies rank candidates and do not prove
reachability, equivalence, exploitability, or safety. They must remain behind
the same authorization, workspace, replay, and sink controls as ordinary
planner execution.

Use `Mcts` when interaction prefixes form a useful causal tree. Use `Evolve`
when a domain has meaningful mutation operators and route diversity matters.
Use `Beam` when breadth and a stable population cap matter, `Frontier` when
the expansion graph is sparse and best-first behavior is useful, and `Anneal`
when local mutations can escape a behavior plateau.
Neither strategy should mutate raw bytes blindly when the target requires
typed requests or representation-aware transformations; mutate authorized
interaction structures and let the workspace produce the behavior signature.

## 11. Common failure modes

| Symptom | Correct response |
| --- | --- |
| `UNSAT_BOUNDED` after opaque or unknown transitions | Inspect uncertainty; do not call it globally unreachable. |
| `BUDGET_EXHAUSTED` | Increase a specific bound only if the authorization and experiment justify it. |
| Symbolic route rejected as incomplete | Add a compatible exact contract or use bounded probes and label the result partial. |
| Flow fails despite a matching string at the sink | Add explicit value-level provenance and a sink consumption contract; do not weaken lineage. |
| Flow fails across a graph seam | Check representation bridge, provenance paths, and correlation quality. |
| Missing region state | Initialize the region explicitly; never rely on global-state fallback. |
| Replay differs from the model | Preserve `MODEL_DIVERGENCE`, compare traces, and revise only supported assumptions. |
| Solver returns `UNKNOWN` | Record the unsupported theory or timeout; do not convert it to UNSAT. |
| One probe finds a behavior | Report a bounded observation, not a universal rule. |

## 12. Recommended AI response format

When an AI model completes an RSVE investigation, return a compact report
with these fields:

```text
Objective:
Authorization:
Target/profile:
Workspace scope:
Model revision:

Result status:
Reachability:
Bounds:
Candidate or witness:
Replay runs/stability:
Model alignment:

Evidence used:
  - declared topology
  - observed events
  - symbolic contracts
  - probes
  - replay

Known gaps:
  - unsupported semantics
  - uncorrelated seams
  - uncontrolled environment branches
  - budget limits

Claims not made:
  - global reachability
  - universal runtime behavior
  - exploitability outside the authorized fixture

Next highest-value observation:
```

The last field should name the observation that would most reduce uncertainty,
not merely request more computation. Examples are a missing sink-consumption
contract, a direct correlation key at a boundary, a symbolic relation for a
non-invertible transform, or a clean replay of the candidate.

## 13. Minimal end-to-end template

```python
from rsve import (
    Authorization,
    Entry,
    Limits,
    Model,
    Objective,
    Operation,
    Planner,
    Same,
    State,
)

authorization = Authorization(
    subject="analysis-agent",
    scopes=frozenset({"fixture-lab"}),
    target_ids=frozenset({"fixture"}),
)

operation = Operation(
    name="increment",
    entry_point=Entry("increment"),
    guard=lambda state, request: request.get("amount", 0) > 0,
    apply=lambda state, request: state.update(
        count=state.get("count", 0) + request["amount"]
    ),
    writes=frozenset({"count"}),
)

model = Model(
    target_id="fixture",
    initial_state=State({"count": 0}),
    inputs=({"amount": 1}, {"amount": 2}),
    operations=(operation,),
)

objective = Objective(
    "reach-two",
    "fixture",
    "fixture-lab",
    (Same("count", 2),),
    state_keys=frozenset({"count"}),
    budget=Limits(max_trace_length=2, max_states=200),
)

report = Planner().plan(model, objective, authorization)

print(report.status.value)
print(report.reachability.value)
if report.witness:
    print(report.witness.interactions)
print(report.gaps)
print(report.unresolved_uncertainty)
```

For a real controlled target, pass the adapter and retain the returned report
and evidence artifacts. For a multi-region target, construct a graph-backed
workspace and inspect `workspace.contracts()` before calling the planner.

## 14. Boundaries to state explicitly

RSVE currently provides a strong foundation for bounded, evidence-backed
analysis. It does not provide universal runtime instrumentation, arbitrary
symbolic execution, complete value provenance inference, unrestricted
multi-interaction Flow regression, global non-reachability proofs, or
autonomous authorization decisions.

An AI model gets the most value from RSVE by making the model, objective,
workspace contracts, bounds, evidence, and uncertainty explicit at every
step. The quality of the result is limited by the weakest relevant semantic
contract and observation path, not by the number of adapters installed.
