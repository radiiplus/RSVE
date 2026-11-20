# Composable Analysis Graph

`Graph` is the platform-neutral workspace composition boundary. It
contains independently identified `Profile` records, extension
instances and bindings, typed regions and ports, typed connections, nested
graphs, canonical IR semantic records, capability manifests, and explicit
budgets.
Profiles are not forced into one stack: multiple versions, implementations,
scopes, and extensions can coexist.

Topology is not execution evidence. A connection records that a relationship
is modeled or possible. Its status is one of:

- `verified_compatibility`: port representations match;
- `explicit_transformation_required`: a named bridge is required;
- `unverified_relationship`: no representation bridge has been established.

`Proofs` is separate. It contains observed `Event` records and
`Link` records. Correlation quality is explicit: direct,
deterministically derived, inferred with uncertainty, or uncorrelated. RSVE
never turns temporal adjacency or extension co-presence into causality.

`Manifest` records namespaced, versioned extension contracts.
`Registry.resolve()` computes coverage for a specific required
path, so an unrelated missing capability does not weaken every analysis. A
missing capability remains missing and must produce an affected `UNKNOWN`
result in the analysis layer.

Nested graphs are attached by identity and can expose only their external
ports to a parent. Graph traversal uses visited sets and explicit depth
bounds, so cycles, callbacks, and re-entry are representable.

`Binding` assigns a profile and extension instance to one or more
regions. Roles belong to bindings, not extension identities. Relationship
types distinguish data, control, state, context, ownership, alias, lifetime,
resource, causal, and comparison edges.

`Interpreter` executes supported `ir.Transform`, `ir.Recognizer`, and
`ir.Transition` records. Missing or opaque semantics produce `UNKNOWN`; they
are never treated as identity. `World` models target and
environment state together and reconciles predicted versus observed
reactions.

`Workspace.contracts()` reports the executable semantic binding for each
graph transform and modeled relation. A binding is `forward` when a concrete
evaluator exists, `backward` when an exact `Symbolic` relation exists, and
`complete` only when both directions are present with compatible references,
versions, relation metadata, and no unresolved limitation. Static probes or
budgeted expanders are recorded as bounded limitations, never as complete
semantic contracts. The planner treats incomplete or mismatched contracts as
`UNKNOWN` and does not use their raw symbolic bindings for synthesis.

Graph zones have independently initialized state when a workspace is created
without an explicit region map. If a caller supplies a partial region map,
an explicitly owned transition whose state is absent produces `UNKNOWN`; it
never falls back to global target state. Only `DATA` connections participate
in value-route execution. Uncorrelated data seams may remain modeled routes,
but their uncertainty is preserved in the resulting event rather than being
promoted to causal evidence.

The graph profile is the canonical identity. The former single-stack
`ExecutionProfile`/`LayerPin` abstraction has been removed from core and
adapter contracts. Concrete Node, EVM, Linux environment, and QEMU code lives
under `rsve.extensions`; importing `rsve` does not import those extensions.
The current source distribution packages these implementations as an optional
extension namespace; separate pip distributions remain a packaging task, not a
core dependency.
