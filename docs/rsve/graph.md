# Composable Analysis Graph

`AnalysisGraph` is the platform-neutral workspace composition boundary. It
contains independently identified `ProfileInstance` records, extension
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

`EvidenceGraph` is separate. It contains observed `TraceEvent` records and
`CorrelationLink` records. Correlation quality is explicit: direct,
deterministically derived, inferred with uncertainty, or uncorrelated. RSVE
never turns temporal adjacency or extension co-presence into causality.

`CapabilityManifest` records namespaced, versioned extension contracts.
`CapabilityRegistry.resolve_path()` computes coverage for a specific required
path, so an unrelated missing capability does not weaken every analysis. A
missing capability remains missing and must produce an affected `UNKNOWN`
result in the analysis layer.

Nested graphs are attached by identity and can expose only their external
ports to a parent. Graph traversal uses visited sets and explicit depth
bounds, so cycles, callbacks, and re-entry are representable.

`WorkspaceBinding` assigns a profile and extension instance to one or more
regions. Roles belong to bindings, not extension identities. Relationship
types distinguish data, control, state, context, ownership, alias, lifetime,
resource, causal, and comparison edges.

`SemanticInterpreter` executes supported `ir.Transform`, `ir.Recognizer`, and
`ir.Transition` records. Missing or opaque semantics produce `UNKNOWN`; they
are never treated as identity. `ReactiveEnvironment` models target and
environment state together and reconciles predicted versus observed
reactions.

The graph profile is the canonical identity. The former single-stack
`ExecutionProfile`/`LayerPin` abstraction has been removed from core and
adapter contracts. Concrete Node, EVM, Linux environment, and QEMU code lives
under `rsve.extensions`; importing `rsve` does not import those extensions.
The current source distribution packages these implementations as an optional
extension namespace; separate pip distributions remain a packaging task, not a
core dependency.
