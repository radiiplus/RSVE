# Node Adapter Contract

`rsve.node.Node` accepts an explicit local Node fixture and manifest. It exposes the generic target lifecycle:

`prepare` -> `snapshot` -> `invoke`/`trace` -> `output` -> `reset`/`replay` -> `teardown`.

The adapter returns platform-neutral `Event` records. Each observed event carries a stable event ID, run/trace IDs, causal parent, entry/component/operation names, input/output representation names, state checkpoint IDs, guard result, environment facts, ordering, timestamp when available, evidence source, and redacted/content-addressed payload references.

The fixture uses Node's `diagnostics_channel` and `AsyncLocalStorage` for the hooks it actually exposes. The adapter does not claim universal discovery, V8 coverage, framework route coverage, or lower-layer observation. Unsupported HTTP, IPC, WebSocket, timer, filesystem, scheduler, network, and environment behavior remains an explicit capability limitation.

Replay reports keep every run separately. `stable` means semantic event/outcome signatures matched across the requested runs; `replayability` is `partially_replayable` because exact clocks, scheduler behavior, environment values, and filesystem/process isolation are not controlled. A mismatch or flaky outcome is retained rather than collapsed into a pass.
