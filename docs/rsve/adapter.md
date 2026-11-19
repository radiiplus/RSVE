# Cross-Runtime Adapter Contracts

The core consumes `Target`, `Event`, `State`, `Authorization`, and `Report` without branching on runtime. Concrete runtime and environment implementations are optional extension modules under `rsve.extensions`; the core public namespace does not eagerly import them. Extensions contribute `Manifest`, `Profile`, `Graph`, and evidence through the common contracts.

## Linux Environment Default

`LinuxEnv` is an optional host-local Unix extension. It records kernel, architecture, libc, ABI, syscall-surface, namespace/cgroup visibility, resource limits, filesystem fixture, virtual-memory assumptions, clock/randomness, scheduler, network, and snapshot scope. `World` is the core state model; the Linux extension supplies observations and capabilities but does not define core semantics.

This is a default profile, not a universal Linux proof. Hardware memory ordering, scheduler behavior, host entropy, external services, and exact host replay remain explicit unknowns. A QEMU or other substrate adapter can replace the host profile with a guest profile without changing the planner or trace schema.

## QEMU Linux substrate

`Qemu` boots the pinned official Ubuntu Server 26.04 amd64 cloud image at `/home/codespace/.cache/rsve/qemu/ubuntu-26.04/ubuntu-26.04-server-cloudimg-amd64.img`. It verifies SHA256 before use, creates a temporary qcow2 overlay, runs QEMU's x86_64 `q35` machine with TCG, and captures bounded serial boot evidence. Reset recreates the overlay from the verified base image. The minimal substrate does not provision cloud-init, SSH, or a guest agent.

The substrate reports the configured guest image, emulated architecture, memory boundary, virtual-memory scope, network policy, and explicit unknowns for guest kernel/libc/ABI, clock, entropy, scheduler, and external services through the existing `Fact`. TCG provides an emulated OS/ISA boundary; it does not prove host hardware behavior or exact scheduler, entropy, wall-clock, external-service, or asynchronous replay semantics. QEMU is therefore substrate evidence, not an automatic fidelity upgrade for the target model.

## JVM

`Java` covers Java-agent attachment, bytecode transformation, JFR events, thread/task correlation, classloader boundaries, and JVM value/exception categories. A future adapter should use `java.lang.instrument` as the stable agent boundary, add Byte Buddy only for measured transformation complexity, and use JFR as complementary runtime evidence. Agent hooks, JFR events, classloader identity, exceptions, and primitive/reference values must map into canonical components, representations, and observations.

## EVM

`Fork` covers local-chain execution, transaction/call entries, accounts, storage, block context, reverts, logs, snapshots, replay, and optional symbolic backends. `Context` preserves chain identity and block/environment values. `Evm` is the first second-runtime slice: it uses Anvil JSON-RPC, Forge fixture compilation, and Cast ABI encoding behind the adapter boundary. The core sees only canonical entries, states, and trace events.

## Native

`Memory` records architecture, ABI, process control, memory observation, instruction instrumentation, and snapshot/reset. A native adapter must keep ABI, loader, architecture, and address-space semantics local to the adapter. No native implementation is included because no Batch 7 divergence demonstrates a requirement below the language-runtime boundary.

## Portability invariant

The same `Objective`, `Planner`, `Status`, `Witness`, and differential workflow are used for the Node and EVM fixtures. Differences in transaction receipts, async events, JVM values, chain context, or native memory must remain evidence carried by adapter-produced `Event` fields, not runtime branches in the planner.

## Execution profiles and layer pins

`Profile` is the graph-owned scope for a run. It can identify a target, runtime, platform, OS/kernel, ISA/ABI, adapter, toolchain, image digest, configuration, and execution context without flattening them into one layer key. `Need` returns `MATCH`, `DRIFT`, or `UNKNOWN`; an unobserved field is never treated as matching. The planner carries the observed profile ID into `Report` and `Proof`, so a solver result is tied to the exact graph scope.

Applications can add package-lock, framework, compiler, loader, firmware, container, or configuration fields to a scoped `Profile` or bind a separate profile for that component. Profile identity identifies the evidence scope; it does not claim that an unobserved internal dependency or external service is deterministic.
