# Cross-Runtime Adapter Contracts

The core consumes `TargetAdapter`, `TraceEvent`, `State`, `Authorization`, and `AnalysisReport` without branching on runtime. Runtime-specific capability records live in `runtime_contracts.py` and describe the evidence boundary rather than changing core planning.

## Linux Environment Default

`LinuxEnvironmentAdapter` is the default environment profile for host-local Unix fixtures. It records kernel, architecture, libc, ABI, syscall-surface, namespace/cgroup visibility, resource limits, filesystem fixture, virtual-memory assumptions, clock/randomness, scheduler, network, and snapshot scope. The profile ID and capabilities are carried in `EnvironmentObservation` and merged into Node/EVM trace evidence.

This is a default profile, not a universal Linux proof. Hardware memory ordering, scheduler behavior, host entropy, external services, and exact host replay remain explicit unknowns. A QEMU or other substrate adapter can replace the host profile with a guest profile without changing the planner or trace schema.

## QEMU Linux substrate

`QemuLinuxSubstrate` boots the pinned official Ubuntu Server 26.04 amd64 cloud image at `/home/codespace/.cache/rsve/qemu/ubuntu-26.04/ubuntu-26.04-server-cloudimg-amd64.img`. It verifies SHA256 before use, creates a temporary qcow2 overlay, runs QEMU's x86_64 `q35` machine with TCG, and captures bounded serial boot evidence. Reset recreates the overlay from the verified base image. The minimal substrate does not provision cloud-init, SSH, or a guest agent.

The substrate reports the configured guest image, emulated architecture, memory boundary, virtual-memory scope, network policy, and explicit unknowns for guest kernel/libc/ABI, clock, entropy, scheduler, and external services through the existing `EnvironmentObservation`. TCG provides an emulated OS/ISA boundary; it does not prove host hardware behavior or exact scheduler, entropy, wall-clock, external-service, or asynchronous replay semantics. QEMU is therefore substrate evidence, not an automatic fidelity upgrade for the target model.

## JVM

`JvmCapabilities` covers Java-agent attachment, bytecode transformation, JFR events, thread/task correlation, classloader boundaries, and JVM value/exception categories. A future adapter should use `java.lang.instrument` as the stable agent boundary, add Byte Buddy only for measured transformation complexity, and use JFR as complementary runtime evidence. Agent hooks, JFR events, classloader identity, exceptions, and primitive/reference values must map into canonical components, representations, and observations.

## EVM

`EvmCapabilities` covers local-chain execution, transaction/call entries, accounts, storage, block context, reverts, logs, snapshots, replay, and optional symbolic backends. `EvmExecutionContext` preserves chain identity and block/environment values. `EvmTargetAdapter` is the first second-runtime slice: it uses Anvil JSON-RPC, Forge fixture compilation, and Cast ABI encoding behind the adapter boundary. The core sees only canonical entries, states, and trace events.

## Native

`NativeCapabilities` records architecture, ABI, process control, memory observation, instruction instrumentation, and snapshot/reset. A native adapter must keep ABI, loader, architecture, and address-space semantics local to the adapter. No native implementation is included because no Batch 7 divergence demonstrates a requirement below the language-runtime boundary.

## Portability invariant

The same `ObjectiveDefinition`, `HybridPlanner`, `AnalysisStatus`, `Witness`, and differential workflow are used for the Node and EVM fixtures. Differences in transaction receipts, async events, JVM values, chain context, or native memory must remain evidence carried by adapter-produced `TraceEvent` fields, not runtime branches in the planner.

## Execution profiles and layer pins

`ExecutionProfile` is the stack scope for a run. It can pin the target/build, runtime, platform, OS/kernel, ISA/ABI, adapter, and runtime-specific tools or image digests. Node contributes target/runtime/platform/adapter pins; EVM adds Forge; QEMU adds the Ubuntu image digest and QEMU version. `ProfileVerification` returns `MATCH`, `DRIFT`, or `UNKNOWN`; an unobserved layer is never treated as matching. The planner carries the resulting profile ID into `AnalysisReport` and `ProofResult`, so a solver result is tied to the exact observed stack scope.

Applications can add package-lock, framework, compiler, loader, firmware, container, or configuration pins through `ExecutionProfile.from_target(..., extra_pins=...)`. Pinning identifies the evidence scope; it does not claim that an unobserved internal dependency or external service is deterministic.
