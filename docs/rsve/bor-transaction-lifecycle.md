# Bor Transaction Lifecycle Profile

This is the first bounded profile for Polygon Bor transaction admission,
execution, and receipts. It is pinned to `develop` at source commit
`c72e248587a19b1c93eda95871c46b53071e58fd`.

The profile is intentionally layered. A result at one layer is not treated as
evidence for a lower layer until that lower layer has its own source contract,
compiled boundary, and, where required, controlled runtime observation.

## Evidence Levels

| Level | Meaning |
| --- | --- |
| Source | The exact Bor source path and function have been identified. |
| Compiled | The selected package builds from the sparse source batch. |
| Observed | A controlled Bor process or fixture emitted the relevant event. |
| Replay validated | The same authorized interaction reproduced the result under the configured replay policy. |
| Unknown | A dependency, branch, environment, or persistence boundary is not yet modeled. |

The current sparse checkout is `/home/codespace/bor/bor-source`. It is a
partial checkout, not a full Bor clone.

## Layer Ledger

| Layer | Bor source batch | Validation offered | State or evidence boundary | Status |
| --- | --- | --- | --- | --- |
| RPC and raw transaction ingress | `internal/ethapi/api.go`, `internal/ethapi/transaction_args.go` | Decode request arguments, select transaction type, construct or decode the transaction, expose submission errors | RPC request -> canonical `types.Transaction` | Source identified; not fetched |
| Transaction encoding and identity | `core/types/transaction.go`, `transaction_marshalling.go`, `transaction_signing.go`, `tx_*.go` | RLP or typed-envelope decoding, transaction type dispatch, size, hash, sender recovery, chain/fork signer selection | Bytes/signature -> typed transaction, sender, hash | Compiled |
| Stateless pool admission | `core/txpool/validation.go` | Pool type support, blob count/sidecar, size, fork activation, init-code and gas caps, non-negative value, block gas limit, fee-cap ordering, signature, nonce ceiling, intrinsic/floor gas, minimum tip | Transaction + header/config -> accepted or rejected | Source fetched and compiled through focused harness |
| Stateful pool admission | `core/txpool/validation.go`, `core/txpool/legacypool/*` | Account nonce ordering and gaps, balance versus transaction cost, queued expenditure, replacement cost, per-account slot limits | Transaction + state + pool contents -> pending/queued/rejected | Source fetched and compiled through focused harness |
| Pool routing and promotion | `core/txpool/txpool.go`, `core/txpool/subpool.go`, `core/txpool/legacypool/*`, `core/txpool/blobpool/*` | Subpool filtering, pending versus queued classification, nonce promotion, replacement, eviction, rebroadcast and reorg handling | Pool admission -> executable pending set | Source fetched; package build pending dependencies |
| Block selection boundary | `miner/*`, `core/txpool/txpool.go` | Select pending transactions under gas, fee, ordering, and interruption constraints | Pending set -> block transaction list | Source not yet fetched |
| Message conversion | `core/state_transition.go` | Recover sender, select message fields, apply effective gas price from base fee, carry access/blob/set-code fields | Typed transaction -> execution message | Source fetched |
| State-transition precheck | `core/state_transition.go` | Nonce checks, gas-limit checks, upfront gas purchase, intrinsic/floor gas, balance checks, fee constraints, authorization checks | Message + state + block context -> executable or core error | Source fetched and compiled through focused harness |
| EVM execution | `core/vm/*` | Opcode semantics, gas accounting, revert, exceptional failure, logs, contract creation, state writes | Message -> execution result and state journal | Source fetched and compiled through focused harness |
| Balance reconciliation | `core/state_transition.go`, `core/state_processor.go`, `core/state/*` | Sender value debit, recipient credit, gas refund, coinbase tip, Bor burn destination, storage mutation, state-root change | Execution + state journal -> observed balance ledger and root delta | Compiled and observed through focused harness |
| Fee settlement and finalization | `core/state_transition.go`, `core/state_processor.go` | Refund calculation, gas return, fee burn/tip, Bor fee-transfer log, nonce/state finalization, cumulative gas | Execution result -> committed state effects and gas totals | Source fetched and compiled through focused harness |
| Receipt construction | `core/state_processor.go` | Success/failure status, tx hash, gas used, cumulative gas, contract address, logs, bloom, block location, blob fields | Execution result + state/logs + block context -> receipt | Source fetched |
| Receipt field derivation | `core/types/receipt.go` | Effective gas price, block and tx metadata, contract address, log indices, bloom, tx/receipt count consistency | Receipt + block/tx context -> derived receipt | Compiled through `core/types` |
| Receipt persistence | `core/rawdb/bor_receipt.go`, raw database packages | Storage encoding, retrieval, receipt-root inputs, canonical/history boundaries | Derived receipt -> persisted receipt/index | Source fetched and compiled through focused harness |
| Receipt RPC and subscriptions | `eth/api_backend.go`, `eth/api_backend_pending.go`, `eth/bor_api_backend.go`, `eth/protocols/eth/receipt.go` | Pending/mined lookup, canonical-chain caveats, receipt delivery and protocol encoding | Persisted/observed receipt -> external API result | Source fetched; runtime boundary not exercised |

## Required Contracts

Each layer must supply these records before it can be used in an RSVE route:

1. `inputs`: typed values and the profile fields they came from.
2. `guards`: every accept/reject condition, including fork and configuration
   predicates.
3. `reads`: state, header, pool, environment, and dependency reads.
4. `writes`: state, pool, logs, receipt, database, and index changes.
5. `outcomes`: accepted, rejected, reverted, invalid, error, and unknown
   branches.
6. `effects`: downstream-visible effects such as promotion, fee transfer,
   log emission, receipt creation, and persistence.
7. `provenance`: exact source file, function, commit, and evidence level.
8. `limitations`: omitted dependencies or assumptions that prevent an exact
   backward relation.

An edge between layers is usable for symbolic regression only when its
representation, direction, and provenance contract are explicit. A call or
import relationship alone is not a causal data route.

## Execution Environment Contract

The lifecycle model must carry an explicit environment frame. The minimum
frame for this batch is:

| Environment component | Required facts | Why it matters |
| --- | --- | --- |
| Host and process | OS, ISA, Go version, cgo/runtime, process limits | Changes compiled behavior, crypto support, scheduling, and available adapters |
| Chain protocol | Chain ID, Bor fork schedule, active EIPs, gas constants | Controls signer selection, accepted transaction types, intrinsic/floor gas, and fee rules |
| Block context | Number, timestamp, gas limit, base fee, blob base fee, coinbase, parent hash | Feeds fork predicates, effective gas price, gas admission, receipt metadata, and fee settlement |
| Account state | Sender nonce/balance, recipient existence/code/storage, authorization state | Controls stateful admission and execution preconditions |
| State backend | StateDB implementation, trie mode, snapshot/access-event behavior, reset point | Controls writes, finalization, state roots, and repeatability |
| VM execution | VM config, tracer/hooks, interrupt/cancellation policy, precompile set | Controls execution results, logs, gas, and observable side effects |
| Time and randomness | Clock source, randomness source, scheduler boundary | Prevents replay from being called stable when the environment is uncontrolled |
| Receipt persistence | Receipt database, canonical head, indexer state, reorg/reset policy | Distinguishes a constructed receipt from a retrievable canonical receipt |

The current RSVE model adds an open balance-ledger observation boundary after
execution and before receipt derivation. It records sender, recipient, fee,
total-delta, and state-root observations without assuming which balance
behavior is vulnerable. A `divergent` observation is accepted as evidence for
further analysis rather than being rejected or assigned a predefined attack
class.

The focused harness should expose only resettable operations such as:

```text
load fixture state -> submit transaction -> admit -> execute -> derive receipt
-> persist/query receipt -> reset fixture state
```

It does not need peer networking, consensus networking, discovery, a full RPC
server, Heimdall, a miner service, or a full Bor node configuration to test
this lifecycle. Those become separate layers only when their behavior is
required by the objective.

## Current RSVE Test Scope

`tests/bor_transaction_lifecycle.py` and `tests/bor_layered_profile.py` model
and test:

- valid admission -> execution success -> successful receipt;
- valid admission -> execution revert -> failed receipt; and
- stateful admission rejection with no receipt; and
- consistent and divergent balance-ledger observations.

Those results are `SAT_CANDIDATE` because no controlled Bor runtime adapter is
connected yet. They are not runtime claims about Polygon Bor.

The focused Go harness at
`/home/codespace/bor/bor-source/harness/transaction_lifecycle_test.go` and the
balance-focused harness files compile and exercise the production
`core/txpool`, `core`, `core/vm`, `core/state`, `core/types`, and `core/rawdb`
packages against a resettable in-memory state. The RPC server, block
selection, canonical-chain lookup, and network layers are intentionally
outside this batch.

The intentional compiled analysis is runnable with:

```text
cd /home/codespace/bor/bor-source
go run ./cmd/bor-balance-analysis > artifacts/bor-balance-analysis.json
```

The current artifact contains nine probes: four admitted executions, five
validation rejections, zero unexplained tracked-balance deltas, and successful
state/trie and receipt/rawdb round trips for every admitted execution.

## Iterative Analysis Loop

The profile is evaluated before every dependency expansion. Its result is a
diagnostic input to the next batch:

1. `SAT_CANDIDATE` with a witness means the strapped model can reach the
   current balance objective; compare its trace with the compiled harness.
2. `UNKNOWN` or budget exhaustion means increase the relevant search bound or
   instrument the missing boundary identified in `gaps` and
   `unresolved_uncertainty`.
3. A `divergent` balance observation is retained as an unexplained result;
   the model does not infer its cause in advance.
4. Promote a result only after the same fixture is replayed through the
   compiled Bor harness and its state, fee, receipt, and persistence outputs
   are reconciled.

`BorTransactionLifecycleProfile.analysis_feedback()` exposes this diagnostic
record. The current profile uses a 10,000,000 state/event ceiling, a seven-step
trace bound, and a 60-second wall-clock guard. The present bounded run reaches
`SAT_CANDIDATE` with a seven-event witness. The compiled analysis has run
separately. `rsve.bor_evidence.BorEvidenceIngest` validates its JSON schema,
reconciles the sender/recipient/coinbase/burn ledger legs with the stored
total, checks state-root reopen and receipt persistence fields, and attaches
the result as `OBSERVED` evidence. It leaves the planner result at
`SAT_CANDIDATE`: the artifact is a compiled harness observation, not a replay
of the planner's exact interaction trace.

## Expansion Order

The next batches should be added in this order:

1. Bind the compiled balance observations to the RSVE witness format and
   reconcile every tracked account delta with the stored receipt.
2. Add focused RPC and contract-call adapters only where the balance trace
   reaches them.
3. Connect a controlled Bor-compatible runtime and promote only
   replay-observed results to `VALIDATED_WITNESS`.

## Attached Storage-Root Finding

The next focused region is attached to the same Bor source profile:
`bor.parallel.storage-root` covers `ParallelStateDB.GetStorageRoot`, and
`bor.evm.create2-guard` covers the collision check in `core/vm/evm.go`.

The compiled probe at
`/home/codespace/bor/bor-source/cmd/bor-storage-root-probe` executes this
transaction order:

```text
SELFDESTRUCT(address) -> recreate(address) + storage write -> CREATE2 collision check
```

For Bor commit `c72e248587a19b1c93eda95871c46b53071e58fd`, serial state returns
storage root `0x9d7bbe35dc5044f7e5a75c01412f8939d00ceae1f6187655dc8d80237724a66b`
and rejects CREATE2. Parallel state returns the zero root and admits it. The
artifact is stored at
`/home/codespace/bor/bor-source/artifacts/bor-storage-root-probe.json` and is
attached by `BorStorageRootIngest` as `OBSERVED` evidence. The RSVE result
remains `SAT_CANDIDATE` because no target-adapter replay has been claimed.

The profile also attaches passive environment-monitoring regions:
`bor.engine.state-write`, `bor.runtime.process`, `bor.os.kernel`,
`bor.memory.cpu`, and `bor.persistence.external`. A controlled adapter can use
these boundaries to compare declared engine writes with process identity,
isolation state, memory/CPU telemetry, and database/filesystem state. An account
delta without a matching engine write is reported as an out-of-band integrity
violation; the model does not include host-memory or kernel mutation routes.
Runtime adapters can provide that boundary record through `BorRuntimeIngest`.
It requires pre/post `(balance, nonce, code_hash, storage_root)` tuples,
declared engine-write fields, environment events, and any remaining unknowns.
An unexplained account-field change is attached as `OBSERVED` evidence but
retains unresolved causal uncertainty until the process, kernel, or persistence
region identifies the source.

## Non-CREATE2 CallWithState path

The autonomous profile also follows a separate account-mutation path beginning
at the blockchain RPC surface:

`rpc.eth_call -> internal.CallWithState -> core.ApplyMessage -> state.SetNonce`

Bor's internal `CallWithState` contract says the supplied `StateDB` changes
during EVM execution and must be copied by the caller. Message conversion marks
nonce checks as skipped for read-only calls, but `stateTransition.execute` still
increments the sender nonce for a non-creation message. The production-package
probe at
`/home/codespace/bor/bor-source/cmd/bor-callwithstate-probe/main.go` records
nonce `7 -> 8` with zero value, zero gas price, no canonical transaction, and
no receipt.

This is an internal live-state boundary candidate, not a claim that the ordinary
public `eth_call` wrapper necessarily leaks into canonical chain state: the
public wrapper obtains isolated state before calling the same execution path.
The RSVE profile preserves that distinction and attaches process, kernel,
memory/CPU, and external persistence regions as unresolved until runtime
instrumentation binds them. The combined autonomous runner can attach the
compiled observation with:

```text
cd /home/codespace/bor/RSVE
PYTHONPATH=src python scripts/bor_autonomous_analysis.py \
  /home/codespace/bor/bor-source/artifacts/bor-storage-root-probe.json \
  --call-artifact /home/codespace/bor/bor-source/artifacts/bor-callwithstate-probe.json
```

The same route contains a stronger modeled balance candidate when an internal
caller supplies state overrides with a live `StateDB`:

`rpc.eth_call -> internal.CallWithState -> override.StateOverride.Apply -> evm.Call.snapshot -> core.StateDB.Commit`

The source ordering places `StateOverride.Apply` at `internal/ethapi/api.go:911`
before the EVM snapshot at `core/vm/evm.go:368`. The bounded model applies a
synthetic balance override `100 -> 1` and storage override `0 -> 99`, then
reverts the contract call and commits the caller-owned state. This is retained
as `SAT_CANDIDATE` rather than `OBSERVED`: the current Bor checkout has the
override implementation staged as deleted, so a clean production-package
replay is still required before treating the balance change as confirmed.

Run the attached RSVE investigation with:

```text
cd /home/codespace/bor/RSVE
PYTHONPATH=src python scripts/bor_storage_root_investigation.py \
  /home/codespace/bor/bor-source/artifacts/bor-storage-root-probe.json
```
