# Bor Investigation Ledger

This ledger records execution evidence for the Bor investigation. A model,
imported artifact, or source-only explanation cannot move an acceptance item to
runtime-confirmed.

Target checkout: `/home/codespace/bor/bor-source`

Target revision: `c72e248587a19b1c93eda95871c46b53071e58fd` (verified locally)

## Phases

| Phase | Status | Evidence |
| --- | --- | --- |
| 1. Inspect current implementation | COMPLETE | Architecture audit inspected the Bor RSVE path and identified model-first claims, artifact provenance loss, and missing live execution. |
| 2. Establish Bor checkout/runtime | COMPLETE | Revision verified; Go `go1.27.1`, linux/amd64; a controlled dev node exposed HTTP RPC on `127.0.0.1:18545`. The checkout retains pre-existing sparse-checkout deletions. |
| 3. Build and run Bor code | COMPLETE | Full Bor CLI built as `/tmp/bor-bin`; `go run ./cmd/bor-balance-analysis` and `go test ./harness` completed against the pinned checkout. |
| 4. Baseline observations | COMPLETE | Balance harness: 9 probes, 4 accepted, 5 rejected, 0 findings; live RPC: unchanged canonical balance/nonce/proof after `eth_call` and state override. |
| 5. Correct investigation semantics | COMPLETE | The runner now executes a target command, derives hypotheses from returned observations, and labels imported artifacts separately. |
| 6. Execute corrected investigator | COMPLETE | `scripts/bor_autonomous_analysis.py` ran Bor twice successfully, producing `artifacts/bor/runtime-investigation.json`. |
| 7. Reproduce/reject hypotheses | COMPLETE | The runner reproduced the caller-owned nonce mutation. Canonical block execution rejected the storage-root helper divergence: serial and parallel roots matched across three runs. The economic sweep produced zero candidates. |
| 8. Regression verification | PARTIAL | 27 Bor-focused RSVE tests, Bor harness, txpool, and ethapi tests passed. Full RSVE suite ran 241 tests with one skip and one deterministic pre-existing `tests/web.py` failure (`SAT_CANDIDATE` vs `VALIDATED_WITNESS`) outside the changed files. |
| 9. Evidence-backed report | COMPLETE | Runtime, RPC, economic-search, canonical-transaction, cross-layer, imported-artifact, command, revision, hypothesis, and regression records are committed with this ledger. |

## Acceptance Criteria

| Criterion | Status | Evidence or blocker |
| --- | --- | --- |
| A. No model-only vulnerability claim | COMPLETE | All findings and rejections came from fresh Bor execution. No model-only result is promoted to runtime evidence. |
| B. Execute actual Bor code | COMPLETE | `/tmp/bor-bin` ran a real isolated Bor dev node; the Go harness ran real Bor packages. |
| C. Capture actual account-state effects | COMPLETE | Harness captured balances, nonces, storage, gas, receipts, database writes, committed roots, and reopened state; RPC artifact captured live account proof before/after. |
| D. Discover without named vulnerable function | PARTIAL | The economic sweep generates a bounded cross-product of executable transaction dimensions; it does not name a vulnerable function, but broader RPC/process input generation remains bounded. |
| E. Derive hypothesis from observation | COMPLETE | `derive_hypotheses()` derives only invariant violations present in runtime JSON; the baseline correctly generated none. |
| F. Independently reproduce/reject hypothesis | COMPLETE | The CallWithState anomaly reproduced; canonical block execution rejected the storage-root helper divergence; live RPC transactions reproduced canonical fee/value accounting. |
| G. Separate imported artifacts from runtime evidence | COMPLETE | Existing JSON ingestors now emit `IMPORTED_ARTIFACT`; live commands emit `RUNTIME_OBSERVATION`. |
| H. Distinguish confirmed/rejected/unresolved | COMPLETE | Runtime, reproduced, imported, and unresolved classifications are distinct; non-JSON verifier success is not promoted to independent verification. |
| I. Preserve regression behavior | PARTIAL | 27 focused RSVE tests and Bor packages passed. The full suite has one deterministic failure in the existing web search test and one skip; no changed file is in the failure call path. |
| J. Integrate end to end | COMPLETE | Economic classifier, execution runner, RPC observer, cross-layer process observer, runtime artifacts, provenance labels, tests, audit, and ledger are integrated on this branch. |

## Baseline Command Record

```text
git rev-parse --verify c72e248587a19b1c93eda95871c46b53071e58fd^{commit}
go version
go run ./cmd/bor-balance-analysis > /tmp/bor-balance-analysis-live.json
go test ./harness
```

Observed baseline summary:

```text
target=polygon-bor
build_hash=c72e248587a19b1c93eda95871c46b53071e58fd
probe_count=9 accepted=4 rejected=5 findings=0
accepted cases: transfer, contract-storage-write, contract-storage-clear-refund, contract-revert
rejected cases: insufficient-funds, nonce-too-low, nonce-gap, fee-cap-ordering, invalid-signature
tracked total delta for accepted cases: 0
```

This baseline is evidence from the compiled Bor packages, not evidence that
the existing RSVE vulnerability profiles are correct.

The objective probes were then executed through the same runner. The
CallWithState probe observed nonce `7 -> 8` in caller-supplied state through
`rpc.eth_call -> internal.CallWithState -> core.ApplyMessage`, while recording
`canonical_transaction=false` and `receipt_created=false`. The runner derived
`out_of_band_state_mutation`, reran the command, and classified it as
`REPRODUCED_RUNTIME_OBSERVATION`.

The storage-root probe observed different serial and parallel storage roots
after self-destruct and recreation. The runner derived
`serial_parallel_state_divergence` and reproduced it on the second execution.
The independent canonical block reproduction rejected it as an exploitable
canonical divergence: serial and parallel roots matched across three runs,
with nonce `1`, balance `0`, and the expected storage result. The helper
observation was caused by manually constructing a parallel account without the
nonce/code state real EVM creation supplies.

## Economic Advantage Search

The execution-driven economic search ran 3,024 real Bor cases across transfer,
storage-write, storage-clear/refund, revert, legacy and dynamic fee fields,
gas limits, values, nonce states, and exact/insufficient/surplus balances.
The result was 864 accepted, 2,160 rejected, zero accounting candidates, and
zero reproduced candidates. The full report is
`artifacts/bor/bor-economic-search.json`.

The isolated node then included two signed transactions at 26 gwei. In both
cases the recipient gained exactly `1`, the sender debit equaled value plus
gas cost, and the burn address received the base-fee component. The canonical
receipts were successful and nonces advanced `0 -> 1 -> 2`. The raw records
are `artifacts/bor/bor-rpc-canonical-tx1.json` and
`artifacts/bor/bor-rpc-canonical-tx2.json`.

The cross-layer observer executed an isolated `eth_call` through Bor using a
controlled account address, then compared account proof, balance, and nonce
before and after. It captured the Bor process's scheduler/resource state,
namespaces, cgroup and security fields, guest-visible kernel/CPU/memory state,
and 2,800+ descendant syscalls with `strace`. The process identity remained
stable and the account was unchanged. A control `eth_chainId` window showed the
same `chaindata` log mutation as the `eth_call` window, so that persistence
activity is attributed to normal node background work rather than the call.
The remaining regions are narrow unresolved residuals: kernel behavior beyond
the traced child, physical/hypervisor behavior, and Go scheduler decisions
between snapshots. Its record is
`artifacts/bor/bor-cross-layer-observation.json`.

Current conclusion: no verified unauthorized economic gain, debit bypass, fee
manipulation, or persistent canonical state manipulation was found. The
CallWithState result remains a reproduced internal caller-owned-state mutation,
but it is not an economic exploit and public RPC readback did not show
canonical leakage.

## Live RPC observation

The isolated Bor dev node was built from the pinned source and run with HTTP
RPC on `127.0.0.1:18545`. The RPC observer recorded `eth_chainId=0x539`, a
funded developer account proof, and identical balance, nonce, and proof before
and after both a normal `eth_call` and a state-override `eth_call`. The result
is stored in `artifacts/bor/bor-rpc-observation.json` and is a
`RUNTIME_OBSERVATION`, not a vulnerability claim.

A signed transaction from the same actual keystore account was admitted to the
transaction pool, but remained pending while the dev miner sealed empty
blocks. The account balance and nonce did not change. This is recorded as an
unresolved miner-inclusion behavior requiring a separate block-production
investigation; it is not reported as a balance discrepancy.
