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
| 7. Reproduce/reject hypotheses | COMPLETE | The execution-driven runner independently reran both objective-relevant probes. It reproduced the caller-owned nonce mutation and the serial/parallel storage-root divergence. Public RPC readback still showed no canonical balance/nonce mutation. |
| 8. Regression verification | PARTIAL | 18 Bor-focused RSVE tests, Bor harness, txpool, and ethapi tests passed. Full RSVE suite ran 232 tests with one deterministic pre-existing `tests/web.py` failure (`SAT_CANDIDATE` vs `VALIDATED_WITNESS`) outside the changed files. |
| 9. Evidence-backed report | COMPLETE | Runtime, RPC, imported-artifact, command, revision, hypothesis, and regression records are committed with this ledger. |

## Acceptance Criteria

| Criterion | Status | Evidence or blocker |
| --- | --- | --- |
| A. No model-only vulnerability claim | COMPLETE | Both reported hypotheses came from fresh Bor command output and matched on an independent rerun. No model-only result is promoted to runtime evidence. |
| B. Execute actual Bor code | COMPLETE | `/tmp/bor-bin` ran a real isolated Bor dev node; the Go harness ran real Bor packages. |
| C. Capture actual account-state effects | COMPLETE | Harness captured balances, nonces, storage, gas, receipts, database writes, committed roots, and reopened state; RPC artifact captured live account proof before/after. |
| D. Discover without named vulnerable function | PARTIAL | The new loop consumes observed target output without a named vulnerable function, but the current Bor harness still supplies a bounded probe set. |
| E. Derive hypothesis from observation | COMPLETE | `derive_hypotheses()` derives only invariant violations present in runtime JSON; the baseline correctly generated none. |
| F. Independently reproduce/reject hypothesis | COMPLETE | Both objective probe artifacts contain a second real Bor execution classified `REPRODUCED_RUNTIME_OBSERVATION`. The public RPC state-override observation rejected canonical-state leakage. |
| G. Separate imported artifacts from runtime evidence | COMPLETE | Existing JSON ingestors now emit `IMPORTED_ARTIFACT`; live commands emit `RUNTIME_OBSERVATION`. |
| H. Distinguish confirmed/rejected/unresolved | COMPLETE | Runtime, reproduced, imported, and unresolved classifications are distinct; non-JSON verifier success is not promoted to independent verification. |
| I. Preserve regression behavior | PARTIAL | Focused Bor tests and Bor packages passed. The full suite has one deterministic failure in the existing web search test; no changed file is in its call path. |
| J. Integrate end to end | COMPLETE | Execution runner, RPC observer, runtime artifacts, provenance labels, tests, audit, and ledger are integrated on this branch. |

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
This is an engine differential finding, not by itself a canonical balance
discrepancy.

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
