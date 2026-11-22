# Bor Entrypoint Map

This is the integration map for tracing an account tuple from an RPC or smart-contract input through admission, EVM execution, serial/parallel state handling, trie persistence, and RPC readback.

Account tuple to carry at every checkpoint:

```text
(address, balance, nonce, code_hash, code_size, storage_root, selected_storage_slots)
```

The minimum state-change evidence is `before`, `engine_writes`, `after`, `post_state_root`, `receipt_status`, `tx_hash`, and `block_hash`. A changed tuple field without a matching declared engine write remains an attached unknown/out-of-band observation; it is not silently attributed to the EVM.

## Source Path

| Region | Exact source boundary | What crosses it | Synthetic fixture fields to bind |
| --- | --- | --- | --- |
| `bor.rpc.raw-transaction` | `/home/codespace/bor/bor-source/internal/ethapi/api.go:2220-2253` (`decodeRawTransaction`, `SendRawTransaction`) | Raw signed bytes become `types.Transaction`, then enter `SubmitTransaction`. | `rpc.method`, `raw_tx_hex`, `tx_hash`, `tx_type`, `nonce`, `from`, `to`, `value`, `gas`, `gas_price`, `fee_cap`, `tip_cap`, `data`, `access_list`, `blob_hashes`, `authorization_list` |
| `bor.rpc.local-signing` | `/home/codespace/bor/bor-source/internal/ethapi/api.go:2155-2185` (`SendTransaction`) | RPC arguments receive defaults, become a legacy transaction, are wallet-signed, then submitted. | `rpc.args`, `wallet_address`, `chain_id`, `default_nonce`, `default_gas`, `default_fee_fields`, `signature`, `signed_tx_hash` |
| `bor.rpc.submit-policy` | `/home/codespace/bor/bor-source/internal/ethapi/api.go:2117-2148` (`SubmitTransaction`) | Fee-cap policy, replay protection, backend `SendTx`, sender recovery, and contract-address logging. | `tx_fee_cap_policy`, `protected_signature`, `sender_recovered`, `send_tx_result`, `derived_contract_address`, `submission_error` |
| `bor.txpool.static-validation` | `/home/codespace/bor/bor-source/core/txpool/validation.go:61-150` (`ValidateTransaction`) | Fork/type gates, size, init-code length, gas bounds, value sign, gas limit, fee fields, signature, nonce overflow, intrinsic gas, tip, and blob validation. | `head_number`, `head_time`, `head_gas_limit`, `fork_rules`, `tx_size`, `init_code_size`, `intrinsic_gas`, `floor_data_gas`, `blob_count`, `signature_valid`, `validation_decision`, `validation_error` |
| `bor.txpool.state-validation` | `/home/codespace/bor/bor-source/core/txpool/validation.go:244-285` (`ValidateTransactionWithState`) | Pool-state nonce ordering, nonce gaps, balance/cost, replacement expenditure, and account existence checks. | `pool_nonce`, `pool_balance`, `tx_cost`, `existing_expenditure`, `existing_nonce_cost`, `first_nonce_gap`, `state_account_tuple`, `state_validation_decision` |
| `bor.rpc.call` | `/home/codespace/bor/bor-source/internal/ethapi/api.go:902-991` (`doCall`, `applyMessage`, `applyMessageWithEVM`) and `:1033-1075` (`Call`, `CallWithState`) | `eth_call`-style input receives block/state overrides, builds a message/EVM, executes `core.ApplyMessage`, and returns output/revert data without canonical block persistence. | `rpc_method=eth_call`, `call_from`, `call_to`, `calldata`, `call_value`, `call_gas`, `block_reference`, `state_overrides`, `block_overrides`, `return_data`, `revert_data`, `mutated_ephemeral_tuple` |
| `bor.rpc.estimate/access-list` | `/home/codespace/bor/bor-source/internal/ethapi/api.go:1125-1165` (`DoEstimateGas`) and `:1679-1775` (`AccessList`) | User-controlled call inputs are executed against copied/overridden state and may exercise guards, reads, and contract code before a transaction is submitted. | `estimation_args`, `access_list_input`, `override_accounts`, `override_storage`, `estimated_gas`, `accessed_addresses`, `accessed_slots`, `simulation_outcome` |
| `bor.state.read-at-block` | `/home/codespace/bor/bor-source/eth/api_backend.go:262-283` and `:290-319` (`StateAndHeaderByNumber/OrHash`) | RPC state reads resolve a header and open `StateAt` or `HistoricState`; canonicality and reorg context matter. | `block_number_or_hash`, `require_canonical`, `header_hash`, `header_root`, `state_open_mode`, `historic_fallback`, `state_read_error` |
| `bor.runtime.message-conversion` | `/home/codespace/bor/bor-source/core/state_transition.go:190-224` (`TransactionToMessage*`) | Transaction fields become the `Message` consumed by state transition; base-fee normalization changes effective gas price. | `message_from`, `message_to`, `message_nonce`, `message_value`, `message_data`, `message_gas_limit`, `message_gas_price`, `message_fee_cap`, `message_tip_cap`, `skip_nonce_checks`, `skip_transaction_checks` |
| `bor.runtime.serial-precheck` | `/home/codespace/bor/bor-source/core/state_transition.go:311-448` (`buyGas`, `preCheck`) | Balance needed for gas/value/blob fees, nonce, sender code/EOA status, fork gas rules, fee caps, blob rules, and authorization list shape are checked before execution. | `sender_before`, `required_upfront_balance`, `gas_pool_before`, `nonce_before`, `sender_code_hash`, `blob_base_fee`, `chain_rules`, `authorization_list`, `precheck_result`, `precheck_error` |
| `bor.runtime.serial-execute` | `/home/codespace/bor/bor-source/core/state_transition.go:473-594` (`execute`) | Intrinsic gas, value transfer guard, account preparation, top-level `CREATE` or `CALL`, nonce increment, and EIP-7702 authorization application. | `pre_state_root`, `sender_tuple_before`, `recipient_tuple_before`, `contract_creation`, `call_target`, `calldata`, `value`, `nonce_increment`, `authorization_effects`, `vm_return`, `vm_error`, `gas_used` |
| `bor.runtime.fee-settlement` | `/home/codespace/bor/bor-source/core/state_transition.go:616-694` and `/home/codespace/bor/bor-source/core/state_processor.go:230-272` | Effective tip is credited to coinbase; Bor base-fee burn is credited to the configured burnt contract; receipts/logs use the resulting values. | `effective_tip`, `base_fee`, `fee_burnt`, `burnt_contract`, `coinbase`, `sender_fee_delta`, `coinbase_delta`, `burn_delta`, `fee_transfer_log`, `balance_total_delta` |
| `bor.evm.call` | `/home/codespace/bor/bor-source/core/vm/evm.go:350-430` (`EVM.Call`) | Contract-to-contract calls perform value-transfer checks, account existence/create behavior, precompile dispatch, code resolution, nested execution, and snapshot revert. | `caller`, `callee`, `call_type`, `input`, `gas_forwarded`, `call_value`, `callee_tuple_before`, `callee_tuple_after`, `precompile`, `snapshot_id`, `reverted`, `nested_logs` |
| `bor.evm.create` | `/home/codespace/bor/bor-source/core/vm/evm.go:596-736` (`EVM.create`) and `:742-755` (`Create`, `Create2`) | Contract address derivation, collision checks, endowment, init-code execution, code deposit, and revert behavior can create or alter account tuples. | `creator`, `create_opcode`, `salt`, `init_code`, `init_code_hash`, `derived_address`, `endowment`, `target_tuple_before`, `target_storage_root`, `collision_guard`, `created_code_hash`, `created_tuple_after`, `creation_result` |
| `bor.evm.precompile` | `/home/codespace/bor/bor-source/core/vm/contracts.go:417-433` (`RunPrecompiledContract`) | Native precompile input/output and gas accounting can influence subsequent contract branches and writes. | `precompile_address`, `precompile_input`, `required_gas`, `supplied_gas`, `precompile_output`, `precompile_error`, `trace_parent` |
| `bor.state.serial-reads` | `/home/codespace/bor/bor-source/core/state/statedb.go:1017-1165` (`Exist`, `Empty`, balance/nonce/code/storage getters) | Serial account and storage reads provide the guards and values consumed by EVM execution. | `read_set`, `account_exists`, `account_empty`, `balance_read`, `nonce_read`, `code_hash_read`, `storage_root_read`, `storage_slot_reads`, `selfdestruct_marker_read` |
| `bor.state.serial-writes` | `/home/codespace/bor/bor-source/core/state/statedb.go:1254-1385` and `:1587-1605` (`SetBalance`, `SetNonce`, `SetCode`, `SetState`, `SelfDestruct`, `CreateAccount`) | Account mutations are journaled and recorded for balance, nonce, code, storage, destruction, and creation. | `write_set`, `balance_writes`, `nonce_writes`, `code_writes`, `storage_writes`, `selfdestructs`, `created_accounts`, `write_reasons`, `journal_entries` |
| `bor.state.parallel-reads` | `/home/codespace/bor/bor-source/core/state/parallel_statedb.go:638-735`, `:796-1070`, `:1076-1095` | BlockSTM/V2 reads consult MV state, prior destruction/creation metadata, and base state. `GetStorageRoot` is a critical differential boundary. | `tx_index`, `incarnation`, `mv_read_keys`, `dependency_tx`, `prior_created_at`, `prior_destructed_at`, `parallel_account_tuple`, `parallel_storage_root`, `base_read_error` |
| `bor.state.parallel-writes` | `/home/codespace/bor/bor-source/core/state/parallel_statedb.go:784-940`, `:1040-1060`, `:1154-1220` | Parallel writes are recorded into MV state; selfdestruct and account recreation must be visible to later transactions. | `mv_write_keys`, `mv_write_values`, `write_versions`, `parallel_selfdestruct`, `parallel_create`, `parallel_set_code`, `parallel_set_state`, `panicked`, `exec_error` |
| `bor.runtime.parallel-execute` | `/home/codespace/bor/bor-source/core/parallel_state_processor.go:101-155` and `:680-718` | Each task copies state, runs EVM execution, records read/write dependencies, detects invalid reads/panics, and delays fee application when needed. | `task_index`, `tx_hash`, `copy_id`, `incarnation`, `read_set`, `write_set`, `dependency_tx`, `invalid_read`, `fee_delay`, `fee_read_addresses`, `panic`, `exec_error` |
| `bor.runtime.parallel-settle` | `/home/codespace/bor/bor-source/core/parallel_state_processor.go:980-1034` | Settled MV writes are applied to final state, fee deltas are applied, roots are computed, and receipts are built. | `settled_tx_index`, `settled_write_set`, `settlement_order`, `final_tuple`, `final_state_root`, `receipt_post_state`, `receipt_cumulative_gas`, `settlement_error` |
| `bor.engine.finalize` | `/home/codespace/bor/bor-source/core/parallel_state_processor.go:1225-1253` | Consensus-engine finalization can add state-sync/reward writes after transaction execution and before root/witness collection. | `engine_name`, `finalize_inputs`, `engine_account_writes`, `state_sync_logs`, `reward_accounts`, `root_before_finalize`, `root_after_finalize` |
| `bor.block.process` | `/home/codespace/bor/bor-source/core/blockchain.go:1313-1415` (`ProcessBlock`) and `:4284-4355` (`processBlock`) | Block execution selects the processor, returns receipts/logs/gas/state, and feeds validation/persistence. | `block_hash`, `parent_hash`, `block_number`, `tx_hashes`, `processor_mode`, `serial_root`, `parallel_root`, `receipts`, `logs`, `gas_used`, `process_error` |
| `bor.persistence.state-commit` | `/home/codespace/bor/bor-source/core/state/statedb.go:2198-2245`, `:2356-2445` (`commit`, `Commit`, `CommitWithUpdate`) | Dirty accounts/storage/code become trie updates and a post-state root; flat diffs expose account/storage/destruction/code changes. | `origin_root`, `post_state_root`, `state_update`, `flat_diff.accounts`, `flat_diff.storage`, `flat_diff.destructs`, `flat_diff.code`, `trie_nodes`, `commit_error` |
| `bor.persistence.block-head` | `/home/codespace/bor/bor-source/core/blockchain.go:3069-3105`, `:3220-3270`, `:5138-5255` | Block/state write paths persist state, receipts, logs, canonical head, and pipelined state status. | `block_header`, `block_body`, `state_root`, `receipt_root`, `receipts`, `logs`, `canonical_head_before`, `canonical_head_after`, `write_status`, `pipelined_root`, `wait_for_state_commit` |
| `bor.persistence.rawdb` | `/home/codespace/bor/bor-source/core/rawdb/accessors_chain.go:798-822`, `:889-893`; `/home/codespace/bor/bor-source/core/rawdb/accessors_trie.go:160-201`; `/home/codespace/bor/bor-source/core/rawdb/accessors_state.go:50-99` | Receipts, blocks, account/storage trie nodes, and contract code are encoded into the configured database scheme. | `db_backend`, `db_path`, `state_scheme`, `receipt_key`, `block_key`, `trie_owner`, `trie_path`, `trie_hash`, `trie_node_digest`, `code_hash`, `code_digest`, `db_put_error` |
| `bor.rpc.readback` | `/home/codespace/bor/bor-source/internal/ethapi/api.go:465-500`, `:1906-1925`, plus `/home/codespace/bor/bor-source/eth/api_backend.go:262-319` | RPC proofs, nonce reads, receipts, and state queries read the committed root and should reconcile with execution evidence. | `readback_method`, `query_block`, `query_tx_hash`, `queried_address`, `queried_slots`, `returned_balance`, `returned_nonce`, `returned_code_hash`, `returned_storage_root`, `proof_nodes`, `readback_error` |

## Validation Boundaries

These are the checks that must be represented as distinct RSVE operations. A fixture should record both the decision and the exact input tuple used by the check.

| Check family | Source | Required decision fields |
| --- | --- | --- |
| Transaction admission | `core/txpool/validation.go:61-150` | `accepted`, `error_class`, `fork`, `type`, `gas`, `fee_caps`, `signature`, `intrinsic_gas`, `blob_rules` |
| Stateful pool admission | `core/txpool/validation.go:244-285` | `sender_nonce`, `tx_nonce`, `sender_balance`, `tx_cost`, `queued_cost`, `replacement_cost`, `nonce_gap` |
| Consensus precheck | `core/state_transition.go:356-448` | `nonce_match`, `sender_is_eoa`, `gas_limit_ok`, `fee_cap_ok`, `blob_fee_ok`, `authorization_shape`, `upfront_balance_ok` |
| Top-level value transfer | `core/state_transition.go:544-551` | `sender_balance_before`, `value`, `can_transfer`, `transfer_applied` |
| Contract collision | `core/vm/evm.go:596-654` | `derived_address`, `nonce`, `code_hash`, `nonce_at_target`, `storage_root`, `collision_result` |
| Nested call transfer/existence | `core/vm/evm.go:350-395` | `caller_balance`, `value`, `callee_exists`, `callee_is_precompile`, `account_created`, `transfer_result` |
| Revert/snapshot | `core/vm/evm.go:368-429` | `snapshot_id`, `execution_error`, `reverted_fields`, `gas_consumed`, `logs_retained` |
| Parallel dependency validation | `core/parallel_state_processor.go:101-122`, `:980-1018` | `read_versions`, `write_versions`, `dependency_tx`, `invalid_read`, `panic`, `base_read_error`, `settled_or_discarded` |
| Fee settlement | `core/state_transition.go:633-694`; `core/parallel_state_processor.go:234-260` | `sender_fee_delta`, `coinbase_delta`, `burn_delta`, `fee_log`, `fee_delay`, `settlement_order` |
| Root/receipt persistence | `core/state_processor.go:298-328`; `core/state/statedb.go:2400-2429`; `core/rawdb/accessors_chain.go:798-814` | `receipt_status`, `receipt_post_state`, `cumulative_gas`, `state_root`, `receipt_key`, `db_write_result` |

## Synthetic Fixture Contract

Use deterministic synthetic values where a live chain, signature, address, or database is unavailable. Synthetic values must be labelled `fixture.synthetic=true` and must be carried through every event; they are not observations.

```json
{
  "fixture": {
    "synthetic": true,
    "target": "polygon-bor",
    "build_hash": "c72e248587a19b1c93eda95871c46b53071e58fd",
    "chain_id": 137,
    "fork_rules": {"london": true, "shanghai": true, "cancun": true, "prague": true},
    "block": {
      "number": 90000000,
      "hash": "0x<synthetic-block-hash>",
      "parent_hash": "0x<synthetic-parent-hash>",
      "state_root_before": "0x<synthetic-pre-root>",
      "state_root_after_serial": "0x<synthetic-serial-root>",
      "state_root_after_parallel": "0x<synthetic-parallel-root>",
      "coinbase": "0x<synthetic-coinbase>",
      "base_fee": 1000000000,
      "gas_limit": 30000000
    },
    "transaction": {
      "hash": "0x<synthetic-tx-hash>",
      "from": "0x<synthetic-sender>",
      "to": "0x<synthetic-target-or-null>",
      "nonce": 7,
      "value": 1,
      "gas": 1000000,
      "gas_price": 2000000000,
      "fee_cap": 3000000000,
      "tip_cap": 1000000000,
      "data": "0x<synthetic-calldata-or-initcode>",
      "access_list": [],
      "authorization_list": [],
      "salt": "0x<synthetic-create2-salt>"
    },
    "account_before": {
      "address": "0x<synthetic-address>",
      "balance": 1000000000000000000,
      "nonce": 1,
      "code_hash": "0x<synthetic-code-hash>",
      "code_size": 32,
      "storage_root": "0x<synthetic-storage-root>",
      "storage_slots": {"0x<synthetic-slot>": "0x<synthetic-value>"}
    },
    "account_after": {
      "address": "0x<synthetic-address>",
      "balance": 999999999000000000,
      "nonce": 2,
      "code_hash": "0x<synthetic-code-hash-after>",
      "code_size": 40,
      "storage_root": "0x<synthetic-storage-root-after>",
      "storage_slots": {"0x<synthetic-slot>": "0x<synthetic-value-after>"}
    },
    "engine_writes": [
      "balance",
      "nonce",
      "code_hash",
      "storage_root"
    ],
    "receipt": {
      "status": 1,
      "tx_hash": "0x<synthetic-tx-hash>",
      "block_hash": "0x<synthetic-block-hash>",
      "gas_used": 21000,
      "cumulative_gas_used": 21000,
      "post_state_root": "0x<synthetic-post-root>",
      "persisted": true
    },
    "runtime": {
      "task_index": 0,
      "incarnation": 1,
      "read_set": ["account:<address>:balance", "account:<address>:storage_root"],
      "write_set": ["account:<address>:balance", "account:<address>:storage_root"],
      "dependency_tx": 0,
      "settlement_order": [0],
      "invalid_read": false,
      "panic": false
    },
    "persistence": {
      "db_path": "fixture://bor-state",
      "state_scheme": "hash-or-path",
      "trie_node_digests": ["sha256:<synthetic-node-digest>"],
      "batch_id": "synthetic-batch-0"
    }
  }
}
```

For the existing storage-root differential, bind the exact sequence `selfdestruct`, `recreate-with-storage`, `create2-collision-check` and these fields: `serial_storage_root`, `parallel_storage_root`, `serial_nonempty`, `parallel_nonempty`, `serial_create2_admitted`, `parallel_create2_admitted`, `divergence`, and `source_refs`. The current RSVE ingestion contract is `/home/codespace/bor/RSVE/src/rsve/bor_evidence.py:263-413`.

For account-integrity comparison, bind `account_before`, `account_after`, `engine_writes`, `environment_events`, and `unknowns`; the current parser and out-of-band calculation are `/home/codespace/bor/RSVE/src/rsve/bor_evidence.py:417-483`, with attachment at `:531-570`.

## RSVE Region Attachments

Attach these regions to every Bor investigation. A region may be observed, modeled, or unknown independently; an unknown region stays in the report until an adapter supplies evidence.

| Region ID | Attach to | Required evidence or synthetic binding | Unknowns that remain attached |
| --- | --- | --- | --- |
| `bor.rpc.ingress` | raw/local send, call, estimate, access-list operations | RPC method, decoded/signed tx fields, caller identity, block reference, override set | wallet/provider behavior, transport framing, caller-side retries, RPC middleware |
| `bor.txpool.admission` | static and stateful validation | validation result/error, head rules, sender tuple, pool expenditure | subpool selection, replacement race, pending-state reset timing |
| `bor.evm.contract` | `EVM.Call`, `Create`, `Create2`, precompiles | nested call trace, calldata/initcode, derived addresses, value transfers, code/storage reads and writes | opaque precompile internals, dynamic contract dispatch not in fixture, gas refund edge paths |
| `bor.state.serial` | `StateDB` getters/setters and commit | ordered read/write set, account tuple deltas, journal, root | trie reader cache effects, unmodeled hooks, database read timing |
| `bor.state.parallel` | `ParallelStateDB`, MVHashMap/V2, task settlement | tx/index/incarnation, versioned reads/writes, dependencies, invalid-read/panic/error flags | scheduler interleavings, worker reuse, speculative incarnation coverage, missing read-set keys |
| `bor.engine.finalize` | consensus-engine finalization | engine-added account writes, state-sync/reward inputs, root before/after finalize | external consensus payload provenance, engine-specific hidden state |
| `bor.persistence.trie` | state commit and trie node writes | origin/post roots, account/storage/code node digests, state scheme, commit errors | compaction/pruning order, filesystem durability, crash recovery, hardware/storage faults |
| `bor.persistence.database` | rawdb block/receipt/trie/code accessors | logical key, value digest, batch/transaction ID, read-after-write result | backend implementation, cache eviction, torn writes, corruption outside the adapter |
| `bor.rpc.readback` | proof, nonce, balance, receipt, code, and storage queries | queried root/block, returned account tuple, proof/node digests, receipt fields | reorg timing, noncanonical reads, remote RPC proxy behavior |
| `bor.runtime.process` | Bor process and Go runtime | pid/start time, executable digest, argv/env digests, goroutine/task IDs, signal/panic events, `/proc` map digest | native memory corruption, scheduler interleavings, signals not captured, dynamically loaded code |
| `bor.runtime.memory` | account/state buffers and process address space | buffer digest before/after, pointer/offset identity, page-fault counters, allocator/runtime event IDs | hardware faults, DMA/device memory, unobserved unsafe code, exact CPU memory ordering |
| `bor.host.kernel` | host OS boundary | kernel release/config digest, syscall/file-I/O trace, cgroup/namespace IDs, resource limits, fault signals | kernel compromise, hypervisor/hardware behavior, untraced syscalls, clock/entropy sources |
| `bor.host.filesystem` | database/config/code files | fixture root, file digests, open/read/write/fsync events, inode/device IDs | remote filesystems, storage-controller behavior, post-capture tampering |

The current profile already keeps uninstrumented runtime regions attached through `BorStorageRootRegressionProfile.attach_unknown_regions` at `/home/codespace/bor/RSVE/src/rsve/bor_profile.py:244-253`. The current source-backed region list is assembled at `:782-823`; extend that list when a new boundary is discovered rather than dropping the boundary from the report.

## Adapter Binding Order

1. Bind `bor.rpc.ingress` and `bor.txpool.admission` from the RPC request and pool decision.
2. Bind `bor.runtime.message-conversion` and all precheck fields before invoking the EVM model.
3. Bind nested EVM events and every account/storage read/write to `bor.evm.contract`, `bor.state.serial`, or `bor.state.parallel` according to the execution path.
4. Bind serial/parallel dependency metadata and compare the final account tuple, receipt, and state root.
5. Bind `bor.engine.finalize` writes before root calculation.
6. Bind trie/database logical writes and readback proofs after commit.
7. Attach process, memory, kernel, and filesystem observations to the same run/trace ID. If a host observation cannot be causally connected to an account delta, retain it as an attached unknown rather than converting it into a cause.

The RSVE graph/workspace mechanisms for keeping omitted seams explicit are `/home/codespace/bor/RSVE/src/rsve/workspace.py:435-515` and `/home/codespace/bor/RSVE/src/rsve/workspace.py:600-669`. The Linux extension supplies host facts at `/home/codespace/bor/RSVE/src/rsve/extensions/linux.py:19-165`; it should populate the host regions above without replacing the Bor state evidence. The EVM extension exposes transaction/call entries, state capture, traces, and snapshots at `/home/codespace/bor/RSVE/src/rsve/extensions/evm.py:76-115`, `:256-280`, and `:326-343`.

