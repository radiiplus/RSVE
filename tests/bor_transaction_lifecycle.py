import unittest

from rsve import (
    Authorization,
    Decision,
    Entry,
    Graph,
    Guard,
    Limits,
    Model,
    Objective,
    Operation,
    Outcome,
    Order,
    Persona,
    Planner,
    Same,
    State,
    Workspace,
)
from rsve.result import Status


BOR_COMMIT = "c72e248587a19b1c93eda95871c46b53071e58fd"
TARGET = "polygon-bor"
SCOPE = "bor-transaction-lifecycle"

SYNTHETIC_ENVIRONMENT = {
    "host.os": "linux",
    "host.arch": "amd64",
    "toolchain.go": "go1.26.11",
    "chain.id": 137,
    "chain.fork_profile": "synthetic-bor-develop",
    "block.number": 100_000_000,
    "block.time": 1_700_000_000,
    "block.gas_limit": 30_000_000,
    "block.base_fee": 30,
    "block.coinbase": "0x00000000000000000000000000000000000000cb",
    "state.root": "0x" + "11" * 32,
    "state.backend": "resettable-memory",
    "vm.config": "deterministic-no-tracing",
    "clock.source": "fixed-fixture",
    "randomness.source": "fixed-fixture",
    "sender.address": "0x" + "22" * 20,
    "recipient.address": "0x" + "33" * 20,
}


def accepted(state, *, observation, effects, writes):
    return Outcome(
        Decision.ACCEPT,
        state,
        observation=observation,
        effects=effects,
        writes=writes,
        guard=True,
    )


def rejected(state, reason):
    return Outcome(
        Decision.REJECT,
        state,
        observation={"reason": reason},
        guard=False,
        terminal=True,
    )


def errored(state, reason):
    return Outcome(
        Decision.ERROR,
        state,
        observation={"reason": reason},
        terminal=True,
        uncertainty=(reason,),
    )


def bor_profile() -> Persona:
    return Persona(
        profile_id=f"bor-develop:{BOR_COMMIT[:12]}",
        family="blockchain-client",
        component="polygon-bor",
        implementation="github.com/0xPolygon/bor",
        version="develop",
        build_digest=BOR_COMMIT,
        execution_scope={
            "source_batch": "transaction-lifecycle",
            "admission": "core/txpool/validation.go",
            "execution": "core/state_processor.go,core/state_transition.go",
            "receipts": "core/state_processor.go,core/types/receipt.go",
            "chain_id": str(SYNTHETIC_ENVIRONMENT["chain.id"]),
            "state_backend": SYNTHETIC_ENVIRONMENT["state.backend"],
            "reset_policy": "fixture-reset-before-each-run",
        },
    )


def bor_graph() -> Graph:
    return Graph.for_profile(
        bor_profile(),
        graph_id="bor-transaction-lifecycle",
        region_id="bor.execution",
        region_name="Bor transaction lifecycle",
    )


def lifecycle_model() -> Model:
    initial = State({
        "pool.pending": False,
        "pool.rejection": "",
        "tx.hash": "",
        "execution.done": False,
        "execution.outcome": "",
        "execution.gas_used": 0,
        "receipt.present": False,
        "receipt.status": "none",
        "receipt.tx_hash": "",
        "receipt.gas_used": 0,
        "receipt.cumulative_gas_used": 0,
    })

    success = {
        "step": "admit",
        "tx_case": "valid",
        "tx_hash": "0xsuccess",
        "execution": "success",
        "gas_used": 21_000,
    }
    revert = {
        "step": "admit",
        "tx_case": "valid",
        "tx_hash": "0xrevert",
        "execution": "revert",
        "gas_used": 24_000,
    }
    invalid = {
        "step": "admit",
        "tx_case": "insufficient_funds",
        "tx_hash": "0xinvalid",
        "execution": "success",
        "gas_used": 21_000,
    }

    def admit(state: State, request):
        if request.get("step") != "admit":
            return (rejected(state, "admission step required"),)
        if request.get("tx_case") != "valid":
            return (rejected(
                state.update(**{"pool.rejection": "insufficient funds"}),
                "stateful admission rejected",
            ),)
        return (accepted(
            state.update(**{"pool.pending": True, "tx.hash": request["tx_hash"]}),
            observation={"stage": "admission", "accepted": True},
            effects=("txpool.admitted",),
            writes=frozenset({"pool.pending", "tx.hash"}),
        ),)

    def execute(state: State, request):
        if not state.get("pool.pending") or request.get("tx_hash") != state.get("tx.hash"):
            return (rejected(state, "transaction is not pending"),)
        if request.get("step") != "execute":
            return (rejected(state, "execution step required"),)
        if request.get("execution") == "core-error":
            return (errored(state, "execution core error"),)
        return (accepted(
            state.update(**{
                "execution.done": True,
                "execution.outcome": request["execution"],
                "execution.gas_used": request["gas_used"],
            }),
            observation={"stage": "execution", "outcome": request["execution"]},
            effects=("state.transition",),
            writes=frozenset({"execution.done", "execution.outcome", "execution.gas_used"}),
        ),)

    def receipt(state: State, request):
        if not state.get("execution.done") or request.get("tx_hash") != state.get("tx.hash"):
            return (rejected(state, "execution result is unavailable"),)
        if request.get("step") != "receipt":
            return (rejected(state, "receipt step required"),)
        status = "failed" if state.get("execution.outcome") == "revert" else "success"
        gas_used = int(state.get("execution.gas_used", 0))
        return (accepted(
            state.update(**{
                "receipt.present": True,
                "receipt.status": status,
                "receipt.tx_hash": state["tx.hash"],
                "receipt.gas_used": gas_used,
                "receipt.cumulative_gas_used": gas_used,
            }),
            observation={"stage": "receipt", "status": status},
            effects=("receipt.created", "receipt.fields.derived"),
            writes=frozenset({
                "receipt.present", "receipt.status", "receipt.tx_hash",
                "receipt.gas_used", "receipt.cumulative_gas_used",
            }),
        ),)

    # The relation helpers below keep rejected/error branches explicit while
    # leaving the source-derived operation boundary visible in each entry.
    operations = (
        Operation("txpool.admit", Entry("txpool.add"), relation=admit, provenance="core/txpool/validation.go"),
        Operation("core.execute", Entry("core.apply_transaction"), relation=execute, provenance="core/state_processor.go"),
        Operation("core.receipt", Entry("core.make_receipt"), relation=receipt, provenance="core/types/receipt.go"),
    )
    execute_requests = tuple(
        dict(item, step="execute") for item in (success, revert)
    )
    receipt_requests = tuple(
        dict(item, step="receipt") for item in (success, revert)
    )
    return Model(
        TARGET,
        initial,
        (success, revert, invalid) + execute_requests + receipt_requests,
        operations,
        build_hash=BOR_COMMIT,
        model_version="bor-transaction-lifecycle.v1",
        assumptions=(
            "transaction signature and fork selection are represented by tx_case",
            "EVM execution is represented by success, revert, or core-error outcomes",
            "receipt persistence and RPC indexing are outside this batch",
        ),
    )


class Suite(unittest.TestCase):
    def setUp(self):
        self.model = lifecycle_model()
        self.workspace = Workspace.flat(
            self.model,
            graph=bor_graph(),
            environment=State(SYNTHETIC_ENVIRONMENT),
        )
        self.authorization = Authorization("rsve-bor-lifecycle", frozenset({SCOPE}), frozenset({TARGET}))

    def test_profile_is_pinned_to_the_source_batch(self):
        profile = bor_profile()
        self.assertEqual(profile.build_digest, BOR_COMMIT)
        self.assertEqual(profile.execution_scope["source_batch"], "transaction-lifecycle")
        self.assertTrue(self.workspace.validate().structural)

    def test_valid_transaction_reaches_success_receipt(self):
        objective = Objective(
            "bor-success-receipt",
            TARGET,
            SCOPE,
            (
                Same("receipt.present", True),
                Same("receipt.status", "success"),
                Same("receipt.tx_hash", "0xsuccess"),
                Order(("txpool.add", "core.apply_transaction", "core.make_receipt")),
                Guard(),
            ),
            state_keys=frozenset({"receipt.present", "receipt.status", "receipt.tx_hash"}),
            budget=Limits(max_trace_length=3, max_states=1_000),
        )
        report = Planner().plan(self.model, objective, self.authorization, workspace=self.workspace)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.witness.final_state["receipt.status"], "success")
        self.assertEqual(
            [event.entry_point for event in report.witness.events],
            ["txpool.add", "core.apply_transaction", "core.make_receipt"],
        )

    def test_revert_execution_produces_failed_receipt(self):
        objective = Objective(
            "bor-revert-receipt",
            TARGET,
            SCOPE,
            (
                Same("receipt.status", "failed"),
                Same("receipt.tx_hash", "0xrevert"),
                Order(("txpool.add", "core.apply_transaction", "core.make_receipt")),
            ),
            state_keys=frozenset({"receipt.status", "receipt.tx_hash"}),
            budget=Limits(max_trace_length=3, max_states=1_000),
        )
        report = Planner().plan(self.model, objective, self.authorization, workspace=self.workspace)
        self.assertEqual(report.status, Status.SAT_CANDIDATE)
        self.assertEqual(report.witness.final_state["receipt.status"], "failed")

    def test_admission_rejection_does_not_create_a_receipt(self):
        operation = self.model.operations[0]
        move = self.workspace.moves(
            self.workspace.start(),
            operation.entry_point.name,
            {"step": "admit", "tx_case": "insufficient_funds", "tx_hash": "0xinvalid"},
            operation=operation,
        )[0]
        self.assertEqual(move.outcome.decision, Decision.REJECT)
        self.assertFalse(move.after.target.get("receipt.present"))


if __name__ == "__main__":
    unittest.main()
