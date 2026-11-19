"""Controlled local EVM adapter backed by Foundry's Anvil/Forge/Cast tools."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .adapters import CapabilityReport, Capabilities
from .environment import LinuxEnvironmentAdapter
from .ir import EnvironmentObservation, Evidence, TargetIdentity
from .model import Authorization, EntryPoint, ExecutionMode, Fidelity, Provenance, State, TraceEvent
from .runtime_contracts import EvmCapabilities, EvmExecutionContext
from .profile import ExecutionProfile, LayerPin


@dataclass(frozen=True)
class EvmReplayRun:
    run_id: str
    events: tuple[TraceEvent, ...]
    outcome: Mapping[str, Any]
    outcome_hash: str


@dataclass(frozen=True)
class EvmReplayReport:
    runs: tuple[EvmReplayRun, ...]
    stable: bool
    replayability: str = "partially_replayable"
    limitations: tuple[str, ...] = ()


class EvmTargetAdapter:
    """Run one explicitly supplied Solidity fixture on a local Anvil chain."""

    def __init__(
        self,
        fixture: str | Path,
        *,
        target_id: str = "evm-target",
        scope: str = "evm-lab",
        port: int = 18545,
        anvil_command: str | None = None,
        forge_command: str | None = None,
        cast_command: str | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        self.fixture = Path(fixture)
        self.target_id = target_id
        self.scope = scope
        self.port = port
        self.anvil_command = anvil_command or self._tool("anvil")
        self.forge_command = forge_command or self._tool("forge")
        self.cast_command = cast_command or self._tool("cast")
        self.timeout_s = timeout_s
        self._process: subprocess.Popen[str] | None = None
        self._compile_dir: tempfile.TemporaryDirectory[str] | None = None
        self._account = ""
        self._contract = ""
        self._bytecode = ""
        self._baseline: dict[str, Any] | None = None
        self._run_counter = 0
        self._last_output: dict[str, Any] = {}
        self._runtime_version = "unknown"

    @property
    def evm_capabilities(self) -> EvmCapabilities:
        return EvmCapabilities(
            local_chain=True,
            transaction_entries=True,
            call_entries=True,
            account_state=True,
            storage_state=True,
            block_context=True,
            revert_outcomes=True,
            logs_events=True,
            deterministic_replay=True,
            symbolic_backend=False,
            limitations=(
                "fixture ABI and bytecode are supplied by the selected Solidity build",
                "exact host/process replay is outside Anvil snapshot scope",
                "no automatic contract discovery beyond the fixture manifest",
            ),
        )

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(
            discover_entries=True,
            invoke=True,
            replay=True,
            capture_state=True,
            capture_traces=True,
            snapshot=True,
        )

    def capability_report(self) -> CapabilityReport:
        return CapabilityReport(
            supported_entry_types=frozenset({"transaction", "call"}),
            supported_event_hooks=frozenset({"transaction.submit", "transaction.receipt", "call.outcome", "evm.log"}),
            state_capture=True,
            snapshot_reset=True,
            deterministic_replay=True,
            limitations=self.evm_capabilities.limitations,
            side_effects=("local Anvil process and in-memory chain state",),
        )

    def identity(self) -> Mapping[str, str]:
        self._detect_runtime()
        return {
            "target_id": self.target_id,
            "runtime": "evm",
            "runtime_version": self._runtime_version,
            "platform": "anvil-local",
            "platform_version": self._tool_version(self.anvil_command),
            "build_hash": self._build_hash(),
            "adapter": "rsve.evm",
            "adapter_version": "1",
        }

    def target_identity(self) -> TargetIdentity:
        identity = self.identity()
        return TargetIdentity(
            target_id=identity["target_id"],
            runtime=identity["runtime"],
            runtime_version=identity["runtime_version"],
            platform=identity["platform"],
            platform_version=identity["platform_version"],
            build_hash=identity["build_hash"],
            adapter=identity["adapter"],
            adapter_version=identity["adapter_version"],
            capabilities=frozenset({"transaction", "call", "storage", "logs", "snapshot"}),
            provenance=Provenance("evm-adapter", "1", (str(self.fixture),), Fidelity.OBSERVED),
        )

    def execution_profile(self) -> ExecutionProfile:
        return ExecutionProfile.from_target(
            self.identity(),
            self.environment_observation(),
            extra_pins=(
                LayerPin("tool", "forge", self._tool_version(self.forge_command), source="evm.toolchain"),
            ),
        )

    def environment_observation(self) -> EnvironmentObservation:
        self._detect_runtime()
        context = self.chain_context() if self._process and self._process.poll() is None else None
        profile = LinuxEnvironmentAdapter(self.fixture.parent).observe() if platform.system().lower() == "linux" else EnvironmentObservation(
            facts={"os": platform.system().lower(), "kernel": platform.release()},
            unknown=("environment_profile", "memory_model", "scheduler", "snapshot_scope"),
        )
        facts = dict(profile.facts)
        facts.update({
            "runtime": self._runtime_version,
            "anvil_version": self._tool_version(self.anvil_command),
            "forge_version": self._tool_version(self.forge_command),
            "chain_id": context.chain_id if context else "unknown",
            "rpc": f"http://127.0.0.1:{self.port}",
            "mining": "automined",
        })
        return EnvironmentObservation(
            facts=facts,
            unknown=tuple(sorted(set(profile.unknown) | {"host_clock", "external_services"})),
            redacted_keys=profile.redacted_keys + ("private_keys",),
            profile_id=profile.profile_id,
            capabilities=profile.capabilities,
        )

    def prepare(self) -> None:
        if self._process and self._process.poll() is None:
            return
        self._detect_runtime()
        self._process = subprocess.Popen(
            [self.anvil_command, "--port", str(self.port), "--accounts", "1", "--silent"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + self.timeout_s
        while time.monotonic() < deadline:
            try:
                accounts = self._rpc("eth_accounts")
                if accounts:
                    break
            except (OSError, RuntimeError, ValueError):
                time.sleep(0.05)
        else:
            raise TimeoutError("Anvil did not start its JSON-RPC endpoint")
        self._account = accounts[0]
        self._compile_and_deploy()
        self._baseline = self.snapshot()

    def teardown(self) -> None:
        process = self._process
        self._process = None
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=self.timeout_s)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=self.timeout_s)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        if self._compile_dir is not None:
            self._compile_dir.cleanup()
            self._compile_dir = None

    def declared_entries(self) -> tuple[EntryPoint, ...]:
        return (
            EntryPoint("increment", capabilities=frozenset({"transaction"}), provenance=Provenance("evm-fixture", "1", (str(self.fixture),), Fidelity.MODELED)),
            EntryPoint("read", capabilities=frozenset({"call"}), provenance=Provenance("evm-fixture", "1", (str(self.fixture),), Fidelity.MODELED)),
        )

    def discover_entries(self) -> tuple[EntryPoint, ...]:
        self.prepare()
        return self.declared_entries()

    def snapshot(self) -> dict[str, Any]:
        self.prepare() if self._process is None else None
        return {"snapshot_id": self._rpc("evm_snapshot"), "contract": self._contract}

    def reset(self, snapshot: Mapping[str, Any]) -> None:
        if not self._rpc("evm_revert", [snapshot["snapshot_id"]]):
            raise RuntimeError("Anvil rejected snapshot restore")
        if isinstance(snapshot, dict):
            snapshot["snapshot_id"] = self._rpc("evm_snapshot")

    def invoke(self, entry_point: str, request: Mapping[str, Any], authorization: Authorization) -> tuple[TraceEvent, ...]:
        if not authorization.permits(self.target_id, self.scope):
            raise PermissionError(f"authorization does not permit {self.target_id!r} in {self.scope!r}")
        return self.execute_trace(({"entry_point": entry_point, "request": dict(request)},), authorization)

    def execute_trace(self, interactions: Sequence[Mapping[str, Any]], authorization: Authorization) -> tuple[TraceEvent, ...]:
        if not authorization.permits(self.target_id, self.scope):
            raise PermissionError(f"authorization does not permit {self.target_id!r} in {self.scope!r}")
        self.prepare()
        self._run_counter += 1
        run_id = f"run-{self._run_counter:06d}"
        trace_id = "trace-" + self._digest(list(interactions))[:20]
        events: list[TraceEvent] = []
        for interaction in interactions:
            entry = str(interaction["entry_point"])
            request = dict(interaction.get("request", {}))
            before = self._read_count()
            accepted = True
            receipt: Mapping[str, Any] | None = None
            if entry == "increment":
                data = self._calldata("increment(uint256,string)", request.get("amount", 0), request.get("canary", ""))
                tx_hash = self._rpc("eth_sendTransaction", [{"from": self._account, "to": self._contract, "data": data}])
                receipt = self._wait_receipt(tx_hash)
                accepted = receipt.get("status") in ("0x1", "0x01", 1, True)
                after = self._read_count()
                event = self._event(
                    "state.mutation" if accepted else "guard.decision",
                    entry,
                    request,
                    before,
                    after,
                    {"accepted": accepted, "count": after, "transaction_hash": tx_hash},
                    run_id,
                    trace_id,
                    len(events),
                    "evm.fixture.state" if accepted else "evm.fixture.guard",
                    accepted,
                )
            elif entry == "read":
                after = self._read_count()
                event = self._event("call.outcome", entry, request, before, after, {"accepted": True, "count": after}, run_id, trace_id, len(events), "evm.fixture.state", True)
            else:
                raise ValueError(f"unsupported EVM fixture entry: {entry}")
            events.append(event)
            self._last_output = {"outcome": {"accepted": accepted, "count": after}, "receipt": dict(receipt or {})}
        return tuple(events)

    def collect_output(self) -> Mapping[str, Any]:
        return dict(self._last_output)

    def replay(self, interactions: Sequence[Mapping[str, Any]], *, runs: int = 1, authorization: Authorization | None = None) -> EvmReplayReport:
        if runs <= 0:
            raise ValueError("runs must be positive")
        authorization = authorization or Authorization("evm-replay", frozenset({self.scope}), frozenset({self.target_id}))
        if not authorization.permits(self.target_id, self.scope):
            raise PermissionError(f"authorization does not permit {self.target_id!r} in {self.scope!r}")
        self.prepare()
        baseline = self._baseline or self.snapshot()
        reports: list[EvmReplayRun] = []
        for _ in range(runs):
            self.reset(baseline)
            events = self.execute_trace(interactions, authorization)
            outcome = dict(self._last_output.get("outcome", {}))
            reports.append(EvmReplayRun(events[0].run_id if events else f"run-{self._run_counter:06d}", events, outcome, self._digest(outcome)))
        signatures = {self._digest({"events": [self._semantic_event(event) for event in run.events], "outcome": run.outcome}) for run in reports}
        return EvmReplayReport(tuple(reports), len(signatures) == 1, "partially_replayable", self.capability_report().limitations)

    def chain_context(self) -> EvmExecutionContext:
        block_number = int(self._rpc("eth_blockNumber"), 16)
        block = self._rpc("eth_getBlockByNumber", [hex(block_number), False])
        return EvmExecutionContext(
            chain_id=str(int(self._rpc("eth_chainId"), 16)),
            block_number=block_number,
            timestamp=int(block["timestamp"], 16) if block and block.get("timestamp") else None,
            base_fee=int(block["baseFeePerGas"], 16) if block and block.get("baseFeePerGas") else None,
            gas_limit=int(block["gasLimit"], 16) if block and block.get("gasLimit") else None,
            sender=self._account or None,
        )

    def _compile_and_deploy(self) -> None:
        self._compile_dir = tempfile.TemporaryDirectory(prefix="rsve-evm-")
        root = Path(self._compile_dir.name)
        source_dir = root / "src"
        source_dir.mkdir()
        shutil.copy2(self.fixture, source_dir / self.fixture.name)
        subprocess.run(
            [self.forge_command, "build", "--root", str(root), "--out", str(root / "out"), "--cache-path", str(root / "cache")],
            check=True,
            capture_output=True,
            text=True,
        )
        artifacts = list((root / "out").rglob(f"{self.fixture.stem}.json"))
        if not artifacts:
            raise RuntimeError("Forge produced no fixture artifact")
        artifact = json.loads(artifacts[0].read_text(encoding="utf-8"))
        self._bytecode = artifact["bytecode"].get("object", "")
        if not self._bytecode:
            raise RuntimeError("fixture artifact has no deployable bytecode")
        deploy_data = self._bytecode if self._bytecode.startswith("0x") else "0x" + self._bytecode
        tx_hash = self._rpc("eth_sendTransaction", [{"from": self._account, "data": deploy_data}])
        receipt = self._wait_receipt(tx_hash)
        self._contract = receipt["contractAddress"]

    def _read_count(self) -> int:
        output = subprocess.run(
            [self.cast_command, "call", self._contract, "count()(uint256)", "--rpc-url", f"http://127.0.0.1:{self.port}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return int(output, 0)

    def _calldata(self, signature: str, *arguments: Any) -> str:
        output = subprocess.run(
            [self.cast_command, "calldata", signature, *(str(argument) for argument in arguments)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return output

    def _wait_receipt(self, transaction_hash: str) -> Mapping[str, Any]:
        deadline = time.monotonic() + self.timeout_s
        while time.monotonic() < deadline:
            receipt = self._rpc("eth_getTransactionReceipt", [transaction_hash])
            if receipt:
                return receipt
            time.sleep(0.02)
        raise TimeoutError(f"timed out waiting for EVM receipt {transaction_hash}")

    def _rpc(self, method: str, params: Sequence[Any] | None = None) -> Any:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}",
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params or ())}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
            payload = json.loads(response.read().decode())
        if payload.get("error"):
            raise RuntimeError(payload["error"].get("message", payload["error"]))
        return payload.get("result")

    def _event(self, operation: str, entry: str, request: Mapping[str, Any], before: int, after: int, observation: Mapping[str, Any], run_id: str, trace_id: str, ordering: int, component: str, guard_result: bool) -> TraceEvent:
        before_state = State({"count": before})
        after_state = State({"count": after})
        return TraceEvent(
            operation=operation,
            entry_point=entry,
            request=dict(request),
            before=before_state,
            after=after_state,
            observation=dict(observation),
            fidelity=Fidelity.OBSERVED,
            mode=ExecutionMode.INSTRUMENTED,
            event_id="event-" + self._digest({"trace": trace_id, "ordering": ordering, "operation": operation, "entry": entry, "before": before, "after": after})[:20],
            run_id=run_id,
            trace_id=trace_id,
            component=component,
            input_representation="evm.calldata",
            output_representation="evm.storage",
            state_before_id="state-" + self._digest(before_state.canonical())[:20],
            state_after_id="state-" + self._digest(after_state.canonical())[:20],
            guard_result=guard_result,
            environment=dict(self.environment_observation().facts),
            evidence_source="anvil.rpc",
            ordering=ordering,
        )

    def _detect_runtime(self) -> None:
        if self._runtime_version != "unknown":
            return
        self._runtime_version = self._tool_version(self.anvil_command)

    @staticmethod
    def _tool(name: str) -> str:
        located = shutil.which(name)
        if located:
            return located
        candidate = Path("/home/codespace/.foundry/bin") / name
        if candidate.exists():
            return str(candidate)
        raise FileNotFoundError(f"required Foundry tool is not installed: {name}")

    @staticmethod
    def _tool_version(command: str) -> str:
        result = subprocess.run([command, "--version"], capture_output=True, text=True, check=True)
        return result.stdout.splitlines()[0].strip()

    def _build_hash(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.fixture.read_bytes())
        if self._bytecode:
            digest.update(self._bytecode.encode())
        return digest.hexdigest()

    @staticmethod
    def _digest(value: Any) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

    @staticmethod
    def _semantic_event(event: TraceEvent) -> dict[str, Any]:
        return {"operation": event.operation, "entry_point": event.entry_point, "request": event.request, "before": event.before.canonical(), "after": event.after.canonical(), "observation": event.observation, "guard_result": event.guard_result}
