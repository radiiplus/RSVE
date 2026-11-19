"""Controlled Node.js adapter using stable built-in observation APIs."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import selectors
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .adapters import ArtifactStore, CapabilityReport, Capabilities
from .environment import LinuxEnvironmentAdapter
from .ir import EnvironmentObservation, Evidence, TargetIdentity
from .model import Authorization, EntryPoint, ExecutionMode, Fidelity, Provenance, State, TraceEvent
from .registry import ObservedEntry, SurfaceRegistry
from .profile import ExecutionProfile


@dataclass(frozen=True)
class ReplayRun:
    run_id: str
    events: tuple[TraceEvent, ...]
    outcome: Mapping[str, Any]
    outcome_hash: str
    environment: Mapping[str, str]


@dataclass(frozen=True)
class ReplayReport:
    runs: tuple[ReplayRun, ...]
    stable: bool
    replayability: str = "partially_replayable"
    limitations: tuple[str, ...] = ()


class NodeTargetAdapter:
    """Launch and observe an explicitly supplied local Node target fixture.

    The target speaks a private line protocol only for the controlled fixture;
    analysis receives normalized ``TraceEvent`` objects and never depends on
    Node types. Inspector/diagnostics hooks remain target-side evidence.
    """

    def __init__(
        self,
        fixture: str | Path,
        *,
        target_id: str = "node-target",
        scope: str = "node-lab",
        manifest: str | Path | None = None,
        artifact_store: ArtifactStore | None = None,
        timeout_s: float = 5.0,
        node_command: str = "node",
        preserve_raw_payloads: bool = False,
    ) -> None:
        self.fixture = Path(fixture)
        self.target_id = target_id
        self.scope = scope
        self.manifest = Path(manifest) if manifest else self.fixture.with_name("manifest.json")
        self.artifact_store = artifact_store
        self.timeout_s = timeout_s
        self.node_command = node_command
        self.preserve_raw_payloads = preserve_raw_payloads
        self._process: subprocess.Popen[str] | None = None
        self._command_counter = 0
        self._run_counter = 0
        self._event_counter = 0
        self._initial_snapshot: dict[str, Any] | None = None
        self._last_output: dict[str, Any] = {}
        self._runtime_version = "unknown"

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
            supported_entry_types=frozenset({"module_function", "stateful_command", "async_function"}),
            supported_event_hooks=frozenset({"entry.invocation", "operation", "async.correlation", "outcome"}),
            state_capture=True,
            snapshot_reset=True,
            deterministic_replay=False,
            limitations=(
                "HTTP, IPC, WebSocket, timer, and framework routes are not discovered unless the target emits them",
                "Inspector Protocol is not used to claim universal JavaScript or V8 coverage",
                "filesystem, clock, randomness, scheduler, and network isolation are not controlled by this adapter",
                "semantic replay is checked; exact timestamp, scheduler, filesystem, and environment replay is unavailable",
            ),
            side_effects=("target-local diagnostics_channel subscribers",),
        )

    def identity(self) -> Mapping[str, str]:
        self._detect_runtime()
        return {
            "target_id": self.target_id,
            "runtime": "node",
            "runtime_version": self._runtime_version,
            "platform": platform.system().lower(),
            "platform_version": platform.release(),
            "build_hash": self._build_hash(),
            "adapter": "rsve.node",
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
            capabilities=frozenset(self.capability_report().supported_event_hooks),
            provenance=Provenance("node-adapter", "1", (str(self.fixture),), Fidelity.OBSERVED),
        )

    def execution_profile(self) -> ExecutionProfile:
        return ExecutionProfile.from_target(self.identity(), self.environment_observation())

    def environment_observation(self) -> EnvironmentObservation:
        self._detect_runtime()
        profile = LinuxEnvironmentAdapter(self.fixture.parent).observe() if platform.system().lower() == "linux" else EnvironmentObservation(
            facts={"os": platform.system().lower(), "kernel": platform.release()},
            unknown=("environment_profile", "memory_model", "scheduler", "snapshot_scope"),
        )
        facts = dict(profile.facts)
        facts.update({
            "runtime": self._runtime_version,
            "runtime_flags": "unknown",
            "environment_keys": ",".join(sorted(
                key for key in os.environ
                if key.lower() not in {"token", "password", "secret", "private_key"}
            )),
            "node_clock_source": "node.process.hrtime.bigint",
            "randomness_seed": "unknown",
        })
        return EnvironmentObservation(
            facts=facts,
            unknown=tuple(sorted(set(profile.unknown) | {"runtime_flags", "randomness_seed"})),
            redacted_keys=profile.redacted_keys + ("secret-looking environment variables",),
            profile_id=profile.profile_id,
            capabilities=profile.capabilities,
        )

    def prepare(self) -> None:
        if self._process and self._process.poll() is None:
            return
        self._detect_runtime()
        self._process = subprocess.Popen(
            [self.node_command, str(self.fixture)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._initial_snapshot = self._request("snapshot")["snapshot"]

    def teardown(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        try:
            if process.poll() is None:
                self._request("shutdown", process=process)
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=self.timeout_s)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=self.timeout_s)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def declared_entries(self) -> tuple[EntryPoint, ...]:
        payload = json.loads(self.manifest.read_text(encoding="utf-8"))
        return tuple(
            EntryPoint(
                name=item["name"],
                declared=True,
                capabilities=frozenset(item.get("capabilities", ())),
                provenance=Provenance("fixture-manifest", str(payload.get("version", "1")), (str(self.manifest),), Fidelity.MODELED),
            )
            for item in payload.get("entries", ())
        )

    def discover_entries(self) -> tuple[EntryPoint, ...]:
        self.prepare()
        response = self._request("discover")
        return tuple(
            EntryPoint(
                name=item["name"],
                declared=bool(item.get("declared", False)),
                capabilities=frozenset(item.get("capabilities", ())),
                provenance=Provenance("node-observation", "1", ("discover",), Fidelity.OBSERVED),
            )
            for item in response.get("entries", ())
        )

    def surface_registry(self) -> SurfaceRegistry:
        declared = self.declared_entries()
        observed = self.discover_entries()
        evidence = tuple(
            ObservedEntry(
                entry_point=entry,
                evidence=(Evidence(
                    evidence_id=f"discover-{entry.name}",
                    tier=Fidelity.OBSERVED,
                    source="node-observation",
                    reference="discover",
                    conditions=("fixture discovery response",),
                ),),
                conditions=("observed during adapter discovery",),
            )
            for entry in observed
        )
        return SurfaceRegistry.from_iterables(self.target_identity(), declared, evidence)

    def snapshot(self) -> dict[str, Any]:
        return self._request("snapshot")["snapshot"]

    def reset(self, snapshot: Any) -> None:
        self._request("restore", snapshot=snapshot)

    def invoke(self, entry_point: str, request: Mapping[str, Any], authorization: Authorization) -> tuple[TraceEvent, ...]:
        if not authorization.permits(self.target_id, self.scope):
            raise PermissionError(f"authorization does not permit {self.target_id!r} in {self.scope!r}")
        self.prepare()
        self._run_counter += 1
        run_id = f"run-{self._run_counter:06d}"
        trace_id = "trace-" + self._digest({"entry": entry_point, "request": dict(request)})[:20]
        events, response = self._invoke_one(entry_point, request, run_id, trace_id, 0)
        self._last_output = response
        return events

    def execute_trace(self, interactions: Sequence[Mapping[str, Any]]) -> tuple[TraceEvent, ...]:
        authorization = Authorization("node-adapter", frozenset({self.scope}), frozenset({self.target_id}))
        if not authorization.permits(self.target_id, self.scope):
            raise PermissionError(f"authorization does not permit {self.target_id!r} in {self.scope!r}")
        self.prepare()
        self._run_counter += 1
        run_id = f"run-{self._run_counter:06d}"
        trace_id = "trace-" + self._digest(list(interactions))[:20]
        events: list[TraceEvent] = []
        for interaction in interactions:
            normalized, response = self._invoke_one(
                interaction["entry_point"],
                interaction.get("request", {}),
                run_id,
                trace_id,
                len(events),
            )
            events.extend(normalized)
            self._last_output = response
        return tuple(events)

    def _invoke_one(
        self,
        entry_point: str,
        request: Mapping[str, Any],
        run_id: str,
        trace_id: str,
        order_offset: int,
    ) -> tuple[tuple[TraceEvent, ...], dict[str, Any]]:
        payload_ref = self._record_payload(request)
        response = self._request("invoke", entry=entry_point, request=dict(request), run_id=run_id)
        return self._normalize_events(response.get("events", ()), run_id, trace_id, payload_ref, order_offset), response

    def replay(
        self,
        interactions: Sequence[Mapping[str, Any]],
        *,
        runs: int = 1,
        authorization: Authorization | None = None,
    ) -> ReplayReport:
        if runs <= 0:
            raise ValueError("runs must be positive")
        authorization = authorization or Authorization("node-replay", frozenset({self.scope}), frozenset({self.target_id}))
        if not authorization.permits(self.target_id, self.scope):
            raise PermissionError(f"authorization does not permit {self.target_id!r} in {self.scope!r}")
        self.prepare()
        baseline = self._initial_snapshot or self.snapshot()
        reports: list[ReplayRun] = []
        limitations = list(self.capability_report().limitations)
        for _ in range(runs):
            self.reset(baseline)
            events = self.execute_trace(interactions)
            outcome = dict(self._last_output.get("outcome", {}))
            reports.append(ReplayRun(
                run_id=events[0].run_id if events else f"run-{self._run_counter:06d}",
                events=events,
                outcome=outcome,
                outcome_hash=self._digest(outcome),
                environment=dict(self.environment_observation().facts),
            ))
        signatures = {
            self._digest({
                "outcome": run.outcome,
                "events": [self._semantic_event(event) for event in run.events],
            })
            for run in reports
        }
        return ReplayReport(tuple(reports), len(signatures) == 1, "partially_replayable", tuple(limitations))

    def collect_output(self) -> Mapping[str, Any]:
        return dict(self._last_output)

    def _normalize_events(
        self,
        raw_events: Sequence[Mapping[str, Any]],
        run_id: str,
        trace_id: str,
        payload_ref: str | None,
        order_offset: int = 0,
    ) -> tuple[TraceEvent, ...]:
        normalized: list[TraceEvent] = []
        event_ids: list[str] = []
        for order, raw in enumerate(raw_events):
            before = State(raw.get("before", {}))
            after = State(raw.get("after", {}))
            event_id = "event-" + self._digest({
                "trace": trace_id,
                "order": order_offset + order,
                "operation": raw.get("operation", raw.get("kind", "unknown")),
                "entry_point": raw.get("entry_point", "unknown"),
                "request": raw.get("request", {}),
                "before": raw.get("before", {}),
                "after": raw.get("after", {}),
                "observation": raw.get("observation", {}),
            })[:20]
            parent_index = raw.get("parent_index")
            parent_id = event_ids[parent_index] if isinstance(parent_index, int) and parent_index < len(event_ids) else None
            event_ids.append(event_id)
            refs = tuple(ref for ref in (payload_ref,) if ref)
            normalized.append(TraceEvent(
                operation=str(raw.get("operation", raw.get("kind", "unknown"))),
                entry_point=str(raw.get("entry_point", "unknown")),
                request=dict(raw.get("request", {})),
                before=before,
                after=after,
                observation=dict(raw.get("observation", {})),
                fidelity=Fidelity.OBSERVED,
                mode=ExecutionMode.INSTRUMENTED,
                event_id=event_id,
                run_id=run_id,
                trace_id=trace_id,
                parent_event_id=parent_id,
                component=str(raw.get("component", "node-target")),
                input_representation=str(raw.get("input_representation", "json")),
                output_representation=str(raw.get("output_representation", "state")),
                state_before_id=self._state_id(before),
                state_after_id=self._state_id(after),
                guard_result=raw.get("guard_result"),
                environment=dict(self.environment_observation().facts),
                evidence_source="node.diagnostics_channel",
                evidence_refs=refs,
                timestamp_ns=raw.get("timestamp_ns", time.time_ns()),
                ordering=order_offset + order,
                correlation_uncertain=bool(raw.get("correlation_uncertain", False)),
            ))
        return tuple(normalized)

    def _request(self, command: str, process: subprocess.Popen[str] | None = None, **payload: Any) -> dict[str, Any]:
        process = process or self._process
        if process is None or process.stdin is None or process.stdout is None:
            raise RuntimeError("Node target is not prepared")
        self._command_counter += 1
        request_id = f"command-{self._command_counter:06d}"
        process.stdin.write(json.dumps({"command": command, "request_id": request_id, **payload}, sort_keys=True) + "\n")
        process.stdin.flush()
        deadline = time.monotonic() + self.timeout_s
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while time.monotonic() < deadline:
                ready = selector.select(max(0.0, deadline - time.monotonic()))
                if not ready:
                    break
                line = process.stdout.readline()
                if not line:
                    break
                response = json.loads(line)
                if response.get("request_id") == request_id:
                    if response.get("error"):
                        raise RuntimeError(response["error"])
                    return response
        finally:
            selector.close()
        raise TimeoutError(f"timed out waiting for Node command {command!r}")

    def _detect_runtime(self) -> None:
        if self._runtime_version != "unknown":
            return
        completed = subprocess.run([self.node_command, "--version"], capture_output=True, text=True, check=True)
        self._runtime_version = completed.stdout.strip()

    def _build_hash(self) -> str:
        digest = hashlib.sha256()
        for path in (self.fixture, self.manifest):
            digest.update(path.read_bytes())
        return digest.hexdigest()

    def _state_id(self, state: State) -> str:
        return "state-" + self._digest(state.canonical())[:20]

    def _digest(self, value: Any) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

    def _record_payload(self, request: Mapping[str, Any]) -> str | None:
        if self.artifact_store is None:
            return None
        encoded = json.dumps(dict(request), sort_keys=True, separators=(",", ":")).encode()
        payload: dict[str, Any] = {"sha256": hashlib.sha256(encoded).hexdigest(), "redacted": self._redact(request)}
        if self.preserve_raw_payloads:
            payload["raw_bytes_hex"] = encoded.hex()
        return self.artifact_store.put("node_input_payload", payload)

    def _redact(self, value: Any, key: str | None = None) -> Any:
        if key and key.lower() in {"secret", "token", "password", "private_key"}:
            return "[REDACTED]"
        if isinstance(value, Mapping):
            return {str(item_key): self._redact(item_value, str(item_key)) for item_key, item_value in value.items()}
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        return value

    def _semantic_event(self, event: TraceEvent) -> dict[str, Any]:
        return {
            "operation": event.operation,
            "entry_point": event.entry_point,
            "request": event.request,
            "after": event.after.canonical(),
            "observation": event.observation,
        }
