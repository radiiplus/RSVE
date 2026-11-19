"""Stable integration boundaries for runtime-specific implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .model import Authorization, EntryPoint, State, TraceEvent, TransitionModel
from .ir import EnvironmentObservation
from .results import AnalysisReport, SolverStatus
from .graph import AnalysisGraph, CapabilityManifest


@dataclass(frozen=True)
class Capabilities:
    discover_entries: bool = False
    invoke: bool = False
    replay: bool = False
    capture_state: bool = False
    capture_traces: bool = False
    symbolize: bool = False
    snapshot: bool = False
    prove: bool = False
    models: bool = False
    unsat_cores: bool = False
    proof_artifacts: bool = False
    incremental_scopes: bool = False


@dataclass(frozen=True)
class CapabilityReport:
    supported_entry_types: frozenset[str] = frozenset()
    supported_event_hooks: frozenset[str] = frozenset()
    state_capture: bool = False
    snapshot_reset: bool = False
    deterministic_replay: bool = False
    limitations: tuple[str, ...] = ()
    side_effects: tuple[str, ...] = ()
    version: str = "1"


class TargetAdapter(Protocol):
    """Adapter for an owned, isolated target and its declared surface."""

    @property
    def capabilities(self) -> Capabilities: ...

    def identity(self) -> Mapping[str, str]: ...

    def capability_report(self) -> CapabilityReport: ...

    def prepare(self) -> None: ...

    def discover_entries(self) -> Sequence[EntryPoint]: ...

    def invoke(self, entry_point: str, request: Mapping[str, Any], authorization: Authorization) -> Sequence[TraceEvent]: ...

    def snapshot(self) -> Any: ...

    def reset(self, snapshot: Any) -> None: ...

    def execute_trace(self, interactions: Sequence[Mapping[str, Any]], authorization: Authorization) -> Sequence[TraceEvent]: ...

    def teardown(self) -> None: ...

    def analysis_profile(self) -> Any: ...

    def capability_manifest(self) -> CapabilityManifest: ...

    def analysis_graph(self) -> AnalysisGraph: ...


class InstrumentationAdapter(Protocol):
    @property
    def capabilities(self) -> Capabilities: ...

    def capture(self) -> Iterable[TraceEvent]: ...


class SolverAdapter(Protocol):
    """Optional solver boundary; the core never assumes a backend exists."""

    @property
    def capabilities(self) -> Capabilities: ...

    def solve(self, query: Any, *, timeout_ms: int | None = None) -> Any: ...


class EnvironmentAdapter(Protocol):
    @property
    def capabilities(self) -> Capabilities: ...

    def describe(self) -> Mapping[str, str]: ...

    def observe(self) -> EnvironmentObservation: ...


class SubstrateAdapter(Protocol):
    """Optional OS/ISA substrate boundary; implementations own guest details."""

    @property
    def capabilities(self) -> Capabilities: ...

    def identity(self) -> Mapping[str, str]: ...

    def capability_report(self) -> CapabilityReport: ...

    def prepare(self) -> None: ...

    def snapshot(self) -> Any: ...

    def reset(self, snapshot: Any) -> None: ...

    def execute(self, command: str) -> str: ...

    def environment_observation(self) -> EnvironmentObservation: ...

    def teardown(self) -> None: ...


class ArtifactStore(Protocol):
    def put(self, kind: str, payload: Mapping[str, Any]) -> str: ...

    def get(self, artifact_id: str) -> Mapping[str, Any] | None: ...

    def record_report(self, report: AnalysisReport) -> str: ...

    def record_solver_result(self, result: Any) -> str: ...


class TransactionalArtifactStore(ArtifactStore, Protocol):
    """Durable store boundary with query invalidation and snapshot metadata."""

    def record_model_delta(self, delta: Any) -> str: ...

    def invalidate_queries(self, query_ids: Sequence[str], *, reason: str, model_revision: str = "unknown", execution_profile_id: str = "unknown", delta_id: str = "") -> int: ...

    def get_solver_result(self, query_id: str, *, model_revision: str | None = None, execution_profile_id: str | None = None, include_stale: bool = False) -> Mapping[str, Any] | None: ...

    def is_query_valid(self, query_id: str, *, model_revision: str, execution_profile_id: str) -> bool: ...
