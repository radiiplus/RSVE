"""Stable integration boundaries for runtime-specific implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .model import Authorization, Entry, State, Event, Model
from .ir import Fact
from .result import Report, Verdict
from .graph import Graph, Manifest


@dataclass(frozen=True)
class Caps:
    discover: bool = False
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
class Offer:
    supported_entry_types: frozenset[str] = frozenset()
    supported_event_hooks: frozenset[str] = frozenset()
    state_capture: bool = False
    snapshot_reset: bool = False
    deterministic_replay: bool = False
    limitations: tuple[str, ...] = ()
    side_effects: tuple[str, ...] = ()
    version: str = "1"


class Target(Protocol):
    """Adapter for an owned, isolated target and its declared surface."""

    @property
    def capabilities(self) -> Caps: ...

    def identity(self) -> Mapping[str, str]: ...

    def offer(self) -> Offer: ...

    def prepare(self) -> None: ...

    def discover(self) -> Sequence[Entry]: ...

    def invoke(self, entry_point: str, request: Mapping[str, Any], authorization: Authorization) -> Sequence[Event]: ...

    def snapshot(self) -> Any: ...

    def reset(self, snapshot: Any) -> None: ...

    def trace(self, interactions: Sequence[Mapping[str, Any]], authorization: Authorization) -> Sequence[Event]: ...

    def teardown(self) -> None: ...

    def profile(self) -> Any: ...

    def manifest(self) -> Manifest: ...

    def graph(self) -> Graph: ...


class Probe(Protocol):
    @property
    def capabilities(self) -> Caps: ...

    def capture(self) -> Iterable[Event]: ...


class Solve(Protocol):
    """Optional solver boundary; the core never assumes a backend exists."""

    @property
    def capabilities(self) -> Caps: ...

    def solve(self, query: Any, *, timeout_ms: int | None = None) -> Any: ...


class Env(Protocol):
    @property
    def capabilities(self) -> Caps: ...

    def describe(self) -> Mapping[str, str]: ...

    def observe(self) -> Fact: ...


class Base(Protocol):
    """Optional OS/ISA substrate boundary; implementations own guest details."""

    @property
    def capabilities(self) -> Caps: ...

    def identity(self) -> Mapping[str, str]: ...

    def offer(self) -> Offer: ...

    def prepare(self) -> None: ...

    def snapshot(self) -> Any: ...

    def reset(self, snapshot: Any) -> None: ...

    def execute(self, command: str) -> str: ...

    def observe(self) -> Fact: ...

    def teardown(self) -> None: ...


class Vault(Protocol):
    def put(self, kind: str, payload: Mapping[str, Any]) -> str: ...

    def get(self, artifact_id: str) -> Mapping[str, Any] | None: ...

    def report(self, report: Report) -> str: ...

    def solve(self, result: Any) -> str: ...


class Ledger(Vault, Protocol):
    """Durable store boundary with query invalidation and snapshot metadata."""

    def delta(self, delta: Any) -> str: ...

    def invalidate(self, query_ids: Sequence[str], *, reason: str, model_revision: str = "unknown", execution_profile_id: str = "unknown", delta_id: str = "") -> int: ...

    def answer(self, query_id: str, *, model_revision: str | None = None, execution_profile_id: str | None = None, include_stale: bool = False) -> Mapping[str, Any] | None: ...

    def valid(self, query_id: str, *, model_revision: str, execution_profile_id: str) -> bool: ...
