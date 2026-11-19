"""Cross-runtime adapter capability contracts with no runtime implementation code."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

from ..adapter import Target


@dataclass(frozen=True)
class Java:
    agent_instrumentation: bool = False
    bytecode_transformation: bool = False
    jfr_events: bool = False
    thread_task_correlation: bool = False
    classloader_boundaries: bool = False
    value_semantics: tuple[str, ...] = ("primitive", "reference", "array", "boxed", "exception")
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class Fork:
    local_chain: bool = False
    transaction_entries: bool = False
    call_entries: bool = False
    account_state: bool = False
    storage_state: bool = False
    block_context: bool = False
    revert_outcomes: bool = False
    logs_events: bool = False
    deterministic_replay: bool = False
    symbolic_backend: bool = False
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class Memory:
    architecture: str = "unknown"
    abi: str = "unknown"
    process_control: bool = False
    memory_observation: bool = False
    instruction_instrumentation: bool = False
    snapshot_reset: bool = False
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class Context:
    chain_id: str
    block_number: int
    timestamp: int | None = None
    base_fee: int | None = None
    gas_limit: int | None = None
    sender: str | None = None


@dataclass(frozen=True)
class Identity:
    binary_hash: str
    architecture: str
    abi: str
    operating_system: str
    loader: str = "unknown"


class Jvm(Target, Protocol):
    @property
    def caps(self) -> Java: ...


class Chain(Target, Protocol):
    @property
    def caps(self) -> Fork: ...

    def context(self) -> Context: ...


class Native(Target, Protocol):
    @property
    def caps(self) -> Memory: ...

    def identity(self) -> Identity: ...
