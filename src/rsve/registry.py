"""Evidence-backed declared and observed surface registries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .ir import Evidence, TargetIdentity
from .model import EntryPoint
from .schema import SchemaMixin


@dataclass(frozen=True)
class ObservedEntry:
    entry_point: EntryPoint
    evidence: tuple[Evidence, ...]
    conditions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("an observed entry point requires evidence")


@dataclass(frozen=True)
class SurfaceRegistry(SchemaMixin):
    target: TargetIdentity
    declared: tuple[EntryPoint, ...] = ()
    observed: tuple[ObservedEntry, ...] = ()

    def __post_init__(self) -> None:
        names = [entry.name for entry in self.declared]
        if len(set(names)) != len(names):
            raise ValueError("declared entry-point names must be unique")

    def phantom_entries(self) -> tuple[ObservedEntry, ...]:
        declared_names = {entry.name for entry in self.declared}
        return tuple(item for item in self.observed if item.entry_point.name not in declared_names)

    def add_declared(self, entry: EntryPoint) -> "SurfaceRegistry":
        if entry.name in {item.name for item in self.declared}:
            raise ValueError(f"duplicate declared entry point: {entry.name}")
        return SurfaceRegistry(self.target, self.declared + (entry,), self.observed)

    def add_observed(self, entry: ObservedEntry) -> "SurfaceRegistry":
        return SurfaceRegistry(self.target, self.declared, self.observed + (entry,))

    @classmethod
    def from_iterables(
        cls,
        target: TargetIdentity,
        declared: Iterable[EntryPoint] = (),
        observed: Iterable[ObservedEntry] = (),
    ) -> "SurfaceRegistry":
        return cls(target, tuple(declared), tuple(observed))
