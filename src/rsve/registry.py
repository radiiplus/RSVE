"""Evidence-backed declared and observed surface registries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .ir import Evidence, Identity
from .model import Entry
from .schema import Schema


@dataclass(frozen=True)
class Seen:
    entry_point: Entry
    evidence: tuple[Evidence, ...]
    conditions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("an observed entry point requires evidence")


@dataclass(frozen=True)
class Surface(Schema):
    target: Identity
    declared: tuple[Entry, ...] = ()
    observed: tuple[Seen, ...] = ()

    def __post_init__(self) -> None:
        names = [entry.name for entry in self.declared]
        if len(set(names)) != len(names):
            raise ValueError("declared entry-point names must be unique")

    def phantoms(self) -> tuple[Seen, ...]:
        declared_names = {entry.name for entry in self.declared}
        return tuple(item for item in self.observed if item.entry_point.name not in declared_names)

    def declare(self, entry: Entry) -> "Surface":
        if entry.name in {item.name for item in self.declared}:
            raise ValueError(f"duplicate declared entry point: {entry.name}")
        return Surface(self.target, self.declared + (entry,), self.observed)

    def seen(self, entry: Seen) -> "Surface":
        return Surface(self.target, self.declared, self.observed + (entry,))

    @classmethod
    def build(
        cls,
        target: Identity,
        declared: Iterable[Entry] = (),
        observed: Iterable[Seen] = (),
    ) -> "Surface":
        return cls(target, tuple(declared), tuple(observed))
