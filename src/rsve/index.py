"""Revision-aware causal indexes for modeled operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .model import Operation, TransitionModel


@dataclass(frozen=True)
class Entry:
    """A transition's declared dependency summary."""

    operation: Operation
    reads: frozenset[str]
    writes: frozenset[str]
    effects: frozenset[str]
    entry: str
    component: str
    unknown: bool = False


class Index:
    """Find possible causal predecessors without assuming layer adjacency."""

    def __init__(self, entries: Iterable[Entry], revision: str = "unknown") -> None:
        self.revision = revision
        self.entries = tuple(entries)
        self.read: dict[str, tuple[Entry, ...]] = {}
        self.write: dict[str, tuple[Entry, ...]] = {}
        self.effect: dict[str, tuple[Entry, ...]] = {}
        self.entry: dict[str, tuple[Entry, ...]] = {}
        for item in self.entries:
            self.add(self.read, item.reads, item)
            self.add(self.write, item.writes, item)
            self.add(self.effect, item.effects, item)
            self.add(self.entry, (item.entry,), item)

    @classmethod
    def build(cls, model: TransitionModel) -> "Index":
        entries = []
        for operation in model.operations:
            reads = frozenset(operation.reads)
            writes = frozenset(operation.writes | operation.must | operation.may)
            symbolic = operation.symbolic_transition
            if symbolic is not None:
                writes |= frozenset(getattr(symbolic, "assignments", {}).keys())
            unknown = bool(operation.unknown)
            entries.append(Entry(
                operation=operation,
                reads=reads,
                writes=writes,
                effects=frozenset(operation.effects),
                entry=operation.entry_point.name,
                component=operation.component,
                unknown=unknown,
            ))
        return cls(entries, model.model_version)

    def predecessors(self, keys: Iterable[str]) -> tuple[Entry, ...]:
        found: dict[tuple[str, str], Entry] = {}
        for key in keys:
            for item in self.write.get(key, ()):
                found[(item.entry, item.operation.name)] = item
        return tuple(found[key] for key in sorted(found))

    def readers(self, keys: Iterable[str]) -> tuple[Entry, ...]:
        return self.collect(self.read, keys)

    def effects(self, names: Iterable[str]) -> tuple[Entry, ...]:
        return self.collect(self.effect, names)

    def lookup(self, names: Iterable[str]) -> tuple[Entry, ...]:
        return self.collect(self.entry, names)

    def refresh(self, model: TransitionModel) -> "Index":
        if model.model_version == self.revision:
            return self
        return self.build(model)

    @staticmethod
    def add(target: dict[str, list[Entry] | tuple[Entry, ...]], keys: Iterable[str], item: Entry) -> None:
        for key in keys:
            current = list(target.get(key, ()))
            current.append(item)
            target[key] = tuple(current)

    @staticmethod
    def collect(source: dict[str, tuple[Entry, ...]], keys: Iterable[str]) -> tuple[Entry, ...]:
        found: dict[tuple[str, str], Entry] = {}
        for key in keys:
            for item in source.get(key, ()):
                found[(item.entry, item.operation.name)] = item
        return tuple(found[key] for key in sorted(found))
