"""Revision-aware causal indexes for modeled operations."""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from typing import Iterable

from .logic import Constraint, Variable
from .model import Decision, Operation, Model


@dataclass(frozen=True)
class Item:
    """A transition's declared dependency summary."""

    operation: Operation
    reads: frozenset[str]
    writes: frozenset[str]
    effects: frozenset[str]
    entry: str
    component: str
    unknown: bool = False
    decision: Decision | None = None


class Index:
    """Find possible causal predecessors without assuming layer adjacency."""

    def __init__(self, entries: Iterable[Item], revision: str = "unknown") -> None:
        self.revision = revision
        self.entries = tuple(entries)
        self.read: dict[str, tuple[Item, ...]] = {}
        self.write: dict[str, tuple[Item, ...]] = {}
        self.effect: dict[str, tuple[Item, ...]] = {}
        self.entry: dict[str, tuple[Item, ...]] = {}
        for item in self.entries:
            self.add(self.read, item.reads, item)
            self.add(self.write, item.writes, item)
            self.add(self.effect, item.effects, item)
            self.add(self.entry, (item.entry,), item)

    @classmethod
    def build(cls, model: Model) -> "Index":
        entries = []
        for operation in model.operations:
            reads = set(_statekeys(operation.reads))
            writes = set(operation.writes | operation.must | operation.may)
            symbolic = operation.symbolic_transition
            if symbolic is not None:
                writes |= frozenset(getattr(symbolic, "assignments", {}).keys())
                reads.update(_statevars(symbolic.guard))
                for expression in getattr(symbolic, "assignments", {}).values():
                    reads.update(_statevars(expression))
            entries.append(Item(
                operation=operation,
                reads=frozenset(reads),
                writes=frozenset(_statekeys(writes)),
                effects=frozenset(operation.effects),
                entry=operation.entry_point.name,
                component=operation.component,
                unknown=bool(operation.unknown),
                decision=Decision.ACCEPT,
            ))
            deny = operation.deny_reads | operation.deny_writes | operation.deny_must | operation.deny_may
            if operation.deny_effects or deny or operation.deny is not None or operation.deny_env:
                entries.append(Item(
                    operation=operation,
                    reads=frozenset(_statekeys(operation.deny_reads)),
                    writes=frozenset(_statekeys(operation.deny_writes | operation.deny_must | operation.deny_may)),
                    effects=frozenset(operation.deny_effects),
                    entry=operation.entry_point.name,
                    component=operation.component,
                    unknown=operation.deny is not None and not deny,
                    decision=Decision.REJECT,
                ))
        return cls(entries, model.model_version)

    def predecessors(self, keys: Iterable[str]) -> tuple[Item, ...]:
        found: dict[tuple[str, str, Decision | None], Item] = {}
        for key in keys:
            for item in self.write.get(key, ()):
                found[(item.entry, item.operation.name, item.decision)] = item
        return tuple(found[key] for key in sorted(found, key=_order))

    def chain(self, keys: Iterable[str]) -> tuple[Item, ...]:
        """Return the bounded causal writer closure for the requested keys.

        A writer is only a candidate predecessor. Its reads become the next
        requirements, so callers can regress through non-adjacent operations
        without treating the dependency summary as proof of reachability.
        """
        needed = set(keys)
        found: dict[tuple[str, str, Decision | None], Item] = {}
        while needed:
            current = set(needed)
            needed.clear()
            for item in self.predecessors(current):
                identity = (item.entry, item.operation.name, item.decision)
                if identity in found:
                    continue
                found[identity] = item
                needed.update(item.reads)
        return tuple(found[key] for key in sorted(found, key=_order))

    def readers(self, keys: Iterable[str]) -> tuple[Item, ...]:
        return self.collect(self.read, keys)

    def effects(self, names: Iterable[str]) -> tuple[Item, ...]:
        return self.collect(self.effect, names)

    def lookup(self, names: Iterable[str]) -> tuple[Item, ...]:
        return self.collect(self.entry, names)

    def refresh(self, model: Model) -> "Index":
        if model.model_version == self.revision:
            return self
        return self.build(model)

    @staticmethod
    def add(target: dict[str, list[Item] | tuple[Item, ...]], keys: Iterable[str], item: Item) -> None:
        for key in keys:
            current = list(target.get(key, ()))
            current.append(item)
            target[key] = tuple(current)

    @staticmethod
    def collect(source: dict[str, tuple[Item, ...]], keys: Iterable[str]) -> tuple[Item, ...]:
        found: dict[tuple[str, str, Decision | None], Item] = {}
        for key in keys:
            for item in source.get(key, ()):
                found[(item.entry, item.operation.name, item.decision)] = item
        return tuple(found[key] for key in sorted(found, key=_order))


def _statevars(value: object) -> set[str]:
    """Collect modeled state reads without treating request variables as state."""
    found: set[str] = set()
    if isinstance(value, Variable) and value.name.startswith("state."):
        found.add(value.name.removeprefix("state."))
    elif isinstance(value, Constraint) and is_dataclass(value):
        for item in fields(value):
            found.update(_statevars(getattr(value, item.name)))
    elif isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            found.update(_statevars(item))
    elif isinstance(value, dict):
        for item in value.values():
            found.update(_statevars(item))
    return found


def _statekeys(values: Iterable[str]) -> set[str]:
    return {value.removeprefix("state.") for value in values}


def _order(value: tuple[str, str, Decision | None]) -> tuple[str, str, str]:
    return value[0], value[1], value[2].value if value[2] is not None else ""
