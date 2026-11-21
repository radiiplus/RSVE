"""Behavior signatures and novelty archives derived from canonical RSVE records."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence

from .model import Event, State, _canonical


class Level(str, Enum):
    COARSE = "coarse"
    EXACT = "exact"


def _digest(value: Any) -> str:
    payload = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def _shape(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _shape(item) for key, item in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (tuple, list)):
        return [_shape(item) for item in value]
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int) and not isinstance(value, bool):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, bytes):
        return "bytes"
    if isinstance(value, str):
        return "str"
    return type(value).__name__


def _project(value: Mapping[str, Any], keys: frozenset[str]) -> Mapping[str, Any]:
    if not keys:
        return {str(key): _shape(item) for key, item in sorted(value.items(), key=lambda item: str(item[0]))}
    return {
        str(key): value[key] if key in keys else _shape(value[key])
        for key in sorted(value)
    }


def _state(value: State | None) -> Mapping[str, Any]:
    return value.as_dict() if value is not None else {}


def _frame(value: Any) -> Mapping[str, Any]:
    """Read a Frame without importing Workspace and creating a cycle."""
    if isinstance(value, State):
        return {
            "target": value.as_dict(),
            "environment": {},
            "regions": {},
            "uncertain": False,
            "reasons": (),
            "aliases": (),
            "lineage": None,
            "origins": None,
        }
    target = getattr(value, "target", State())
    environment = getattr(value, "environment", State())
    regions = getattr(value, "regions", {})
    return {
        "target": _state(target),
        "environment": _state(environment),
        "regions": {
            str(name): _state(state)
            for name, state in sorted(regions.items(), key=lambda item: str(item[0]))
        },
        "uncertain": bool(getattr(value, "uncertain", False)),
        "reasons": tuple(str(reason) for reason in getattr(value, "reasons", ())),
        "aliases": _canonical(getattr(value, "aliases", ())),
        "lineage": _canonical(getattr(value, "lineage", None)),
        "origins": _canonical(getattr(value, "origins", None)),
    }


def _delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> Mapping[str, Any]:
    keys = sorted(set(before) | set(after))
    return {
        key: {"before": before.get(key), "after": after.get(key)}
        for key in keys
        if before.get(key) != after.get(key)
    }


def _event(event: Event, keys: frozenset[str], level: Level) -> Mapping[str, Any]:
    before = event.before.as_dict()
    after = event.after.as_dict()
    base: dict[str, Any] = {
        "operation": event.operation,
        "entry": event.entry_point,
        "component": event.component,
        "decision": event.decision.value,
        "guard": event.guard_result,
        "terminal": event.terminal,
        "effects": tuple(sorted(event.effects)),
        "reads": tuple(sorted(event.reads)),
        "writes": tuple(sorted(event.writes)),
        "input_representation": event.input_representation,
        "output_representation": event.output_representation,
        "correlation_uncertain": event.correlation_uncertain,
        "uncertainty": tuple(sorted(event.uncertainty)),
        "reaction_keys": tuple(sorted(event.reaction)),
        "delta": _project(_delta(before, after), keys),
        "observation_keys": tuple(sorted(event.observation)),
        "ordering": event.ordering,
        "parent_event_id": event.parent_event_id,
    }
    if level is Level.EXACT:
        base.update({
            "before": before,
            "after": after,
            "observation": _digest(event.observation),
            "reaction": _digest(event.reaction),
            "event_id": event.event_id,
        })
    return base


@dataclass(frozen=True)
class Signature:
    """A multi-resolution behavior signature, never an equivalence proof."""

    target: str
    profile: str
    state: Mapping[str, str]
    transition: Mapping[str, str]
    path: Mapping[str, str]
    levels: Mapping[str, str]
    scope: Mapping[str, Any] = field(default_factory=dict)
    state_continuations: tuple[tuple[str, str, str], ...] = ()

    @classmethod
    def make(
        cls,
        events: Sequence[Event],
        final: State | Any,
        *,
        target: str = "unknown",
        profile: str = "unknown",
        keys: Iterable[str] = (),
        scope: Mapping[str, Any] | None = None,
    ) -> "Signature":
        selected = frozenset(keys)
        frame = _frame(final)
        state_coarse = {
            "target": _project(frame["target"], selected),
            "environment": _project(frame["environment"], selected),
            "regions": {
                name: _project(value, selected)
                for name, value in frame["regions"].items()
            },
            "uncertain": frame["uncertain"],
            "reasons": tuple(frame["reasons"]),
            "aliases": _shape(frame["aliases"]),
            "lineage": _shape(frame["lineage"]),
            "origins": _shape(frame["origins"]),
        }
        state_exact = frame
        transition_coarse = tuple(_event(event, selected, Level.COARSE) for event in events)
        transition_exact = tuple(_event(event, selected, Level.EXACT) for event in events)
        path_coarse = {
            "events": transition_coarse,
            "orders": tuple(event.ordering for event in events),
        }
        path_exact = {
            "events": transition_exact,
            "state": state_exact,
            "environment": frame["environment"],
            "orders": tuple(event.ordering for event in events),
            "parents": tuple(event.parent_event_id for event in events),
        }
        state_continuations = tuple(
            (
                _digest({
                    "target": _project(event.after.as_dict(), selected),
                    "environment": {},
                    "regions": {},
                    "uncertain": False,
                    "reasons": (),
                    "aliases": _shape(()),
                    "lineage": _shape(None),
                    "origins": _shape(None),
                }),
                _digest({
                    "target": event.after.as_dict(),
                    "environment": {},
                    "regions": {},
                    "uncertain": False,
                    "reasons": (),
                    "aliases": (),
                    "lineage": None,
                    "origins": None,
                }),
                _digest(tuple(_event(item, selected, Level.COARSE) for item in events[index + 1 :])),
            )
            for index, event in enumerate(events[:-1])
        )
        return cls(
            target,
            profile,
            {"coarse": _digest(state_coarse), "exact": _digest(state_exact)},
            {"coarse": _digest(transition_coarse), "exact": _digest(transition_exact)},
            {"coarse": _digest(path_coarse), "exact": _digest(path_exact)},
            {"coarse": _digest({"state": state_coarse, "transition": transition_coarse, "path": path_coarse}),
             "exact": _digest({"state": state_exact, "transition": transition_exact, "path": path_exact})},
            dict(scope or {}),
            state_continuations,
        )

    def partition(self) -> tuple[str, str, str]:
        """Return the archive partition for this target/profile/scope."""
        return self.target, self.profile, _digest(self.scope)

    def key(self, level: Level = Level.COARSE) -> tuple[str, str, str, str]:
        return (*self.partition(), self.levels[level.value])

    def canonical(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "profile": self.profile,
            "state": dict(self.state),
            "transition": dict(self.transition),
            "path": dict(self.path),
            "levels": dict(self.levels),
            "scope": _canonical(self.scope),
            "state_continuations": self.state_continuations,
        }


@dataclass(frozen=True)
class Novelty:
    """Novelty observations for one execution; this does not rank safety."""

    state: bool
    transition: bool
    path: bool
    profile: str

    @property
    def score(self) -> int:
        return int(self.state) + int(self.transition) + int(self.path)


@dataclass(frozen=True)
class Archive:
    """Profile-partitioned state, transition, and path behavior archives."""

    states: frozenset[tuple[str, str, str, str]] = frozenset()
    transitions: frozenset[tuple[str, str, str, str]] = frozenset()
    paths: frozenset[tuple[str, str, str, str]] = frozenset()
    states_exact: frozenset[tuple[str, str, str, str]] = frozenset()
    transitions_exact: frozenset[tuple[str, str, str, str]] = frozenset()
    paths_exact: frozenset[tuple[str, str, str, str]] = frozenset()
    state_records: frozenset[tuple[tuple[str, str, str], str, str]] = frozenset()
    refinements: frozenset[tuple[tuple[str, str, str], str, str, str]] = frozenset()

    @staticmethod
    def _refined_key(
        partition: tuple[str, str, str],
        coarse_state: str,
        exact_state: str,
    ) -> tuple[str, str, str, str]:
        refined = _digest({"coarse": coarse_state, "exact": exact_state})
        return (*partition, refined)

    def _divergent_states(self) -> frozenset[tuple[tuple[str, str, str], str]]:
        continuations: dict[tuple[tuple[str, str, str], str], set[str]] = {}
        for partition, coarse_state, _exact_state, continuation in self.refinements:
            continuations.setdefault((partition, coarse_state), set()).add(continuation)
        return frozenset(key for key, values in continuations.items() if len(values) > 1)

    def offer(self, signature: Signature) -> tuple["Archive", Novelty]:
        partition = signature.partition()
        state_key = (*partition, signature.state[Level.COARSE.value])
        transition_key = (*partition, signature.transition[Level.COARSE.value])
        path_key = (*partition, signature.path[Level.COARSE.value])
        state_exact = (*partition, signature.state[Level.EXACT.value])
        transition_exact = (*partition, signature.transition[Level.EXACT.value])
        path_exact = (*partition, signature.path[Level.EXACT.value])
        records = set(self.state_records)
        records.add((partition, signature.state[Level.COARSE.value], signature.state[Level.EXACT.value]))
        records.update(
            (partition, coarse_state, exact_state)
            for coarse_state, exact_state, _continuation in signature.state_continuations
        )
        continuations = set(self.refinements)
        continuations.update(
            (partition, coarse_state, exact_state, continuation)
            for coarse_state, exact_state, continuation in signature.state_continuations
        )
        divergent = self._divergent_states() | Archive(
            refinements=frozenset(continuations),
        )._divergent_states()
        current_state_keys = {
            self._refined_key(record_partition, coarse_state, exact_state)
            if (record_partition, coarse_state) in divergent
            else (*record_partition, coarse_state)
            for record_partition, coarse_state, exact_state in records
        }
        states = set(self.states)
        for record_partition, coarse_state in divergent:
            states.discard((*record_partition, coarse_state))
        states.update(current_state_keys)
        current_keys = {
            self._refined_key(partition, coarse_state, exact_state)
            if (partition, coarse_state) in divergent
            else (*partition, coarse_state)
            for coarse_state, exact_state, _continuation in signature.state_continuations
        }
        current_keys.add(
            self._refined_key(partition, signature.state[Level.COARSE.value], signature.state[Level.EXACT.value])
            if (partition, signature.state[Level.COARSE.value]) in divergent
            else state_key
        )
        novelty = Novelty(
            bool(current_keys - self.states),
            transition_key not in self.transitions,
            path_key not in self.paths,
            signature.profile,
        )
        return (
            Archive(
                states=frozenset(states),
                transitions=self.transitions | {transition_key},
                paths=self.paths | {path_key},
                states_exact=self.states_exact | {state_exact},
                transitions_exact=self.transitions_exact | {transition_exact},
                paths_exact=self.paths_exact | {path_exact},
                state_records=frozenset(records),
                refinements=frozenset(continuations),
            ),
            novelty,
        )

    def seen(self, signature: Signature, level: Level = Level.COARSE) -> bool:
        partition = signature.partition()
        if level is Level.EXACT:
            return (
                (*partition, signature.state[level.value]) in self.states_exact
                and (*partition, signature.transition[level.value]) in self.transitions_exact
                and (*partition, signature.path[level.value]) in self.paths_exact
            )
        state_coarse = signature.state[Level.COARSE.value]
        state_key = (
            self._refined_key(partition, state_coarse, signature.state[Level.EXACT.value])
            if (partition, state_coarse) in self._divergent_states()
            else (*partition, state_coarse)
        )
        return (
            state_key in self.states
            and (*partition, signature.transition[level.value]) in self.transitions
            and (*partition, signature.path[level.value]) in self.paths
        )
