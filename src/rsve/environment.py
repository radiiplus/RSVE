"""Runtime-neutral reactive environment state and prediction contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping

from .model import State


class Signal(str, Enum):
    PREDICTED = "predicted"
    OBSERVED = "observed"
    DIVERGENCE = "divergence"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Context:
    target: State
    environment: State
    scope: str = "workspace"


@dataclass(frozen=True)
class Step:
    transition_id: str
    before: Context
    after: Context
    outputs: Mapping[str, Any] = field(default_factory=dict)
    status: Signal = Signal.PREDICTED
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class Drift:
    transition_id: str
    predicted: Step
    observed: Step
    differing_target_keys: tuple[str, ...]
    differing_environment_keys: tuple[str, ...]


Reaction = Callable[[Context, Mapping[str, Any]], tuple[State, State, Mapping[str, Any]]]


class World:
    """Predict and reconcile environment reactions without assuming determinism."""

    def __init__(
        self,
        initial: Context,
        transitions: Mapping[str, Reaction],
        *,
        nondeterministic: frozenset[str] = frozenset(),
    ) -> None:
        self.initial = initial
        self.transitions = dict(transitions)
        self.nondeterministic = nondeterministic

    def predict(self, transition_id: str, state: Context, request: Mapping[str, Any]) -> Step:
        transition = self.transitions.get(transition_id)
        if transition is None:
            return Step(transition_id, state, state, status=Signal.UNKNOWN, reasons=("environment transition semantics unavailable",))
        try:
            target, environment, outputs = transition(state, request)
        except Exception as exc:
            return Step(transition_id, state, state, status=Signal.UNKNOWN, reasons=(f"environment transition failed: {type(exc).__name__}",))
        status = Signal.UNKNOWN if transition_id in self.nondeterministic else Signal.PREDICTED
        return Step(transition_id, state, Context(target, environment, state.scope), outputs, status)

    def observe(
        self,
        transition_id: str,
        before: Context,
        after: Context,
        outputs: Mapping[str, Any] | None = None,
    ) -> Step:
        return Step(transition_id, before, after, dict(outputs or {}), Signal.OBSERVED)

    def reconcile(self, predicted: Step, observed: Step) -> Drift | None:
        target_keys = tuple(sorted(set(predicted.after.target.as_dict()) | set(observed.after.target.as_dict())))
        environment_keys = tuple(sorted(set(predicted.after.environment.as_dict()) | set(observed.after.environment.as_dict())))
        target_diff = tuple(key for key in target_keys if predicted.after.target.get(key) != observed.after.target.get(key))
        environment_diff = tuple(key for key in environment_keys if predicted.after.environment.get(key) != observed.after.environment.get(key))
        if not target_diff and not environment_diff and dict(predicted.outputs) == dict(observed.outputs):
            return None
        return Drift(predicted.transition_id, predicted, observed, target_diff, environment_diff)
