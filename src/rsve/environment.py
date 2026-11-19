"""Runtime-neutral reactive environment state and prediction contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Mapping

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


Reaction = Callable[[Context, Mapping[str, Any]], tuple[State, State, Mapping[str, Any]] | Iterable[tuple[State, State, Mapping[str, Any]]]]


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
        options = self.options(transition_id, state, request)
        if not options:
            return Step(transition_id, state, state, status=Signal.UNKNOWN, reasons=("environment transition semantics unavailable",))
        step = options[0]
        if transition_id in self.nondeterministic:
            return Step(
                transition_id,
                step.before,
                step.after,
                step.outputs,
                Signal.UNKNOWN,
                ("environment transition has multiple or uncontrolled outcomes",),
            )
        return step

    def options(self, transition_id: str, state: Context, request: Mapping[str, Any]) -> tuple[Step, ...]:
        transition = self.transitions.get(transition_id)
        if transition is None:
            return (Step(transition_id, state, state, status=Signal.UNKNOWN, reasons=("environment transition semantics unavailable",)),)
        try:
            result = transition(state, request)
            values = _reactions(result)
        except Exception as exc:
            return (Step(transition_id, state, state, status=Signal.UNKNOWN, reasons=(f"environment transition failed: {type(exc).__name__}",)),)
        status = Signal.UNKNOWN if transition_id in self.nondeterministic else Signal.PREDICTED
        reasons = (
            ("environment transition has uncontrolled outcomes",)
            if status is Signal.UNKNOWN
            else ()
        )
        return tuple(
            Step(transition_id, state, Context(target, environment, state.scope), outputs, status, reasons)
            for target, environment, outputs in values
        )

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


def _reactions(value: Any) -> tuple[tuple[State, State, Mapping[str, Any]], ...]:
    if isinstance(value, tuple) and len(value) == 3 and isinstance(value[0], State) and isinstance(value[1], State) and isinstance(value[2], Mapping):
        return (value,)
    if isinstance(value, Iterable):
        values = tuple(value)
        if all(isinstance(item, tuple) and len(item) == 3 for item in values):
            return values
    raise TypeError("environment reaction must return one or more (target, environment, outputs) tuples")
