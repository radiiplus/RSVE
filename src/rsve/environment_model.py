"""Runtime-neutral reactive environment state and prediction contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping

from .model import State


class EnvironmentResultStatus(str, Enum):
    PREDICTED = "predicted"
    OBSERVED = "observed"
    DIVERGENCE = "divergence"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReactiveEnvironmentState:
    target: State
    environment: State
    scope: str = "workspace"


@dataclass(frozen=True)
class EnvironmentStep:
    transition_id: str
    before: ReactiveEnvironmentState
    after: ReactiveEnvironmentState
    outputs: Mapping[str, Any] = field(default_factory=dict)
    status: EnvironmentResultStatus = EnvironmentResultStatus.PREDICTED
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class EnvironmentDivergence:
    transition_id: str
    predicted: EnvironmentStep
    observed: EnvironmentStep
    differing_target_keys: tuple[str, ...]
    differing_environment_keys: tuple[str, ...]


TargetEnvironmentTransition = Callable[[ReactiveEnvironmentState, Mapping[str, Any]], tuple[State, State, Mapping[str, Any]]]


class ReactiveEnvironment:
    """Predict and reconcile environment reactions without assuming determinism."""

    def __init__(
        self,
        initial: ReactiveEnvironmentState,
        transitions: Mapping[str, TargetEnvironmentTransition],
        *,
        nondeterministic: frozenset[str] = frozenset(),
    ) -> None:
        self.initial = initial
        self.transitions = dict(transitions)
        self.nondeterministic = nondeterministic

    def predict(self, transition_id: str, state: ReactiveEnvironmentState, request: Mapping[str, Any]) -> EnvironmentStep:
        transition = self.transitions.get(transition_id)
        if transition is None:
            return EnvironmentStep(transition_id, state, state, status=EnvironmentResultStatus.UNKNOWN, reasons=("environment transition semantics unavailable",))
        try:
            target, environment, outputs = transition(state, request)
        except Exception as exc:
            return EnvironmentStep(transition_id, state, state, status=EnvironmentResultStatus.UNKNOWN, reasons=(f"environment transition failed: {type(exc).__name__}",))
        status = EnvironmentResultStatus.UNKNOWN if transition_id in self.nondeterministic else EnvironmentResultStatus.PREDICTED
        return EnvironmentStep(transition_id, state, ReactiveEnvironmentState(target, environment, state.scope), outputs, status)

    def observe(
        self,
        transition_id: str,
        before: ReactiveEnvironmentState,
        after: ReactiveEnvironmentState,
        outputs: Mapping[str, Any] | None = None,
    ) -> EnvironmentStep:
        return EnvironmentStep(transition_id, before, after, dict(outputs or {}), EnvironmentResultStatus.OBSERVED)

    def reconcile(self, predicted: EnvironmentStep, observed: EnvironmentStep) -> EnvironmentDivergence | None:
        target_keys = tuple(sorted(set(predicted.after.target.as_dict()) | set(observed.after.target.as_dict())))
        environment_keys = tuple(sorted(set(predicted.after.environment.as_dict()) | set(observed.after.environment.as_dict())))
        target_diff = tuple(key for key in target_keys if predicted.after.target.get(key) != observed.after.target.get(key))
        environment_diff = tuple(key for key in environment_keys if predicted.after.environment.get(key) != observed.after.environment.get(key))
        if not target_diff and not environment_diff and dict(predicted.outputs) == dict(observed.outputs):
            return None
        return EnvironmentDivergence(predicted.transition_id, predicted, observed, target_diff, environment_diff)
