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
    logical_step: int = 0
    pending: tuple["ScheduledEvent", ...] = ()


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


@dataclass(frozen=True)
class Schedule:
    """A bounded request to run an environment transition after logical steps."""

    transition_id: str
    delay_steps: int
    payload: Mapping[str, Any] = field(default_factory=dict)
    event_id: str = ""

    def __post_init__(self) -> None:
        if not self.transition_id or self.delay_steps < 1:
            raise ValueError("scheduled transitions need an identity and a positive delay")


@dataclass(frozen=True)
class ScheduledEvent:
    event_id: str
    transition_id: str
    due_step: int
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReactionResult:
    target: State
    environment: State
    outputs: Mapping[str, Any] = field(default_factory=dict)
    schedules: tuple[Schedule, ...] = ()


Reaction = Callable[[Context, Mapping[str, Any]], ReactionResult | tuple[State, State, Mapping[str, Any]] | Iterable[Any]]


class World:
    """Predict and reconcile environment reactions without assuming determinism."""

    def __init__(
        self,
        initial: Context,
        transitions: Mapping[str, Reaction],
        *,
        nondeterministic: frozenset[str] = frozenset(),
        complete: frozenset[str] = frozenset(),
        max_pending: int = 256,
        max_events_per_tick: int = 64,
    ) -> None:
        if max_pending <= 0 or max_events_per_tick <= 0:
            raise ValueError("environment scheduler limits must be positive")
        self.initial = initial
        self.transitions = dict(transitions)
        self.nondeterministic = nondeterministic
        self.complete = complete
        self.max_pending = max_pending
        self.max_events_per_tick = max_events_per_tick

    def schedule(self, context: Context, schedule: Schedule) -> Context:
        """Add one delayed transition while preserving the immutable context."""
        if len(context.pending) >= self.max_pending:
            raise ValueError("environment pending-event limit reached")
        event_id = schedule.event_id or f"{schedule.transition_id}@{context.logical_step + schedule.delay_steps}:{len(context.pending)}"
        if any(event.event_id == event_id for event in context.pending):
            raise ValueError(f"duplicate scheduled event identity: {event_id}")
        event = ScheduledEvent(
            event_id,
            schedule.transition_id,
            context.logical_step + schedule.delay_steps,
            dict(schedule.payload),
        )
        return Context(
            context.target, context.environment, context.scope,
            context.logical_step, tuple(sorted(context.pending + (event,), key=lambda item: (item.due_step, item.event_id))),
        )

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
        if not values and transition_id not in self.complete:
            return (Step(
                transition_id,
                state,
                state,
                status=Signal.UNKNOWN,
                reasons=("environment relation returned no successors without completeness evidence",),
            ),)
        status = Signal.UNKNOWN if transition_id in self.nondeterministic else Signal.PREDICTED
        reasons = (
            ("environment transition has uncontrolled outcomes",)
            if status is Signal.UNKNOWN
            else ()
        )
        steps = []
        for value in values:
            after = Context(value.target, value.environment, state.scope, state.logical_step, state.pending)
            for scheduled in value.schedules:
                if len(after.pending) >= self.max_pending:
                    return (Step(transition_id, state, state, status=Signal.UNKNOWN, reasons=("environment pending-event limit reached",)),)
                after = self.schedule(after, scheduled)
            steps.append(Step(transition_id, state, after, value.outputs, status, reasons))
        return tuple(steps)

    def tick(self, state: Context, *, steps: int = 1, max_events: int | None = None) -> tuple[Step, ...]:
        """Advance logical time and execute every due environment event in order."""
        if steps < 0:
            raise ValueError("logical time cannot move backwards")
        event_limit = self.max_events_per_tick if max_events is None else min(max_events, self.max_events_per_tick)
        if event_limit <= 0:
            raise ValueError("max_events must be positive")
        branches: list[tuple[Context, tuple[Mapping[str, Any], ...], Signal, tuple[str, ...]]] = [
            (state, (), Signal.PREDICTED, ())
        ]
        for _ in range(steps):
            advanced = []
            for context, events, status, reasons in branches:
                current = Context(context.target, context.environment, context.scope, context.logical_step + 1, context.pending)
                due = tuple(event for event in current.pending if event.due_step <= current.logical_step)
                remaining = tuple(event for event in current.pending if event.due_step > current.logical_step)
                current = Context(current.target, current.environment, current.scope, current.logical_step, remaining)
                event_branches = [(current, events, status, reasons)]
                for event in due:
                    next_branches = []
                    for branch_context, branch_events, branch_status, branch_reasons in event_branches:
                        if len(branch_events) >= event_limit:
                            next_branches.append((branch_context, branch_events, Signal.UNKNOWN, branch_reasons + ("environment event limit reached",)))
                            continue
                        options = self.options(event.transition_id, branch_context, event.payload)
                        for option in options:
                            record = {
                                "event_id": event.event_id,
                                "transition_id": event.transition_id,
                                "due_step": event.due_step,
                                "outputs": dict(option.outputs),
                                "status": option.status.value,
                            }
                            next_branches.append((
                                option.after,
                                branch_events + (record,),
                                Signal.UNKNOWN if option.status is Signal.UNKNOWN or branch_status is Signal.UNKNOWN else branch_status,
                                branch_reasons + option.reasons,
                            ))
                    if len(next_branches) > event_limit:
                        event_branches = next_branches[:event_limit]
                        context0, events0, _status0, reasons0 = event_branches[0]
                        event_branches[0] = (
                            context0, events0, Signal.UNKNOWN,
                            reasons0 + ("environment event branch limit reached",),
                        )
                    else:
                        event_branches = next_branches
                advanced.extend(event_branches)
            if len(advanced) > event_limit:
                branches = advanced[:event_limit]
                context0, events0, _status0, reasons0 = branches[0]
                branches[0] = (
                    context0, events0, Signal.UNKNOWN,
                    reasons0 + ("environment tick branch limit reached",),
                )
            else:
                branches = advanced
        return tuple(
            Step(
                "environment.tick", state, context,
                {"environment_events": events} if events else {},
                status, reasons,
            )
            for context, events, status, reasons in branches
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


def _reactions(value: Any) -> tuple[ReactionResult, ...]:
    if isinstance(value, ReactionResult):
        return (value,)
    if isinstance(value, tuple) and len(value) == 3 and isinstance(value[0], State) and isinstance(value[1], State) and isinstance(value[2], Mapping):
        return (ReactionResult(value[0], value[1], value[2]),)
    if isinstance(value, Iterable):
        values = tuple(value)
        normalized = []
        for item in values:
            if isinstance(item, ReactionResult):
                normalized.append(item)
            elif isinstance(item, tuple) and len(item) == 3 and isinstance(item[0], State) and isinstance(item[1], State) and isinstance(item[2], Mapping):
                normalized.append(ReactionResult(item[0], item[1], item[2]))
            else:
                break
        else:
            return tuple(normalized)
    raise TypeError("environment reaction must return one or more (target, environment, outputs) tuples")
