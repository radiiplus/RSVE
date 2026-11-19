"""Executable interpretation of the canonical semantic graph records."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Mapping

from .graph import AnalysisGraph
from .model import State


class SemanticStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SemanticBranch:
    value: Any
    status: SemanticStatus
    representations: tuple[str, ...] = ()
    recognizer_results: tuple[tuple[str, bool | None], ...] = ()
    state: State = field(default_factory=State)
    reasons: tuple[str, ...] = ()


TransformEvaluator = Callable[[Any, State], Any | Iterable[Any]]
RecognizerEvaluator = Callable[[Any, State], bool]


class SemanticInterpreter:
    """Traverse graph transitions without inventing semantics for opaque nodes."""

    def __init__(
        self,
        graph: AnalysisGraph,
        *,
        transforms: Mapping[str, TransformEvaluator] | None = None,
        recognizers: Mapping[str, RecognizerEvaluator] | None = None,
    ) -> None:
        self.graph = graph
        self.transforms = dict(transforms or {})
        self.recognizers = dict(recognizers or {})

    def execute_transition(
        self,
        transition_id: str,
        value: Any,
        *,
        state: State | None = None,
    ) -> tuple[SemanticBranch, ...]:
        transition = next((item for item in self.graph.transitions if item.transition_id == transition_id), None)
        if transition is None:
            return (SemanticBranch(value, SemanticStatus.UNKNOWN, reasons=(f"unknown transition: {transition_id}",)),)
        branches = (SemanticBranch(value, SemanticStatus.ACCEPTED, state=state or State()),)
        for transform_id in transition.transform_ids:
            transform = next((item for item in self.graph.transforms if item.transform_id == transform_id), None)
            if transform is None:
                branches = tuple(
                    SemanticBranch(item.value, SemanticStatus.UNKNOWN, item.representations, item.recognizer_results, item.state, item.reasons + (f"unknown transform: {transform_id}",))
                    for item in branches
                )
                continue
            evaluator = self.transforms.get(transform_id)
            if evaluator is None:
                branches = tuple(
                    SemanticBranch(item.value, SemanticStatus.UNKNOWN, item.representations + (transform.output_representation,), item.recognizer_results, item.state, item.reasons + (f"opaque transform: {transform_id}",))
                    for item in branches
                )
                continue
            expanded: list[SemanticBranch] = []
            for branch in branches:
                try:
                    outputs = evaluator(branch.value, branch.state)
                    values = _relation_values(outputs)
                    for output in values:
                        expanded.append(SemanticBranch(output, branch.status, branch.representations + (transform.output_representation,), branch.recognizer_results, branch.state, branch.reasons))
                except Exception as exc:
                    expanded.append(SemanticBranch(branch.value, SemanticStatus.UNKNOWN, branch.representations + (transform.output_representation,), branch.recognizer_results, branch.state, branch.reasons + (f"transform {transform_id} failed: {type(exc).__name__}",)))
            branches = tuple(expanded)
        for recognizer_id in transition.recognizer_ids:
            evaluator = self.recognizers.get(recognizer_id)
            if evaluator is None:
                branches = tuple(
                    SemanticBranch(item.value, SemanticStatus.UNKNOWN, item.representations, item.recognizer_results + ((recognizer_id, None),), item.state, item.reasons + (f"opaque recognizer: {recognizer_id}",))
                    for item in branches
                )
                continue
            checked: list[SemanticBranch] = []
            for branch in branches:
                try:
                    accepted = bool(evaluator(branch.value, branch.state))
                    checked.append(SemanticBranch(branch.value, branch.status if accepted else SemanticStatus.REJECTED, branch.representations, branch.recognizer_results + ((recognizer_id, accepted),), branch.state, branch.reasons))
                except Exception as exc:
                    checked.append(SemanticBranch(branch.value, SemanticStatus.UNKNOWN, branch.representations, branch.recognizer_results + ((recognizer_id, None),), branch.state, branch.reasons + (f"recognizer {recognizer_id} failed: {type(exc).__name__}",)))
            branches = tuple(checked)
        return branches


def _relation_values(value: Any) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, bytearray, Mapping)) or value is None:
        return (value,)
    if isinstance(value, Iterable):
        return tuple(value)
    return (value,)
