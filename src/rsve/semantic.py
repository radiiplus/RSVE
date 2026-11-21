"""Executable interpretation of the canonical semantic graph records."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Mapping

from .graph import Graph
from .model import Decision, Fidelity, Mode, Outcome, State
from .transforms import ObservedTransformResult


class Meaning(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Branch:
    value: Any
    status: Meaning
    representations: tuple[str, ...] = ()
    recognizer_results: tuple[tuple[str, bool | None], ...] = ()
    state: State = field(default_factory=State)
    reasons: tuple[str, ...] = ()
    lineage: tuple[str, ...] | None = None
    origins: Mapping[str, tuple[str, ...]] | None = None


TransformEvaluator = Callable[[Any, State], Any | Iterable[Any]]
RecognizerEvaluator = Callable[[Any, State], bool]
EffectEvaluator = Callable[[State, Any], State]


class Interpreter:
    """Traverse graph transitions without inventing semantics for opaque nodes."""

    def __init__(
        self,
        graph: Graph,
        *,
        transforms: Mapping[str, TransformEvaluator] | None = None,
        recognizers: Mapping[str, RecognizerEvaluator] | None = None,
        effects: Mapping[str, EffectEvaluator] | None = None,
    ) -> None:
        self.graph = graph
        self.transforms = dict(transforms or {})
        for transform_id, evaluator in self.transforms.items():
            observed_id = getattr(evaluator, "transform_id", transform_id)
            if observed_id != transform_id:
                raise ValueError(
                    f"observed transform identity {observed_id!r} does not match binding {transform_id!r}"
                )
        self.recognizers = dict(recognizers or {})
        self.effects = dict(effects or {})

    def execute(
        self,
        transition_id: str,
        value: Any,
        *,
        state: State | None = None,
        lineage: tuple[str, ...] | None = None,
        origins: Mapping[str, tuple[str, ...]] | None = None,
    ) -> tuple[Branch, ...]:
        transition = next((item for item in self.graph.transitions if item.transition_id == transition_id), None)
        if transition is None:
            return (Branch(value, Meaning.UNKNOWN, reasons=(f"unknown transition: {transition_id}",)),)
        composition_issues = self.graph.transition_composition_issues(transition_id)
        if composition_issues:
            return (Branch(
                value,
                Meaning.UNKNOWN,
                representations=(transition.input_representation,),
                reasons=tuple(f"incompatible transform composition: {issue}" for issue in composition_issues),
            ),)
        branches = (Branch(
            value,
            Meaning.ACCEPTED,
            representations=(transition.input_representation,),
            state=state or State(),
            lineage=lineage,
            origins=origins,
        ),)
        for transform_id in transition.transform_ids:
            transform = next((item for item in self.graph.transforms if item.transform_id == transform_id), None)
            if transform is None:
                branches = tuple(
                    Branch(item.value, Meaning.UNKNOWN, item.representations, item.recognizer_results, item.state, item.reasons + (f"unknown transform: {transform_id}",), None, None)
                    for item in branches
                )
                continue
            evaluator = self.transforms.get(transform_id)
            if evaluator is None:
                branches = tuple(
                    Branch(item.value, Meaning.UNKNOWN, item.representations + (transform.output_representation,), item.recognizer_results, item.state, item.reasons + (f"opaque transform: {transform_id}",), None, None)
                    for item in branches
                )
                continue
            expanded: list[Branch] = []
            for branch in branches:
                try:
                    outputs = evaluator(branch.value, branch.state)
                    if isinstance(outputs, ObservedTransformResult):
                        evidence = (
                            f"observed evidence: {', '.join(outputs.evidence_ids)}"
                            if outputs.evidence_ids else "no matching observed evidence"
                        )
                        reason = f"{outputs.limitation} ({evidence})"
                        if not outputs.values:
                            expanded.append(Branch(
                                branch.value,
                                Meaning.UNKNOWN,
                                branch.representations + (transform.output_representation,),
                                branch.recognizer_results,
                                branch.state,
                                branch.reasons + (reason,),
                                None,
                                None,
                            ))
                            continue
                        for output in outputs.values:
                            lineage, lineage_reason = _transfer(transform.provenance, branch.lineage)
                            origins, origin_reason = _origins(
                                transform.provenance,
                                transform.provenance_paths,
                                branch.origins,
                            )
                            reasons = branch.reasons + (reason,)
                            reasons += ((lineage_reason,) if lineage_reason else ())
                            reasons += ((origin_reason,) if origin_reason else ())
                            expanded.append(Branch(
                                output,
                                Meaning.UNKNOWN,
                                branch.representations + (transform.output_representation,),
                                branch.recognizer_results,
                                branch.state,
                                reasons,
                                lineage,
                                origins,
                            ))
                        continue
                    values = _relation_values(outputs)
                    if not values:
                        if transform.complete:
                            continue
                        expanded.append(Branch(
                            branch.value,
                            Meaning.UNKNOWN,
                            branch.representations + (transform.output_representation,),
                            branch.recognizer_results,
                            branch.state,
                            branch.reasons + (
                                f"transform relation returned no successors without completeness evidence: {transform_id}",
                            ),
                            None,
                            None,
                        ))
                        continue
                    for output in values:
                        lineage, reason = _transfer(transform.provenance, branch.lineage)
                        origins, origin_reason = _origins(
                            transform.provenance,
                            transform.provenance_paths,
                            branch.origins,
                        )
                        reasons = branch.reasons + ((reason,) if reason else ())
                        reasons += ((origin_reason,) if origin_reason else ())
                        expanded.append(Branch(output, branch.status, branch.representations + (transform.output_representation,), branch.recognizer_results, branch.state, reasons, lineage, origins))
                except Exception as exc:
                    expanded.append(Branch(branch.value, Meaning.UNKNOWN, branch.representations + (transform.output_representation,), branch.recognizer_results, branch.state, branch.reasons + (f"transform {transform_id} failed: {type(exc).__name__}",), None, None))
            branches = tuple(expanded)
        for recognizer_id in transition.recognizer_ids:
            evaluator = self.recognizers.get(recognizer_id)
            if evaluator is None:
                branches = tuple(
                    Branch(item.value, Meaning.UNKNOWN, item.representations, item.recognizer_results + ((recognizer_id, None),), item.state, item.reasons + (f"opaque recognizer: {recognizer_id}",), item.lineage, item.origins)
                    for item in branches
                )
                continue
            checked: list[Branch] = []
            for branch in branches:
                try:
                    accepted = bool(evaluator(branch.value, branch.state))
                    status = (
                        branch.status
                        if branch.status is Meaning.UNKNOWN
                        else branch.status if accepted else Meaning.REJECTED
                    )
                    checked.append(Branch(branch.value, status, branch.representations, branch.recognizer_results + ((recognizer_id, accepted),), branch.state, branch.reasons, branch.lineage, branch.origins))
                except Exception as exc:
                    checked.append(Branch(branch.value, Meaning.UNKNOWN, branch.representations, branch.recognizer_results + ((recognizer_id, None),), branch.state, branch.reasons + (f"recognizer {recognizer_id} failed: {type(exc).__name__}",), None, None))
            branches = tuple(checked)
        for effect_id in transition.effect_ids:
            evaluator = self.effects.get(effect_id)
            if evaluator is None:
                branches = tuple(
                    Branch(
                        item.value,
                        Meaning.UNKNOWN,
                        item.representations,
                        item.recognizer_results,
                        item.state,
                        item.reasons + (f"opaque effect: {effect_id}",),
                        item.lineage,
                        item.origins,
                    )
                    for item in branches
                )
                continue
            applied: list[Branch] = []
            for branch in branches:
                try:
                    applied.append(Branch(
                        branch.value,
                        branch.status,
                        branch.representations,
                        branch.recognizer_results,
                        evaluator(branch.state, branch.value),
                        branch.reasons,
                        branch.lineage,
                        branch.origins,
                    ))
                except Exception as exc:
                    applied.append(Branch(
                        branch.value,
                        Meaning.UNKNOWN,
                        branch.representations,
                        branch.recognizer_results,
                        branch.state,
                        branch.reasons + (f"effect {effect_id} failed: {type(exc).__name__}",),
                        None,
                        None,
                    ))
            branches = tuple(applied)
        return branches

    def outcomes(
        self,
        transition_id: str,
        value: Any,
        *,
        state: State | None = None,
        lineage: tuple[str, ...] | None = None,
        origins: Mapping[str, tuple[str, ...]] | None = None,
    ) -> tuple[Outcome, ...]:
        """Lower supported graph semantics into the canonical outcome model."""
        transition = next(
            (item for item in self.graph.transitions if item.transition_id == transition_id),
            None,
        )
        branches = self.execute(transition_id, value, state=state, lineage=lineage, origins=origins)
        if transition is None:
            return tuple(
                Outcome(
                    Decision.UNKNOWN,
                    branch.state,
                    guard=None,
                    fidelity=Fidelity.MODELED,
                    mode=Mode.ABSTRACT,
                    evidence=(transition_id,),
                    uncertainty=branch.reasons,
                    lineage=branch.lineage,
                    origins=branch.origins,
                )
                for branch in branches
            )
        effect_ids = tuple(transition.effect_ids)
        effect_observables = tuple(
            effect.observable
            for effect_id in effect_ids
            for effect in self.graph.effects
            if effect.effect_id == effect_id
        )
        effect_inputs = tuple(
            path
            for effect_id in effect_ids
            for effect in self.graph.effects
            if effect.effect_id == effect_id
            for path in effect.provenance_inputs
        )
        effect_writes = frozenset(
            state_effect
            for effect_id in transition.effect_ids
            for effect in self.graph.effects
            if effect.effect_id == effect_id
            for state_effect in effect.state_effects
        )
        reads = frozenset(
            dependency
            for recognizer_id in transition.recognizer_ids
            for recognizer in self.graph.recognizers
            if recognizer.recognizer_id == recognizer_id
            for dependency in recognizer.state_dependencies
        )
        writes = frozenset(transition.state_effects) | effect_writes
        results: list[Outcome] = []
        for branch in branches:
            if branch.status is Meaning.ACCEPTED:
                decision = Decision.ACCEPT
            elif branch.status is Meaning.REJECTED:
                decision = Decision.REJECT
            else:
                decision = Decision.UNKNOWN
            guard_values = tuple(result for _name, result in branch.recognizer_results)
            guard = None if not guard_values or any(value is None for value in guard_values) else all(guard_values)
            results.append(
                Outcome(
                    decision=decision,
                    after=branch.state,
                    observation={
                        "value": branch.value,
                        "effect_observables": effect_observables,
                        "provenance_consumed": effect_inputs,
                    },
                    effects=effect_ids,
                    reads=reads,
                    writes=writes,
                    guard=guard,
                    fidelity=Fidelity.MODELED,
                    mode=Mode.ABSTRACT,
                    evidence=(transition_id,),
                    uncertainty=branch.reasons,
                    lineage=branch.lineage,
                    origins=branch.origins,
                )
            )
        return tuple(results)


def _relation_values(value: Any) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, bytearray, Mapping)) or value is None:
        return (value,)
    if isinstance(value, Iterable):
        return tuple(value)
    return (value,)


def _transfer(mode: str, lineage: tuple[str, ...] | None) -> tuple[tuple[str, ...] | None, str | None]:
    if lineage is None:
        return None, "provenance is already unknown"
    if mode in {"preserve", "duplicate", "combine"}:
        return lineage, None
    if mode == "discard":
        return (), None
    return None, "provenance transfer is unknown"


def _origins(
    mode: str,
    paths: Mapping[str, tuple[str, ...]],
    origins: Mapping[str, tuple[str, ...]] | None,
) -> tuple[Mapping[str, tuple[str, ...]] | None, str | None]:
    if origins is None:
        return None, "value provenance is unknown"
    if mode == "discard":
        return {}, None
    if mode not in {"preserve", "duplicate", "combine"}:
        return None, "value provenance transfer is unknown"
    if not paths:
        return None, "value provenance paths are required for value-level transfer"
    result: dict[str, tuple[str, ...]] = {}
    for output, inputs in paths.items():
        values: list[str] = []
        for source in inputs:
            values.extend(origins.get(source, ()))
        result[output] = tuple(dict.fromkeys(values))
    if any(not values for values in result.values()):
        return None, "value provenance transfer is incomplete"
    return result, None
