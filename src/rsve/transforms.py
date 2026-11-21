"""Explicit, reusable semantic transforms with concrete and symbolic bindings."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from types import MappingProxyType
from typing import Any, Mapping

from .ir import Evidence, Invertibility, Loss, Partiality, Relation, Transform
from .logic import Equal, Literal, Sort, Variable
from .model import Fidelity, State, _canonical
from .wp import Symbolic


@dataclass(frozen=True)
class ObservedTransformResult:
    """Observed outputs for one exact input/state pair; never a complete relation."""

    values: tuple[Any, ...]
    evidence_ids: tuple[str, ...]
    complete: bool = field(default=False, init=False)
    limitation: str = "observations do not prove the full output relation"


@dataclass(frozen=True)
class TransformObservation:
    input_value: Any
    state: Mapping[str, Any]
    output_value: Any
    evidence: Evidence

    def __post_init__(self) -> None:
        if not isinstance(self.state, Mapping):
            raise TypeError("transform observation state must be a mapping")
        if not isinstance(self.evidence, Evidence):
            raise TypeError("transform observation evidence must be an Evidence record")
        if self.evidence.tier is not Fidelity.OBSERVED:
            raise ValueError("transform observations require observed-fidelity evidence")
        if not self.evidence.evidence_id or not self.evidence.source:
            raise ValueError("transform observations require evidence identity and source")
        object.__setattr__(self, "input_value", _snapshot(self.input_value))
        object.__setattr__(self, "state", _snapshot(dict(self.state)))
        object.__setattr__(self, "output_value", _snapshot(self.output_value))


@dataclass(frozen=True)
class ObservedTransformModel:
    """Exact-context observations for an otherwise opaque transform.

    The model answers only for an input and state already observed. It keeps
    conflicting outputs as alternatives and always reports the relation as
    incomplete; finite samples never establish a universal transform rule.
    """

    transform_id: str
    observations: tuple[TransformObservation, ...] = ()

    def __post_init__(self) -> None:
        if not self.transform_id:
            raise ValueError("observed transform identity is required")
        if any(not isinstance(item, TransformObservation) for item in self.observations):
            raise TypeError("observed transform records must be TransformObservation values")
        ids = [item.evidence.evidence_id for item in self.observations]
        if len(ids) != len(set(ids)):
            raise ValueError("transform observation evidence identifiers must be unique")

    def observe(
        self,
        input_value: Any,
        state: State | Mapping[str, Any],
        output_value: Any,
        evidence: Evidence,
    ) -> "ObservedTransformModel":
        observation = TransformObservation(
            input_value,
            state.as_dict() if isinstance(state, State) else state,
            output_value,
            evidence,
        )
        if any(item.evidence.evidence_id == evidence.evidence_id for item in self.observations):
            raise ValueError(f"duplicate transform evidence identifier: {evidence.evidence_id}")
        return ObservedTransformModel(self.transform_id, self.observations + (observation,))

    def __call__(self, input_value: Any, state: State) -> ObservedTransformResult:
        input_key = _fingerprint(input_value)
        state_key = _fingerprint(state.as_dict())
        matches = tuple(
            item for item in self.observations
            if _fingerprint(item.input_value) == input_key
            and _fingerprint(item.state) == state_key
        )
        values: list[Any] = []
        for item in matches:
            if not any(_fingerprint(item.output_value) == _fingerprint(value) for value in values):
                values.append(_thaw(item.output_value))
        return ObservedTransformResult(
            tuple(values),
            tuple(item.evidence.evidence_id for item in matches),
            limitation=(
                "observed outputs are incomplete; the transform's full relation is unknown"
                if matches else
                "no observation matches this exact input and state; transform behavior is unknown"
            ),
        )

    def probe_inputs(
        self,
        limit: int | None = None,
        *,
        mappings_only: bool = False,
    ) -> tuple[Any, ...]:
        """Return observed inputs as bounded-search seeds, without state claims."""
        if limit is not None and limit <= 0:
            return ()
        unique: list[Any] = []
        seen: set[str] = set()
        for item in self.observations:
            if mappings_only and not isinstance(item.input_value, Mapping):
                continue
            key = _fingerprint(item.input_value)
            if key not in seen:
                seen.add(key)
                unique.append(_thaw(item.input_value))
                if limit is not None and len(unique) >= limit:
                    break
        return tuple(unique)


def _snapshot(value: Any) -> Any:
    """Detach recorded evidence from mutable caller-owned containers."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _snapshot(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(_snapshot(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_snapshot(item) for item in value)
    if isinstance(value, bytearray):
        return bytes(value)
    return value


class _FrozenList(tuple):
    """Immutable storage that remembers an observed list's runtime type."""


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, _FrozenList):
        return [_thaw(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_thaw(item) for item in value)
    return value


def _fingerprint(value: Any) -> str:
    return json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), default=repr)


@dataclass(frozen=True)
class UTF8Decoder:
    """Strict UTF-8 byte-to-text semantics; malformed sequences raise."""

    transform_id: str = "utf8.decode.strict"
    max_bytes: int = 1 << 20

    def __post_init__(self) -> None:
        if not self.transform_id or self.max_bytes <= 0:
            raise ValueError("UTF-8 transform identity and positive byte limit are required")

    @property
    def transform(self) -> Transform:
        return Transform(
            self.transform_id,
            "bytes",
            "unicode-text",
            "rsve.utf8.decode.strict",
            "1",
            Partiality.PARTIAL,
            Relation.FUNCTION,
            Invertibility.INJECTIVE,
            Loss.NONE,
            complete=True,
            provenance="preserve",
            provenance_paths={"output.text": ("input.bytes",)},
        )

    def forward(self, value: bytes, _state=None) -> str:
        if not isinstance(value, bytes):
            raise TypeError("strict UTF-8 decoding requires bytes")
        if len(value) > self.max_bytes:
            raise ValueError(f"UTF-8 input exceeds {self.max_bytes} byte limit")
        return value.decode("utf-8", errors="strict")

    def backward(self, value: str) -> bytes:
        if not isinstance(value, str):
            raise TypeError("strict UTF-8 encoding requires text")
        encoded = value.encode("utf-8", errors="strict")
        if len(encoded) > self.max_bytes:
            raise ValueError(f"UTF-8 preimage exceeds {self.max_bytes} byte limit")
        return encoded

    def symbolic_for(self, value: str) -> Symbolic:
        """Build an exact WP relation for one concrete decoded-text objective."""
        encoded = self.backward(value)
        return Symbolic(
            self.transform_id,
            self.transform_id,
            Equal(
                Variable("input.bytes", Sort.BYTES),
                Literal(encoded, Sort.BYTES),
            ),
            assignments={"output.text": Literal(value, Sort.STRING)},
            semantics_ref="rsve.utf8.decode.strict",
            semantics_version="1",
        )
