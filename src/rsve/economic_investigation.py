"""Execution-derived economic advantage analysis.

This module consumes observations produced by a runtime adapter.  It does not
name a Bor function or assume that a balance discrepancy is an exploit.  A
positive advantage is first a hypothesis; verification requires a repeated
observation, an independent observation, and a changed state that survives
commit and reopen.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping


_RUNTIME_CLASSES = frozenset({
    "RUNTIME_OBSERVATION",
    "REPRODUCED_RUNTIME_OBSERVATION",
    "INDEPENDENTLY_VERIFIED_RESULT",
})
_UNKNOWN_STATUSES = frozenset({"unknown", "unobserved", "missing", "unresolved"})
_UNKNOWN_LAYERS = frozenset({"process", "environment", "kernel"})


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def _number(value: Any) -> int | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None


def _first_number(observation: Mapping[str, Any], *names: str) -> int | None:
    for name in names:
        value = _number(observation.get(name))
        if value is not None:
            return value
    return None


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:20]


def _as_sequence(value: Any) -> Iterable[Any]:
    if isinstance(value, Mapping):
        return value.values()
    if isinstance(value, (list, tuple)):
        return value
    return ()


def retain_unknown_regions(payload: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Return explicit unknown regions without turning them into evidence.

    Region inventories use several shapes across the Bor adapters.  This
    normalizes only the envelope; it deliberately does not invent observations
    for an absent process, kernel, or environment capture.
    """
    retained: list[dict[str, Any]] = []

    def add(value: Any, default_layer: str | None = None) -> None:
        if isinstance(value, str):
            retained.append({"region_id": value, "status": "unknown", **({"layer": default_layer} if default_layer else {})})
            return
        if not isinstance(value, Mapping):
            return
        status = str(value.get("status", "")).lower()
        layer = str(value.get("layer", value.get("scope", default_layer or ""))).lower()
        is_unknown = value.get("unknown") is True or status in _UNKNOWN_STATUSES
        if is_unknown or layer in _UNKNOWN_LAYERS and not value.get("observed", False):
            retained.append(dict(value))

    for item in _as_sequence(payload.get("unknown_regions")):
        add(item)
    for item in _as_sequence(payload.get("regions")):
        add(item)
    for layer in ("process", "environment", "kernel"):
        if layer in payload:
            values = payload[layer]
            if values is None:
                add({"region_id": layer, "layer": layer, "status": "unknown", "reason": "capture absent"})
            else:
                for item in _as_sequence(values):
                    add(item, layer)

    unique: dict[str, dict[str, Any]] = {}
    for item in retained:
        identity = str(item.get("region_id", item.get("id", item.get("name", _fingerprint(item)))))
        unique.setdefault(identity, item)
    return tuple(_canonical(item) for item in unique.values())


@dataclass(frozen=True)
class EconomicHypothesis:
    """A candidate advantage derived from one runtime observation."""

    hypothesis_id: str
    case: str
    kind: str
    advantage: int
    observed: Mapping[str, Any]
    classification: str = "HYPOTHESIS"
    requirements: tuple[str, ...] = (
        "repeat the same execution",
        "obtain an independent runtime observation",
        "confirm canonical state persistence after reopen",
    )

    def record(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "case": self.case,
            "kind": self.kind,
            "advantage": self.advantage,
            "observed": _canonical(self.observed),
            "classification": self.classification,
            "requirements": list(self.requirements),
        }


def _observation_hypothesis(observation: Mapping[str, Any], index: int) -> EconomicHypothesis | None:
    case = str(observation.get("case", f"observation-{index}"))
    before = _first_number(observation, "attacker_balance_before", "sender_balance_before", "balance_before")
    after = _first_number(observation, "attacker_balance_after", "sender_balance_after", "balance_after")
    delta = _first_number(observation, "attacker_delta", "sender_delta", "balance_delta")
    if delta is None and before is not None and after is not None:
        delta = after - before
    if delta is None:
        return None

    equivalent = _first_number(
        observation,
        "equivalent_value",
        "legitimate_credit",
        "value_received",
        "attacker_reward",
    )
    required_debit = _first_number(observation, "required_debit", "expected_debit")
    actual_debit = _first_number(observation, "actual_debit")
    if actual_debit is None and delta < 0:
        actual_debit = -delta
    if required_debit is None:
        value_sent = _first_number(observation, "value_sent", "transfer_value", "value_out")
        fee = _first_number(observation, "fee_paid", "gas_fee", "execution_fee")
        if value_sent is not None and fee is not None:
            required_debit = value_sent + fee

    advantage: int | None = None
    kind: str | None = None
    if delta > 0 and equivalent is not None and delta > equivalent:
        advantage = delta - equivalent
        kind = "unbacked_balance_increase"
    elif required_debit is not None and actual_debit is not None and required_debit > actual_debit:
        advantage = required_debit - actual_debit
        kind = "bypassed_debit"
    elif delta > 0 and equivalent is None:
        # This is deliberately unresolved: a positive delta alone is not an
        # exploit until its economic basis is independently established.
        advantage = delta
        kind = "balance_increase_with_unknown_consideration"
    if advantage is None or advantage <= 0:
        return None

    observed = {
        "balance_before": before,
        "balance_after": after,
        "balance_delta": delta,
        "equivalent_value": equivalent,
        "required_debit": required_debit,
        "actual_debit": actual_debit,
        "economic_basis_known": equivalent is not None or kind == "bypassed_debit",
        "canonical_state_changed": observation.get("canonical_state_changed", observation.get("state_mutated")),
        "persisted": observation.get("persisted", observation.get("receipt_persisted")),
        "reopened": observation.get("reopened"),
    }
    identity = {"case": case, "kind": kind, "advantage": advantage, "observed": observed}
    return EconomicHypothesis("economic:" + _fingerprint(identity), case, kind, advantage, observed)


def derive_economic_hypotheses(payload: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Derive economic candidates exclusively from supplied runtime observations."""
    observations = payload.get("observations", payload if isinstance(payload, Mapping) else {})
    if isinstance(observations, Mapping):
        observations = [observations]
    if not isinstance(observations, (list, tuple)):
        return ()
    result = []
    for index, observation in enumerate(observations):
        if isinstance(observation, Mapping):
            hypothesis = _observation_hypothesis(observation, index)
            if hypothesis is not None:
                result.append(hypothesis.record())
    return tuple(result)


def _hypothesis_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    return (item.get("case"), item.get("kind"), _number(item.get("advantage")))


def _runtime_observation(value: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    if value is None:
        return None
    classification = str(value.get("classification", "RUNTIME_OBSERVATION"))
    if classification not in _RUNTIME_CLASSES:
        return None
    payload = value.get("payload")
    return payload if isinstance(payload, Mapping) else value


def investigate_economic_advantage(
    observation: Mapping[str, Any],
    *,
    reproduction: Mapping[str, Any] | None = None,
    independent: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify runtime economic hypotheses without overstating exploitability."""
    unknown = retain_unknown_regions(observation)
    hypotheses = list(derive_economic_hypotheses(observation))
    for hypothesis in hypotheses:
        hypothesis["classification"] = "HYPOTHESIS"

    reproduced_payload = _runtime_observation(reproduction)
    reproduced = derive_economic_hypotheses(reproduced_payload or {})
    independent_payload = _runtime_observation(independent)
    independently_observed = derive_economic_hypotheses(independent_payload or {})
    reproduced_keys = {_hypothesis_key(item) for item in reproduced}
    independent_keys = {_hypothesis_key(item) for item in independently_observed}
    independent_by_key = {_hypothesis_key(item): item for item in independently_observed}

    findings: list[dict[str, Any]] = []
    for hypothesis in hypotheses:
        key = _hypothesis_key(hypothesis)
        if key not in reproduced_keys:
            hypothesis["classification"] = "UNREPRODUCED_HYPOTHESIS"
            continue
        hypothesis["classification"] = "REPRODUCED_HYPOTHESIS"
        if key not in independent_keys:
            continue
        independent_observation = independent_by_key[key]["observed"]
        persisted = independent_observation.get("canonical_state_changed") is True
        persisted = persisted and independent_observation.get("persisted") is True
        persisted = persisted and independent_observation.get("reopened") is True
        basis_known = hypothesis["observed"].get("economic_basis_known") is True
        if basis_known and persisted and not unknown and independent_payload is not None:
            finding = dict(hypothesis)
            finding["classification"] = "VERIFIED_EXPLOIT"
            finding["verification"] = {
                "repeated": True,
                "independent_runtime_observation": True,
                "canonical_state_persisted_after_reopen": True,
            }
            findings.append(finding)
        else:
            hypothesis["classification"] = "UNRESOLVED_ECONOMIC_HYPOTHESIS"

    if findings:
        classification = "VERIFIED_EXPLOIT"
        conclusion = "verified_attacker_economic_advantage"
    elif hypotheses:
        classification = "HYPOTHESES_ONLY"
        conclusion = "economic_hypotheses_require_independent_verification"
    else:
        classification = "RUNTIME_OBSERVATION"
        conclusion = "no_economic_advantage_observed"
    return {
        "investigation": "bor-economic-advantage",
        "classification": classification,
        "conclusion": conclusion,
        "hypotheses": hypotheses,
        "findings": findings,
        "unknown_regions": list(unknown),
    }


__all__ = [
    "EconomicHypothesis",
    "derive_economic_hypotheses",
    "investigate_economic_advantage",
    "retain_unknown_regions",
]
