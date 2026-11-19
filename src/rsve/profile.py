"""Versioned execution-stack pins and profile verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from .schema import SchemaMixin


_UNKNOWN = frozenset({"", "unknown", "unobserved", "not-observed"})


class ProfileStatus(str, Enum):
    MATCH = "MATCH"
    DRIFT = "DRIFT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class LayerPin(SchemaMixin):
    """A stable identity claim for one execution layer."""

    layer: str
    name: str
    version: str = "unknown"
    digest: str = ""
    source: str = "unknown"
    evidence: tuple[str, ...] = ()
    required: bool = True

    @property
    def key(self) -> str:
        return f"{self.layer}:{self.name}"


@dataclass(frozen=True)
class ProfileVerification(SchemaMixin):
    profile_id: str
    status: ProfileStatus
    checked: tuple[str, ...] = ()
    drifted: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()
    observed: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutionProfile(SchemaMixin):
    """The versioned stack scope attached to a run and solver result."""

    pins: tuple[LayerPin, ...]
    assumptions: tuple[str, ...] = ()
    profile_id: str = ""

    def __post_init__(self) -> None:
        keys = [pin.key for pin in self.pins]
        if len(keys) != len(set(keys)):
            raise ValueError("execution profile pins must have unique layer/name keys")
        if not self.profile_id:
            payload = [(pin.key, pin.version, pin.digest) for pin in self.pins]
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
            object.__setattr__(self, "profile_id", f"profile-{digest}")

    @classmethod
    def from_target(
        cls,
        identity: Mapping[str, str],
        environment: Any | None = None,
        *,
        extra_pins: Iterable[LayerPin] = (),
        assumptions: tuple[str, ...] = (),
    ) -> "ExecutionProfile":
        facts = dict(getattr(environment, "facts", environment or {}))
        pins = [
            LayerPin("target", identity.get("target_id", "unknown"), identity.get("runtime_version", "unknown"), identity.get("build_hash", ""), "target.identity"),
            LayerPin("runtime", identity.get("runtime", "unknown"), identity.get("runtime_version", "unknown"), "", "target.identity"),
            LayerPin("platform", identity.get("platform", "unknown"), identity.get("platform_version", "unknown"), "", "target.identity"),
            LayerPin("adapter", identity.get("adapter", "unknown"), identity.get("adapter_version", "unknown"), "", "target.identity"),
        ]
        profile_id = getattr(environment, "profile_id", "unknown")
        if profile_id not in _UNKNOWN:
            pins.append(LayerPin("environment", "profile", profile_id, "", "environment.observation"))
        if facts.get("os") not in _UNKNOWN:
            pins.append(LayerPin("os", facts["os"], facts.get("kernel", "unknown"), facts.get("os_image_sha256", ""), "environment.observation"))
        if facts.get("architecture") not in _UNKNOWN:
            pins.append(LayerPin("isa", facts["architecture"], facts.get("abi", "unknown"), "", "environment.observation"))
        pins.extend(extra_pins)
        return cls(tuple(pins), assumptions=assumptions)

    def verify(self, observed: Iterable[LayerPin]) -> ProfileVerification:
        observed_by_key = {pin.key: pin for pin in observed}
        checked: list[str] = []
        drifted: list[str] = []
        unknown: list[str] = []
        for expected in self.pins:
            actual = observed_by_key.get(expected.key)
            if actual is None:
                unknown.append(expected.key)
                continue
            if (
                expected.version not in _UNKNOWN
                and actual.version not in _UNKNOWN
                and expected.version != actual.version
            ) or (
                expected.digest
                and actual.digest
                and expected.digest != actual.digest
            ):
                drifted.append(expected.key)
            elif expected.version in _UNKNOWN or (expected.digest and not actual.digest):
                unknown.append(expected.key)
            else:
                checked.append(expected.key)
        status = ProfileStatus.DRIFT if drifted else ProfileStatus.UNKNOWN if unknown else ProfileStatus.MATCH
        return ProfileVerification(
            profile_id=self.profile_id,
            status=status,
            checked=tuple(sorted(checked)),
            drifted=tuple(sorted(drifted)),
            unknown=tuple(sorted(unknown)),
            observed=tuple(sorted(observed_by_key)),
        )
