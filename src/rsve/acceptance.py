"""Small, explicit residual-set helpers for recognizer analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class Residual:
    """Finite-domain evidence for the two acceptance residual directions."""

    domain: tuple[Any, ...]
    accepted_actual: frozenset[Any]
    accepted_intended: frozenset[Any]
    over_acceptance: frozenset[Any]
    under_acceptance: frozenset[Any]


def compare(
    actual: Callable[[Any], bool],
    intended: Callable[[Any], bool],
    domain: Iterable[Any],
) -> Residual:
    values = tuple(domain)
    actual_set = frozenset(value for value in values if actual(value))
    intended_set = frozenset(value for value in values if intended(value))
    return Residual(
        domain=values,
        accepted_actual=actual_set,
        accepted_intended=intended_set,
        over_acceptance=actual_set - intended_set,
        under_acceptance=intended_set - actual_set,
    )


def gap(
    transform: Callable[[Any], Any],
    source_domain: Iterable[Any],
    downstream_domain: Iterable[Any],
) -> frozenset[Any]:
    """Compute Image(T) minus D over a declared finite source domain."""
    image = frozenset(transform(value) for value in source_domain)
    return image - frozenset(downstream_domain)
