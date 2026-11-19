"""Deterministic, budgeted expansion for open interaction domains."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from .result import AnalysisStatus


@dataclass(frozen=True)
class DomainSearchBudget:
    max_candidates: int = 1_000
    max_trace_length: int = 4
    max_time_ms: int = 5_000

    def __post_init__(self) -> None:
        if min(self.max_candidates, self.max_trace_length, self.max_time_ms) <= 0:
            raise ValueError("domain search budgets must be positive")


@dataclass(frozen=True)
class DomainSearchResult:
    status: AnalysisStatus
    attempts: int
    generated: int
    candidate: tuple[Mapping[str, Any], ...] = ()
    detail: str = ""
    frontier_digest: str = ""


class DeterministicDomainExplorer:
    """Explore an expanding interaction domain without claiming completeness."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        evaluate: Callable[[tuple[Mapping[str, Any], ...]], bool],
        *,
        budget: DomainSearchBudget = DomainSearchBudget(),
    ) -> DomainSearchResult:
        queue = [self._normalize(candidate) for candidate in seeds]
        seen: set[str] = set()
        attempts = 0
        generated = len(queue)
        started = time.monotonic()
        budget_hit = False
        while queue:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            candidate = queue.pop(0)
            key = self._key(candidate)
            if key in seen:
                continue
            seen.add(key)
            if len(candidate) > budget.max_trace_length:
                continue
            attempts += 1
            if evaluate(candidate):
                return DomainSearchResult(
                    AnalysisStatus.VALIDATED_WITNESS,
                    attempts,
                    generated,
                    candidate,
                    "candidate was accepted by the supplied replay validator",
                    self._frontier_digest(queue),
                )
            for child in expand(candidate):
                normalized = self._normalize(child)
                if len(normalized) <= budget.max_trace_length and self._key(normalized) not in seen:
                    queue.append(normalized)
                    generated += 1
        status = AnalysisStatus.BUDGET_EXHAUSTED if budget_hit else AnalysisStatus.UNSAT_BOUNDED
        detail = (
            "open interaction domain exhausted its explicit candidate/time budget"
            if budget_hit
            else "no candidate in the generated finite interaction region satisfied the replay validator"
        )
        return DomainSearchResult(status, attempts, generated, detail=detail, frontier_digest=self._frontier_digest(queue))

    @staticmethod
    def _normalize(candidate: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
        return tuple({"entry_point": str(item["entry_point"]), "request": dict(item.get("request", {}))} for item in candidate)

    @staticmethod
    def _key(candidate: Sequence[Mapping[str, Any]]) -> str:
        return json.dumps(list(candidate), sort_keys=True, separators=(",", ":"), default=str)

    @classmethod
    def _frontier_digest(cls, frontier: Sequence[Sequence[Mapping[str, Any]]]) -> str:
        payload = json.dumps([list(item) for item in frontier], sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]
