"""Deterministic, budgeted expansion for open interaction domains."""

from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from .result import Status
from .signature import Archive, Signature


@dataclass(frozen=True)
class Bounds:
    max_candidates: int = 1_000
    max_trace_length: int = 4
    max_time_ms: int = 5_000

    def __post_init__(self) -> None:
        if min(self.max_candidates, self.max_trace_length, self.max_time_ms) <= 0:
            raise ValueError("domain search budgets must be positive")


@dataclass(frozen=True)
class Found:
    status: Status
    attempts: int
    generated: int
    candidate: tuple[Mapping[str, Any], ...] = ()
    detail: str = ""
    frontier_digest: str = ""


@dataclass(frozen=True)
class Trial:
    """One evaluated candidate and its behavior evidence."""

    accepted: bool
    signature: Signature | None
    detail: str = ""


class Explorer:
    """Explore an expanding interaction domain without claiming completeness."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        evaluate: Callable[[tuple[Mapping[str, Any], ...]], bool],
        *,
        budget: Bounds = Bounds(),
    ) -> Found:
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
                return Found(
                    Status.VALIDATED_WITNESS,
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
        status = Status.BUDGET_EXHAUSTED if budget_hit else Status.UNSAT_BOUNDED
        detail = (
            "open interaction domain exhausted its explicit candidate/time budget"
            if budget_hit
            else "no candidate in the generated finite interaction region satisfied the replay validator"
        )
        return Found(status, attempts, generated, detail=detail, frontier_digest=self._frontier_digest(queue))

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


@dataclass
class _Node:
    candidate: tuple[Mapping[str, Any], ...]
    parent: "_Node | None" = None
    children: dict[str, "_Node"] | None = None
    visits: int = 0
    value: float = 0.0
    expanded: bool = False

    def __post_init__(self) -> None:
        if self.children is None:
            self.children = {}


class Mcts:
    """Deterministic, bounded Monte Carlo tree search over behavior novelty.

    ``assess`` must execute or model a candidate and return its objective
    result plus a ``Signature`` derived from that execution. Novelty only
    ranks candidates; ``accepted`` remains the caller's objective decision.
    """

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
        explore: float = 1.41421356237,
    ) -> Found:
        root = _Node(())
        known: set[str] = set()
        generated = 0
        for seed in seeds:
            candidate = Explorer._normalize(seed)
            key = Explorer._key(candidate)
            if len(candidate) <= budget.max_trace_length and key not in known:
                root.children[key] = _Node(candidate, root)
                known.add(key)
                generated += 1
        if not root.children:
            return Found(Status.UNSAT_BOUNDED, 0, 0, detail="no seed candidates were supplied")

        cache: dict[str, Trial] = {}
        attempts = 0
        started = time.monotonic()
        budget_hit = False
        details: list[str] = []

        while root.children:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            if len(cache) >= len(known):
                break
            node = self._select(root, explore)
            key = Explorer._key(node.candidate)
            trial = cache.get(key)
            if trial is None:
                trial = assess(node.candidate)
                cache[key] = trial
                attempts += 1
                if trial.signature is None:
                    details.append(f"candidate {key} produced no behavior signature")
                    novelty = 0
                else:
                    archive, observation = archive.offer(trial.signature)
                    novelty = observation.score
                node.value = float((10_000 if trial.accepted else 0) + novelty)
                node.visits = 1
                if trial.accepted:
                    return Found(
                        Status.VALIDATED_WITNESS,
                        attempts,
                        generated,
                        node.candidate,
                        "MCTS accepted a candidate after behavior-aware assessment",
                        Explorer._frontier_digest(tuple(item.candidate for item in root.children.values())),
                    )
                if trial.detail:
                    details.append(trial.detail)
            self._expand(node, expand, known, budget)
            generated = len(known)
            self._back(node)

        status = Status.BUDGET_EXHAUSTED if budget_hit else Status.UNSAT_BOUNDED
        detail = (
            "MCTS exhausted its explicit candidate/time budget"
            if budget_hit
            else "MCTS exhausted the generated finite candidate tree"
        )
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(status, attempts, generated, detail=detail, frontier_digest=Explorer._frontier_digest(tuple(item.candidate for item in root.children.values())))

    @staticmethod
    def _select(root: _Node, explore: float) -> _Node:
        node = root
        while node.children:
            unvisited = [child for child in node.children.values() if child.visits == 0]
            if unvisited:
                return min(unvisited, key=lambda child: Explorer._key(child.candidate))
            parent_visits = max(1, node.visits)
            node = max(
                node.children.values(),
                key=lambda child: (
                    child.value / child.visits
                    + explore * math.sqrt(math.log(parent_visits + 1) / child.visits),
                    Explorer._key(child.candidate),
                ),
            )
        return node

    @staticmethod
    def _expand(
        node: _Node,
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        known: set[str],
        budget: Bounds,
    ) -> None:
        if node.expanded:
            return
        node.expanded = True
        for child in expand(node.candidate):
            candidate = Explorer._normalize(child)
            if len(candidate) > budget.max_trace_length:
                continue
            key = Explorer._key(candidate)
            if key in known:
                continue
            known.add(key)
            node.children[key] = _Node(candidate, node)

    @staticmethod
    def _back(node: _Node) -> None:
        current = node.parent
        while current is not None:
            current.visits += 1
            current.value = max(current.value, node.value)
            current = current.parent


class Evolve:
    """Bounded evolutionary search selected by behavior novelty."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        mutate: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
        size: int = 8,
    ) -> Found:
        if size <= 0:
            raise ValueError("evolution population size must be positive")
        population: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for seed in seeds:
            candidate = Explorer._normalize(seed)
            if len(candidate) <= budget.max_trace_length:
                population.setdefault(Explorer._key(candidate), candidate)
        if not population:
            return Found(Status.UNSAT_BOUNDED, 0, 0, detail="no seed candidates were supplied")

        attempts = 0
        generated = len(population)
        started = time.monotonic()
        budget_hit = False
        details: list[str] = []
        while population:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            scored: list[tuple[int, str, tuple[Mapping[str, Any], ...]]] = []
            for key, candidate in sorted(population.items()):
                if attempts >= budget.max_candidates:
                    budget_hit = True
                    break
                trial = assess(candidate)
                attempts += 1
                novelty = 0
                if trial.signature is not None:
                    archive, observation = archive.offer(trial.signature)
                    novelty = observation.score
                else:
                    details.append(f"candidate {key} produced no behavior signature")
                if trial.detail:
                    details.append(trial.detail)
                if trial.accepted:
                    return Found(
                        Status.VALIDATED_WITNESS,
                        attempts,
                        generated,
                        candidate,
                        "evolution accepted a candidate after behavior-aware assessment",
                        Explorer._frontier_digest(tuple(population.values())),
                    )
                scored.append((novelty, key, candidate))
            if budget_hit or not scored:
                break
            scored.sort(key=lambda item: (-item[0], item[1]))
            parents = [item[2] for item in scored[:max(1, min(size, len(scored) // 2 or 1))]]
            next_population: dict[str, tuple[Mapping[str, Any], ...]] = {}
            for parent in parents:
                for child in mutate(parent):
                    candidate = Explorer._normalize(child)
                    if len(candidate) > budget.max_trace_length:
                        continue
                    key = Explorer._key(candidate)
                    if key not in next_population:
                        next_population[key] = candidate
                        generated += 1
                    if len(next_population) >= size:
                        break
                if len(next_population) >= size:
                    break
            population = next_population

        status = Status.BUDGET_EXHAUSTED if budget_hit else Status.UNSAT_BOUNDED
        detail = (
            "evolution exhausted its explicit candidate/time budget"
            if budget_hit
            else "evolution exhausted the generated finite candidate population"
        )
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(status, attempts, generated, detail=detail, frontier_digest=Explorer._frontier_digest(tuple(population.values())))
