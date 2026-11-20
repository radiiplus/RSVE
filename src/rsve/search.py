"""Deterministic, budgeted expansion for open interaction domains."""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import random
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable, Mapping, Sequence

from .result import Status
from .signature import Archive, Signature
from .model import Authorization, Event, State
from .objective import Objective
from .workspace import Frame, Workspace


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
    archive: Archive = Archive()


@dataclass(frozen=True)
class Trial:
    """One evaluated candidate and its behavior evidence."""

    accepted: bool
    signature: Signature | None
    detail: str = ""
    status: Status = Status.SAT_CANDIDATE
    progress: float = 0.0
    replayed: bool = False
    stable: bool | None = None

    def __post_init__(self) -> None:
        if self.progress < 0:
            raise ValueError("trial progress must be non-negative")
        if self.status is Status.VALIDATED_WITNESS and not (self.accepted and self.replayed and self.stable is True):
            raise ValueError("validated trials require accepted stable replay evidence")


class Guide:
    """Connect novelty search to RSVE regression and workspace execution.

    The guide owns candidate discovery and assessment for a composed workspace.
    Strategies remain responsible only for ordering the candidates they are
    given. Model-only results are reported as ``MODEL_SAT``; adapter replay is
    required before ``VALIDATED_WITNESS`` can be returned.
    """

    def __init__(
        self,
        workspace: Workspace,
        objective: Objective,
        authorization: Authorization,
        *,
        harness_sinks: set[str] | frozenset[str] = frozenset(),
        adapter: Any | None = None,
    ) -> None:
        if workspace.model.target_id != objective.target_id:
            raise ValueError("workspace and objective target identities must match")
        objective.validate(
            authorization,
            harness_sinks=harness_sinks,
            environment=workspace.start().environment.as_dict(),
        )
        self.workspace = workspace
        self.objective = objective
        self.authorization = authorization
        self.adapter = adapter
        from .planner import Regressor

        self.plan = Regressor().regress(
            workspace.model,
            objective,
            workspace=workspace,
            solver_timeout_ms=objective.budget.solver_timeout_ms,
        )
        self.notes = list(self.plan.uncertainty)
        self._requests: dict[str, tuple[Mapping[str, Any], ...]] | None = None
        self._prepared = False
        self._baseline: Any = None

    def close(self) -> None:
        if self._prepared and self.adapter is not None:
            self.adapter.teardown()
            self._prepared = False

    def _prepare(self) -> None:
        if self.adapter is not None and not self._prepared:
            self.adapter.prepare()
            self._baseline = self.adapter.snapshot()
            self._prepared = True

    def _entries(self) -> tuple[str, ...]:
        return tuple(sorted({item.entry_point.name for item in self.workspace.operations()}))

    def _domains(self) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
        if self._requests is not None:
            return self._requests
        values: dict[str, list[Mapping[str, Any]]] = {entry: [] for entry in self._entries()}
        for entry, request in self.plan.required_actions:
            values.setdefault(entry, []).append(dict(request))
        for entry in tuple(values):
            try:
                values[entry].extend(self.workspace.probes_for(entry, self.objective.budget.max_states))
            except Exception as exc:
                self.notes.append(f"probe expansion for {entry} is unknown: {type(exc).__name__}")
        model_requests = self.workspace.model.args()
        for entry in values:
            values[entry].extend(model_requests)
            if not values[entry]:
                values[entry].append({})
            unique: dict[str, Mapping[str, Any]] = {}
            for request in values[entry]:
                key = json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)
                unique.setdefault(key, dict(request))
            values[entry] = list(unique.values())[: self.objective.budget.max_states]
        self._requests = {entry: tuple(requests) for entry, requests in values.items()}
        return self._requests

    def seeds(self) -> tuple[tuple[Mapping[str, Any], ...], ...]:
        found: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for trace in self.plan.required_traces:
            candidate = tuple(dict(item) for item in trace)
            found.setdefault(self._key(candidate), candidate)
        for entry, request in self.plan.required_actions:
            candidate = ({"entry_point": entry, "request": dict(request)},)
            found.setdefault(self._key(candidate), candidate)
        if not found:
            for entry, requests in self._domains().items():
                for request in requests:
                    candidate = ({"entry_point": entry, "request": dict(request)},)
                    found.setdefault(self._key(candidate), candidate)
        return tuple(found.values())

    def expand(self, candidate: tuple[Mapping[str, Any], ...]) -> tuple[tuple[Mapping[str, Any], ...], ...]:
        if len(candidate) >= self.objective.budget.max_trace_length:
            return ()
        result: list[tuple[Mapping[str, Any], ...]] = []
        for entry, requests in self._domains().items():
            for request in requests:
                if not self.workspace.model.allows(entry, request):
                    continue
                result.append(candidate + ({"entry_point": entry, "request": dict(request)},))
        return tuple(result)

    def _model(self, candidate: Sequence[Mapping[str, Any]]) -> tuple[tuple[Frame, tuple[Event, ...], bool], ...]:
        frontier: list[tuple[Frame, tuple[Event, ...], bool]] = [(self.workspace.start(), (), False)]
        for index, interaction in enumerate(candidate):
            entry = str(interaction["entry_point"])
            request = dict(interaction.get("request", {}))
            if not self.workspace.model.allows(entry, request):
                return ()
            operations = self.workspace.operations(entry)
            if not operations:
                return ()
            next_frontier: list[tuple[Frame, tuple[Event, ...], bool]] = []
            for frame, events, uncertain in frontier:
                for operation in operations:
                    for move in self.workspace.moves(frame, entry, request, operation=operation):
                        event = replace(move.event, ordering=len(events))
                        next_frontier.append((move.after, events + (event,), uncertain or move.after.uncertain))
                        if len(next_frontier) >= self.objective.budget.max_states:
                            self.notes.append("workspace candidate branches were bounded by max_states")
                            break
                    if len(next_frontier) >= self.objective.budget.max_states:
                        break
                if len(next_frontier) >= self.objective.budget.max_states:
                    break
            frontier = next_frontier
            if not frontier:
                return ()
        return tuple(frontier)

    def _signature(self, events: Sequence[Event], frame: Frame) -> Signature:
        profile = "workspace"
        scope: dict[str, Any] = {
            "model_version": self.workspace.model.model_version,
            "build_hash": self.workspace.model.build_hash,
            "objective_version": self.objective.version,
        }
        if self.adapter is not None:
            try:
                identity = self.adapter.identity()
                profile = str(identity.get("profile_id", identity.get("version", "adapter")))
                scope.update({str(key): value for key, value in identity.items()})
            except Exception as exc:
                self.notes.append(f"adapter identity is unknown: {type(exc).__name__}")
        return Signature.make(
            tuple(events),
            frame,
            target=self.workspace.model.target_id,
            profile=profile,
            keys=self.objective.state_keys,
            scope=scope,
        )

    def _replay(self, candidate: tuple[Mapping[str, Any], ...], predicted: Trial) -> Trial:
        self._prepare()
        outcomes: list[bool] = []
        signatures: list[str] = []
        observed_events: tuple[Event, ...] = ()
        try:
            for _ in range(self.objective.budget.replay_runs):
                self.adapter.reset(self._baseline)
                observed_events = tuple(self.adapter.trace(candidate, self.authorization))
                final = observed_events[-1].after if observed_events else self.workspace.model.initial_state
                result = self.objective.evaluate(final, observed_events)
                result = result and self.objective.satisfy(self.workspace.start().view(), observed_events)
                outcomes.append(result)
                signatures.append(json.dumps([event.canonical() for event in observed_events], sort_keys=True, default=str))
        except Exception as exc:
            return Trial(False, predicted.signature, f"authorized replay failed: {type(exc).__name__}", Status.UNKNOWN)
        accepted = bool(outcomes) and all(outcomes)
        stable = bool(outcomes) and len(set(outcomes)) == 1 and len(set(signatures)) == 1
        status = Status.VALIDATED_WITNESS if accepted and stable and predicted.accepted else Status.MODEL_DIVERGENCE if accepted != predicted.accepted else Status.SAT_CANDIDATE
        return Trial(accepted, predicted.signature, "replay did not match the model" if accepted != predicted.accepted else "", status, predicted.progress, True, stable)

    def assess(self, candidate: tuple[Mapping[str, Any], ...]) -> Trial:
        branches = self._model(candidate)
        if not branches:
            return Trial(False, None, "candidate has no modeled successor", Status.UNKNOWN)
        best: tuple[float, Frame, tuple[Event, ...], bool, bool] | None = None
        for frame, events, uncertain in branches:
            satisfied = sum(predicate.evaluate(frame.view(), events) for predicate in self.objective.postconditions)
            progress = satisfied / max(1, len(self.objective.postconditions))
            accepted = self.objective.evaluate(frame.view(), events) and self.objective.satisfy(self.workspace.start().view(), events)
            item = (progress, frame, events, uncertain, accepted)
            if best is None or item[0] > best[0]:
                best = item
            if accepted and not uncertain:
                signature = self._signature(events, frame)
                trial = Trial(True, signature, status=Status.MODEL_SAT, progress=progress)
                return self._replay(candidate, trial) if self.adapter is not None else trial
        assert best is not None
        progress, frame, events, uncertain, accepted = best
        signature = self._signature(events, frame)
        if accepted and uncertain:
            return Trial(False, signature, "objective reached through an uncertain modeled branch", Status.UNKNOWN, progress)
        return Trial(False, signature, "objective not reached in modeled branches", Status.UNKNOWN if uncertain else Status.SAT_CANDIDATE, progress)

    @staticmethod
    def _key(candidate: Sequence[Mapping[str, Any]]) -> str:
        return json.dumps(list(candidate), sort_keys=True, separators=(",", ":"), default=str)

    def search(
        self,
        strategy: str | Any = "frontier",
        *,
        budget: Bounds | None = None,
        archive: Archive = Archive(),
        **options: Any,
    ) -> Found:
        strategies = {
            "mcts": Mcts,
            "evolve": Evolve,
            "beam": Beam,
            "frontier": Frontier,
            "anneal": Anneal,
        }
        selected = strategies[strategy] if isinstance(strategy, str) else strategy
        runner = selected() if isinstance(selected, type) else selected
        bounds = budget or Bounds(
            max_candidates=self.objective.budget.max_states,
            max_trace_length=max(1, self.objective.budget.max_trace_length),
            max_time_ms=self.objective.budget.max_time_ms,
        )
        try:
            if isinstance(runner, (Evolve, Anneal)):
                return runner.search(self.seeds(), self.expand, self.assess, budget=bounds, archive=archive, **options)
            return runner.search(self.seeds(), self.expand, self.assess, budget=bounds, archive=archive, **options)
        finally:
            self.close()


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
            if generated >= budget.max_candidates:
                break
            candidate = Explorer._normalize(seed)
            key = Explorer._key(candidate)
            if len(candidate) <= budget.max_trace_length and key not in known:
                root.children[key] = _Node(candidate, root)
                known.add(key)
                generated += 1
        if not root.children:
            return Found(Status.UNSAT_BOUNDED, 0, 0, detail="no seed candidates were supplied", archive=archive)

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
                reward = float((10_000 if trial.accepted else 0) + novelty + trial.progress)
                if trial.accepted:
                    return Found(
                        trial.status,
                        attempts,
                        generated,
                        node.candidate,
                        "MCTS accepted a candidate after behavior-aware assessment",
                        Explorer._frontier_digest(tuple(item.candidate for item in root.children.values())),
                        archive,
                    )
                if trial.detail:
                    details.append(trial.detail)
            else:
                reward = float(10_000 if trial.accepted else 0) + trial.progress
            self._expand(node, expand, known, budget)
            generated = len(known)
            self._back(node, reward)

        status = Status.BUDGET_EXHAUSTED if budget_hit else Status.UNSAT_BOUNDED
        detail = (
            "MCTS exhausted its explicit candidate/time budget"
            if budget_hit
            else "MCTS exhausted the generated finite candidate tree"
        )
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(status, attempts, generated, detail=detail, frontier_digest=Explorer._frontier_digest(tuple(item.candidate for item in root.children.values())), archive=archive)

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
            if len(known) >= budget.max_candidates:
                break
            candidate = Explorer._normalize(child)
            if len(candidate) > budget.max_trace_length:
                continue
            key = Explorer._key(candidate)
            if key in known:
                continue
            known.add(key)
            node.children[key] = _Node(candidate, node)

    @staticmethod
    def _back(node: _Node, reward: float) -> None:
        current: _Node | None = node
        while current is not None:
            current.visits += 1
            current.value += reward
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
            if len(population) >= budget.max_candidates:
                break
            candidate = Explorer._normalize(seed)
            if len(candidate) <= budget.max_trace_length:
                population.setdefault(Explorer._key(candidate), candidate)
        if not population:
            return Found(Status.UNSAT_BOUNDED, 0, 0, detail="no seed candidates were supplied", archive=archive)

        attempts = 0
        generated = len(population)
        started = time.monotonic()
        budget_hit = False
        details: list[str] = []
        while population:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            scored: list[tuple[float, str, tuple[Mapping[str, Any], ...]]] = []
            for key, candidate in sorted(population.items()):
                if attempts >= budget.max_candidates:
                    budget_hit = True
                    break
                trial = assess(candidate)
                attempts += 1
                novelty = 0.0
                if trial.signature is not None:
                    archive, observation = archive.offer(trial.signature)
                    novelty = float(observation.score) + trial.progress
                else:
                    details.append(f"candidate {key} produced no behavior signature")
                if trial.detail:
                    details.append(trial.detail)
                if trial.accepted:
                    return Found(
                        trial.status,
                        attempts,
                        generated,
                        candidate,
                        "evolution accepted a candidate after behavior-aware assessment",
                        Explorer._frontier_digest(tuple(population.values())),
                        archive,
                    )
                scored.append((novelty, key, candidate))
            if budget_hit or not scored:
                break
            scored.sort(key=lambda item: (-item[0], item[1]))
            parents = [item[2] for item in scored[:max(1, min(size, len(scored) // 2 or 1))]]
            next_population: dict[str, tuple[Mapping[str, Any], ...]] = {}
            for parent in parents:
                for child in mutate(parent):
                    if generated >= budget.max_candidates:
                        budget_hit = True
                        break
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
            if budget_hit:
                break

        status = Status.BUDGET_EXHAUSTED if budget_hit else Status.UNSAT_BOUNDED
        detail = (
            "evolution exhausted its explicit candidate/time budget"
            if budget_hit
            else "evolution exhausted the generated finite candidate population"
        )
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(status, attempts, generated, detail=detail, frontier_digest=Explorer._frontier_digest(tuple(population.values())), archive=archive)


class Beam:
    """Layer-wise novelty search that retains a bounded diverse beam."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
        width: int = 8,
    ) -> Found:
        if width <= 0:
            raise ValueError("beam width must be positive")
        population = self._seeds(seeds, budget)
        if not population:
            return Found(Status.UNSAT_BOUNDED, 0, 0, detail="no seed candidates were supplied", archive=archive)
        known = {Explorer._key(item) for item in population}
        attempts = 0
        generated = len(population)
        started = time.monotonic()
        details: list[str] = []
        budget_hit = False
        while population:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            scored: list[tuple[float, str, tuple[Mapping[str, Any], ...]]] = []
            for candidate in sorted(population, key=Explorer._key):
                if attempts >= budget.max_candidates:
                    budget_hit = True
                    break
                trial = assess(candidate)
                attempts += 1
                novelty, detail = self._novel(trial, archive)
                if trial.signature is not None:
                    archive, _ = archive.offer(trial.signature)
                if detail:
                    details.append(detail)
                if trial.detail:
                    details.append(trial.detail)
                if trial.accepted:
                    return Found(trial.status, attempts, generated, candidate, "beam accepted a behavior-assessed candidate", archive=archive)
                scored.append((novelty, Explorer._key(candidate), candidate))
            if budget_hit or not scored:
                break
            scored.sort(key=lambda item: (-item[0], item[1]))
            children: dict[str, tuple[Mapping[str, Any], ...]] = {}
            for _novelty, _key, parent in scored[:width]:
                for child in expand(parent):
                    if generated >= budget.max_candidates:
                        budget_hit = True
                        break
                    candidate = Explorer._normalize(child)
                    if len(candidate) > budget.max_trace_length:
                        continue
                    key = Explorer._key(candidate)
                    if key not in known and key not in children:
                        children[key] = candidate
                        known.add(key)
                        generated += 1
                    if len(children) >= width:
                        break
                if len(children) >= width:
                    break
            population = tuple(children.values())
            if budget_hit:
                break
        status = Status.BUDGET_EXHAUSTED if budget_hit else Status.UNSAT_BOUNDED
        detail = "beam exhausted its explicit candidate/time budget" if budget_hit else "beam exhausted the generated finite layers"
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(status, attempts, generated, detail=detail, archive=archive)

    @staticmethod
    def _seeds(seeds: Iterable[Sequence[Mapping[str, Any]]], budget: Bounds) -> tuple[tuple[Mapping[str, Any], ...], ...]:
        found: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for seed in seeds:
            if len(found) >= budget.max_candidates:
                break
            candidate = Explorer._normalize(seed)
            if len(candidate) <= budget.max_trace_length:
                found.setdefault(Explorer._key(candidate), candidate)
        return tuple(found.values())

    @staticmethod
    def _novel(trial: Trial, archive: Archive) -> tuple[float, str | None]:
        if trial.signature is None:
            return trial.progress, "candidate produced no behavior signature"
        _, novelty = archive.offer(trial.signature)
        return float(novelty.score) + trial.progress, None


class Frontier:
    """Best-first novelty search over an explicitly generated candidate frontier."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        expand: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
    ) -> Found:
        queue: list[tuple[float, str, tuple[Mapping[str, Any], ...]]] = []
        known: set[str] = set()
        for seed in seeds:
            if len(known) >= budget.max_candidates:
                break
            candidate = Explorer._normalize(seed)
            if len(candidate) <= budget.max_trace_length:
                key = Explorer._key(candidate)
                if key not in known:
                    known.add(key)
                    heapq.heappush(queue, (0, key, candidate))
        if not queue:
            return Found(Status.UNSAT_BOUNDED, 0, 0, detail="no seed candidates were supplied", archive=archive)
        attempts = 0
        generated = len(known)
        started = time.monotonic()
        budget_hit = False
        details: list[str] = []
        while queue:
            if attempts >= budget.max_candidates or (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            _priority, key, candidate = heapq.heappop(queue)
            trial = assess(candidate)
            attempts += 1
            novelty, detail = Beam._novel(trial, archive)
            if trial.signature is not None:
                archive, _ = archive.offer(trial.signature)
            if detail:
                details.append(detail)
            if trial.detail:
                details.append(trial.detail)
            if trial.accepted:
                return Found(trial.status, attempts, generated, candidate, "frontier accepted a behavior-assessed candidate", archive=archive)
            for child in expand(candidate):
                if generated >= budget.max_candidates:
                    budget_hit = True
                    break
                normalized = Explorer._normalize(child)
                if len(normalized) > budget.max_trace_length:
                    continue
                child_key = Explorer._key(normalized)
                if child_key in known:
                    continue
                known.add(child_key)
                generated += 1
                heapq.heappush(queue, (-novelty, child_key, normalized))
            if budget_hit:
                break
        status = Status.BUDGET_EXHAUSTED if budget_hit else Status.UNSAT_BOUNDED
        detail = "frontier exhausted its explicit candidate/time budget" if budget_hit else "frontier exhausted the generated finite candidates"
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(status, attempts, generated, detail=detail, frontier_digest=Explorer._frontier_digest(tuple(item[2] for item in queue)), archive=archive)


class Anneal:
    """Deterministic simulated-annealing search over behavior signatures."""

    def search(
        self,
        seeds: Iterable[Sequence[Mapping[str, Any]]],
        mutate: Callable[[tuple[Mapping[str, Any], ...]], Iterable[Sequence[Mapping[str, Any]]]],
        assess: Callable[[tuple[Mapping[str, Any], ...]], Trial],
        *,
        budget: Bounds = Bounds(),
        archive: Archive = Archive(),
        seed: int = 0,
        start: float = 3.0,
        cool: float = 0.85,
    ) -> Found:
        if start <= 0 or not 0 < cool < 1:
            raise ValueError("annealing requires positive start temperature and cooling in (0, 1)")
        population = Beam._seeds(seeds, budget)
        if not population:
            return Found(Status.UNSAT_BOUNDED, 0, 0, detail="no seed candidates were supplied", archive=archive)
        current = min(population, key=Explorer._key)
        known = {Explorer._key(item) for item in population}
        attempts = 0
        generated = len(known)
        started = time.monotonic()
        temperature = start
        rng = random.Random(seed)
        details: list[str] = []
        current_score = 0
        budget_hit = False
        while attempts < budget.max_candidates:
            if (time.monotonic() - started) * 1000 >= budget.max_time_ms:
                budget_hit = True
                break
            trial = assess(current)
            attempts += 1
            score, detail = Beam._novel(trial, archive)
            if trial.signature is not None:
                archive, _ = archive.offer(trial.signature)
            if detail:
                details.append(detail)
            if trial.detail:
                details.append(trial.detail)
            if trial.accepted:
                return Found(trial.status, attempts, generated, current, "annealing accepted a behavior-assessed candidate", archive=archive)
            current_score = score
            candidates: list[tuple[float, str, tuple[Mapping[str, Any], ...]]] = []
            for child in mutate(current):
                if attempts >= budget.max_candidates:
                    budget_hit = True
                    break
                candidate = Explorer._normalize(child)
                if len(candidate) > budget.max_trace_length:
                    continue
                key = Explorer._key(candidate)
                if key in known:
                    continue
                known.add(key)
                generated += 1
                child_trial = assess(candidate)
                attempts += 1
                child_score, child_detail = Beam._novel(child_trial, archive)
                if child_trial.signature is not None:
                    archive, _ = archive.offer(child_trial.signature)
                if child_detail:
                    details.append(child_detail)
                if child_trial.detail:
                    details.append(child_trial.detail)
                if child_trial.accepted:
                    return Found(child_trial.status, attempts, generated, candidate, "annealing accepted a behavior-assessed candidate", archive=archive)
                candidates.append((child_score, key, candidate))
                if attempts >= budget.max_candidates:
                    budget_hit = True
                    break
            if budget_hit or not candidates:
                break
            candidates.sort(key=lambda item: (-item[0], item[1]))
            score, _key, candidate = candidates[0]
            delta = score - current_score
            probability = 1.0 if delta >= 0 else math.exp(delta / max(temperature, 1e-9))
            if delta >= 0 or rng.random() < probability:
                current = candidate
                current_score = score
            temperature *= cool
        status = Status.BUDGET_EXHAUSTED if budget_hit or attempts >= budget.max_candidates else Status.UNSAT_BOUNDED
        detail = "annealing exhausted its explicit candidate/time budget" if status is Status.BUDGET_EXHAUSTED else "annealing exhausted the generated mutation neighborhood"
        if details:
            detail += "; " + "; ".join(dict.fromkeys(details))
        return Found(status, attempts, generated, detail=detail, archive=archive)
