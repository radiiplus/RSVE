import unittest
from pathlib import Path

from rsve import (
    Authorization,
    DeterministicDomainExplorer,
    DomainSearchBudget,
    FlowToSink,
    GuardInvariant,
    NodeTargetAdapter,
    ObjectiveBudget,
    ObjectiveDefinition,
    StateEquals,
)
from rsve.results import AnalysisStatus
from rsve.semantics import compare_acceptance


FIXTURE = Path(__file__).parent / "fixtures" / "node" / "http_lab.mjs"
MANIFEST = Path(__file__).parent / "fixtures" / "node" / "http_manifest.json"


class HttpOpenDomainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = NodeTargetAdapter(FIXTURE, manifest=MANIFEST, target_id="http-lab", scope="http-lab")
        self.authorization = Authorization("http-domain-test", frozenset({"http-lab"}), frozenset({"http-lab"}))

    def tearDown(self) -> None:
        self.adapter.teardown()

    def _session_accepts(self, mode: str) -> bool:
        report = self.adapter.replay(
            ({"entry_point": "http.session", "request": {"mode": mode}},),
            authorization=self.authorization,
        )
        return any(event.operation == "guard.decision" and event.guard_result is True for event in report.runs[0].events)

    def test_obscure_http_weakness_is_found_by_open_interaction_search(self) -> None:
        observed_domain = ("viewer", "review", "admin")
        residual = compare_acceptance(
            actual=self._session_accepts,
            intended=lambda mode: mode == "admin",
            domain=observed_domain,
        )
        self.assertEqual(residual.over_acceptance, frozenset({"review"}))
        self.assertEqual(residual.under_acceptance, frozenset())

        objective = ObjectiveDefinition(
            "http-canary-import",
            "http-lab",
            "http-lab",
            (
                StateEquals("delivered", 1),
                FlowToSink("http.import", "RSVE-CANARY", "controlled.local.sink"),
                GuardInvariant(),
            ),
            permitted_sinks=frozenset({"controlled.local.sink"}),
            budget=ObjectiveBudget(max_trace_length=2, replay_runs=2),
        )
        objective.validate(self.authorization, harness_sinks={"controlled.local.sink"})

        atoms = (
            {"entry_point": "http.session", "request": {"mode": "viewer"}},
            {"entry_point": "http.session", "request": {"mode": "review"}},
            {"entry_point": "http.session", "request": {"mode": "admin"}},
            {"entry_point": "http.import", "request": {"proof": ""}},
            {"entry_point": "http.import", "request": {"proof": "RSVE-CANARY"}},
        )
        seeds = tuple((atom,) for atom in atoms)

        def expand(candidate):
            return tuple(candidate + (atom,) for atom in atoms)

        def replay_validates(candidate) -> bool:
            report = self.adapter.replay(candidate, runs=2, authorization=self.authorization)
            run = report.runs[0]
            return report.stable and objective.evaluate(run.events[-1].after, run.events)

        result = DeterministicDomainExplorer().search(
            seeds,
            expand,
            replay_validates,
            budget=DomainSearchBudget(max_candidates=50, max_trace_length=2, max_time_ms=5_000),
        )

        self.assertEqual(result.status, AnalysisStatus.VALIDATED_WITNESS)
        self.assertEqual(
            result.candidate,
            (
                {"entry_point": "http.session", "request": {"mode": "review"}},
                {"entry_point": "http.import", "request": {"proof": "RSVE-CANARY"}},
            ),
        )

    def test_open_domain_reports_budget_when_no_witness_is_found(self) -> None:
        atom = {"entry_point": "http.session", "request": {"mode": "viewer"}}
        result = DeterministicDomainExplorer().search(
            ((atom,),),
            lambda candidate: (candidate + (atom,),),
            lambda _candidate: False,
            budget=DomainSearchBudget(max_candidates=2, max_trace_length=4, max_time_ms=5_000),
        )
        self.assertEqual(result.status, AnalysisStatus.BUDGET_EXHAUSTED)


if __name__ == "__main__":
    unittest.main()
