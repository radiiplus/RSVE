import tempfile
import unittest
from pathlib import Path

from rsve import (
    acceptance_residual,
    bounded_path_residual,
    Authorization,
    Budget,
    CandidateRegion,
    Engine,
    EffectLemma,
    EntryPoint,
    JsonlArtifactStore,
    Objective,
    Operation,
    State,
    TraceEvent,
    TransitionModel,
)
from rsve.engine import AuthorizationError
from rsve.results import AnalysisStatus, GapKind, SolverStatus
from rsve.semantics import compare_acceptance, transform_domain_mismatch
from rsve import (
    AllOf,
    AnyOf,
    ConstraintQuery,
    Equal,
    Evidence,
    ExecutionMode,
    InformationLoss,
    IntRange,
    Invertibility,
    Literal,
    Partiality,
    RelationKind,
    Representation,
    ResultScope,
    Sort,
    StateRelation,
    SolverLimits,
    SurfaceRegistry,
    TargetIdentity,
    Transform,
    Transition,
    Variable,
    Z3SolverAdapter,
    transform_domain_residual,
)
from rsve.constraints import NamedAssumption
from rsve.ir import ObjectiveAst, ObjectiveCheckpoint
from rsve.model import Fidelity, Provenance


def fixture_model() -> TransitionModel:
    return TransitionModel(
        target_id="fixture",
        initial_state=State({"count": 0}),
        inputs=({"amount": 1}, {"amount": 2}),
        operations=(
            Operation(
                name="increment",
                entry_point=EntryPoint("lab.increment"),
                guard=lambda _state, request: request["amount"] > 0,
                apply=lambda state, request: state.with_updates(count=state["count"] + request["amount"]),
            ),
        ),
        build_hash="fixture-build",
    )


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = Engine()
        self.auth = Authorization("tests", frozenset({"fixture-lab"}))
        self.objective = Objective("reach-two", "fixture-lab", lambda state, _trace: state["count"] == 2)

    def test_deterministically_synthesizes_shortest_witness(self) -> None:
        report = self.engine.analyze(fixture_model(), self.objective, self.auth, Budget(max_depth=2))
        self.assertEqual(report.status, AnalysisStatus.MODEL_SAT)
        self.assertFalse(report.witness.validated)
        self.assertEqual(report.proof.status, SolverStatus.SAT)
        self.assertIsNotNone(report.witness)
        assert report.witness is not None
        self.assertEqual([event.request for event in report.witness.events], [{"amount": 2}])

    def test_unauthorized_objective_is_rejected(self) -> None:
        with self.assertRaises(AuthorizationError):
            self.engine.analyze(
                fixture_model(),
                self.objective,
                Authorization("tests", frozenset()),
                Budget(max_depth=1),
            )

    def test_no_witness_is_bounded_not_global_proof(self) -> None:
        objective = Objective("reach-nine", "fixture-lab", lambda state, _trace: state["count"] == 9)
        report = self.engine.analyze(fixture_model(), objective, self.auth, Budget(max_depth=1))
        self.assertEqual(report.status, AnalysisStatus.UNSAT_BOUNDED)
        self.assertEqual(report.proof.status, SolverStatus.UNSAT_BOUNDED)
        self.assertEqual(report.gaps[0].kind, GapKind.BOUND)

    def test_effect_lemmas_are_validated_on_trace_checkpoints(self) -> None:
        objective = Objective(
            "reach-two-through-one",
            "fixture-lab",
            lambda state, _trace: state["count"] == 2,
            effect_lemmas=(EffectLemma("reached-one", lambda state, _trace: state["count"] == 1),),
        )
        report = self.engine.analyze(fixture_model(), objective, self.auth, Budget(max_depth=2))
        self.assertEqual(report.status, AnalysisStatus.MODEL_SAT)
        self.assertFalse(report.witness.validated)
        assert report.witness is not None
        self.assertEqual([event.request for event in report.witness.events], [{"amount": 1}, {"amount": 1}])

    def test_budget_is_reported_as_unknown(self) -> None:
        objective = Objective("reach-nine", "fixture-lab", lambda state, _trace: state["count"] == 9)
        report = self.engine.analyze(fixture_model(), objective, self.auth, Budget(max_depth=4, max_events=1))
        self.assertEqual(report.status, AnalysisStatus.BUDGET_EXHAUSTED)
        self.assertEqual(report.proof.status, SolverStatus.UNKNOWN)
        self.assertEqual(report.gaps[0].kind, GapKind.EVENT_BUDGET)

    def test_reconcile_localizes_first_divergence(self) -> None:
        report = self.engine.analyze(fixture_model(), self.objective, self.auth, Budget(max_depth=2))
        assert report.witness is not None
        event = report.witness.events[0]
        observed = TraceEvent(
            operation=event.operation,
            entry_point=event.entry_point,
            request=event.request,
            before=event.before,
            after=State({"count": 3}),
        )
        reconciled = self.engine.reconcile(report, (observed,))
        self.assertEqual(reconciled.status, AnalysisStatus.MODEL_DIVERGENCE)
        self.assertEqual(reconciled.divergences[0].index, 0)

    def test_artifacts_are_stable_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JsonlArtifactStore(Path(directory) / "evidence.jsonl")
            first = store.put("trace", {"token": "secret-value", "count": 1})
            second = store.put("trace", {"token": "secret-value", "count": 1})
            self.assertEqual(first, second)
            record = store.get(first)
            assert record is not None
            self.assertEqual(record["payload"]["token"], "[REDACTED]")

    def test_acceptance_residual_directions_remain_distinct(self) -> None:
        residual = compare_acceptance(
            actual=lambda value: value >= 0,
            intended=lambda value: value > 0,
            domain=(-1, 0, 1),
        )
        self.assertEqual(residual.over_acceptance, frozenset({0}))
        self.assertEqual(residual.under_acceptance, frozenset())
        self.assertEqual(transform_domain_mismatch(lambda value: value + 1, (0, 1), (1,)), frozenset({2}))

    def test_typed_ir_round_trips_with_schema_version(self) -> None:
        target = TargetIdentity(
            target_id="fixture",
            runtime="synthetic",
            runtime_version="1",
            platform="portable",
            platform_version="1",
            build_hash="abc",
            adapter="fixture",
            adapter_version="1",
        )
        transform = Transform(
            transform_id="decode",
            input_representation="bytes",
            output_representation="text",
            semantics_ref="fixture.decode",
            semantics_version="1",
            partiality=Partiality.PARTIAL,
            relation=RelationKind.FUNCTION,
            invertibility=Invertibility.MANY_TO_ONE,
            information_loss=InformationLoss.POSSIBLE,
            evidence=(Evidence("e1", Fidelity.MODELED, "test"),),
        )
        record = transform.to_record()
        self.assertEqual(Transform.from_record(record), transform)
        self.assertEqual(TargetIdentity.from_record(target.to_record()), target)
        transition = Transition("t1", "lab.increment", "bytes", "text", transform_ids=("decode",))
        self.assertEqual(Transition.from_record(transition.to_record()), transition)
        with self.assertRaises(ValueError):
            Transform.from_record({**record, "schema_version": "rsve.schema/999"})
        with self.assertRaises(ValueError):
            Transform.from_record({**record, "payload": {"transform_id": "bad"}})

    def test_canonical_transform_round_trips_without_legacy_conversion(self) -> None:
        transform = Transform(
            "decode", "bytes", "text", "fixture.decode", "1", Partiality.PARTIAL,
            RelationKind.FUNCTION, Invertibility.NON_INVERTIBLE, InformationLoss.CONFIRMED,
        )
        self.assertEqual(Transform.from_record(transform.to_record()), transform)

    def test_objective_ast_and_checkpoint_constraint_round_trip(self) -> None:
        predicate = Equal(Variable("count", Sort.INT), Literal(2, Sort.INT))
        objective = ObjectiveAst(
            "reach-two",
            "fixture-lab",
            predicate,
            (ObjectiveCheckpoint("at-one", Equal(Variable("count", Sort.INT), Literal(1, Sort.INT))),),
        )
        self.assertEqual(ObjectiveAst.from_record(objective.to_record()), objective)

    def test_surface_registry_requires_evidence_for_phantom_entries(self) -> None:
        target = TargetIdentity("fixture", "synthetic", "1", "portable", "1", "abc", "fixture", "1")
        registry = SurfaceRegistry.from_iterables(target, declared=(EntryPoint("declared"),))
        with self.assertRaises(ValueError):
            registry.add_observed(__import__("rsve").ObservedEntry(EntryPoint("phantom"), ()))
        observed = __import__("rsve").ObservedEntry(
            EntryPoint("phantom", declared=False),
            (Evidence("trace-1", Fidelity.OBSERVED, "runtime", "trace/1", ("flag=true",)),),
        )
        registry = registry.add_observed(observed)
        self.assertEqual([item.entry_point.name for item in registry.phantom_entries()], ["phantom"])

    def test_z3_sat_unsat_core_and_unknown_are_distinct(self) -> None:
        adapter = Z3SolverAdapter()
        scope = ResultScope("fixture", "abc", "r1", 2, 10, mode=ExecutionMode.SYMBOLIC, tier=Fidelity.MODELED)
        sat = adapter.solve(ConstraintQuery(
            "sat",
            AllOf((IntRange(Variable("x", Sort.INT), 1, 3), Equal(Variable("x", Sort.INT), Literal(2, Sort.INT)))),
            scope,
        ))
        self.assertEqual(sat.status.value, "SAT")
        self.assertEqual(sat.model["x"], 2)

        unsat = adapter.solve(ConstraintQuery(
            "unsat",
            AllOf((NamedAssumption("nonnegative", IntRange(Variable("x", Sort.INT), 0, 3)),
                   NamedAssumption("negative", IntRange(Variable("x", Sort.INT), -3, -1)))),
            scope,
        ))
        self.assertEqual(unsat.status.value, "UNSAT_BOUNDED")
        self.assertTrue(set(unsat.unsat_core) >= {"nonnegative", "negative"})
        self.assertEqual(set(unsat.named_assertions), {"nonnegative", "negative"})
        unknown = adapter.solve(ConstraintQuery(
            "unknown",
            Equal(Variable("payload", Sort.BYTES), Literal("x", Sort.BYTES)),
            scope,
        ))
        self.assertEqual(unknown.status.value, "UNKNOWN")
        self.assertIn("UNSUPPORTED", unknown.unknown_reason or "")

    def test_z3_state_relations_translate_without_eager_failure(self) -> None:
        query = ConstraintQuery(
            "state-relation",
            StateRelation(Variable("x", Sort.INT), "<", Literal(3, Sort.INT)),
        )
        result = Z3SolverAdapter().solve(query)
        self.assertEqual(result.status.value, "SAT")
        self.assertLess(result.model["x"], 3)

    def test_nested_named_assumptions_preserve_formula_scope(self) -> None:
        x = Variable("x", Sort.INT)
        formula = AllOf((
            AnyOf((NamedAssumption("left_branch", Equal(x, Literal(1, Sort.INT))), Equal(x, Literal(2, Sort.INT)))),
            Equal(x, Literal(2, Sort.INT)),
        ))
        result = Z3SolverAdapter().solve(ConstraintQuery("nested-assumption", formula))
        self.assertEqual(result.status.value, "SAT")
        self.assertEqual(result.model["x"], 2)
        self.assertEqual(result.named_assertions, ("left_branch",))
        self.assertNotIn("left_branch", result.unsat_core)

    def test_incremental_scope_and_residual_queries(self) -> None:
        adapter = Z3SolverAdapter()
        with adapter.incremental() as session:
            session.add(IntRange(Variable("x", Sort.INT), 0, 10))
            self.assertEqual(session.solve().status.value, "SAT")
            session.push()
            session.add(IntRange(Variable("x", Sort.INT), 20, 30))
            self.assertEqual(session.solve().status.value, "UNSAT_BOUNDED")
            session.pop()
            self.assertEqual(session.solve().status.value, "SAT")

    def test_residual_queries_track_regions_and_path_scope(self) -> None:
        region = CandidateRegion("inputs", (0, 1, 2))
        mismatch = transform_domain_residual(lambda value: value + 1, region, (1,))
        self.assertEqual(mismatch.residual, (2, 3))
        self.assertEqual(mismatch.region.coverage, 1.0)
        over = acceptance_residual(lambda value: value >= 0, lambda value: value > 0, region, over=True)
        under = acceptance_residual(lambda value: value > 1, lambda value: value >= 1, region, over=False)
        self.assertEqual(over.residual, (0,))
        self.assertEqual(under.residual, (1,))

        path = bounded_path_residual(
            (IntRange(Variable("x", Sort.INT), 0, 2), Equal(Variable("x", Sort.INT), Literal(1, Sort.INT))),
            Z3SolverAdapter(),
            query_id="path-1",
        )
        self.assertEqual(path.status.value, "FOUND")
        self.assertEqual(path.solver_result.scope, None)


if __name__ == "__main__":
    unittest.main()
