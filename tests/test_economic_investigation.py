import unittest

from rsve.economic_investigation import (
    derive_economic_hypotheses,
    investigate_economic_advantage,
    retain_unknown_regions,
)


class EconomicInvestigationTests(unittest.TestCase):
    def test_positive_delta_without_basis_is_only_a_hypothesis(self):
        observation = {
            "observations": [{
                "case": "runtime-transfer",
                "attacker_balance_before": 10,
                "attacker_balance_after": 15,
                "canonical_state_changed": True,
                "persisted": True,
                "reopened": True,
            }],
        }
        result = investigate_economic_advantage(observation, reproduction=observation, independent=observation)
        self.assertEqual(result["classification"], "HYPOTHESES_ONLY")
        self.assertEqual(result["hypotheses"][0]["classification"], "UNRESOLVED_ECONOMIC_HYPOTHESIS")
        self.assertEqual(result["findings"], [])

    def test_equivalent_value_does_not_create_an_advantage(self):
        self.assertEqual(derive_economic_hypotheses({
            "observations": [{
                "case": "legitimate-reward",
                "attacker_balance_before": 10,
                "attacker_balance_after": 15,
                "equivalent_value": 5,
            }],
        }), ())

    def test_debit_bypass_is_derived_from_observed_accounting(self):
        hypotheses = derive_economic_hypotheses({
            "observations": [{
                "case": "fee-path",
                "attacker_delta": -2,
                "value_sent": 1,
                "fee_paid": 4,
            }],
        })
        self.assertEqual(hypotheses[0]["kind"], "bypassed_debit")
        self.assertEqual(hypotheses[0]["advantage"], 3)
        self.assertEqual(hypotheses[0]["classification"], "HYPOTHESIS")

    def test_verification_requires_reproduction_independent_runtime_and_reopen(self):
        first = {
            "observations": [{
                "case": "persistent-gain",
                "attacker_balance_before": 10,
                "attacker_balance_after": 15,
                "equivalent_value": 0,
                "canonical_state_changed": True,
                "persisted": True,
                "reopened": True,
            }],
        }
        result = investigate_economic_advantage(
            first,
            reproduction=first,
            independent={"classification": "RUNTIME_OBSERVATION", **first},
        )
        self.assertEqual(result["classification"], "VERIFIED_EXPLOIT")
        self.assertEqual(result["findings"][0]["classification"], "VERIFIED_EXPLOIT")

        no_reopen = {"observations": [{**first["observations"][0], "reopened": False}]}
        result = investigate_economic_advantage(
            first,
            reproduction=first,
            independent={"classification": "RUNTIME_OBSERVATION", **no_reopen},
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["hypotheses"][0]["classification"], "UNRESOLVED_ECONOMIC_HYPOTHESIS")

    def test_imported_artifact_cannot_verify_runtime_hypothesis(self):
        observation = {
            "observations": [{
                "case": "artifact-only",
                "attacker_delta": 5,
                "equivalent_value": 0,
                "canonical_state_changed": True,
                "persisted": True,
                "reopened": True,
            }],
        }
        result = investigate_economic_advantage(
            observation,
            reproduction=observation,
            independent={"classification": "IMPORTED_ARTIFACT", **observation},
        )
        self.assertEqual(result["findings"], [])

    def test_imported_reproduction_cannot_complete_verification(self):
        observation = {
            "observations": [{
                "case": "imported-reproduction",
                "attacker_delta": -2,
                "value_sent": 1,
                "fee_paid": 4,
                "canonical_state_changed": True,
                "persisted": True,
                "reopened": True,
            }],
        }
        result = investigate_economic_advantage(
            observation,
            reproduction={"classification": "IMPORTED_ARTIFACT", **observation},
            independent=observation,
        )
        self.assertEqual(result["findings"], [])

    def test_unknown_process_and_environment_regions_are_retained(self):
        payload = {
            "unknown_regions": [
                {"region_id": "runtime.process", "layer": "process", "status": "unknown"},
                {"region_id": "host.environment", "layer": "environment", "status": "unknown"},
            ],
        }
        regions = retain_unknown_regions(payload)
        self.assertEqual({item["region_id"] for item in regions}, {"runtime.process", "host.environment"})
        result = investigate_economic_advantage(payload)
        self.assertEqual(result["unknown_regions"], list(regions))


if __name__ == "__main__":
    unittest.main()
