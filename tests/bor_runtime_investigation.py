import unittest

from rsve.bor_runtime_investigation import derive_hypotheses


class BorRuntimeInvestigationTests(unittest.TestCase):
    def test_consistent_observations_do_not_create_a_finding(self):
        payload = {
            "observations": [{
                "case": "generated-case",
                "admission": "accepted",
                "execution": "completed",
                "receipt_status": "success",
                "sender_delta": "-3",
                "recipient_delta": "1",
                "coinbase_delta": "1",
                "burn_delta": "1",
                "total_tracked_delta": "0",
                "state_root_after": "0xafter",
                "committed_state_root": "0xafter",
                "reopened": True,
                "receipt_persisted": True,
            }],
        }
        self.assertEqual(derive_hypotheses(payload), ())

    def test_hypothesis_is_derived_from_observed_balance_fields(self):
        payload = {
            "observations": [{
                "case": "generated-case",
                "admission": "accepted",
                "execution": "completed",
                "receipt_status": "success",
                "sender_delta": "-3",
                "recipient_delta": "1",
                "coinbase_delta": "1",
                "burn_delta": "1",
                "total_tracked_delta": "1",
                "state_root_after": "0xafter",
                "committed_state_root": "0xafter",
                "reopened": True,
                "receipt_persisted": True,
            }],
        }
        hypotheses = derive_hypotheses(payload)
        self.assertEqual(len(hypotheses), 1)
        self.assertEqual(hypotheses[0]["kind"], "balance_conservation_violation")
        self.assertEqual(hypotheses[0]["classification"], "UNRESOLVED")
        self.assertEqual(hypotheses[0]["difference"], {"derived_total": 0, "reported_total": 1})

    def test_rejected_execution_is_derived_without_named_vulnerability(self):
        payload = {
            "observations": [{
                "case": "generated-case",
                "admission": "rejected",
                "execution": "completed",
                "receipt_status": "success",
            }],
        }
        hypotheses = derive_hypotheses(payload)
        self.assertEqual(hypotheses[0]["kind"], "rejected_execution_or_receipt")
        self.assertEqual(hypotheses[0]["source_fields"], ["admission", "execution", "receipt_status"])


if __name__ == "__main__":
    unittest.main()
