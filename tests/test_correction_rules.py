import copy
import unittest
from skill_sandbox import correction_rules as c


def pack(action="suppress"):
    return {"schema_version": 1, "version": "test-v1", "contract_sha256": c.contract_digest(),
            "rules": [{"id": format(i, "08x"), "detector": d, "action": "suppress" if d in {"pii_ssn", "phi_patient_record"} else "downgrade" if d=="secret_exfiltration" else action, "all_features": [f]}
                      for i, (f, d) in enumerate(c.feature_schema().items(), 1)]}


class CorrectionTests(unittest.TestCase):
    def test_source_owned_corpus(self):
        result = c.evaluate_pack(pack())
        self.assertTrue(result["passed"], result)
        self.assertTrue(c.evaluate_pack(pack("downgrade"))["passed"])

    def test_unknown_features_code_and_forged_oracle_rejected(self):
        for mutate in (lambda p: p.update(regressions=[]),
                       lambda p: p.update(contract_sha256="0"*64),
                       lambda p: p["rules"][0].update(all_features=["eval(1)"]),
                       lambda p: p["rules"][0].update(regex=".*")):
            bad = pack()
            mutate(bad)
            with self.assertRaises(ValueError):
                c.validate_pack(bad)

    def test_context_resets_after_exception(self):
        finding = {"id": "pii_ssn", "count": 1, "observations": [{"line": 1, "text": "12345-6789"}]}
        text = "ZIP code: 12345-6789"
        self.assertEqual(c.apply_corrections("s.txt", text, [finding]), [finding])
        with self.assertRaises(RuntimeError):
            with c.using_pack(pack()):
                self.assertEqual(c.apply_corrections("s.txt", text, [finding]), [])
                raise RuntimeError()
        self.assertEqual(c.apply_corrections("s.txt", text, [finding]), [finding])

    def test_mixed_and_truncated_evidence_retained(self):
        f = {"id": "pii_ssn", "count": 1, "observations": [{"line": 1, "text": "synthetic"}]}
        self.assertEqual(c.apply_corrections("s", "ZIP code 12345-6789\nSSN: 123-45-6789", [f], pack()), [f])
        f["count"] = 2
        self.assertEqual(c.apply_corrections("s", "ZIP code 12345-6789", [f], pack()), [f])

    def test_db_typed_phone_classifier_follows_reviewed_pack(self):
        from skill_sandbox.database_analysis import ColumnState
        baseline = ColumnState("contacts", "telephone", "TEXT")
        baseline.observe_text("202555018")
        with c.using_pack(pack()):
            corrected = ColumnState("contacts", "telephone", "TEXT")
            corrected.observe_text("202555018")
            self.assertNotIn("ssn", corrected.finalize(None))
            real = ColumnState("contacts", "telephone", "TEXT")
            real.observe_text("123-45-6789")
            self.assertIn("ssn", real.finalize(None))


if __name__ == "__main__":
    unittest.main()
