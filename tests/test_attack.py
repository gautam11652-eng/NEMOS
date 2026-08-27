import unittest

from nemos.attack import enrich_alert, technique_metadata


class AttackCatalogTests(unittest.TestCase):
    def test_known_technique_is_enriched(self):
        item = technique_metadata("T1046")
        self.assertTrue(item["mapped"])
        self.assertEqual(item["name"], "Network Service Discovery")
        self.assertEqual(item["tactic"], "Discovery")

    def test_behavioral_anomaly_is_not_falsely_mapped(self):
        item = enrich_alert({"threat": "BEHAVIORAL_TRAFFIC_ANOMALY", "technique": ""})
        self.assertFalse(item["attack"]["mapped"])
        self.assertEqual(item["signal"]["type"], "behavioral-signal")
        self.assertIn("insufficient", item["signal"]["reason"])

    def test_unknown_technique_stays_unmapped(self):
        item = technique_metadata("T9999")
        self.assertFalse(item["mapped"])
        self.assertEqual(item["name"], "")


if __name__ == "__main__":
    unittest.main()
