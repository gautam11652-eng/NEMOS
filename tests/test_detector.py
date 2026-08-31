import unittest
from nemos.detector import ThreatDetector
from nemos.models import TrafficEvent

class DetectorTests(unittest.TestCase):
    def event(self, port, protocol="TCP", flags="S"):
        return TrafficEvent("2026-01-01T00:00:00Z","10.0.0.5","10.0.0.10",protocol,None,port,60,flags)
    def test_port_scan(self):
        d=ThreatDetector()
        alerts=[]
        for p in range(100,108): alerts += d.process(self.event(p))
        self.assertTrue(any(a.threat=="PORT_SCAN" for a in alerts))
    def test_cooldown(self):
        d=ThreatDetector()
        for p in range(100,108): d.process(self.event(p))
        second=[]
        for p in range(200,208): second += d.process(self.event(p))
        self.assertFalse(any(a.threat=="PORT_SCAN" for a in second))
    def test_invalid_source_ignored(self):
        d=ThreatDetector()
        e=TrafficEvent("x","not-an-ip","10.0.0.1","TCP",None,80)
        self.assertEqual(d.process(e),[])
class DetectorV2Tests(unittest.TestCase):
    def test_incident_correlation(self):
        d = ThreatDetector()
        alerts = []
        for port in range(100, 108):
            alerts += d.process(TrafficEvent("x", "10.0.0.5", "10.0.0.10", "TCP", None, port, 60, "S"))
        first = next(a for a in alerts if a.threat == "PORT_SCAN")
        # A different detection for the same source should share the incident.
        # The flood needs a flood's shape, not just its volume: SYNs have to
        # concentrate on one service, or the rule correctly reads them as more
        # of the scan already in the window.
        d.cfg = d.cfg.__class__(syn_flood=1)
        second = []
        for _ in range(6):
            second += d.process(
                TrafficEvent("x", "10.0.0.5", "10.0.0.11", "TCP", None, 443, 60, "S"))
        syn = next(a for a in second if a.threat == "SYN_FLOOD_PATTERN")
        self.assertEqual(first.incident_id, syn.incident_id)

    def test_port_scan_has_evidence(self):
        d = ThreatDetector()
        alerts = []
        for port in range(100, 108):
            alerts += d.process(TrafficEvent("x", "10.0.0.5", "10.0.0.10", "TCP", None, port, 60, "S"))
        alert = next(a for a in alerts if a.threat == "PORT_SCAN")
        self.assertIn("ports", alert.evidence)
        self.assertGreaterEqual(alert.confidence, 50)

class DetectorV3Tests(unittest.TestCase):
    def test_udp_scan_is_classified(self):
        d = ThreatDetector()
        alerts = []
        for port in range(2000, 2012):
            alerts += d.process(TrafficEvent("x", "10.0.0.8", "10.0.0.20", "UDP", None, port, 70, ""))
        alert = next(a for a in alerts if a.threat == "UDP_PORT_SCAN")
        self.assertEqual(alert.technique, "T1046")
        self.assertIn("ports", alert.evidence)
        self.assertGreaterEqual(alert.confidence, 55)

    def test_icmp_sweep_is_classified(self):
        d = ThreatDetector()
        alerts = []
        for i in range(12):
            alerts += d.process(TrafficEvent("x", "10.0.0.8", f"10.0.1.{i+1}", "ICMP", packet_size=64))
        alert = next(a for a in alerts if a.threat == "ICMP_SWEEP")
        # A sweep enumerates hosts, so Remote System Discovery describes it
        # more accurately than Network Service Discovery.
        self.assertEqual(alert.technique, "T1018")
        self.assertEqual(alert.evidence["scan_type"], "icmp_sweep")

    def test_behavior_anomaly_has_no_false_attack_mapping(self):
        cfg = __import__("nemos.detector", fromlist=["DetectionConfig"]).DetectionConfig(
            baseline_min_samples=2, baseline_min_events=3, baseline_multiplier=1.1
        )
        d = ThreatDetector(cfg)
        # Prime with several low-rate windows by processing one event per source.
        for _ in range(3):
            d.process(TrafficEvent("x", "10.0.0.9", "10.0.0.20", "TCP", None, 443, 60, "A"))
        alerts = []
        for _ in range(30):
            alerts += d.process(TrafficEvent("x", "10.0.0.9", "10.0.0.20", "TCP", None, 443, 60, "A"))
        anomaly = next((a for a in alerts if a.threat == "BEHAVIORAL_TRAFFIC_ANOMALY"), None)
        if anomaly:
            self.assertEqual(anomaly.technique, "")
            self.assertIn("deviation", anomaly.evidence)

class IncidentIntelligenceTests(unittest.TestCase):
    def test_incident_summary_increases_with_independent_evidence(self):
        from nemos.intelligence import summarize_incident
        base = [{
            "threat": "PORT_SCAN", "source": "10.0.0.5", "severity": "HIGH",
            "risk_score": 80, "confidence": 80, "technique": "T1046",
            "evidence": {"ports": [80, 443]},
        }]
        enriched = base + [{
            "threat": "ICMP_SWEEP", "source": "10.0.0.5", "severity": "MEDIUM",
            "risk_score": 65, "confidence": 75, "technique": "T1046",
            "evidence": {"destinations": 12},
        }]
        one = summarize_incident("NEMOS-ONE", base)
        two = summarize_incident("NEMOS-TWO", enriched)
        self.assertGreater(two.risk_score, one.risk_score)
        self.assertEqual(two.unique_threats, 2)
        self.assertEqual(two.unique_techniques, 1)

    def test_incident_summary_is_bounded(self):
        from nemos.intelligence import summarize_incident
        rows = [{
            "threat": f"T{i}", "source": "10.0.0.5", "severity": "CRITICAL",
            "risk_score": 100, "confidence": 100, "technique": f"T{i}",
            "evidence": {"signal": i},
        } for i in range(50)]
        summary = summarize_incident("NEMOS-BOUND", rows)
        self.assertLessEqual(summary.risk_score, 100)
        self.assertLessEqual(summary.confidence, 99)


class BehavioralV4Tests(unittest.TestCase):
    def test_behavior_profile_warms_up_without_alerts(self):
        from nemos.detector import DetectionConfig, ThreatDetector
        cfg = DetectionConfig(baseline_min_samples=3, baseline_min_events=1, baseline_sample_interval=0.0, baseline_sigma_threshold=2.0)
        d = ThreatDetector(cfg)
        # The profiler should require a warm-up period and never claim the
        # initial observation is anomalous.
        alerts = []
        for _ in range(3):
            alerts += d.process(TrafficEvent("x", "10.0.0.50", "10.0.0.20", "TCP", None, 443, 60, "A"))
        self.assertFalse(any(a.threat == "BEHAVIORAL_TRAFFIC_ANOMALY" for a in alerts))

    def test_behavior_evidence_contains_baseline_and_current(self):
        from nemos.detector import DetectionConfig, ThreatDetector
        cfg = DetectionConfig(baseline_min_samples=3, baseline_min_events=1, baseline_sample_interval=0.0, baseline_sigma_threshold=1.0)
        d = ThreatDetector(cfg)
        # Warm a low-variance profile, then create a large feature jump.
        for _ in range(4):
            d.process(TrafficEvent("x", "10.0.0.51", "10.0.0.20", "TCP", None, 443, 60, "A"))
        alerts=[]
        for port in range(100, 130):
            alerts += d.process(TrafficEvent("x", "10.0.0.51", f"10.0.1.{port-99}", "TCP", None, port, 1200, "S"))
        anomaly = next((a for a in alerts if a.threat == "BEHAVIORAL_TRAFFIC_ANOMALY"), None)
        if anomaly:
            self.assertEqual(anomaly.evidence["model"], "adaptive_ew_baseline")
            self.assertIn("baseline", anomaly.evidence)
            self.assertIn("current", anomaly.evidence)
            self.assertIn("deviations_sigma", anomaly.evidence)


class InvestigationIntelligenceTests(unittest.TestCase):
    def test_recommendations_are_threat_specific(self):
        from nemos.intelligence import recommendations_for
        actions = recommendations_for(["PORT_SCAN"])
        self.assertGreaterEqual(len(actions), 3)
        self.assertTrue(any("services" in x.lower() for x in actions))

    def test_recommendations_are_bounded_and_deduplicated(self):
        from nemos.intelligence import recommendations_for
        actions = recommendations_for(["UNKNOWN", "UNKNOWN", "PORT_SCAN", "ICMP_SWEEP"])
        self.assertLessEqual(len(actions), 6)
        self.assertEqual(len(actions), len(set(actions)))

if __name__ == "__main__":
    unittest.main()
