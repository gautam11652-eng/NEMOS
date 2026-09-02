"""DetectionConfig.from_env() must expose every rule threshold, safely.

Two things are load-bearing here, not just convenience:

1. Every field is reachable from an env var, or an operator whose network is
   genuinely hotter or quieter than the defaults has no way to say so short
   of editing detector.py and rebuilding.
2. Every field is clamped, so a fat-fingered value cannot silently disable a
   rule (a threshold of 0 or a negative number would fire on every packet,
   or never) or crash the sensor on startup.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from nemos.detector import DetectionConfig

# (env var, field name, value to set, expected parsed value)
TUNABLE_FIELDS = [
    ("NEMOS_DETECT_WINDOW", "window", "20", 20),
    ("NEMOS_DETECT_PORT_SCAN", "port_scan", "5", 5),
    ("NEMOS_DETECT_SYN_FLOOD", "syn_flood", "500", 500),
    ("NEMOS_DETECT_SYN_FLOOD_CONCENTRATION", "syn_flood_concentration", "0.5", 0.5),
    ("NEMOS_DETECT_ICMP_FLOOD", "icmp_flood", "200", 200),
    ("NEMOS_DETECT_FANOUT", "fanout", "50", 50),
    ("NEMOS_DETECT_DNS_BURST", "dns_burst", "160", 160),
    ("NEMOS_DETECT_SERVICE_BURST", "service_burst", "80", 80),
    ("NEMOS_DETECT_UDP_SCAN", "udp_scan", "24", 24),
    ("NEMOS_DETECT_ICMP_SWEEP", "icmp_sweep", "24", 24),
    ("NEMOS_DETECT_STEALTH_SCAN", "stealth_scan", "12", 12),
    ("NEMOS_DETECT_LATERAL_HOSTS", "lateral_hosts", "10", 10),
    ("NEMOS_DETECT_BRUTE_FORCE", "brute_force", "40", 40),
    ("NEMOS_DETECT_EXFIL_BYTES", "exfil_bytes", "50000000", 50_000_000),
    ("NEMOS_DETECT_DNS_TUNNEL_PACKETS", "dns_tunnel_packets", "60", 60),
    ("NEMOS_DETECT_DNS_TUNNEL_MEAN_SIZE", "dns_tunnel_mean_size", "300", 300),
    ("NEMOS_DETECT_MINING_PACKETS", "mining_packets", "20", 20),
    ("NEMOS_DETECT_TOR_PACKETS", "tor_packets", "20", 20),
    ("NEMOS_DETECT_SPRAY_HOSTS", "spray_hosts", "16", 16),
    ("NEMOS_DETECT_SPRAY_MAX_ATTEMPTS", "spray_max_attempts", "12", 12),
    ("NEMOS_DETECT_ICMP_TUNNEL_PACKETS", "icmp_tunnel_packets", "24", 24),
    ("NEMOS_DETECT_ICMP_TUNNEL_MEAN_SIZE", "icmp_tunnel_mean_size", "400", 400),
    ("NEMOS_DETECT_SERVICE_DOS", "service_dos", "240", 240),
    ("NEMOS_DETECT_AMPLIFICATION_PACKETS", "amplification_packets", "120", 120),
    ("NEMOS_DETECT_INGRESS_BYTES", "ingress_bytes", "50000000", 50_000_000),
    ("NEMOS_DETECT_NONSTANDARD_PACKETS", "nonstandard_packets", "80", 80),
    ("NEMOS_DETECT_NONSTANDARD_MIN_PORT", "nonstandard_min_port", "20000", 20000),
    ("NEMOS_DETECT_BEACON_MIN_INTERVALS", "beacon_min_intervals", "10", 10),
    ("NEMOS_DETECT_BEACON_MAX_JITTER", "beacon_max_jitter", "0.3", 0.3),
    ("NEMOS_DETECT_BEACON_MIN_PERIOD", "beacon_min_period", "5.0", 5.0),
    ("NEMOS_DETECT_BEACON_HORIZON", "beacon_horizon", "1800.0", 1800.0),
    ("NEMOS_DETECT_SLOW_HORIZON", "slow_horizon", "7200.0", 7200.0),
    ("NEMOS_DETECT_SLOW_SCAN_PORTS", "slow_scan_ports", "80", 80),
    ("NEMOS_DETECT_SLOW_SWEEP_HOSTS", "slow_sweep_hosts", "60", 60),
    ("NEMOS_DETECT_SLOW_EVAL_SECONDS", "slow_eval_interval", "60.0", 60.0),
    ("NEMOS_DETECT_SLOW_MAX_SOURCES", "slow_max_sources", "2048", 2048),
    ("NEMOS_DETECT_SLOW_MAX_TRACKED", "slow_max_tracked", "512", 512),
    ("NEMOS_DETECT_COOLDOWN", "cooldown", "60", 60),
    ("NEMOS_DETECT_CORRELATION_WINDOW", "correlation_window", "120", 120),
    ("NEMOS_DETECT_MAX_SOURCES", "max_sources", "8192", 8192),
    ("NEMOS_DETECT_BASELINE_MULTIPLIER", "baseline_multiplier", "5.0", 5.0),
    ("NEMOS_DETECT_BASELINE_MIN_EVENTS", "baseline_min_events", "40", 40),
    ("NEMOS_DETECT_MIN_CONFIDENCE", "min_confidence", "70", 70),
    ("NEMOS_DETECT_TLS_HORIZON", "tls_horizon", "1800", 1800.0),
    ("NEMOS_DETECT_TLS_MAX_FINGERPRINTS", "tls_max_fingerprints", "9", 9),
    ("NEMOS_DETECT_TLS_ODD_PORT_HANDSHAKES", "tls_odd_port_handshakes", "5", 5),
    ("NEMOS_DETECT_TLS_MAX_TRACKED", "tls_max_tracked", "32", 32),
    # Pre-existing env vars, kept under their original names for compatibility.
    ("NEMOS_MAX_EVENTS", "max_events", "2000", 2000),
    ("NEMOS_BEHAVIOR_ALPHA", "baseline_alpha", "0.5", 0.5),
    ("NEMOS_BEHAVIOR_MIN_SAMPLES", "baseline_min_samples", "16", 16),
    ("NEMOS_BEHAVIOR_SIGMA", "baseline_sigma_threshold", "4.0", 4.0),
    ("NEMOS_BEHAVIOR_SAMPLE_SECONDS", "baseline_sample_interval", "10.0", 10.0),
    ("NEMOS_BEHAVIOR_EXTREME_SIGMA", "baseline_extreme_sigma", "8.0", 8.0),
]

# Fields whose defaults deliberately are not exposed: architectural sizing,
# not detection behaviour.
UNEXPOSED_FIELDS = set()

ALL_DETECTION_FIELDS = set(DetectionConfig.__dataclass_fields__)


class EveryFieldIsTunable(unittest.TestCase):
    def test_every_env_var_reaches_its_field(self):
        for env_var, field, raw, expected in TUNABLE_FIELDS:
            with self.subTest(env_var=env_var):
                with mock.patch.dict(os.environ, {env_var: raw}, clear=False):
                    cfg = DetectionConfig.from_env()
                self.assertEqual(getattr(cfg, field), expected)

    def test_every_dataclass_field_is_covered_by_this_table_or_excluded(self):
        covered = {field for _, field, _, _ in TUNABLE_FIELDS}
        missing = ALL_DETECTION_FIELDS - covered - UNEXPOSED_FIELDS
        self.assertEqual(missing, set(), f"fields with no env var and no exclusion: {missing}")

    def test_defaults_survive_a_clean_environment(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("NEMOS_DETECT_", "NEMOS_BEHAVIOR_", "NEMOS_MAX_EVENTS"))}
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = DetectionConfig.from_env()
        self.assertEqual(cfg, DetectionConfig())


class CorruptOrHostileValuesCannotDisableARule(unittest.TestCase):
    def test_zero_or_negative_thresholds_are_clamped_above_zero(self):
        with mock.patch.dict(os.environ, {
            "NEMOS_DETECT_SYN_FLOOD": "0",
            "NEMOS_DETECT_PORT_SCAN": "-5",
        }):
            cfg = DetectionConfig.from_env()
        self.assertGreater(cfg.syn_flood, 0)
        self.assertGreater(cfg.port_scan, 0)

    def test_garbage_values_fall_back_to_the_default(self):
        with mock.patch.dict(os.environ, {
            "NEMOS_DETECT_SYN_FLOOD": "not-a-number",
            "NEMOS_DETECT_SYN_FLOOD_CONCENTRATION": "also-not-a-number",
        }):
            cfg = DetectionConfig.from_env()
        self.assertEqual(cfg.syn_flood, DetectionConfig().syn_flood)
        self.assertEqual(cfg.syn_flood_concentration, DetectionConfig().syn_flood_concentration)

    def test_a_ridiculous_confidence_floor_is_clamped_to_the_valid_range(self):
        with mock.patch.dict(os.environ, {"NEMOS_DETECT_MIN_CONFIDENCE": "999"}):
            cfg = DetectionConfig.from_env()
        self.assertLessEqual(cfg.min_confidence, 100)

    def test_a_concentration_ratio_above_one_is_clamped(self):
        with mock.patch.dict(os.environ, {"NEMOS_DETECT_SYN_FLOOD_CONCENTRATION": "50"}):
            cfg = DetectionConfig.from_env()
        self.assertLessEqual(cfg.syn_flood_concentration, 1.0)

    def test_max_events_floor_stays_above_the_largest_default_threshold(self):
        # Documented invariant: max_events' floor (200) must not drop below
        # the syn_flood default (150), or the flood rule starves itself of
        # evidence via eviction before it ever reaches threshold.
        with mock.patch.dict(os.environ, {"NEMOS_MAX_EVENTS": "1"}):
            cfg = DetectionConfig.from_env()
        self.assertGreaterEqual(cfg.max_events, DetectionConfig().syn_flood)


if __name__ == "__main__":
    unittest.main()
