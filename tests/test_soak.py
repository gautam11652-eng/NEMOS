"""Tests for the soak harness.

A soak test that reports "no growth" because its own arithmetic is wrong is
worse than no soak test: it manufactures the reassurance it was built to earn.
So the trend fit, the warm-up exclusion and the safety of the generated load
are checked here.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "tools"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from tools import soak  # noqa: E402


class TrendTests(unittest.TestCase):
    def test_a_flat_series_has_no_slope(self):
        self.assertEqual(soak.trend([100.0] * 10), 0.0)

    def test_a_rising_series_has_a_positive_slope(self):
        self.assertAlmostEqual(soak.trend([0, 2, 4, 6, 8]), 2.0)

    def test_a_falling_series_has_a_negative_slope(self):
        self.assertAlmostEqual(soak.trend([10, 8, 6, 4, 2]), -2.0)

    def test_noise_around_a_flat_mean_does_not_read_as_growth(self):
        """Sampling jitter must not be reported as a leak."""
        series = [100, 102, 99, 101, 98, 102, 100, 99, 101, 100]
        self.assertLess(abs(soak.trend(series)), 0.2)

    def test_too_few_points_is_undefined_rather_than_zero(self):
        """Two samples cannot distinguish a leak from warm-up."""
        self.assertIsNone(soak.trend([1.0, 2.0]))
        self.assertIsNone(soak.trend([]))

    def test_the_fit_is_least_squares_not_endpoint_subtraction(self):
        """A single spike at the end would dominate an endpoint difference."""
        flat_with_spike = [100] * 9 + [400]
        endpoint = flat_with_spike[-1] - flat_with_spike[0]
        self.assertLess(soak.trend(flat_with_spike) * 10, endpoint)


class ReadingTests(unittest.TestCase):
    def test_it_reads_its_own_process(self):
        import os
        pid = os.getpid()
        self.assertGreater(soak.rss_kb(pid), 0)
        self.assertGreater(soak.threads_of(pid), 0)
        self.assertGreater(soak.fds_of(pid), 0)

    def test_a_dead_process_reads_as_unknown_not_zero(self):
        """Zero RSS would look like a process that shrank, not one that died."""
        self.assertIsNone(soak.rss_kb(999_999))
        self.assertIsNone(soak.threads_of(999_999))
        self.assertIsNone(soak.fds_of(999_999))


class SafetyTests(unittest.TestCase):
    def test_the_generator_only_ever_addresses_loopback(self):
        source = (ROOT / "tools" / "soak.py").read_text()
        start = source.index("def traffic(")
        end = source.index("def trend(")
        body = source[start:end]
        self.assertIn('"127.0.0.1"', body)
        for token in ("0.0.0.0", "gethostbyname", "getaddrinfo", "http://", "https://"):
            self.assertNotIn(token, body,
                             f"the load generator must not reach beyond loopback ({token})")

    def test_rate_scales_the_load_rather_than_being_decorative(self):
        source = (ROOT / "tools" / "soak.py").read_text()
        body = source[source.index("def traffic("):source.index("def trend(")]
        self.assertGreaterEqual(body.count("rate"), 4,
                                "rate must actually scale the generated load")


if __name__ == "__main__":
    unittest.main()
