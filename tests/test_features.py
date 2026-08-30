from __future__ import annotations

import unittest

from nemos.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    extract,
    extract_all,
    shannon_entropy,
    to_matrix,
)
from nemos.flows import FlowTable, group_by_source
from nemos.models import TrafficEvent


def event(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80,
          proto="TCP", size=100, flags="S"):
    return TrafficEvent("2026-01-01T00:00:00+00:00", src, dst, proto, sport, dport, size, flags)


def flows_from(events, times=None):
    table = FlowTable(idle_timeout=1e9)
    for i, e in enumerate(events):
        table.observe(e, now=(times[i] if times else float(i) * 0.01))
    return table.snapshot()


class SchemaTests(unittest.TestCase):
    def test_names_are_unique_and_ordered(self):
        self.assertEqual(len(FEATURE_NAMES), len(set(FEATURE_NAMES)))

    def test_vector_length_matches_schema(self):
        vector = extract("10.0.0.1", flows_from([event()]), 10.0)
        self.assertEqual(len(vector.values), len(FEATURE_NAMES))
        self.assertEqual(vector.schema_version, FEATURE_SCHEMA_VERSION)

    def test_as_dict_maps_names_to_values(self):
        vector = extract("10.0.0.1", flows_from([event()]), 10.0)
        self.assertEqual(set(vector.as_dict()), set(FEATURE_NAMES))

    def test_get_rejects_unknown_feature(self):
        vector = extract("10.0.0.1", flows_from([event()]), 10.0)
        with self.assertRaises(KeyError):
            vector.get("not_a_feature")

    def test_all_values_are_finite_floats(self):
        vector = extract("10.0.0.1", flows_from([event() for _ in range(5)]), 10.0)
        for name, value in vector.as_dict().items():
            self.assertIsInstance(value, float, name)
            self.assertEqual(value, value, name)          # not NaN
            self.assertNotEqual(abs(value), float("inf"), name)


class EmptyWindowTests(unittest.TestCase):
    def test_empty_window_is_all_zero_not_an_error(self):
        vector = extract("10.0.0.1", [], 10.0)
        self.assertEqual(set(vector.values), {0.0})

    def test_zero_window_does_not_divide_by_zero(self):
        vector = extract("10.0.0.1", flows_from([event()]), 0.0)
        self.assertEqual(vector.get("packets"), 1.0)


class CountingTests(unittest.TestCase):
    def test_packets_and_bytes(self):
        vector = extract("10.0.0.1", flows_from([event(size=100) for _ in range(4)]), 10.0)
        self.assertEqual(vector.get("packets"), 4.0)
        self.assertEqual(vector.get("bytes"), 400.0)

    def test_rates_use_the_window_not_the_flow(self):
        vector = extract("10.0.0.1", flows_from([event(size=50) for _ in range(20)]), 10.0)
        self.assertAlmostEqual(vector.get("packets_per_second"), 2.0)
        self.assertAlmostEqual(vector.get("bytes_per_second"), 100.0)

    def test_unique_destinations_and_ports(self):
        events = [event(dst=f"10.0.0.{i}", dport=1000 + i) for i in range(2, 12)]
        vector = extract("10.0.0.1", flows_from(events), 10.0)
        self.assertEqual(vector.get("unique_destinations"), 10.0)
        self.assertEqual(vector.get("unique_destination_ports"), 10.0)
        self.assertEqual(vector.get("flow_count"), 10.0)

    def test_vertical_scan_shape_many_ports_one_destination(self):
        events = [event(dst="10.0.0.5", dport=p) for p in range(1, 51)]
        vector = extract("10.0.0.1", flows_from(events), 10.0)
        self.assertEqual(vector.get("unique_destinations"), 1.0)
        self.assertEqual(vector.get("unique_destination_ports"), 50.0)

    def test_horizontal_scan_shape_many_destinations_one_port(self):
        events = [event(dst=f"10.0.1.{i}", dport=445) for i in range(1, 51)]
        vector = extract("10.0.0.1", flows_from(events), 10.0)
        self.assertEqual(vector.get("unique_destinations"), 50.0)
        self.assertEqual(vector.get("unique_destination_ports"), 1.0)


class RatioTests(unittest.TestCase):
    def test_syn_ratio_of_a_syn_only_burst(self):
        vector = extract("10.0.0.1", flows_from([event(dport=p, flags="S") for p in range(1, 21)]), 10.0)
        self.assertAlmostEqual(vector.get("syn_ratio"), 1.0)
        self.assertAlmostEqual(vector.get("ack_ratio"), 0.0)

    def test_established_traffic_has_ack_not_syn(self):
        vector = extract("10.0.0.1", flows_from([event(flags="PA") for _ in range(10)]), 10.0)
        self.assertAlmostEqual(vector.get("ack_ratio"), 1.0)
        self.assertAlmostEqual(vector.get("syn_ratio"), 0.0)

    def test_protocol_ratios_sum_sensibly(self):
        events = ([event(proto="TCP") for _ in range(5)]
                  + [event(proto="UDP", dport=53) for _ in range(3)]
                  + [event(proto="ICMP", sport=None, dport=None, flags="") for _ in range(2)])
        vector = extract("10.0.0.1", flows_from(events), 10.0)
        self.assertAlmostEqual(vector.get("tcp_ratio"), 0.5)
        self.assertAlmostEqual(vector.get("udp_ratio"), 0.3)
        self.assertAlmostEqual(vector.get("icmp_ratio"), 0.2)

    def test_dns_ratio(self):
        events = [event(proto="DNS", dport=53) for _ in range(8)] + [event(proto="TCP") for _ in range(2)]
        vector = extract("10.0.0.1", flows_from(events), 10.0)
        self.assertAlmostEqual(vector.get("dns_ratio"), 0.8)

    def test_small_packet_ratio(self):
        events = [event(dport=1, size=60)] + [event(dport=2, size=1400)]
        vector = extract("10.0.0.1", flows_from(events), 10.0)
        self.assertAlmostEqual(vector.get("small_packet_ratio"), 0.5)


class EntropyTests(unittest.TestCase):
    def test_entropy_of_empty_and_single_value(self):
        self.assertEqual(shannon_entropy([]), 0.0)
        self.assertEqual(shannon_entropy([10]), 0.0)

    def test_uniform_distribution_maximises_entropy(self):
        # Four equally-likely outcomes carry exactly 2 bits.
        self.assertAlmostEqual(shannon_entropy([5, 5, 5, 5]), 2.0)

    def test_skewed_distribution_has_lower_entropy(self):
        self.assertLess(shannon_entropy([97, 1, 1, 1]), shannon_entropy([25, 25, 25, 25]))

    def test_entropy_separates_spread_from_concentrated_traffic(self):
        # Same unique-destination count, very different shapes.
        spread = flows_from([event(dst=f"10.0.0.{i}") for i in range(2, 10)])
        concentrated = flows_from(
            [event(dst="10.0.0.2") for _ in range(100)] + [event(dst=f"10.0.0.{i}") for i in range(3, 10)]
        )
        a = extract("10.0.0.1", spread, 10.0).get("destination_entropy")
        b = extract("10.0.0.1", concentrated, 10.0).get("destination_entropy")
        self.assertGreater(a, b)


class DerivedStatisticTests(unittest.TestCase):
    def test_mean_packet_size(self):
        events = [event(dport=1, size=100), event(dport=2, size=300)]
        self.assertAlmostEqual(extract("10.0.0.1", flows_from(events), 10.0).get("mean_packet_size"), 200.0)

    def test_stddev_is_zero_for_uniform_sizes(self):
        events = [event(dport=p, size=200) for p in range(1, 6)]
        self.assertAlmostEqual(extract("10.0.0.1", flows_from(events), 10.0).get("stddev_packet_size"), 0.0)

    def test_stddev_is_positive_for_mixed_sizes(self):
        events = [event(dport=1, size=64), event(dport=2, size=1500)]
        self.assertGreater(extract("10.0.0.1", flows_from(events), 10.0).get("stddev_packet_size"), 0.0)

    def test_per_flow_means(self):
        events = [event(dport=1, size=100), event(dport=1, size=100), event(dport=2, size=100)]
        vector = extract("10.0.0.1", flows_from(events), 10.0)
        self.assertAlmostEqual(vector.get("mean_packets_per_flow"), 1.5)
        self.assertAlmostEqual(vector.get("mean_bytes_per_flow"), 150.0)


class BatchTests(unittest.TestCase):
    def test_extract_all_is_sorted_and_per_source(self):
        table = FlowTable(idle_timeout=1e9)
        table.observe(event(src="10.0.0.9"), now=0.0)
        table.observe(event(src="10.0.0.1"), now=0.0)
        vectors = extract_all(group_by_source(table.snapshot()), 10.0)
        self.assertEqual([v.source for v in vectors], ["10.0.0.1", "10.0.0.9"])

    def test_to_matrix_shape(self):
        table = FlowTable(idle_timeout=1e9)
        for i in range(3):
            table.observe(event(src=f"10.0.0.{i}"), now=0.0)
        matrix = to_matrix(extract_all(group_by_source(table.snapshot()), 10.0))
        self.assertEqual(len(matrix), 3)
        self.assertTrue(all(len(row) == len(FEATURE_NAMES) for row in matrix))


if __name__ == "__main__":
    unittest.main()
