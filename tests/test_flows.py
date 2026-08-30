from __future__ import annotations

import unittest

from nemos.flows import FlowKey, FlowTable, group_by_source
from nemos.models import TrafficEvent


def event(src="192.0.2.1", dst="192.0.2.2", sport=1234, dport=80,
          proto="TCP", size=100, flags="S", ts="2026-01-01T00:00:00+00:00"):
    return TrafficEvent(ts, src, dst, proto, sport, dport, size, flags)


class FlowKeyTests(unittest.TestCase):
    def test_key_is_not_normalised(self):
        """The central unidirectional guarantee: direction is never collapsed."""
        forward = FlowTable.key_for(event(src="10.0.0.1", dst="10.0.0.2"))
        reverse = FlowTable.key_for(
            event(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234)
        )
        self.assertNotEqual(forward, reverse)

    def test_reversed_builds_the_opposite_key(self):
        key = FlowKey("10.0.0.1", "10.0.0.2", 1234, 80, "TCP")
        self.assertEqual(key.reversed(), FlowKey("10.0.0.2", "10.0.0.1", 80, 1234, "TCP"))
        self.assertEqual(key.reversed().reversed(), key)

    def test_protocol_is_part_of_identity(self):
        a = FlowTable.key_for(event(proto="TCP"))
        b = FlowTable.key_for(event(proto="UDP"))
        self.assertNotEqual(a, b)

    def test_ports_are_part_of_identity(self):
        self.assertNotEqual(
            FlowTable.key_for(event(dport=80)), FlowTable.key_for(event(dport=443))
        )


class FlowTableDirectionTests(unittest.TestCase):
    def test_opposite_directions_are_separate_flows(self):
        table = FlowTable()
        table.observe(event(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80), now=0.0)
        table.observe(event(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234), now=0.1)
        self.assertEqual(len(table), 2)

    def test_reverse_of_finds_the_opposite_record_without_merging(self):
        table = FlowTable()
        forward = table.observe(event(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80), now=0.0)
        table.observe(event(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234), now=0.1)
        reverse = table.reverse_of(forward.key)
        self.assertIsNotNone(reverse)
        self.assertEqual(reverse.key.source, "10.0.0.2")
        # Still two independent records.
        self.assertEqual(len(table), 2)
        self.assertEqual(forward.packets, 1)
        self.assertEqual(reverse.packets, 1)

    def test_reverse_of_returns_none_for_unidirectional_capture(self):
        # The realistic case for a one-way tap: only one side is ever seen.
        table = FlowTable()
        flow = table.observe(event(), now=0.0)
        self.assertIsNone(table.reverse_of(flow.key))


class FlowAggregationTests(unittest.TestCase):
    def test_packets_and_bytes_accumulate(self):
        table = FlowTable()
        for i in range(5):
            table.observe(event(size=100), now=float(i))
        flow = table.snapshot()[0]
        self.assertEqual(flow.packets, 5)
        self.assertEqual(flow.bytes, 500)

    def test_duration_and_rates(self):
        table = FlowTable()
        table.observe(event(size=100), now=10.0)
        table.observe(event(size=100), now=14.0)
        flow = table.snapshot()[0]
        self.assertAlmostEqual(flow.duration, 4.0)
        self.assertAlmostEqual(flow.packets_per_second, 0.5)
        self.assertAlmostEqual(flow.bytes_per_second, 50.0)

    def test_single_packet_flow_has_zero_duration(self):
        table = FlowTable()
        table.observe(event(size=60), now=1.0)
        flow = table.snapshot()[0]
        self.assertEqual(flow.duration, 0.0)
        # Rate falls back to the raw count rather than dividing by zero.
        self.assertEqual(flow.packets_per_second, 1.0)

    def test_packet_size_statistics(self):
        table = FlowTable()
        for size in (100, 200, 300):
            table.observe(event(size=size), now=0.0)
        flow = table.snapshot()[0]
        self.assertEqual(flow.size_min, 100)
        self.assertEqual(flow.size_max, 300)
        self.assertAlmostEqual(flow.mean_packet_size, 200.0)
        # Population stddev of [100,200,300] is sqrt(20000/3) ~= 81.65
        self.assertAlmostEqual(flow.stddev_packet_size, 81.6497, places=3)

    def test_identical_sizes_give_zero_stddev(self):
        table = FlowTable()
        for _ in range(10):
            table.observe(event(size=64), now=0.0)
        self.assertEqual(table.snapshot()[0].stddev_packet_size, 0.0)

    def test_tcp_flags_are_counted(self):
        table = FlowTable()
        table.observe(event(flags="S"), now=0.0)
        table.observe(event(flags="SA"), now=0.1)
        table.observe(event(flags="PA"), now=0.2)
        table.observe(event(flags="R"), now=0.3)
        flow = table.snapshot()[0]
        self.assertEqual(flow.flags["S"], 2)
        self.assertEqual(flow.flags["A"], 2)
        self.assertEqual(flow.flags["P"], 1)
        self.assertEqual(flow.flags["R"], 1)

    def test_unknown_flag_characters_are_ignored(self):
        table = FlowTable()
        table.observe(event(flags="XYZ"), now=0.0)
        self.assertEqual(sum(table.snapshot()[0].flags.values()), 0)

    def test_empty_flags_are_safe(self):
        table = FlowTable()
        table.observe(event(proto="ICMP", flags="", sport=None, dport=None), now=0.0)
        self.assertEqual(table.snapshot()[0].packets, 1)

    def test_negative_packet_size_is_clamped(self):
        table = FlowTable()
        table.observe(event(size=-50), now=0.0)
        self.assertEqual(table.snapshot()[0].bytes, 0)


class FlowExpiryTests(unittest.TestCase):
    def test_idle_flow_expires(self):
        table = FlowTable(idle_timeout=10.0)
        table.observe(event(), now=0.0)
        self.assertEqual(table.expire(now=5.0), [])
        expired = table.expire(now=11.0)
        self.assertEqual(len(expired), 1)
        self.assertEqual(len(table), 0)

    def test_long_running_flow_expires_on_duration(self):
        table = FlowTable(idle_timeout=1000.0, max_duration=60.0)
        table.observe(event(), now=0.0)
        for t in range(1, 61, 5):
            table.observe(event(), now=float(t))
        self.assertEqual(len(table.expire(now=60.0)), 1)

    def test_force_drains_everything(self):
        table = FlowTable(idle_timeout=1000.0)
        for i in range(5):
            table.observe(event(dport=1000 + i), now=0.0)
        self.assertEqual(len(table.expire(now=0.0, force=True)), 5)
        self.assertEqual(len(table), 0)


class FlowBoundsTests(unittest.TestCase):
    def test_table_is_bounded_and_evicts_least_recent(self):
        # A flow key holds attacker-controlled values; growth must be bounded.
        table = FlowTable(max_flows=50)
        for i in range(500):
            table.observe(event(dst=f"10.0.{i // 256}.{i % 256}"), now=float(i))
        self.assertLessEqual(len(table), 50)
        self.assertGreater(table.evicted, 0)
        # The most recent flows survived.
        sources = {f.key.destination for f in table.snapshot()}
        self.assertIn("10.0.1.243", sources)

    def test_metrics_report_state(self):
        table = FlowTable(max_flows=10)
        table.observe(event(), now=0.0)
        metrics = table.metrics()
        self.assertEqual(metrics["active_flows"], 1)
        self.assertEqual(metrics["observed_packets"], 1)
        self.assertEqual(metrics["max_flows"], 10)


class GroupingTests(unittest.TestCase):
    def test_group_by_source_uses_the_sending_side(self):
        table = FlowTable()
        table.observe(event(src="10.0.0.1", dst="10.0.0.2"), now=0.0)
        table.observe(event(src="10.0.0.1", dst="10.0.0.3"), now=0.0)
        table.observe(event(src="10.0.0.9", dst="10.0.0.2"), now=0.0)
        grouped = group_by_source(table.snapshot())
        self.assertEqual(sorted(grouped), ["10.0.0.1", "10.0.0.9"])
        self.assertEqual(len(grouped["10.0.0.1"]), 2)


class SerializationTests(unittest.TestCase):
    def test_as_dict_is_json_friendly_and_complete(self):
        import json

        table = FlowTable()
        table.observe(event(size=120, flags="SA"), now=0.0)
        data = table.snapshot()[0].as_dict()
        json.dumps(data)  # must not raise
        for field in ("source", "destination", "source_port", "destination_port",
                      "protocol", "packets", "bytes", "duration", "syn", "ack"):
            self.assertIn(field, data)
        self.assertEqual(data["source"], "192.0.2.1")
        self.assertEqual(data["destination"], "192.0.2.2")


if __name__ == "__main__":
    unittest.main()
