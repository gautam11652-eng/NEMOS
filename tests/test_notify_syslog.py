"""Syslog/CEF export, and the escaping that keeps it from being forgeable.

A finding that exists only in NEMOS's own dashboard is not part of anyone's
detection stack. CEF over syslog is the format the widest range of collectors
parse without a custom decoder.

The escaping tests are the important ones. Alert fields carry
attacker-influenced content -- a reason string quotes evidence, and evidence
quotes the network. A raw newline reaching a collector would let an attacker
terminate the record and forge a separate log entry after it, which is worse
than not exporting at all: it puts adversary-controlled text into the record
a responder trusts.
"""

from __future__ import annotations

import socket
import unittest

from nemos.notify import (
    CEF_SEVERITY,
    AlertNotifier,
    DeliveryError,
    NotifierConfig,
    SyslogChannel,
    format_cef,
)
from nemos.version import VERSION

FINDING = {
    "timestamp": "2026-01-01T00:00:00+00:00",
    "threat": "PORT_SCAN",
    "category": "RECONNAISSANCE",
    "source": "203.0.113.9",
    "destination": "192.168.1.10",
    "destination_port": 443,
    "protocol": "TCP",
    "severity": "HIGH",
    "risk_score": 74,
    "confidence": 88,
    "reason": "20 distinct ports probed in 10s",
    "technique": "T1595",
    "incident_id": "NEMOS-ABC123",
}


class CefRendering(unittest.TestCase):
    def test_the_header_has_the_seven_required_fields(self):
        header = format_cef(FINDING, VERSION).split("|")
        self.assertEqual(header[0], "CEF:0")
        self.assertEqual(header[1], "NEMOS")
        self.assertEqual(header[2], "NEMOS")
        self.assertEqual(header[3], VERSION)
        self.assertEqual(header[4], "PORT_SCAN")
        self.assertEqual(header[6], str(CEF_SEVERITY["HIGH"]))

    def test_the_evidence_reaches_the_extension(self):
        line = format_cef(FINDING, VERSION)
        for expected in (
            "src=203.0.113.9", "dst=192.168.1.10", "dpt=443", "proto=TCP",
            "cn1=74", "cn2=88", "cs1=T1595", "cs2=NEMOS-ABC123",
        ):
            self.assertIn(expected, line)

    def test_labels_accompany_the_custom_fields(self):
        # A bare cs1 is meaningless to a SIEM without its label.
        line = format_cef(FINDING, VERSION)
        self.assertIn("cs1Label=mitreTechnique", line)
        self.assertIn("cn1Label=riskScore", line)

    def test_absent_fields_are_omitted_not_rendered_empty(self):
        line = format_cef({"threat": "X", "severity": "LOW"}, VERSION)
        self.assertNotIn("src=", line)
        self.assertNotIn("=None", line)

    def test_a_label_is_never_emitted_without_its_value(self):
        # cs1Label with no cs1 is noise the SIEM has to filter back out.
        line = format_cef({"threat": "X", "severity": "LOW"}, VERSION)
        for label in ("cn1Label", "cn2Label", "cs1Label", "cs2Label"):
            self.assertNotIn(label, line)

    def test_every_severity_maps_into_the_cef_range(self):
        for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            value = CEF_SEVERITY[severity]
            self.assertGreaterEqual(value, 0)
            self.assertLessEqual(value, 10)

    def test_an_unknown_severity_does_not_raise(self):
        self.assertIn("|3", format_cef({"threat": "X", "severity": "WEIRD"}, VERSION))


def split_cef_header(line: str) -> list[str]:
    """Split a CEF line the way a collector does: on *unescaped* pipes only.

    A plain ``str.split("|")`` would also split on ``\\|``, which is exactly
    the mistake that would make an escaping bug look like correct behaviour.
    """
    fields: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and index + 1 < len(line):
            current.append(line[index + 1])
            index += 2
            continue
        if char == "|":
            fields.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    fields.append("".join(current))
    return fields


class InjectionIsNotPossible(unittest.TestCase):
    """The security boundary: no field may terminate or forge a record."""

    def test_a_newline_in_a_field_cannot_forge_a_second_record(self):
        hostile = dict(FINDING)
        hostile["reason"] = "benign\nCEF:0|Evil|Evil|1|OWNED|Nothing to see|0"
        line = format_cef(hostile, VERSION)
        self.assertNotIn("\n", line)
        self.assertIn("\\n", line)

    def test_a_pipe_in_a_header_field_cannot_add_header_fields(self):
        hostile = dict(FINDING)
        hostile["threat"] = "PORT_SCAN|9|injected"
        line = format_cef(hostile, VERSION)
        # Seven header fields, then the extension: the injected pipes must be
        # escaped rather than shifting the severity column.
        self.assertIn("\\|", line)
        fields = split_cef_header(line)
        self.assertEqual(fields[6], str(CEF_SEVERITY["HIGH"]),
                         "an injected pipe shifted the severity column")
        self.assertEqual(fields[4], "PORT_SCAN|9|injected",
                         "the pipes must survive as data, not as structure")

    def test_an_equals_in_an_extension_value_cannot_add_keys(self):
        hostile = dict(FINDING)
        hostile["reason"] = "scan of dpt=22 and src=10.0.0.1"
        line = format_cef(hostile, VERSION)
        self.assertIn("\\=", line)

    def test_a_backslash_is_escaped_before_anything_else(self):
        # Escaping "|" before "\" would let \| be produced from a literal
        # backslash and turn into an unescaped separator downstream.
        line = format_cef({"threat": "A\\B", "severity": "LOW"}, VERSION)
        self.assertIn("A\\\\B", line)

    def test_the_rendered_syslog_line_never_contains_a_newline(self):
        hostile = dict(FINDING)
        hostile["reason"] = "a\nb\rc\r\nd"
        hostile["threat"] = "T\nX"
        channel = SyslogChannel("127.0.0.1", hostname="sensor")
        self.assertNotIn("\n", channel.render(hostile))
        self.assertNotIn("\r", channel.render(hostile))

    def test_a_hostile_hostname_cannot_break_the_frame(self):
        channel = SyslogChannel("127.0.0.1", hostname="host\nname")
        self.assertNotIn("\n", channel.hostname)


class SyslogFraming(unittest.TestCase):
    def test_the_priority_encodes_facility_and_severity(self):
        channel = SyslogChannel("127.0.0.1", facility=13)
        # PRI = facility * 8 + level; CRITICAL maps to syslog level 2.
        self.assertEqual(channel._priority("CRITICAL"), 13 * 8 + 2)
        self.assertEqual(channel._priority("LOW"), 13 * 8 + 5)

    def test_a_higher_severity_produces_a_lower_syslog_level(self):
        channel = SyslogChannel("127.0.0.1")
        self.assertLess(channel._priority("CRITICAL"), channel._priority("LOW"))

    def test_the_line_starts_with_rfc5424_version_1(self):
        line = SyslogChannel("127.0.0.1", hostname="sensor").render(FINDING)
        self.assertRegex(line, r"^<\d+>1 ")

    def test_the_payload_is_truncated_rather_than_fragmented(self):
        huge = dict(FINDING)
        huge["reason"] = "A" * 20000
        sent = []
        channel = SyslogChannel(
            "127.0.0.1", socket_factory=lambda *a: _FakeSocket(sent))
        channel.send(huge, None, 1.0)
        self.assertLessEqual(len(sent[0]), 8192)


class _FakeSocket:
    """Stands in for a socket, recording what would go on the wire."""

    def __init__(self, sink, fail=False):
        self.sink = sink
        self.fail = fail
        self.closed = False
        self.connected = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        if self.fail:
            raise OSError("connection refused")
        self.connected = address

    def sendto(self, payload, address):
        if self.fail:
            raise OSError("network unreachable")
        self.sink.append(payload)

    def sendall(self, payload):
        if self.fail:
            raise OSError("broken pipe")
        self.sink.append(payload)

    def close(self):
        self.closed = True


class Delivery(unittest.TestCase):
    def test_udp_sends_one_datagram_with_no_trailing_newline(self):
        sent = []
        channel = SyslogChannel("10.0.0.9", 514, "udp",
                                socket_factory=lambda *a: _FakeSocket(sent))
        channel.send(FINDING, None, 1.0)
        self.assertEqual(len(sent), 1)
        self.assertFalse(sent[0].endswith(b"\n"))

    def test_tcp_delimits_with_a_newline(self):
        sent = []
        channel = SyslogChannel("10.0.0.9", 601, "tcp",
                                socket_factory=lambda *a: _FakeSocket(sent))
        channel.send(FINDING, None, 1.0)
        self.assertTrue(sent[0].endswith(b"\n"))
        self.assertEqual(sent[0].count(b"\n"), 1,
                         "the delimiter must be the only newline in the frame")

    def test_the_socket_is_closed_even_when_sending_fails(self):
        created = []

        def factory(*args):
            sock = _FakeSocket([], fail=True)
            created.append(sock)
            return sock

        channel = SyslogChannel("10.0.0.9", socket_factory=factory)
        with self.assertRaises(DeliveryError):
            channel.send(FINDING, None, 1.0)
        self.assertTrue(created[0].closed, "a failed send must not leak the socket")

    def test_an_unreachable_collector_raises_delivery_error_not_oserror(self):
        channel = SyslogChannel(
            "10.0.0.9", socket_factory=lambda *a: _FakeSocket([], fail=True))
        with self.assertRaises(DeliveryError):
            channel.send(FINDING, None, 1.0)

    def test_delivery_reaches_a_real_udp_listener(self):
        """End to end over a real socket, not a double."""
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(3)
        try:
            channel = SyslogChannel("127.0.0.1", server.getsockname()[1], "udp")
            channel.send(FINDING, None, 2.0)
            data, _ = server.recvfrom(8192)
        finally:
            server.close()
        text = data.decode()
        self.assertIn("CEF:0|NEMOS|NEMOS", text)
        self.assertIn("PORT_SCAN", text)
        self.assertIn("src=203.0.113.9", text)


class Configuration(unittest.TestCase):
    def test_syslog_alone_is_enough_to_activate_delivery(self):
        config = NotifierConfig(syslog_host="10.0.0.9")
        self.assertTrue(config.syslog_configured)
        self.assertTrue(config.any_channel)
        self.assertTrue(config.active)

    def test_no_channel_configured_stays_inactive(self):
        self.assertFalse(NotifierConfig().active)

    def test_the_notifier_builds_a_syslog_channel_from_config(self):
        notifier = AlertNotifier(NotifierConfig(syslog_host="10.0.0.9", syslog_port=1514))
        names = [channel.name for channel in notifier.channels]
        self.assertIn("syslog", names)

    def test_syslog_coexists_with_the_other_channels(self):
        notifier = AlertNotifier(NotifierConfig(
            syslog_host="10.0.0.9",
            telegram_token="t" * 20, telegram_chat_id="123",
            webhook_url="https://collector.example/hook",
        ))
        names = {channel.name for channel in notifier.channels}
        self.assertEqual(names, {"syslog", "telegram", "webhook"})


if __name__ == "__main__":
    unittest.main()
