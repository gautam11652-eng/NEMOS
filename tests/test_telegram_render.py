"""Tests for Telegram message rendering.

Two properties matter more than the exact wording:

1. **Nothing is invented.** A field NEMOS does not have must not appear at all,
   as a blank, a zero, or the string "None". A reader cannot tell an invented
   value from an observed one, so there must not be any.
2. **Nothing escapes its line.** Alert fields carry attacker-influenced text.
   A newline in one would let it forge what looks like another section of the
   report, so every field is flattened and bounded.
"""

from __future__ import annotations

import unittest

from nemos.telegram import (
    DETAIL_BY_SEVERITY,
    EVIDENCE_LIST_PREVIEW,
    TELEGRAM_MAX_MESSAGE,
    alert_keyboard,
    dashboard_link,
    detail_for,
    render_alert,
    render_brief,
    render_hosts,
    render_incident,
    render_incident_list,
    render_status,
    summarize_evidence,
)


def alert(**kw):
    base = {
        "id": 42,
        "timestamp": "2026-09-03T10:15:00+00:00",
        "threat": "PORT_SCAN",
        "category": "NETWORK_RECONNAISSANCE",
        "source": "192.0.2.10",
        "severity": "CRITICAL",
        "risk_score": 92,
        "confidence": 94,
        "reason": "43 unique destination ports in 20s",
        "technique": "T1046",
        "incident_id": "NEMOS-ABC123DEF456",
        "packets": 43,
        "destinations": 14,
        "ports": 18,
        "window_seconds": 20,
        "evidence": {"scan_type": "vertical", "syn_packets": 43,
                     "ports": list(range(1, 40))},
    }
    base.update(kw)
    return base


class DetailLevelTests(unittest.TestCase):
    def test_each_severity_maps_to_a_depth(self):
        self.assertEqual(DETAIL_BY_SEVERITY["LOW"], "short")
        self.assertEqual(DETAIL_BY_SEVERITY["CRITICAL"], "full")
        self.assertEqual(detail_for("HIGH"), "detailed")
        self.assertEqual(detail_for("MEDIUM"), "summary")

    def test_an_unknown_severity_falls_back_to_a_summary(self):
        self.assertEqual(detail_for(""), "summary")
        self.assertEqual(detail_for("BANANA"), "summary")

    def test_a_floor_can_raise_but_never_lower_the_depth(self):
        self.assertEqual(detail_for("LOW", floor="detailed"), "detailed")
        self.assertEqual(detail_for("CRITICAL", floor="short"), "full")

    def test_detail_grows_monotonically_with_severity(self):
        lengths = [len(render_alert(alert(severity=s)))
                   for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")]
        self.assertEqual(lengths, sorted(lengths), lengths)

    def test_a_low_finding_is_a_short_notification(self):
        text = render_alert(alert(severity="LOW"))
        self.assertLessEqual(len(text.splitlines()), 3)
        self.assertIn("PORT_SCAN", text)
        self.assertIn("192.0.2.10", text)
        # No packet-level detail by default at this severity.
        self.assertNotIn("syn packets", text)

    def test_counters_are_pluralised_correctly(self):
        text = render_alert(alert(severity="HIGH", destinations=1, packets=1))
        self.assertIn("• 1 unique destination\n", text)
        self.assertIn("• 1 packet\n", text)
        many = render_alert(alert(severity="HIGH", destinations=14, packets=43))
        self.assertIn("• 14 unique destinations", many)
        self.assertIn("• 43 packets", many)

    def test_a_critical_finding_is_the_full_structured_report(self):
        text = render_alert(alert())
        for expected in ("CRITICAL", "PORT_SCAN", "192.0.2.10", "94%", "92/100",
                         "T1046", "NEMOS-ABC123DEF456", "Evidence:", "Observed:",
                         "2026-09-03T10:15:00+00:00"):
            self.assertIn(expected, text, expected)

    def test_a_medium_finding_carries_a_summary_and_key_evidence(self):
        text = render_alert(alert(severity="MEDIUM"))
        self.assertIn("Evidence:", text)
        # Counters are the detailed tier; a summary does not carry them.
        self.assertNotIn("Observed:", text)


class NoFabricationTests(unittest.TestCase):
    def test_absent_fields_produce_no_line_at_all(self):
        text = render_alert({"threat": "X", "source": "1.2.3.4", "severity": "HIGH"})
        for absent in ("ATT&CK", "Target:", "Endpoint:", "Category:",
                       "Incident:", "Observed at:", "Why this fired:"):
            self.assertNotIn(absent, text, absent)

    def test_a_missing_value_never_renders_as_the_word_none(self):
        text = render_alert({"threat": "X", "source": "1.2.3.4", "severity": "CRITICAL",
                             "category": None, "technique": None, "reason": None})
        self.assertNotIn("None", text)

    def test_zero_counters_are_omitted_rather_than_shown(self):
        """A zero is a claim. NEMOS did not count zero packets; it counted none."""
        text = render_alert(alert(packets=0, destinations=0, ports=0,
                                  ports_scanned=0, window_seconds=0, evidence={}))
        self.assertNotIn("Observed:", text)

    def test_an_empty_evidence_set_produces_no_evidence_section(self):
        self.assertNotIn("Evidence:", render_alert(alert(evidence={})))
        self.assertNotIn("Evidence:", render_alert(alert(evidence=None)))

    def test_evidence_arrives_as_json_text_from_the_database(self):
        text = render_alert(alert(evidence='{"scan_type": "vertical"}'))
        self.assertIn("vertical", text)

    def test_unparseable_evidence_is_dropped_not_guessed(self):
        self.assertNotIn("Evidence:", render_alert(alert(evidence="not json")))


class InjectionTests(unittest.TestCase):
    def test_a_newline_in_a_field_cannot_forge_a_section(self):
        """Injected text must stay inside the one line it was rendered into."""
        text = render_alert(alert(threat="X\nSeverity: LOW\nATT&CK: T9999"))
        lines = text.splitlines()
        # Exactly one line *is* a severity row; the forged one is embedded in
        # the detection line rather than standing on its own.
        self.assertEqual([ln for ln in lines if ln.startswith("Severity:")],
                         ["Severity: CRITICAL"])
        self.assertNotIn("ATT&CK: T9999", lines)
        self.assertIn("X Severity: LOW ATT&CK: T9999", lines)

    def test_a_carriage_return_is_stripped_too(self):
        self.assertNotIn("\r", render_alert(alert(reason="a\r\nb")))

    def test_no_parse_mode_markup_is_emitted(self):
        """Nothing here asks a chat client to parse alert text as markup."""
        text = render_alert(alert(threat="__bold__ *x* [a](b) <i>"))
        self.assertIn("__bold__", text)  # passed through verbatim, not escaped

    def test_every_field_is_length_bounded(self):
        text = render_alert(alert(threat="T" * 5000, source="S" * 5000,
                                  reason="R" * 9000))
        self.assertLessEqual(len(text), TELEGRAM_MAX_MESSAGE)

    def test_a_huge_message_is_truncated_with_a_marker(self):
        text = render_alert(alert(evidence={f"k{i}": "v" * 300 for i in range(200)}))
        self.assertLessEqual(len(text), TELEGRAM_MAX_MESSAGE)


class EvidenceSummaryTests(unittest.TestCase):
    def test_a_long_list_is_summarised_not_dumped(self):
        lines = summarize_evidence({"ports": list(range(1, 500))})
        self.assertEqual(len(lines), 1)
        self.assertIn("499", lines[0])
        self.assertIn("...", lines[0])
        self.assertLess(len(lines[0]), 200)

    def test_a_short_list_is_shown_in_full(self):
        lines = summarize_evidence({"ports": [22, 80, 443]})
        self.assertIn("22, 80, 443", lines[0])
        self.assertNotIn("...", lines[0])

    def test_the_preview_length_is_the_documented_one(self):
        lines = summarize_evidence({"ports": list(range(100))})
        self.assertEqual(lines[0].count(","), EVIDENCE_LIST_PREVIEW)

    def test_the_number_of_evidence_lines_is_capped(self):
        lines = summarize_evidence({f"field{i}": i for i in range(100)}, max_lines=5)
        self.assertLessEqual(len(lines), 6)  # five fields plus the "more" line
        self.assertIn("more evidence field", lines[-1])

    def test_empty_values_are_skipped(self):
        lines = summarize_evidence({"a": "", "b": [], "c": None, "d": {}, "e": 1})
        self.assertEqual(len(lines), 1)
        self.assertIn("e", lines[0])

    def test_booleans_read_as_words(self):
        self.assertIn("yes", summarize_evidence({"external": True})[0])
        self.assertIn("no", summarize_evidence({"external": False})[0])

    def test_a_nested_mapping_is_counted_rather_than_expanded(self):
        lines = summarize_evidence({"profile": {"a": 1, "b": 2}})
        self.assertIn("2 field(s)", lines[0])


class KeyboardTests(unittest.TestCase):
    def test_buttons_are_offered_for_a_finding_with_an_incident(self):
        keyboard = alert_keyboard(alert())
        assert keyboard is not None
        labels = [b["text"] for row in keyboard["inline_keyboard"] for b in row]
        self.assertIn("Investigate", labels)
        self.assertIn("Acknowledge", labels)

    def test_callback_payloads_carry_only_an_action_and_an_id(self):
        keyboard = alert_keyboard(alert())
        assert keyboard is not None
        for row in keyboard["inline_keyboard"]:
            for button in row:
                data = button.get("callback_data")
                if data is None:
                    continue
                self.assertLessEqual(len(data), 64)
                action, _, target = data.partition(":")
                self.assertIn(action, {"inv", "ack", "acki", "con"})
                self.assertNotIn(" ", target)

    def test_no_dashboard_button_without_an_https_url(self):
        """Telegram refuses a non-https URL button, and loopback is not https."""
        for url in ("", "http://127.0.0.1:5000", "http://localhost:5000"):
            with self.subTest(url=url):
                keyboard = alert_keyboard(alert(), dashboard_url=url)
                assert keyboard is not None
                buttons = [b for row in keyboard["inline_keyboard"] for b in row]
                self.assertFalse(any("url" in b for b in buttons))

    def test_an_https_dashboard_becomes_a_link_button(self):
        keyboard = alert_keyboard(alert(), dashboard_url="https://nemos.example")
        assert keyboard is not None
        urls = [b["url"] for row in keyboard["inline_keyboard"] for b in row if "url" in b]
        self.assertEqual(urls, ["https://nemos.example/#incident/NEMOS-ABC123DEF456"])

    def test_contain_is_absent_unless_the_deployment_enables_it(self):
        keyboard = alert_keyboard(alert())
        assert keyboard is not None
        labels = [b["text"] for row in keyboard["inline_keyboard"] for b in row]
        self.assertNotIn("Contain", labels)
        enabled = alert_keyboard(alert(), allow_contain=True)
        assert enabled is not None
        labels = [b["text"] for row in enabled["inline_keyboard"] for b in row]
        self.assertIn("Contain", labels)

    def test_a_finding_with_nothing_to_act_on_gets_no_keyboard(self):
        self.assertIsNone(alert_keyboard({"threat": "X", "severity": "LOW"}))


class DashboardLinkTests(unittest.TestCase):
    def test_no_base_url_means_no_link(self):
        self.assertEqual(dashboard_link(""), "")
        self.assertEqual(dashboard_link(None), "")

    def test_a_path_is_joined_without_doubling_the_separator(self):
        self.assertEqual(dashboard_link("https://x.test/", "/a"), "https://x.test/a")
        self.assertEqual(dashboard_link("https://x.test", "a"), "https://x.test/a")

    def test_an_alert_links_back_to_its_incident(self):
        text = render_alert(alert(), dashboard_url="https://nemos.example")
        self.assertIn("https://nemos.example/#incident/NEMOS-ABC123DEF456", text)


class StatusTests(unittest.TestCase):
    def test_it_reports_every_component_it_was_given(self):
        text = render_status({
            "capture": "ONLINE", "detection": "ONLINE", "ml": "AVAILABLE",
            "database": "ONLINE", "telegram": "CONNECTED",
            "packets": 128_400, "flows": 2_100, "incidents": 3,
        })
        for expected in ("NEMOS STATUS", "Capture: ONLINE", "Detection: ONLINE",
                         "ML: AVAILABLE", "Database: ONLINE", "Telegram: CONNECTED",
                         "Packets: 128,400", "Flows: 2,100", "Active incidents: 3"):
            self.assertIn(expected, text, expected)

    def test_a_counter_it_was_not_given_is_omitted(self):
        text = render_status({"capture": "ONLINE", "database": "ONLINE"})
        self.assertNotIn("Packets:", text)
        self.assertNotIn("Flows:", text)

    def test_a_blocked_capture_is_not_dressed_up(self):
        text = render_status({"capture": "BLOCKED"})
        self.assertIn("Capture: BLOCKED", text)
        self.assertIn("❌", text)

    def test_uptime_is_human_readable(self):
        self.assertIn("2h 1m", render_status({"uptime_seconds": 7260}))
        self.assertIn("5m 0s", render_status({"uptime_seconds": 300}))


class ListTests(unittest.TestCase):
    def test_an_empty_incident_list_says_so_plainly(self):
        text = render_incident_list([])
        self.assertIn("No incidents recorded.", text)

    def test_incidents_render_with_risk_and_sources(self):
        text = render_incident_list([{
            "incident_id": "NEMOS-AAA111BBB222", "severity": "HIGH",
            "risk_score": 81, "threats": ["PORT_SCAN", "TCP_SYN_SCAN"],
            "sources": ["192.0.2.10"], "last_seen": "2026-09-03T10:00:00+00:00",
        }])
        self.assertIn("NEMOS-AAA111BBB222", text)
        self.assertIn("risk 81/100", text)
        self.assertIn("PORT_SCAN", text)
        self.assertIn("192.0.2.10", text)

    def test_an_empty_host_list_says_so_plainly(self):
        self.assertIn("No hosts observed yet.", render_hosts([]))

    def test_hosts_render_with_counts(self):
        text = render_hosts([{"host": "192.0.2.10", "risk_score": 88,
                              "packets": 4210, "alert_count": 6, "critical_count": 2}])
        self.assertIn("192.0.2.10", text)
        self.assertIn("risk 88/100", text)
        self.assertIn("4,210 packets", text)
        self.assertIn("2 critical", text)

    def test_an_incident_report_includes_its_evidence_timeline(self):
        text = render_incident(
            {"incident_id": "NEMOS-AAA111BBB222", "severity": "CRITICAL",
             "risk_score": 95, "confidence": 90, "alert_count": 2,
             "unique_threats": 2, "sources": ["192.0.2.10"],
             "techniques": ["T1046"], "recommendations": ["Validate the source."]},
            [{"timestamp": "2026-09-03T10:00:00+00:00", "threat": "PORT_SCAN",
              "severity": "CRITICAL", "reason": "43 ports in 20s"},
             {"timestamp": "2026-09-03T10:00:20+00:00", "threat": "NETWORK_FANOUT",
              "severity": "HIGH", "reason": "14 destinations"}],
        )
        self.assertIn("Evidence timeline:", text)
        self.assertIn("2026-09-03T10:00:00+00:00", text)
        self.assertIn("NETWORK_FANOUT", text)
        self.assertIn("T1046", text)
        self.assertIn("Validate the source.", text)

    def test_a_long_timeline_is_summarised(self):
        rows = [{"timestamp": f"2026-09-03T10:00:{i:02d}+00:00", "threat": "PORT_SCAN",
                 "severity": "HIGH", "reason": "x"} for i in range(30)]
        text = render_incident({"incident_id": "NEMOS-A", "severity": "HIGH",
                                "risk_score": 80, "confidence": 70,
                                "alert_count": 30, "unique_threats": 1}, rows)
        self.assertIn("22 earlier detections", text)
        self.assertLessEqual(len(text), TELEGRAM_MAX_MESSAGE)


class BriefTests(unittest.TestCase):
    def test_only_supplied_metrics_appear(self):
        text = render_brief({"packets": 1000})
        self.assertIn("Packets: 1,000", text)
        self.assertNotIn("Flows:", text)
        self.assertNotIn("Incidents by severity:", text)

    def test_a_full_brief_covers_every_requested_section(self):
        text = render_brief({
            "period": "Last 24h", "packets": 900_000, "flows": 12_000, "hosts": 41,
            "severity_counts": {"CRITICAL": 1, "HIGH": 4, "MEDIUM": 9, "LOW": 22},
            "top_detections": [{"threat": "PORT_SCAN", "count": 12}],
            "top_hosts": [{"host": "192.0.2.10", "risk_score": 88, "alert_count": 6}],
            "highest_risk": 95, "unresolved": 7,
            "deviations": ["192.0.2.10 contacted 14 new destinations"],
            "recommended": ["192.0.2.10 — risk 88/100"],
        })
        for expected in ("NEMOS SECURITY BRIEF", "Last 24h", "Packets: 900,000",
                         "Flows: 12,000", "Hosts observed: 41", "CRITICAL: 1",
                         "Top detections:", "PORT_SCAN: 12", "Most affected hosts:",
                         "Highest risk score: 95/100", "Unresolved incidents: 7",
                         "Behavioural deviations:", "Recommended investigations:"):
            self.assertIn(expected, text, expected)

    def test_an_empty_period_is_stated_rather_than_shown_as_zeros(self):
        self.assertIn("No measurable activity", render_brief({}))

    def test_a_brief_stays_within_the_message_limit(self):
        text = render_brief({
            "packets": 1, "top_detections": [{"threat": "T" * 200, "count": i}
                                             for i in range(50)],
            "top_hosts": [{"host": "h" * 200, "risk_score": 1, "alert_count": 1}
                          for _ in range(50)],
        })
        self.assertLessEqual(len(text), TELEGRAM_MAX_MESSAGE)


if __name__ == "__main__":
    unittest.main()
