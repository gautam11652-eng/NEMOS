"""The console must lead with what matters, not with what arrived last.

Before this, a chronological ungrouped feed meant a forty-host beaconing
campaign filled the first three pages of every list and pushed the single
CRITICAL flood out of sight entirely. That is not a cosmetic complaint: a
console that buries its worst finding under repetition trains its operator to
stop reading it.

Two halves have to hold together, and each is useless alone:

- The **server** orders by risk, because sorting the page a client already
  holds cannot change which rows are on it.
- The **client** groups repeats, because forty identical findings are one
  campaign however they are sorted.
"""

from __future__ import annotations

import re
import sqlite3
import unittest
from pathlib import Path

from nemos.api import create_app
from nemos.database import initialize

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "nemos" / "static" / "app.js").read_text()
CSS = (ROOT / "nemos" / "static" / "app.css").read_text()
HTML = (ROOT / "nemos" / "templates" / "index.html").read_text()


def seed(path: Path) -> None:
    """A noisy campaign that arrived last, and one critical that arrived first."""
    initialize(path)
    c = sqlite3.connect(path)
    rows = [(
        "2026-01-01T00:00:00+00:00", "SYN_FLOOD_PATTERN", "DENIAL_OF_SERVICE",
        "198.51.100.23", "CRITICAL", 90, 90, "150 SYN packets to port 443",
        0, 0, 0, 0, 10, "T1498.001", "NEMOS-CRITICAL", "{}",
    )]
    # Forty later, lower-risk findings: by arrival order these bury the above.
    rows += [(
        f"2026-01-01T00:0{index // 10}:{index % 10}0+00:00", "C2_BEACONING",
        "COMMAND_AND_CONTROL", f"192.168.1.{100 + index}", "HIGH", 86, 80,
        "6 contacts at a regular 2.4s interval",
        0, 0, 0, 0, 10, "T1071", f"NEMOS-BEACON-{index}", "{}",
    ) for index in range(40)]
    c.executemany(
        """INSERT INTO alerts(timestamp,threat,category,source,severity,risk_score,
                              confidence,reason,ports_scanned,packets,destinations,
                              ports,window_seconds,technique,incident_id,evidence)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
    c.commit()
    c.close()


class Settings:
    """Minimal settings stand-in; the API only reads these for this endpoint."""

    def __init__(self, db_path):
        self.db_path = db_path
        self.api_token = None
        self.dashboard_limit = 100
        self.trusted_hosts = ()
        self.host = "127.0.0.1"
        self.api_rate_limit = 100_000
        self.api_auth_rate_limit = 10_000
        self.interface = None
        self.capture_enabled = False
        self.max_traffic = 100_000
        self.max_alerts = 10_000

    @property
    def remote(self):
        return False


class Writer:
    def metrics(self):
        return {}


class ServerOrdersByRisk(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db = Path(self.dir.name) / "nemos.db"
        seed(self.db)
        self.client = create_app(Settings(self.db), Writer()).test_client()

    def test_alerts_default_to_arrival_order(self):
        """The documented contract, which scripts depend on."""
        body = self.client.get("/api/alerts?limit=5").get_json()
        self.assertEqual(body[0]["threat"], "C2_BEACONING")

    def test_sort_risk_puts_the_critical_finding_first(self):
        body = self.client.get("/api/alerts?limit=5&sort=risk").get_json()
        self.assertEqual(body[0]["threat"], "SYN_FLOOD_PATTERN")
        self.assertEqual(body[0]["severity"], "CRITICAL")

    def test_the_critical_finding_survives_a_first_page_sized_limit(self):
        """The point of ordering in SQL rather than in the browser.

        With arrival order and a 25-row page, the one CRITICAL finding is on
        page two and an operator glancing at the console never sees it.
        """
        page = self.client.get("/api/alerts?limit=25&sort=risk").get_json()
        self.assertIn("SYN_FLOOD_PATTERN", [a["threat"] for a in page])

        buried = self.client.get("/api/alerts?limit=25").get_json()
        self.assertNotIn("SYN_FLOOD_PATTERN", [a["threat"] for a in buried],
                         "the fixture no longer reproduces the burial it exists to test")

    def test_incidents_offer_the_same_ordering(self):
        body = self.client.get("/api/incidents?limit=5&sort=risk").get_json()
        self.assertEqual(body[0]["max_risk"], 90)

    def test_the_dashboard_endpoint_is_risk_ordered_without_asking(self):
        """It exists only to feed the console, so it needs no opt-in."""
        body = self.client.get("/api/dashboard").get_json()
        self.assertEqual(body["incidents"][0]["max_risk"], 90)


class ClientGroupsRepeats(unittest.TestCase):
    """Asserted against the script's source: there is no build step to hook."""

    def test_findings_are_grouped_before_they_are_paginated(self):
        # Paginating raw findings and grouping only the visible page would
        # still hand the operator a first page of one repeated campaign.
        self.assertIn("const rows = groupFindings(matched);", JS)
        order = JS.index("groupFindings(matched)"), JS.index("state.detPage * PAGE")
        self.assertLess(order[0], order[1])

    def test_the_group_key_excludes_the_source(self):
        """The source is what varies across a campaign."""
        key = re.search(r"function groupKey\(a\) \{.*?\n\}", JS, re.S).group(0)
        self.assertNotIn("a.source", key)
        self.assertIn("a.threat", key)

    def test_the_console_asks_for_triage_order(self):
        self.assertIn("/api/alerts?limit=500&sort=risk", JS)

    def test_a_group_can_be_expanded_to_its_members(self):
        """Grouping must never be the same thing as hiding."""
        self.assertIn("state.expanded", JS)
        self.assertIn('data-group=', JS)
        self.assertIn("tr.child", CSS)


class NothingIsClippedOrOverrun(unittest.TestCase):
    """A comma-joined threat list used to paint over the risk beside it."""

    def test_the_incident_table_has_a_deterministic_layout(self):
        # max-width on a td does not constrain an auto-layout table, which is
        # what let the most important row render on top of its own severity.
        self.assertIn(".table-incidents { table-layout: fixed; }", CSS)

    def test_long_threat_lists_are_truncated_with_a_count(self):
        self.assertIn('class="more"', JS)
        self.assertIn("threats.slice(0, 2)", JS)

    def test_headers_are_not_ellipsised_into_nonsense(self):
        # "ALER", "SEVER…" are not column names.
        self.assertIn(".table-incidents th { white-space: nowrap; }", CSS)

    def test_the_opaque_incident_id_does_not_occupy_a_column(self):
        self.assertNotIn("<th>Incident</th>", HTML)
        self.assertIn('title="Incident ${esc(i.incident_id)}"', JS)


class LabelsAreReadableWithoutLosingTheIdentifier(unittest.TestCase):
    def test_threat_identifiers_are_humanised_for_display(self):
        self.assertIn("const threatLabel =", JS)

    def test_the_raw_identifier_stays_available(self):
        """It is the value in the API, in Telegram and in syslog."""
        self.assertIn('title="${esc(a.threat)}"', JS)

    def test_acronyms_are_not_title_cased(self):
        # "C2 Beaconing" is right; "C2 beaconing" is right; "c2 Beaconing" is not.
        self.assertIn('"c2"', JS)
        self.assertIn('"dns"', JS)

    def test_the_sentence_helper_is_not_applied_to_identifiers(self):
        """It appended a full stop, rendering "C2_BEACONING."."""
        self.assertNotIn("sentence(a.threat)", JS)
        self.assertNotIn("sentence(g.threat)", JS)


class MetricsAreTriageNotVolume(unittest.TestCase):
    def test_the_first_metric_is_what_needs_attention(self):
        self.assertIn('k: "Critical open"', JS)

    def test_the_console_never_asks_for_a_telegram_chat_id(self):
        """QR pairing replaced it. A panel still naming TELEGRAM_CHAT_ID sends
        the operator down the path the pairing card below it says to avoid."""
        assert "TELEGRAM_CHAT_ID" not in JS
        assert "TELEGRAM_BOT_USERNAME" in JS

    def test_a_backend_reason_is_punctuated_before_the_next_sentence(self):
        """The reason is a clause carrying no trailing stop, so it ran straight
        into the sentence after it -- observed on a real deployment as
        '...deployment An administrator sets...'."""
        assert 'replace(/\\.?$/, ".")' in JS

    def test_capture_state_is_shown_as_a_word_not_a_token(self):
        # "not_configured" set in 25px type overflowed its own card.
        self.assertIn("CAPTURE_LABEL", JS)
        self.assertIn('not_configured: "Off"', JS)

    def test_a_long_metric_value_cannot_overflow_its_card(self):
        self.assertIn("overflow-wrap: anywhere", CSS)

    def test_model_health_reaches_the_console(self):
        self.assertIn("analysis?.model?.health", JS)


if __name__ == "__main__":
    unittest.main()
