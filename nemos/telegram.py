"""Telegram message rendering for NEMOS.

Every function here is pure: data in, a string out. Nothing performs I/O, so
what the tests exercise is exactly what an operator receives, and a rendering
mistake cannot take down the delivery worker.

Two decisions shape all of it.

**Plain text, no parse mode.** Alert fields carry attacker-influenced content
-- a hostname from an SNI extension, a threat name derived from observed
traffic. Asking Telegram to parse that as Markdown or HTML turns an unbalanced
``_`` into a delivery failure at best and formatting injection at worst.
Structure comes from icons, separators and indentation, which no parser has to
agree with. The only escaping needed is therefore none, and the only rule is
that a rendered field is length-bounded.

**Detail scales with severity.** A LOW finding gets a line; a CRITICAL one gets
the full structured report. This is not cosmetic: a channel that sends the same
wall of text for everything trains its reader to ignore it, and the point of
the severity field is to spend the reader's attention where it matters.
"""

from __future__ import annotations

import json
from typing import Any
from collections.abc import Iterable, Mapping

TELEGRAM_MAX_MESSAGE = 3500

RULE = "━" * 18

SEVERITY_ICON = {
    "CRITICAL": "\U0001f6a8",   # rotating light
    "HIGH": "⚠️",     # warning sign
    "MEDIUM": "\U0001f7e1",     # yellow circle
    "LOW": "\U0001f535",        # blue circle
}

STATE_ICON = {
    "ok": "✅",
    "warn": "⚠️",
    "bad": "❌",
    "idle": "⬜",
}

# How much of a report each severity earns.
DETAIL_BY_SEVERITY = {
    "LOW": "short",
    "MEDIUM": "summary",
    "HIGH": "detailed",
    "CRITICAL": "full",
}
DETAIL_ORDER = ("short", "summary", "detailed", "full")

# Evidence keys that are noise in a chat message: they repeat a field already
# printed above, or they are internal bookkeeping.
_EVIDENCE_SKIP = frozenset({"note", "source_position"})

# A single evidence list is summarised past this many items rather than printed.
EVIDENCE_LIST_PREVIEW = 6
EVIDENCE_MAX_LINES = 10


def detail_for(severity: str, floor: str = "") -> str:
    """The report depth for a severity, never below ``floor``."""
    level = DETAIL_BY_SEVERITY.get(str(severity or "").upper(), "summary")
    if floor in DETAIL_ORDER and DETAIL_ORDER.index(floor) > DETAIL_ORDER.index(level):
        return floor
    return level


def _clean(value: Any, limit: int = 120) -> str:
    """Flatten a field to one safe, bounded line.

    Newlines are removed rather than escaped. A field that can carry a newline
    can otherwise forge what looks like another section of the report.
    """
    if value is None:
        # str(None) is "None", which would print a field NEMOS does not have as
        # though it had the literal value "None". Callers treat "" as absent.
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = " ".join(text.split())
    return text[:limit]


def _as_dict(value: Any) -> dict[str, Any]:
    """Evidence arrives as a dict in memory and as JSON text from SQLite."""
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _label(key: str) -> str:
    return str(key).replace("_", " ").strip()[:32]


def summarize_evidence(evidence: Any, max_lines: int = EVIDENCE_MAX_LINES) -> list[str]:
    """Render evidence as bullet lines, summarising rather than dumping.

    A port scan's evidence legitimately contains a hundred port numbers. Sending
    all of them helps nobody and risks the message limit, so a long list becomes
    its count plus a preview. This is the "summarise large evidence sets"
    requirement, and it is applied to every list without needing to know which
    detection produced it.
    """
    data = _as_dict(evidence)
    lines: list[str] = []
    for key, value in data.items():
        if len(lines) >= max_lines:
            remaining = len(data) - len(lines)
            if remaining > 0:
                lines.append(f"• ... {remaining} more evidence field(s)")
            break
        if key in _EVIDENCE_SKIP or value in (None, "", [], {}):
            continue
        if isinstance(value, (list, tuple)):
            items = list(value)
            preview = ", ".join(_clean(item, 24) for item in items[:EVIDENCE_LIST_PREVIEW])
            if len(items) > EVIDENCE_LIST_PREVIEW:
                lines.append(f"• {_label(key)}: {len(items)} — {preview}, ...")
            else:
                lines.append(f"• {_label(key)}: {preview}")
        elif isinstance(value, Mapping):
            lines.append(f"• {_label(key)}: {len(value)} field(s)")
        elif isinstance(value, bool):
            lines.append(f"• {_label(key)}: {'yes' if value else 'no'}")
        else:
            lines.append(f"• {_label(key)}: {_clean(value, 60)}")
    return lines


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def dashboard_link(base_url: str, path: str = "") -> str:
    """Join a configured dashboard base URL with a view path.

    Returns "" when no base URL is configured, which every caller treats as
    "omit the link" -- NEMOS binds to loopback by default, so a link is only
    useful where the operator has told us the sensor is reachable.
    """
    base = str(base_url or "").strip().rstrip("/")
    if not base:
        return ""
    return f"{base}/{path.lstrip('/')}" if path else base


def render_alert(alert: Mapping[str, Any], *, detail: str = "",
                 dashboard_url: str = "") -> str:
    """Render one finding as a structured incident report.

    Only fields the finding actually carries are printed. There is no
    placeholder row for a value NEMOS does not have: an empty "Destination:"
    line invites the reader to believe NEMOS looked and found nothing, when in
    truth this detection never had a single destination to report.
    """
    severity = _clean(alert.get("severity") or "UNKNOWN", 16).upper()
    level = detail or detail_for(severity)
    icon = SEVERITY_ICON.get(severity, "\U0001f535")
    evidence = _as_dict(alert.get("evidence"))

    threat = _clean(alert.get("threat") or "DETECTION", 64)
    source = _clean(alert.get("source") or "unknown", 64)
    risk = _int(alert.get("risk_score"))
    confidence = _int(alert.get("confidence"))

    if level == "short":
        # One line plus provenance. Enough to decide whether to look.
        parts = [
            f"{icon} NEMOS {severity}: {threat}",
            f"Source: {source}   Risk: {risk}/100   Confidence: {confidence}%",
        ]
        incident = _clean(alert.get("incident_id"), 40)
        if incident:
            parts.append(f"Incident: {incident}")
        return _truncate("\n".join(parts))

    lines = [f"{icon} NEMOS SECURITY INCIDENT", RULE, "", f"Severity: {severity}", ""]
    lines += ["Detection:", threat, ""]
    if _clean(alert.get("category")):
        lines += [f"Category: {_clean(alert.get('category'), 48)}", ""]
    lines += [f"Confidence: {confidence}%", f"Risk score: {risk}/100", ""]
    lines += ["Source:", source, ""]

    destination = _clean(alert.get("destination") or evidence.get("target")
                         or evidence.get("destination"), 64)
    if destination:
        lines += ["Target:", destination, ""]

    endpoints = []
    for field, label in (("source_port", "src port"), ("destination_port", "dst port"),
                         ("protocol", "protocol")):
        value = alert.get(field) if alert.get(field) not in (None, "") else evidence.get(field)
        if value not in (None, ""):
            endpoints.append(f"{label} {_clean(value, 24)}")
    if endpoints:
        lines += ["Endpoint: " + "  ".join(endpoints), ""]

    reason = _clean(alert.get("reason"), 240)
    if reason:
        lines += ["Why this fired:", reason, ""]

    if level in ("detailed", "full"):
        counters = []
        for field, singular, plural in (
            ("packets", "packet", "packets"),
            ("destinations", "unique destination", "unique destinations"),
            ("ports", "unique port", "unique ports"),
            ("ports_scanned", "port scanned", "ports scanned"),
            ("window_seconds", "second observation window",
             "second observation window"),
        ):
            value = _int(alert.get(field), 0)
            if value:
                counters.append(f"• {value} {singular if value == 1 else plural}")
        if counters:
            lines += ["Observed:", *counters, ""]

    if level in ("summary", "detailed", "full"):
        budget = 4 if level == "summary" else EVIDENCE_MAX_LINES
        bullets = summarize_evidence(evidence, budget)
        if bullets:
            lines += ["Evidence:", *bullets, ""]

    technique = _clean(alert.get("technique"), 24)
    if technique:
        name = _clean((alert.get("attack") or {}).get("name")
                      if isinstance(alert.get("attack"), Mapping) else
                      alert.get("technique_name"), 60)
        tactic = _clean((alert.get("attack") or {}).get("tactic")
                        if isinstance(alert.get("attack"), Mapping) else
                        alert.get("tactic"), 48)
        lines += ["ATT&CK:", f"{technique}" + (f" — {name}" if name else "")]
        if tactic and level in ("detailed", "full"):
            lines += [f"Tactic: {tactic}"]
        lines += [""]

    if level == "full":
        correlated = alert.get("correlated") or alert.get("correlated_events")
        if isinstance(correlated, (list, tuple)) and correlated:
            lines += ["Correlated events:",
                      *[f"• {_clean(item, 72)}" for item in list(correlated)[:8]], ""]

    incident = _clean(alert.get("incident_id"), 40)
    if incident:
        lines += [f"Incident: {incident}"]
    status = _clean(alert.get("status") or
                    ("acknowledged" if alert.get("acknowledged") else ""), 32)
    if status:
        lines += [f"Status: {status}"]
    timestamp = _clean(alert.get("timestamp"), 40)
    if timestamp:
        lines += [f"Observed at: {timestamp}"]

    link = dashboard_link(dashboard_url, f"#incident/{incident}" if incident else "")
    if link:
        lines += ["", link]

    return _truncate("\n".join(lines).strip())


def alert_keyboard(alert: Mapping[str, Any], *, dashboard_url: str = "",
                   allow_contain: bool = False) -> dict[str, Any] | None:
    """Inline buttons for one finding, or None when there is nothing to offer.

    Callback payloads carry only an action verb and an id NEMOS itself minted.
    Nothing in a callback selects a chat, a credential or a file path, so a
    forged callback can at worst act on an incident the sender is already
    authorised to see -- and authorisation is re-checked when it arrives.
    """
    incident = _clean(alert.get("incident_id"), 40)
    alert_id = alert.get("id")
    row: list[dict[str, str]] = []
    if incident:
        row.append({"text": "Investigate", "callback_data": f"inv:{incident}"[:64]})
    if alert_id is not None:
        row.append({"text": "Acknowledge", "callback_data": f"ack:{_int(alert_id)}"[:64]})
    elif incident:
        row.append({"text": "Acknowledge", "callback_data": f"acki:{incident}"[:64]})

    rows: list[list[dict[str, str]]] = []
    if row:
        rows.append(row)
    if allow_contain and incident:
        rows.append([{"text": "Contain", "callback_data": f"con:{incident}"[:64]}])
    link = dashboard_link(dashboard_url, f"#incident/{incident}" if incident else "")
    # Telegram only accepts an https URL button, so a loopback dashboard URL
    # cannot become one -- it is already in the message body as text.
    if link.startswith("https://"):
        rows.append([{"text": "Open Dashboard", "url": link}])
    return {"inline_keyboard": rows} if rows else None


def _truncate(text: str, limit: int = TELEGRAM_MAX_MESSAGE) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


# -- command responses -------------------------------------------------------


def render_status(state: Mapping[str, Any]) -> str:
    """The ``/status`` reply.

    Reports the states NEMOS actually tracks. A component NEMOS cannot observe
    is printed as unknown rather than as healthy.
    """
    def row(label: str, value: Any, tone: str = "ok") -> str:
        return f"{STATE_ICON.get(tone, STATE_ICON['idle'])} {label}: {value}"

    capture = str(state.get("capture") or "UNKNOWN").upper()
    capture_tone = "ok" if capture == "ONLINE" else "warn" if capture in {"NO TRAFFIC", "STARTING"} else "bad"
    ml = str(state.get("ml") or "UNAVAILABLE").upper()
    ml_tone = "ok" if ml == "AVAILABLE" else "warn" if ml in {"FALLBACK", "LEARNING"} else "bad"
    database = str(state.get("database") or "UNKNOWN").upper()
    telegram = str(state.get("telegram") or "DISCONNECTED").upper()
    detection = str(state.get("detection") or "UNKNOWN").upper()

    lines = [
        "\U0001f6f0️ NEMOS STATUS",
        RULE,
        "",
        row("Capture", capture, capture_tone),
        row("Detection", detection, "ok" if detection == "ONLINE" else "bad"),
        row("ML", ml, ml_tone),
        row("Database", database, "ok" if database == "ONLINE" else "bad"),
        row("Telegram", telegram, "ok" if telegram == "CONNECTED" else "warn"),
        "",
    ]
    interface = _clean(state.get("interface"), 32)
    if interface:
        lines.append(f"Interface: {interface}")
    for label, key in (("Packets", "packets"), ("Flows", "flows"),
                       ("Hosts observed", "hosts"), ("Active incidents", "incidents"),
                       ("Unacknowledged", "unacknowledged")):
        if state.get(key) is not None:
            lines.append(f"{label}: {_int(state.get(key)):,}")
    baseline = _clean(state.get("baseline"), 24)
    if baseline:
        lines.append(f"Baseline: {baseline.upper()}")
    uptime = state.get("uptime_seconds")
    if uptime is not None:
        lines.append(f"Uptime: {_duration(float(uptime))}")
    note = _clean(state.get("note"), 160)
    if note:
        lines += ["", note]
    return _truncate("\n".join(lines))


def _duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def render_incident_list(rows: Iterable[Mapping[str, Any]], *, title: str = "OPEN INCIDENTS",
                         empty: str = "No incidents recorded.",
                         dashboard_url: str = "") -> str:
    items = list(rows)
    if not items:
        return f"{title}\n{RULE}\n\n{empty}"
    lines = [f"\U0001f4cb {title}", RULE, ""]
    for item in items:
        severity = _clean(item.get("severity"), 16).upper()
        icon = SEVERITY_ICON.get(severity, "\U0001f535")
        incident = _clean(item.get("incident_id"), 40)
        threats = item.get("threats")
        if isinstance(threats, (list, tuple)):
            label = ", ".join(_clean(t, 28) for t in list(threats)[:3])
        else:
            label = _clean(threats, 72)
        lines.append(f"{icon} {incident}  risk {_int(item.get('risk_score'))}/100")
        if label:
            lines.append(f"   {label}")
        sources = item.get("sources")
        if isinstance(sources, (list, tuple)) and sources:
            more = f" +{len(sources) - 2}" if len(sources) > 2 else ""
            lines.append(f"   from {', '.join(_clean(s, 40) for s in list(sources)[:2])}{more}")
        last_seen = _clean(item.get("last_seen") or item.get("timestamp"), 32)
        if last_seen:
            lines.append(f"   last seen {last_seen}")
        lines.append("")
    link = dashboard_link(dashboard_url)
    if link:
        lines.append(link)
    return _truncate("\n".join(lines).strip())


def render_hosts(rows: Iterable[Mapping[str, Any]]) -> str:
    items = list(rows)
    if not items:
        return f"HOSTS\n{RULE}\n\nNo hosts observed yet."
    lines = ["\U0001f5a5️ HOSTS BY RISK", RULE, ""]
    for item in items:
        host = _clean(item.get("host"), 46)
        risk = _int(item.get("risk_score"))
        icon = "\U0001f6a8" if risk >= 90 else "⚠️" if risk >= 75 else "\U0001f7e1" if risk >= 50 else "\U0001f535"
        lines.append(f"{icon} {host}  risk {risk}/100")
        detail = [f"{_int(item.get('packets')):,} packets"]
        if _int(item.get("alert_count")):
            detail.append(f"{_int(item.get('alert_count'))} detections")
        if _int(item.get("critical_count")):
            detail.append(f"{_int(item.get('critical_count'))} critical")
        baseline = _clean(item.get("baseline") or item.get("baseline_state"), 16)
        if baseline:
            detail.append(f"baseline {baseline.upper()}")
        lines.append("   " + ", ".join(detail))
    return _truncate("\n".join(lines))


def render_incident(summary: Mapping[str, Any], alerts: Iterable[Mapping[str, Any]],
                    *, dashboard_url: str = "") -> str:
    """The ``/incident <id>`` reply: the incident plus its evidence timeline."""
    rows = list(alerts)
    incident = _clean(summary.get("incident_id"), 40)
    severity = _clean(summary.get("severity"), 16).upper()
    icon = SEVERITY_ICON.get(severity, "\U0001f535")
    lines = [
        f"{icon} INCIDENT {incident}",
        RULE,
        "",
        f"Severity: {severity}",
        f"Risk score: {_int(summary.get('risk_score'))}/100",
        f"Confidence: {_int(summary.get('confidence'))}%",
        f"Detections: {_int(summary.get('alert_count'))}"
        f" ({_int(summary.get('unique_threats'))} distinct)",
        "",
    ]
    sources = summary.get("sources")
    if isinstance(sources, (list, tuple)) and sources:
        lines += ["Sources:", *[f"• {_clean(s, 46)}" for s in list(sources)[:6]], ""]
    techniques = summary.get("techniques")
    if isinstance(techniques, (list, tuple)) and techniques:
        lines += ["ATT&CK:", *[f"• {_clean(t, 32)}" for t in list(techniques)[:8]], ""]

    if rows:
        lines.append("Evidence timeline:")
        for row in rows[:8]:
            stamp = _clean(row.get("timestamp"), 32)
            lines.append(f"• {stamp}  {_clean(row.get('threat'), 40)}"
                         f"  ({_clean(row.get('severity'), 10)})")
            reason = _clean(row.get("reason"), 90)
            if reason:
                lines.append(f"    {reason}")
        if len(rows) > 8:
            lines.append(f"• ... {len(rows) - 8} earlier detections")
        lines.append("")

    recommendations = summary.get("recommendations")
    if isinstance(recommendations, (list, tuple)) and recommendations:
        lines += ["Recommended next steps:",
                  *[f"• {_clean(r, 100)}" for r in list(recommendations)[:4]], ""]

    link = dashboard_link(dashboard_url, f"#incident/{incident}")
    if link:
        lines.append(link)
    return _truncate("\n".join(lines).strip())


def render_brief(data: Mapping[str, Any], *, dashboard_url: str = "") -> str:
    """The scheduled security brief.

    Only metrics present in ``data`` are printed. A section with nothing behind
    it is omitted rather than shown as zero, because a zero here would be a
    claim NEMOS has not earned -- "no incidents" and "not measured" are
    different statements.
    """
    lines = ["\U0001f4ca NEMOS SECURITY BRIEF", RULE, ""]
    period = _clean(data.get("period"), 64)
    if period:
        lines += [period, ""]

    volume = []
    for label, key in (("Packets", "packets"), ("Flows", "flows"),
                       ("Hosts observed", "hosts")):
        if data.get(key) is not None:
            volume.append(f"• {label}: {_int(data.get(key)):,}")
    if volume:
        lines += ["Traffic:", *volume, ""]

    severities = data.get("severity_counts")
    if isinstance(severities, Mapping) and severities:
        lines.append("Incidents by severity:")
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if severity in severities:
                icon = SEVERITY_ICON.get(severity, "")
                lines.append(f"{icon} {severity}: {_int(severities[severity])}")
        lines.append("")

    top = data.get("top_detections")
    if isinstance(top, (list, tuple)) and top:
        lines.append("Top detections:")
        for item in list(top)[:5]:
            lines.append(f"• {_clean(item.get('threat'), 40)}: {_int(item.get('count'))}")
        lines.append("")

    hosts = data.get("top_hosts")
    if isinstance(hosts, (list, tuple)) and hosts:
        lines.append("Most affected hosts:")
        for item in list(hosts)[:5]:
            lines.append(f"• {_clean(item.get('host'), 46)}: "
                         f"risk {_int(item.get('risk_score'))}/100, "
                         f"{_int(item.get('alert_count'))} detections")
        lines.append("")

    if data.get("highest_risk") is not None:
        lines += [f"Highest risk score: {_int(data.get('highest_risk'))}/100", ""]

    deviations = data.get("deviations")
    if isinstance(deviations, (list, tuple)) and deviations:
        lines += ["Behavioural deviations:",
                  *[f"• {_clean(d, 100)}" for d in list(deviations)[:5]], ""]

    unresolved = data.get("unresolved")
    if unresolved is not None:
        lines += [f"Unresolved incidents: {_int(unresolved)}", ""]

    investigate = data.get("recommended")
    if isinstance(investigate, (list, tuple)) and investigate:
        lines += ["Recommended investigations:",
                  *[f"• {_clean(item, 100)}" for item in list(investigate)[:5]], ""]

    if len(lines) <= 3:
        lines.append("No measurable activity in this period.")

    link = dashboard_link(dashboard_url)
    if link:
        lines += ["", link]
    return _truncate("\n".join(lines).strip())


TEST_NOTIFICATION = (
    "✅ NEMOS Telegram Integration\n"
    f"{RULE}\n\n"
    "Your Telegram account is successfully connected.\n\n"
    "Security notifications are enabled."
)

PAIRED_NOTIFICATION = (
    "✅ NEMOS pairing complete\n"
    f"{RULE}\n\n"
    "This chat is now linked to a NEMOS sensor and will receive security "
    "notifications.\n\n"
    "Commands: /status /incidents /critical /hosts /incident <id> /help"
)

HELP_TEXT = (
    "NEMOS commands\n"
    f"{RULE}\n\n"
    "/status — sensor, detection, ML, database and delivery health\n"
    "/incidents — the most recent incidents by risk\n"
    "/critical — critical findings only\n"
    "/hosts — observed hosts ranked by risk\n"
    "/incident <id> — one incident with its evidence timeline\n"
    "/brief — the security summary on demand\n"
    "/help — this message"
)

UNAUTHORIZED_TEXT = (
    "This chat is not linked to a NEMOS sensor.\n\n"
    "Open the NEMOS dashboard, generate a pairing QR code, and scan it."
)


__all__ = [
    "DETAIL_BY_SEVERITY",
    "EVIDENCE_LIST_PREVIEW",
    "EVIDENCE_MAX_LINES",
    "HELP_TEXT",
    "PAIRED_NOTIFICATION",
    "RULE",
    "SEVERITY_ICON",
    "TELEGRAM_MAX_MESSAGE",
    "TEST_NOTIFICATION",
    "UNAUTHORIZED_TEXT",
    "alert_keyboard",
    "dashboard_link",
    "detail_for",
    "render_alert",
    "render_brief",
    "render_hosts",
    "render_incident",
    "render_incident_list",
    "render_status",
    "summarize_evidence",
]
