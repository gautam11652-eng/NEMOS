/* NEMOS operations console.
 *
 * No framework and no build step: the sensor serves two static files and a
 * JSON API, and a dashboard that needs a toolchain to render is a dashboard an
 * operator cannot debug at 3am.
 *
 * Structure: fetch -> normalise -> render pure functions -> paint. Every render
 * takes the state it needs as an argument so nothing reaches into the DOM to
 * discover what it should draw.
 */
"use strict";

const $ = (id) => document.getElementById(id);

/* ── State ──────────────────────────────────────────────────────────── */

const state = {
  view: "overview",
  live: true,
  data: null,
  alerts: [],          // detections with evidence, from /api/alerts
  analysis: null,
  notify: null,
  detFilter: { text: "", severity: "ALL" },
  detPage: 0,
  hostFilter: "",
  hostPage: 0,
  paletteIndex: 0,
  expanded: new Set(),   // detection groups the operator has opened
};

const PAGE = 25;
const VIEWS = ["overview", "incidents", "detections", "hosts", "attack", "sensor"];

const TITLES = {
  overview:   ["Overview", "Live security posture"],
  incidents:  ["Incidents", "Correlated findings by source"],
  detections: ["Detections", "Every finding and its evidence"],
  hosts:      ["Hosts", "Per-source risk rollup"],
  attack:     ["ATT&CK", "Technique coverage and what has been observed"],
  sensor:     ["Sensor", "Capture, storage, model and delivery"],
};

/* The order intrusions actually progress in. Findings are placed on the
 * tactic their technique evidences, so the chain shows how far an actor has
 * got rather than merely how many alerts fired. */
const CHAIN = [
  { key: "Reconnaissance",    label: "Reconnaissance",    match: /reconnaissance/i },
  { key: "Discovery",         label: "Discovery",        match: /discovery/i },
  { key: "Credential Access", label: "Credential Access", match: /credential/i },
  { key: "Lateral Movement",  label: "Lateral Movement",  match: /lateral/i },
  { key: "Command and Control", label: "Command & Control", match: /command/i },
  { key: "Exfiltration",      label: "Exfiltration",      match: /exfil/i },
  { key: "Impact",            label: "Impact",            match: /impact/i },
];

const SEV_CLASS = { CRITICAL: "sev-crit", HIGH: "sev-high", MEDIUM: "sev-med", LOW: "sev-low" };

/* ── Utilities ──────────────────────────────────────────────────────── */

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
));

const num = (v) => (Number(v) || 0).toLocaleString();

function clock(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return isNaN(d) ? String(ts).slice(11, 19) : d.toLocaleTimeString();
}

function ago(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d)) return String(ts);
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return d.toLocaleDateString();
}

function bytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  if (v < 1048576) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1073741824) return `${(v / 1048576).toFixed(1)} MB`;
  return `${(v / 1073741824).toFixed(2)} GB`;
}

/* Reasons come from the backend as fragments; give them terminal punctuation
   so they read as sentences next to the guidance that follows. */
const sentence = (v) => {
  const text = String(v ?? "").trim();
  if (!text) return "";
  return /[.!?]$/.test(text) ? text : `${text}.`;
};

const sevClass = (s) => SEV_CLASS[String(s || "").toUpperCase()] || "sev-low";

/* Threat labels are identifiers -- C2_BEACONING, SYN_FLOOD_PATTERN -- and they
 * are also the values that appear in the API, in Telegram and in syslog. Show
 * a readable form, keep the identifier available on hover and in the evidence
 * drawer so an operator can still grep for exactly what the sensor emitted. */
const ACRONYMS = new Set(["c2", "dns", "icmp", "tcp", "udp", "syn", "arp", "ndp", "ip"]);
/* Capture states are machine tokens; the card needs a word, not the token. */
const CAPTURE_LABEL = {
  running: "Live", starting: "Starting", stopped: "Stopped", failed: "Failed",
  permission_denied: "Blocked", unavailable: "Unavailable",
  not_configured: "Off", error: "Failed",
};
const captureLabel = (c) => (c?.running ? "Live"
  : CAPTURE_LABEL[String(c?.state || "").toLowerCase()] || "Off");

const threatLabel = (v) => String(v ?? "").split("_").filter(Boolean).map((word, i) => {
  const lower = word.toLowerCase();
  if (ACRONYMS.has(lower)) return word.toUpperCase();
  return i === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
}).join(" ");

/* ML lifecycle states, as nemos/bootstrap.py reports them. The console shows
 * the word, never the token, and never claims more than the state means:
 * ACTIVE is only ever set after a real Isolation Forest was fitted, validated
 * and loaded. */
const ML_LABEL = {
  NO_MODEL: "Unavailable", WARMING_UP: "Warming up", TRAINING: "Training",
  VALIDATING: "Validating", ACTIVE: "Active", RETRAINING: "Retraining",
  FAILED: "Failed",
};
const ML_TONE = {
  ACTIVE: "ok", RETRAINING: "ok", FAILED: "bad", NO_MODEL: "warn",
};

/* mm:ss for an observation period. Hours appear once there are any. */
function duration(seconds) {
  const total = Math.max(0, Math.round(Number(seconds) || 0));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n) => String(n).padStart(2, "0");
  return h ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

function emptyState(mark, title, body) {
  return `<div class="empty"><span class="empty-mark" aria-hidden="true">${mark}</span>
          <b>${esc(title)}</b><p>${body}</p></div>`;
}

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 2600);
}

/* ── Token handling ─────────────────────────────────────────────────── */

const tokenKey = "nemos.token";
const getToken = () => { try { return localStorage.getItem(tokenKey) || ""; } catch { return ""; } };
const setToken = (v) => { try { v ? localStorage.setItem(tokenKey, v) : localStorage.removeItem(tokenKey); } catch { /* private mode */ } };

async function api(path) {
  const headers = {};
  const token = getToken();
  // X-NEMOS-Token is the header the API documents and checks. Sending only
  // Authorization: Bearer meant the dashboard could never authenticate against
  // a token-protected sensor.
  if (token) headers["X-NEMOS-Token"] = token;
  const response = await fetch(path, { headers, cache: "no-store" });
  if (response.status === 401) { $("authbar").hidden = false; throw new Error("unauthorized"); }
  // A disabled subsystem answers 503. That is a state to render, not a failure
  // to report: the sensor is working exactly as configured.
  if (response.status === 503) return { unavailable: true };
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/* ── Rendering: overview ────────────────────────────────────────────── */

function renderChain(alerts) {
  const worst = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const buckets = CHAIN.map((stage) => {
    const hits = alerts.filter((a) => stage.match.test(a.attack?.tactic || ""));
    let top = "";
    for (const a of hits) {
      if ((worst[a.severity] || 0) > (worst[top] || 0)) top = a.severity;
    }
    return { stage, count: hits.length, severity: top };
  });

  $("chain").innerHTML = buckets.map((b, i) => `
    <li class="stage ${b.count ? `hit ${sevClass(b.severity)}` : ""}">
      <span class="stage-n">STAGE ${i + 1}</span>
      <b>${esc(b.stage.label)}</b>
      <span class="stage-c">${b.count}</span>
      <span class="stage-t">${b.count ? `${esc(b.severity || "")} observed` : "not observed"}</span>
    </li>`).join("");

  const reached = buckets.filter((b) => b.count).length;
  const deepest = [...buckets].reverse().find((b) => b.count);
  const verdict = $("chain-verdict");
  if (!reached) {
    verdict.textContent = "No activity";
  } else {
    verdict.textContent = `${reached}/${CHAIN.length} stages · deepest: ${deepest.stage.label}`;
  }
}

/* ── Grouping ───────────────────────────────────────────────────────────
 * Forty hosts beaconing to one address is one campaign, not forty findings.
 * Listed individually it fills the first three pages and pushes the single
 * CRITICAL flood out of sight, which is how a console trains its operator to
 * stop reading it. Identical findings are therefore collapsed into one row
 * carrying the count and the sources behind it; nothing is discarded, and
 * expanding a group shows every constituent.
 */
function groupKey(a) {
  // Same detection, same severity, same technique -- the source is what
  // varies across a campaign, so it is deliberately not part of the key.
  return `${a.threat} ${a.severity} ${a.technique || ""} ${a.risk_score}`;
}

function groupFindings(alerts) {
  const groups = new Map();
  for (const a of alerts) {
    const key = groupKey(a);
    let g = groups.get(key);
    if (!g) {
      g = {
        key, threat: a.threat, severity: a.severity, technique: a.technique,
        risk_score: a.risk_score, confidence: a.confidence, reason: a.reason,
        category: a.category, members: [], sources: new Set(),
        latest: a.timestamp, id: a.id,
      };
      groups.set(key, g);
    }
    g.members.push(a);
    g.sources.add(a.source);
    if (String(a.timestamp) > String(g.latest)) g.latest = a.timestamp;
  }
  return [...groups.values()].sort(
    (x, y) => (Number(y.risk_score) || 0) - (Number(x.risk_score) || 0)
      || y.members.length - x.members.length,
  );
}

const SEV_RANK = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };

function byTriage(a, b) {
  return (SEV_RANK[b.severity] ?? -1) - (SEV_RANK[a.severity] ?? -1)
    || (Number(b.risk_score ?? b.max_risk) || 0) - (Number(a.risk_score ?? a.max_risk) || 0)
    || String(b.timestamp ?? b.last_seen ?? "").localeCompare(String(a.timestamp ?? a.last_seen ?? ""));
}

/* Summarise a set of sources without letting it overrun its column. */
function sourceSummary(sources) {
  const list = [...sources];
  if (list.length === 1) return esc(list[0]);
  return `${esc(list[0])} <span class="more">+${list.length - 1} more</span>`;
}

function renderKpis(stats, capture) {
  // Triage metrics, not traffic volume. Packet counts say how busy the wire
  // is; they never say what an operator should look at next, and they were
  // occupying the most valuable strip of the screen to say it.
  const alerts = state.alerts || [];
  const open = alerts.filter((a) => !a.acknowledged);
  const critical = open.filter((a) => a.severity === "CRITICAL");
  const high = open.filter((a) => a.severity === "HIGH");
  const sources = new Set(open.map((a) => a.source));
  const techniques = new Set(open.map((a) => a.technique).filter(Boolean));
  const health = state.status?.analysis?.model?.health || {};
  const modelNote = health.drifted ? "drifted — retrain"
    : health.stale ? "stale — retrain"
    : health.score_inflated ? "calibration suspect"
    : state.status?.analysis?.model?.available ? "model healthy" : "no model";

  const cards = [
    { k: "Critical open", v: num(critical.length), s: critical.length ? "act now" : "nothing critical",
      alarm: critical.length > 0 },
    { k: "High open", v: num(high.length), s: high.length ? "review today" : "clear" },
    { k: "Sources", v: num(sources.size), s: "distinct hosts with findings" },
    { k: "Techniques", v: num(techniques.size), s: "distinct ATT&CK IDs" },
    { k: "Capture", v: captureLabel(capture),
      s: capture?.interface && capture.interface !== "default"
        ? capture.interface : (capture?.state || "").replace(/_/g, " ") || "no interface",
      alarm: Boolean(capture?.error) || capture?.state === "failed" },
    { k: "Packets", v: num(stats.packets), s: modelNote },
  ];
  $("kpis").innerHTML = cards.map((c) => `
    <article class="kpi ${c.alarm ? "alarm" : ""}">
      <div class="kpi-k">${esc(c.k)}</div>
      <div class="kpi-v">${esc(c.v)}</div>
      <div class="kpi-s">${esc(c.s)}</div>
    </article>`).join("");
}

const pct = (part, total) => (Number(total) ? `${((Number(part) / Number(total)) * 100).toFixed(1)}% of traffic` : "no traffic yet");

function renderPosture(alerts) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  let peak = 0;
  for (const a of alerts) {
    if (counts[a.severity] !== undefined) counts[a.severity] += 1;
    peak = Math.max(peak, Number(a.risk_score) || 0);
  }

  const ring = $("posture-ring");
  ring.style.setProperty("--pct", peak);
  const band = peak >= 90 ? "CRITICAL" : peak >= 75 ? "HIGH" : peak >= 50 ? "MEDIUM" : peak > 0 ? "LOW" : "";
  ring.style.setProperty("--sev", band ? `var(--${band === "CRITICAL" ? "crit" : band === "HIGH" ? "high" : band === "MEDIUM" ? "med" : "low"})` : "var(--ok)");

  $("posture-score").textContent = peak;
  $("posture-label").textContent = peak >= 90 ? "Critical" : peak >= 75 ? "Elevated"
    : peak >= 50 ? "Guarded" : peak > 0 ? "Low" : "Nominal";
  $("posture-note").textContent = peak
    ? "Highest risk score among recorded findings. A risk score is not a probability of compromise."
    : "No findings recorded.";

  const max = Math.max(1, ...Object.values(counts));
  $("sev-list").innerHTML = Object.entries(counts).map(([sev, n]) => `
    <li class="${sevClass(sev)}">
      <span class="lbl">${esc(sev[0] + sev.slice(1).toLowerCase())}</span>
      <span class="bar"><i></i></span>
      <span class="n">${n}</span>
    </li>`).join("");
  // Widths are set as custom properties rather than inline style attributes.
  [...$("sev-list").children].forEach((li, i) => {
    li.querySelector(".bar i").style.setProperty("--pct", (Object.values(counts)[i] / max) * 100);
  });
}

function feedRows(alerts, limit) {
  if (!alerts.length) {
    return emptyState("◌", "No detections yet",
      "The sensor is running and nothing has crossed a threshold. That is the expected state on a quiet network.");
  }
  // Grouped for the same reason the tables are: eight repetitions of one
  // campaign is not a summary of what is happening on the network.
  return `<div class="feed">${groupFindings(alerts).slice(0, limit).map((g) => {
    const a = g.members[0];
    const spread = g.members.length > 1
      ? `<span class="count">${g.members.length} findings · ${g.sources.size} sources</span>`
      : "";
    return `
    <div class="feed-row row ${sevClass(g.severity)}" data-alert="${esc(a.id)}" tabindex="0" role="button">
      <span class="feed-t">${esc(clock(g.latest))}</span>
      <span class="feed-main">
        <b title="${esc(g.threat)}">${esc(threatLabel(g.threat))}</b>${spread}
        <span>${g.members.length > 1
          ? `${esc([...g.sources][0])} and ${g.sources.size - 1} other host(s)`
          : esc(a.source)} · ${esc(a.reason)}</span>
      </span>
      <span class="score">${esc(g.risk_score)}</span>
    </div>`; }).join("")}</div>`;
}

/* ── Rendering: tables ──────────────────────────────────────────────── */

function renderIncidents(incidents) {
  $("inc-count").textContent = `${incidents.length} open`;
  $("nav-incidents").textContent = incidents.length || "";
  const body = $("inc-body");
  const empty = $("inc-empty");
  if (!incidents.length) {
    body.innerHTML = "";
    empty.innerHTML = emptyState("◇", "No incidents",
      "An incident groups findings from one source inside the correlation window. None have formed.");
    return;
  }
  empty.innerHTML = "";
  // Incidents correlate per source, which is correct: one host's findings
  // belong together. But forty hosts each beaconing to the same address
  // produce forty single-alert incidents, and listed individually they bury
  // the two that matter. Incidents sharing one threat signature are collapsed
  // into a campaign row; anything multi-threat stays on its own line, because
  // that is precisely the incident an operator must not miss.
  const campaigns = new Map();
  const singular = [];
  for (const i of incidents) {
    const threats = String(i.threats || "").split(",").filter(Boolean);
    if (threats.length !== 1 || Number(i.alert_count) > 1) { singular.push(i); continue; }
    const key = `${threats[0]}|${i.severity}|${i.max_risk}`;
    const group = campaigns.get(key);
    if (group) {
      group.alert_count += Number(i.alert_count) || 0;
      group.members.push(i);
      if (String(i.last_seen) > String(group.last_seen)) group.last_seen = i.last_seen;
    } else {
      campaigns.set(key, { ...i, alert_count: Number(i.alert_count) || 0, members: [i] });
    }
  }
  const rows = [...singular, ...campaigns.values()].sort(byTriage);
  body.innerHTML = rows.map((i) => {
    if (i.members && i.members.length > 1) {
      const sources = i.members.map((m) => String(m.sources || "").split(",")[0]).filter(Boolean);
      const threat = String(i.threats || "").split(",")[0] || "";
      return `
    <tr class="row campaign ${sevClass(i.severity)}" data-incident="${esc(i.incident_id)}">
      <td class="mono nowrap">${esc(sources[0])} <span class="more">+${sources.length - 1} hosts</span></td>
      <td class="cell-threat">
        <span class="tag" title="${esc(threat)}">${esc(threatLabel(threat))}</span>
        <span class="count">${i.members.length} hosts</span>
      </td>
      <td class="num">${num(i.alert_count)}</td>
      <td class="num score">${esc(i.max_risk)}</td>
      <td><span class="sev">${esc(i.severity)}</span></td>
      <td class="dim nowrap">${esc(ago(i.last_seen))}</td>
    </tr>`;
    }
    return renderIncidentRow(i);
  }).join("");
}

function renderIncidentRow(i) {
  {
    // A raw comma-joined list of SCREAMING_SNAKE labels was overrunning its
    // column and painting over the risk and severity beside it -- and it did
    // that worst on the multi-stage incidents, which are the ones that matter
    // most. Show the leading techniques and count the rest.
    const threats = String(i.threats || "").split(",").filter(Boolean);
    const shown = threats.slice(0, 2).map((t) => `<span class="tag" title="${esc(t)}">${esc(threatLabel(t))}</span>`).join("");
    const extra = threats.length > 2 ? `<span class="more">+${threats.length - 2} more</span>` : "";
    const sources = String(i.sources || "").split(",").filter(Boolean);
    return `
    <tr class="row ${sevClass(i.severity)}${threats.length > 2 ? " multistage" : ""}"
        data-incident="${esc(i.incident_id)}" title="Incident ${esc(i.incident_id)}">
      <td class="mono nowrap">${sources.length > 1
        ? `${esc(sources[0])} <span class="more">+${sources.length - 1}</span>`
        : esc(sources[0] || "—")}</td>
      <td class="cell-threat">${shown}${extra}</td>
      <td class="num">${num(i.alert_count)}</td>
      <td class="num score">${esc(i.max_risk)}</td>
      <td><span class="sev">${esc(i.severity)}</span></td>
      <td class="dim nowrap">${esc(ago(i.last_seen))}</td>
    </tr>`;
  }
}

function filteredDetections() {
  const { text, severity } = state.detFilter;
  const needle = text.trim().toLowerCase();
  return state.alerts.filter((a) => {
    if (severity !== "ALL" && a.severity !== severity) return false;
    if (!needle) return true;
    return `${a.threat} ${a.source} ${a.reason} ${a.technique}`.toLowerCase().includes(needle);
  });
}

function renderDetections() {
  const matched = filteredDetections();
  // Group first, then paginate the groups. Paginating raw findings and
  // grouping only the visible page would still hand the operator a first
  // page made entirely of one repeated campaign.
  const rows = groupFindings(matched);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  state.detPage = Math.min(state.detPage, pages - 1);
  const page = rows.slice(state.detPage * PAGE, state.detPage * PAGE + PAGE);

  $("det-count").textContent = rows.length === matched.length
    ? `${matched.length} of ${state.alerts.length}`
    : `${rows.length} groups · ${matched.length} of ${state.alerts.length} findings`;
  $("nav-detections").textContent = state.alerts.length || "";

  const body = $("det-body");
  const empty = $("det-empty");
  if (!rows.length) {
    body.innerHTML = "";
    empty.innerHTML = state.alerts.length
      ? emptyState("⌕", "No matches", "No finding matches this filter. Clear the search or pick another severity.")
      : emptyState("◌", "No detections yet",
          "Nothing has crossed a detection threshold. On a quiet network that is the correct result, not a failure.");
    $("det-pager").hidden = true;
    return;
  }
  empty.innerHTML = "";
  $("det-pager").hidden = pages <= 1;
  $("det-page").textContent = `Page ${state.detPage + 1} of ${pages}`;
  $("det-prev").disabled = state.detPage === 0;
  $("det-next").disabled = state.detPage >= pages - 1;

  body.innerHTML = page.map((g) => {
    if (g.members.length === 1) {
      const a = g.members[0];
      return `
    <tr class="row ${sevClass(a.severity)}" data-alert="${esc(a.id)}">
      <td class="dim mono nowrap">${esc(clock(a.timestamp))}</td>
      <td class="cell-threat"><b title="${esc(a.threat)}">${esc(threatLabel(a.threat))}</b><br><span class="dim">${esc(a.reason)}</span></td>
      <td class="mono nowrap">${esc(a.source)}</td>
      <td class="num score">${esc(a.risk_score)}</td>
      <td class="num dim">${esc(a.confidence)}%</td>
      <td class="mono dim nowrap">${esc(a.technique || "—")}</td>
      <td><span class="sev">${esc(a.severity)}</span></td>
    </tr>`;
    }
    const expanded = state.expanded.has(g.key);
    const head = `
    <tr class="row grouped ${sevClass(g.severity)}" data-group="${esc(g.key)}" tabindex="0" role="button"
        aria-expanded="${expanded}">
      <td class="dim mono nowrap">${esc(clock(g.latest))}</td>
      <td class="cell-threat">
        <b title="${esc(g.threat)}">${esc(threatLabel(g.threat))}</b>
        <span class="count">${g.members.length} findings · ${g.sources.size} sources</span>
        <br><span class="dim">${esc(g.reason)}</span>
      </td>
      <td class="mono nowrap">${sourceSummary(g.sources)}</td>
      <td class="num score">${esc(g.risk_score)}</td>
      <td class="num dim">${esc(g.confidence)}%</td>
      <td class="mono dim nowrap">${esc(g.technique || "—")}</td>
      <td><span class="sev">${esc(g.severity)}</span><span class="caret" aria-hidden="true">${expanded ? "▾" : "▸"}</span></td>
    </tr>`;
    if (!expanded) return head;
    return head + g.members.slice(0, 60).map((a) => `
    <tr class="row child ${sevClass(a.severity)}" data-alert="${esc(a.id)}">
      <td class="dim mono nowrap">${esc(clock(a.timestamp))}</td>
      <td class="cell-threat dim">${esc(a.reason)}</td>
      <td class="mono nowrap">${esc(a.source)}</td>
      <td class="num score">${esc(a.risk_score)}</td>
      <td class="num dim">${esc(a.confidence)}%</td>
      <td class="mono dim nowrap">${esc(a.technique || "—")}</td>
      <td></td>
    </tr>`).join("");
  }).join("");
}

function renderHosts(hosts) {
  const needle = state.hostFilter.trim().toLowerCase();
  const rows = hosts.filter((h) => !needle || String(h.host).toLowerCase().includes(needle));
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  state.hostPage = Math.min(state.hostPage, pages - 1);
  const page = rows.slice(state.hostPage * PAGE, state.hostPage * PAGE + PAGE);

  $("host-count").textContent = `${rows.length} hosts`;
  const body = $("host-body");
  const empty = $("host-empty");
  if (!rows.length) {
    body.innerHTML = "";
    empty.innerHTML = emptyState("▢", "No hosts", "No traffic has been attributed to a source address yet.");
    $("host-pager").hidden = true;
    return;
  }
  empty.innerHTML = "";
  $("host-pager").hidden = pages <= 1;
  $("host-page").textContent = `Page ${state.hostPage + 1} of ${pages}`;
  $("host-prev").disabled = state.hostPage === 0;
  $("host-next").disabled = state.hostPage >= pages - 1;

  body.innerHTML = page.map((h) => {
    const risk = Number(h.max_risk) || 0;
    const band = risk >= 90 ? "CRITICAL" : risk >= 75 ? "HIGH" : risk >= 50 ? "MEDIUM" : "LOW";
    return `<tr class="row ${sevClass(band)}" data-host="${esc(h.host)}">
      <td class="mono">${esc(h.host)}</td>
      <td class="num score">${risk || "—"}</td>
      <td class="num">${num(h.alert_count)}</td>
      <td class="num">${num(h.critical_count)}</td>
      <td class="num dim">${num(h.packets)}</td>
      <td class="dim">${esc(h.last_alert ? ago(h.last_alert) : "—")}</td>
    </tr>`;
  }).join("");
}

function renderAttack(alerts, catalog) {
  const seen = new Map();
  for (const a of alerts) {
    if (a.technique) seen.set(a.technique, (seen.get(a.technique) || 0) + 1);
  }
  const byTactic = new Map();
  for (const t of catalog) {
    const tactic = t.tactic || "Other";
    if (!byTactic.has(tactic)) byTactic.set(tactic, []);
    byTactic.get(tactic).push(t);
  }
  $("attack-count").textContent = `${seen.size} of ${catalog.length} observed`;
  $("attack-matrix").innerHTML = [...byTactic.entries()].map(([tactic, techs]) => `
    <div>
      <div class="tactic-h"><span>${esc(tactic)}</span><span>${techs.filter((t) => seen.has(t.technique_id)).length}/${techs.length}</span></div>
      ${techs.map((t) => `
        <article class="tech ${seen.has(t.technique_id) ? "seen" : ""}">
          ${seen.has(t.technique_id) ? `<span class="tech-badge">${seen.get(t.technique_id)}×</span>` : ""}
          <span class="tech-id">${esc(t.technique_id)}</span>
          <b>${esc(t.name)}</b>
          <p>${esc(t.description)}</p>
        </article>`).join("")}
    </div>`).join("");
}

/* ── Rendering: sensor ──────────────────────────────────────────────── */

const facts = (pairs) => pairs.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");

/* The three detection layers, and which of them is carrying the sensor right
 * now. NEMOS is deliberately not ML-dependent: rules and the statistical
 * baseline run whether or not a model exists, and saying so is the point of
 * this block -- "no model" must not read as "no detection". */
function layerList(analysis) {
  const state = analysis.bootstrap?.state || "NO_MODEL";
  const mlOn = Boolean(analysis.model?.available);
  const rows = [
    ["on", "Deterministic detection", "active"],
    ["on", "Behavioural baseline", analysis.enabled === false ? "inactive" : "active"],
    [mlOn ? "on" : "off", "ML anomaly detection",
     mlOn ? "active" : (ML_LABEL[state] || state).toLowerCase()],
  ];
  return `<ul class="layers">${rows.map(([cls, name, note]) => `
    <li class="${cls}"><span class="tick" aria-hidden="true">${cls === "on" ? "\u2713" : "\u25cb"}</span>
      <b>${esc(name)}</b><span>${esc(note)}</span></li>`).join("")}</ul>`;
}

function renderModel(analysis) {
  const model = $("sensor-model");
  const boot = analysis.bootstrap || {};
  const state = boot.state || "NO_MODEL";
  const meta = analysis.model?.metadata || {};
  $("ml-state").textContent = ML_LABEL[state] || state;
  $("ml-state").className = `chip ${ML_TONE[state] || ""}`;

  if (analysis.enabled === false) {
    model.innerHTML = `<div class="notice"><b>Windowed analysis is disabled</b>
      <p>${esc(sentence(analysis.reason) || "Not enabled.")} Set <code>NEMOS_ANALYSIS=true</code>
         to enable flow aggregation, feature extraction and model scoring.
         Deterministic rules are unaffected.</p></div>${layerList(analysis)}`;
    return;
  }

  if (analysis.model?.available) {
    // Only ever reached when a real forest was fitted, validated and loaded.
    model.innerHTML = `<dl class="facts">${facts([
      ["Status", ML_LABEL[state] || state],
      ["Algorithm", boot.algorithm || "Isolation Forest"],
      ["Model file", "anomaly_model.joblib"],
      ["Trained", meta.trained_at ? ago(meta.trained_at) : "—"],
      ["Training samples", num(meta.samples)],
      ["Window", `${analysis.window_seconds ?? "—"} seconds`],
      ["Schema version", analysis.model.schema_version ?? "—"],
      ["Windows scored", num(analysis.model.scored_windows)],
      ["Source", boot.auto_trained ? "trained automatically by this sensor" : "trained out of band"],
      ["scikit-learn", meta.sklearn_version || "—"],
    ])}</dl>${layerList(analysis)}`;
    return;
  }

  if (state === "NO_MODEL") {
    model.innerHTML = `<div class="notice warn"><b>Automatic training unavailable</b>
      <p>${esc(sentence(boot.reason) || sentence(analysis.model?.reason) || "No model is loaded.")}
         You can still train one by hand with
         <code>python tools/train_model.py --source database</code>.
         NEMOS ships no pretrained model on purpose: a model fitted on another
         network describes another network's normal.</p></div>${layerList(analysis)}`;
    return;
  }

  if (state === "FAILED") {
    model.innerHTML = `<div class="notice bad"><b>Training failed</b>
      <p>${esc(sentence(boot.last_error) || "The last training run did not complete.")}
         Collection continues and NEMOS will try again. Detection is unaffected.</p>
      </div>${layerList(analysis)}`;
    return;
  }

  // Warming up, training or validating: show the real progress, and nothing
  // the sensor has not actually measured.
  const need = Number(boot.samples_required) || 0;
  const have = Number(boot.samples) || 0;
  const needSeconds = Number(boot.observed_seconds_required) || 0;
  const seen = Number(boot.observed_seconds) || 0;
  model.innerHTML = `
    <dl class="facts">${facts([
      ["Status", ML_LABEL[state] || state],
      ["Training samples", `${num(have)} / ${num(need)}`],
      ["Observation period", needSeconds
        ? `${duration(seen)} / ${duration(needSeconds)}` : "not required"],
      ["Window", `${analysis.window_seconds ?? "—"} seconds`],
      ["Samples excluded", num(boot.samples_rejected)],
      ["Model", "not active"],
    ])}</dl>
    <div class="progress"><i></i></div>
    <p class="card-note">NEMOS is learning what this network's ordinary traffic
       looks like. Only windows that every detection layer judged unremarkable
       are kept, so traffic it flagged never becomes training data. It fits an
       Isolation Forest once both thresholds are met; an anomaly score is a
       measure of how unlike that traffic a window is, and is not a probability
       of compromise.</p>
    ${layerList(analysis)}`;
  // Width via a custom property: an inline style attribute would be refused
  // by the page's own Content-Security-Policy.
  const bar = model.querySelector(".progress i");
  if (bar) {
    const time = needSeconds ? Math.min(1, seen / needSeconds) : 1;
    const rows = need ? Math.min(1, have / need) : 1;
    bar.style.setProperty("--pct", Math.min(time, rows) * 100);
  }
}

function renderSensor(data, status) {
  const capture = status.capture || data.capture || {};
  $("sensor-capture").innerHTML = facts([
    ["State", capture.state || "unknown"],
    ["Running", capture.running ? "yes" : "no"],
    ["Interface", capture.interface || "auto-selected"],
    ["Packets seen", num(capture.packets_seen)],
    ["Last packet", capture.last_packet ? ago(capture.last_packet) : "—"],
    ["Error", capture.error || "none"],
  ]);

  const w = status.writer || {};
  $("sensor-storage").innerHTML = facts([
    ["Thread alive", w.thread_alive ? "yes" : "no"],
    ["Queue depth", `${num(w.queue_depth)} / ${num(w.queue_capacity)}`],
    ["Queue high-water", num(w.queue_high_watermark)],
    ["Batches written", num(w.batches_written)],
    ["Dropped (traffic)", num(w.dropped_traffic)],
    ["Dropped (alerts)", num(w.dropped_alerts)],
    ["Write errors", num(w.write_errors)],
  ]);

  renderModel(status.analysis || {});

  // Delivery.
  const n = status.notifications || {};
  const d = $("sensor-delivery");
  if (!n.enabled || !n.active) {
    const configured = [n.telegram_configured && "Telegram", n.webhook_configured && "webhook"].filter(Boolean);
    d.innerHTML = `<div class="notice"><b>Outbound delivery is off</b>
      <p>${configured.length
          ? `${esc(configured.join(" and "))} configured but delivery is not active.`
          : "No channel is configured."}
         Findings are still recorded and shown here — only the outbound copy is
         affected. Set <code>TELEGRAM_BOT_TOKEN</code> and
         <code>TELEGRAM_CHAT_ID</code>, or <code>NEMOS_WEBHOOK_URL</code>.</p></div>`;
  } else {
    d.innerHTML = `<dl class="facts">${facts([
      ["Channels", Object.keys(n.channels || {}).join(", ") || "none"],
      ["Accepted", num(n.accepted)],
      ["Delivered", num(n.delivered)],
      ["Failed", num(n.failed)],
      ["Suppressed (severity)", num(n.suppressed_severity)],
      ["Suppressed (cooldown)", num(n.suppressed_cooldown)],
      ["Suppressed (rate)", num(n.suppressed_rate)],
      ["Queue depth", num(n.queue_depth)],
    ])}</dl>`;
  }
}

/* ── Evidence drawer ────────────────────────────────────────────────── */

function openDrawer(alert) {
  if (!alert) return;
  $("drawer-title").textContent = alert.threat;
  $("drawer-sub").textContent = `${alert.source} · ${clock(alert.timestamp)} · ${alert.severity}`;

  let evidence = alert.evidence;
  if (typeof evidence === "string") {
    try { evidence = JSON.parse(evidence); } catch { /* leave as text */ }
  }

  const parts = [];

  parts.push(`<div class="sect"><h3>Why this fired</h3>
    <p class="reason">${esc(alert.reason)}</p></div>`);

  parts.push(`<div class="sect"><h3>Assessment</h3><dl class="kv">
    ${[["Risk score", `${alert.risk_score} / 100`],
       ["Confidence", `${alert.confidence}%`],
       ["Severity", alert.severity],
       ["Category", alert.category],
       ["Incident", alert.incident_id || "—"],
       ["Observed", new Date(alert.timestamp).toLocaleString()],
      ].map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}
    </dl></div>`);

  // ATT&CK, or an explicit statement that the evidence does not support one.
  if (alert.attack?.mapped) {
    parts.push(`<div class="sect"><h3>ATT&amp;CK</h3><dl class="kv">
      <div><dt>Technique</dt><dd><a href="${esc(alert.attack.url)}" rel="noreferrer noopener">${esc(alert.attack.technique_id)}</a></dd></div>
      <div><dt>Name</dt><dd>${esc(alert.attack.name)}</dd></div>
      <div><dt>Tactic</dt><dd>${esc(alert.attack.tactic)}</dd></div>
      </dl><p class="reason">${esc(alert.attack.description)}</p></div>`);
  } else {
    parts.push(`<div class="sect"><h3>ATT&amp;CK</h3>
      <p class="reason">Unmapped. ${esc(alert.signal?.reason
        || "This finding is a behavioural signal; the evidence does not support naming a specific technique.")}</p></div>`);
  }

  // Beaconing gets a periodicity plot: regularity is the whole finding, and it
  // is far easier to see than to read as a list of numbers.
  if (evidence && Array.isArray(evidence.intervals_seconds) && evidence.intervals_seconds.length) {
    const gaps = evidence.intervals_seconds;
    const peak = Math.max(...gaps, 1);
    parts.push(`<div class="sect"><h3>Contact periodicity</h3>
      <div class="beacon">${gaps.map(() => "<i></i>").join("")}</div>
      <p class="beacon-cap">Each bar is the gap between consecutive contacts.
         Mean ${esc(evidence.mean_interval_seconds)}s, jitter ratio
         ${esc(evidence.jitter_ratio)} (threshold ${esc(evidence.jitter_threshold)}).
         Bars of near-equal height are what makes this a beacon rather than
         ordinary traffic.</p></div>`);
    // Heights via custom property, so no inline style attribute is emitted.
    const bars = parts.length;
    queueMicrotask(() => {
      const el = $("drawer-body").querySelectorAll(".beacon i");
      el.forEach((bar, i) => bar.style.setProperty("--pct", (gaps[i] / peak) * 100));
      void bars;
    });
  }

  if (evidence && typeof evidence === "object") {
    parts.push(`<div class="sect"><h3>Evidence</h3>
      <pre class="json">${esc(JSON.stringify(evidence, null, 2))}</pre></div>`);
  }

  $("drawer-body").innerHTML = parts.join("");
  $("drawer").hidden = false;
  $("scrim").hidden = false;
  $("drawer-close").focus();
}

function closeDrawer() {
  $("drawer").hidden = true;
  $("scrim").hidden = true;
}

/* ── Command palette ────────────────────────────────────────────────── */

function paletteItems(query) {
  const q = query.trim().toLowerCase();
  const items = VIEWS.map((v) => ({ label: TITLES[v][0], hint: "view", action: () => go(v) }));

  for (const host of (state.data?.hosts || []).slice(0, 40)) {
    items.push({
      label: host.host, hint: "host",
      action: () => { state.hostFilter = host.host; $("host-search").value = host.host; go("hosts"); },
    });
  }
  for (const threat of [...new Set(state.alerts.map((a) => a.threat))]) {
    items.push({
      label: threat, hint: "threat",
      action: () => { state.detFilter.text = threat; $("det-search").value = threat; state.detPage = 0; go("detections"); },
    });
  }
  return items.filter((i) => !q || i.label.toLowerCase().includes(q)).slice(0, 12);
}

function renderPalette() {
  const items = paletteItems($("palette-input").value);
  state.paletteIndex = Math.min(state.paletteIndex, Math.max(0, items.length - 1));
  $("palette-list").innerHTML = items.map((item, i) => `
    <li class="${i === state.paletteIndex ? "on" : ""}" data-index="${i}">
      ${esc(item.label)}<small>${esc(item.hint)}</small>
    </li>`).join("") || `<li class="dim">No matches</li>`;
  renderPalette._items = items;
}

function togglePalette(open) {
  const wrap = $("palette");
  wrap.hidden = !open;
  if (open) {
    $("palette-input").value = "";
    state.paletteIndex = 0;
    renderPalette();
    $("palette-input").focus();
  }
}

/* ── Routing ────────────────────────────────────────────────────────── */

function go(view) {
  if (!VIEWS.includes(view)) view = "overview";
  state.view = view;
  if (location.hash.slice(1) !== view) location.hash = view;

  for (const v of VIEWS) $(`view-${v}`).hidden = v !== view;
  for (const link of document.querySelectorAll(".rail-link")) {
    link.classList.toggle("on", link.dataset.view === view);
  }
  const [title, sub] = TITLES[view];
  $("view-title").textContent = title;
  $("view-sub").textContent = sub;
  window.scrollTo({ top: 0 });
}

/* ── Paint ──────────────────────────────────────────────────────────── */

function paint() {
  const data = state.data;
  if (!data) return;

  renderChain(state.alerts);
  renderKpis(data.stats || {}, data.capture);
  renderPosture(state.alerts);
  $("ov-incidents").innerHTML = (data.incidents || []).length
    ? `<div class="tablewrap"><table class="table"><tbody>${[...(data.incidents || [])]
        .sort(byTriage).slice(0, 6).map((i) => {
          const threats = String(i.threats || "").split(",").filter(Boolean);
          return `
        <tr class="row ${sevClass(i.severity)}" data-incident="${esc(i.incident_id)}">
          <td class="mono nowrap">${esc(String(i.sources || "").split(",")[0] || "—")}</td>
          <td class="cell-threat dim">${esc(threatLabel(threats[0] || ""))}${
            threats.length > 1 ? ` <span class="more">+${threats.length - 1} more</span>` : ""}</td>
          <td class="num score">${esc(i.max_risk)}</td>
          <td><span class="sev">${esc(i.severity)}</span></td>
        </tr>`; }).join("")}</tbody></table></div>`
    : emptyState("◇", "No incidents", "Findings from a single source are grouped into an incident. None have formed.");
  $("ov-timeline").innerHTML = feedRows(state.alerts, 8);

  renderIncidents(data.incidents || []);
  renderDetections();
  renderHosts(data.hosts || []);
  renderAttack(state.alerts, state.catalog || []);
  renderSensor(data, state.status || {});

  const capture = data.capture || {};
  const dot = $("conn-dot");
  dot.className = `dot ${capture.running ? "ok" : capture.error ? "bad" : "warn"}`;
  $("conn-text").textContent = capture.running ? "Capturing" : (capture.state || "Idle");
  $("conn-sub").textContent = capture.interface || "no interface";
  $("updated-at").textContent = new Date().toLocaleTimeString();
}

async function refresh() {
  try {
    const [dash, alerts, catalog, status] = await Promise.all([
      api("/api/dashboard"),
      api("/api/alerts?limit=500&sort=risk"),
      api("/api/techniques"),
      api("/api/status"),
    ]);
    state.data = dash;
    state.alerts = Array.isArray(alerts) ? alerts : (alerts.alerts || []);
    state.catalog = catalog.techniques || [];
    state.status = status;
    $("authbar").hidden = true;
    paint();
  } catch (error) {
    if (String(error.message) !== "unauthorized") {
      $("conn-dot").className = "dot bad";
      $("conn-text").textContent = "Disconnected";
      $("conn-sub").textContent = "retrying";
    }
  }
}

/* ── Wiring ─────────────────────────────────────────────────────────── */

function alertById(id) {
  return state.alerts.find((a) => String(a.id) === String(id));
}

function init() {
  // Theme
  try {
    const saved = localStorage.getItem("nemos.theme");
    if (saved) document.documentElement.dataset.theme = saved;
  } catch { /* private mode */ }

  $("theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("nemos.theme", next); } catch { /* private mode */ }
  });

  // Routing
  window.addEventListener("hashchange", () => go(location.hash.slice(1)));
  go(location.hash.slice(1) || "overview");

  // Live polling
  $("live-toggle").addEventListener("click", () => {
    state.live = !state.live;
    $("live-toggle").setAttribute("aria-pressed", String(state.live));
    $("live-label").textContent = state.live ? "Live" : "Paused";
    if (state.live) refresh();
  });
  $("refresh-now").addEventListener("click", refresh);

  // Token
  $("token-save").addEventListener("click", () => {
    setToken($("token-input").value.trim());
    $("token-input").value = "";
    toast("Token saved");
    refresh();
  });
  $("token-clear").addEventListener("click", () => { setToken(""); toast("Token cleared"); refresh(); });

  // Detection filters
  $("det-search").addEventListener("input", (e) => {
    state.detFilter.text = e.target.value; state.detPage = 0; renderDetections();
  });
  $("det-severity").addEventListener("click", (e) => {
    const button = e.target.closest("[data-sev]");
    if (!button) return;
    state.detFilter.severity = button.dataset.sev;
    state.detPage = 0;
    for (const seg of $("det-severity").children) seg.classList.toggle("on", seg === button);
    renderDetections();
  });
  $("det-prev").addEventListener("click", () => { state.detPage = Math.max(0, state.detPage - 1); renderDetections(); });
  $("det-next").addEventListener("click", () => { state.detPage += 1; renderDetections(); });

  // Host filters
  $("host-search").addEventListener("input", (e) => {
    state.hostFilter = e.target.value; state.hostPage = 0; renderHosts(state.data?.hosts || []);
  });
  $("host-prev").addEventListener("click", () => { state.hostPage = Math.max(0, state.hostPage - 1); renderHosts(state.data?.hosts || []); });
  $("host-next").addEventListener("click", () => { state.hostPage += 1; renderHosts(state.data?.hosts || []); });

  // Row activation -> drawer, or host -> filtered detections
  document.addEventListener("click", (e) => {
    // Group headers expand in place. Checked before [data-alert] so a click
    // on a collapsed campaign opens it rather than jumping into one member.
    const groupRow = e.target.closest("[data-group]");
    if (groupRow) {
      const key = groupRow.dataset.group;
      if (state.expanded.has(key)) state.expanded.delete(key);
      else state.expanded.add(key);
      renderDetections();
      return;
    }

    const alertRow = e.target.closest("[data-alert]");
    if (alertRow) { openDrawer(alertById(alertRow.dataset.alert)); return; }

    const hostRow = e.target.closest("[data-host]");
    if (hostRow) {
      state.detFilter.text = hostRow.dataset.host;
      $("det-search").value = hostRow.dataset.host;
      state.detPage = 0;
      go("detections");
      renderDetections();
      return;
    }
    const incidentRow = e.target.closest("[data-incident]");
    if (incidentRow) {
      state.detFilter.text = "";
      const first = state.alerts.find((a) => a.incident_id === incidentRow.dataset.incident);
      if (first) openDrawer(first);
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const key = e.target.dataset?.group;
    if (key) {
      if (state.expanded.has(key)) state.expanded.delete(key);
      else state.expanded.add(key);
      renderDetections();
      return;
    }
    if (e.target.dataset?.alert) openDrawer(alertById(e.target.dataset.alert));
  });

  $("drawer-close").addEventListener("click", closeDrawer);
  $("scrim").addEventListener("click", closeDrawer);

  // Palette
  $("open-palette").addEventListener("click", () => togglePalette(true));
  $("palette-input").addEventListener("input", () => { state.paletteIndex = 0; renderPalette(); });
  $("palette-list").addEventListener("click", (e) => {
    const li = e.target.closest("[data-index]");
    if (!li) return;
    renderPalette._items[Number(li.dataset.index)].action();
    togglePalette(false);
  });
  $("palette").addEventListener("click", (e) => { if (e.target === $("palette")) togglePalette(false); });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); togglePalette($("palette").hidden); return; }
    if (e.key === "Escape") { togglePalette(false); closeDrawer(); return; }
    if ($("palette").hidden) return;
    const items = renderPalette._items || [];
    if (e.key === "ArrowDown") { e.preventDefault(); state.paletteIndex = Math.min(items.length - 1, state.paletteIndex + 1); renderPalette(); }
    if (e.key === "ArrowUp") { e.preventDefault(); state.paletteIndex = Math.max(0, state.paletteIndex - 1); renderPalette(); }
    if (e.key === "Enter" && items[state.paletteIndex]) { items[state.paletteIndex].action(); togglePalette(false); }
  });

  refresh();
  setInterval(() => { if (state.live && !document.hidden) refresh(); }, 5000);
}

document.addEventListener("DOMContentLoaded", init);
