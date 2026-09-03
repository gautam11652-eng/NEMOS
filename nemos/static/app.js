/* NEMOS security operations console.
 *
 * No framework and no build step: the sensor serves two static files and a
 * JSON API. A console that needs a toolchain to render is one an operator
 * cannot debug at 3am.
 *
 * Shape: fetch -> normalise -> pure render functions -> paint. Every renderer
 * takes what it needs as an argument, so nothing reaches into the DOM to
 * discover what it should draw.
 *
 * The guiding constraint is that this interface must not assume its reader
 * already speaks SOC. Every panel says in plain words what it is, findings are
 * ordered worst-first rather than newest-first, and nothing is ever shown that
 * the sensor did not actually measure. Where a number would be a guess, the
 * console says so instead of printing one.
 */
"use strict";

const $ = (id) => document.getElementById(id);

/* ══ State ═════════════════════════════════════════════════════════ */

const state = {
  view: "overview",
  live: true,
  data: null,          // /api/dashboard
  alerts: [],          // /api/alerts, risk-ordered, carries evidence
  incidents: [],       // /api/incidents, arrays rather than joined strings
  catalog: [],         // /api/techniques
  unmapped: [],
  status: null,        // /api/status
  flows: [],
  baselines: [],
  anomalies: [],
  ovFilter: { text: "", severity: "ALL" },
  ovRange: 60,
  detFilter: { text: "", severity: "ALL", threat: "ALL", sort: "risk" },
  detPage: 0,
  hostFilter: "",
  hostPage: 0,
  paletteIndex: 0,
  expanded: new Set(),  // campaign groups the operator has opened
  pairing: null,        // /api/telegram/pair
  // The plaintext pairing code exists only here, in this tab, until it expires.
  // It is never written to storage: a code on disk outlives its own expiry.
  pairCode: null,
};

const PAGE = 25;

const VIEWS = ["overview", "incidents", "detections", "hosts", "network",
               "attack", "analytics", "sensor", "settings"];

/* Title and, more importantly, the plain sentence under it. */
const TITLES = {
  overview:   ["Overview", "What needs your attention right now"],
  incidents:  ["Incidents", "Everything one address did, gathered together"],
  detections: ["Detections", "Every finding, with the evidence behind it"],
  hosts:      ["Hosts", "Addresses seen on this network, most concerning first"],
  network:    ["Network", "Who is talking to whom, from recorded flows"],
  attack:     ["ATT&CK", "Which attacker techniques have actually been observed"],
  analytics:  ["Analytics", "The learning layers and whether they still fit"],
  sensor:     ["Sensor", "Is the sensor healthy and is anything being missed"],
  settings:   ["Settings", "How this console and this sensor are configured"],
};

/* The order an intrusion actually progresses in. Findings sit on the tactic
 * their technique evidences, so this shows how far an actor got rather than
 * merely how many alerts fired. Every tactic in the catalog needs a stage
 * here or its findings would render nowhere. */
const CHAIN = [
  { label: "Reconnaissance",    match: /reconnaissance/i },
  { label: "Discovery",         match: /discovery/i },
  { label: "Credential Access", match: /credential/i },
  { label: "Lateral Movement",  match: /lateral/i },
  { label: "Command & Control", match: /command/i },
  { label: "Exfiltration",      match: /exfil/i },
  { label: "Impact",            match: /impact/i },
];

const SEV_CLASS = { CRITICAL: "sev-crit", HIGH: "sev-high", MEDIUM: "sev-med", LOW: "sev-low" };
const SEV_RANK = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };

/* Capture states arrive as machine tokens; a card needs a word, not a token. */
const CAPTURE_LABEL = {
  running: "Live", starting: "Starting", stopped: "Stopped", failed: "Failed",
  permission_denied: "Blocked", unavailable: "Unavailable",
  not_configured: "Off", error: "Failed",
};

/* ML lifecycle states as nemos/bootstrap.py reports them. ACTIVE is only ever
 * set after a real Isolation Forest was fitted, validated and loaded, so the
 * console can show the word without qualifying it. */
const ML_LABEL = {
  NO_MODEL: "Unavailable", WARMING_UP: "Warming up", TRAINING: "Training",
  VALIDATING: "Validating", ACTIVE: "Active", RETRAINING: "Retraining",
  FAILED: "Failed",
};
const ML_TONE = { ACTIVE: "ok", RETRAINING: "ok", FAILED: "bad", NO_MODEL: "warn" };

/* ══ Utilities ═════════════════════════════════════════════════════ */

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
));

const num = (v) => (Number(v) || 0).toLocaleString();

const sevClass = (s) => SEV_CLASS[String(s || "").toUpperCase()] || "sev-low";

/* "1 addresses" and "4 findings needs attention" are the kind of thing that
   makes an interface feel unfinished, so counting and wording stay together. */
const plural = (n, one, many) => `${num(n)} ${Number(n) === 1 ? one : many}`;

/* Every list endpoint here is bounded, so a full page means "at least this
   many", not "this many". Printing the page size as a total is how a console
   ends up stating a number nobody measured -- the host list showed "50
   addresses" on a sensor that had seen 211. */
const LIMITS = { alerts: 500, incidents: 200, hosts: 50, flows: 200 };
const atCap = (n, limit) => Number(n) >= limit;
const capped = (n, limit) => (atCap(n, limit) ? `${num(n)}+` : num(n));

/* "CRITICAL" shouted in a table cell is louder than it is informative. */
const sevWord = (s) => {
  const v = String(s || "").toUpperCase();
  return v ? v.charAt(0) + v.slice(1).toLowerCase() : "—";
};

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

const stamp = (ts) => (ts && !isNaN(new Date(ts)) ? new Date(ts).getTime() : 0);

function bytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  if (v < 1048576) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1073741824) return `${(v / 1048576).toFixed(1)} MB`;
  return `${(v / 1073741824).toFixed(2)} GB`;
}

/* mm:ss, growing an hours field only once there are hours to show. */
function duration(seconds) {
  const total = Math.max(0, Math.round(Number(seconds) || 0));
  const pad = (n) => String(n).padStart(2, "0");
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  return h ? `${h}:${pad(m)}:${pad(total % 60)}` : `${pad(m)}:${pad(total % 60)}`;
}

/* Reasons arrive from the backend as fragments; give them terminal
   punctuation so they read as sentences beside the guidance that follows. */
const sentence = (v) => {
  const text = String(v ?? "").trim();
  if (!text) return "";
  return /[.!?]$/.test(text) ? text : `${text}.`;
};

/* Threat names are identifiers -- C2_BEACONING, SYN_FLOOD_PATTERN -- and they
 * are also the exact values that appear in the API, in Telegram and in syslog.
 * Show a readable form and keep the identifier on hover and in the evidence
 * drawer, so an operator can still grep for precisely what the sensor emitted. */
const ACRONYMS = new Set(["c2", "dns", "icmp", "tcp", "udp", "syn", "arp", "ndp", "ip"]);
const threatLabel = (v) => String(v ?? "").split("_").filter(Boolean).map((word, i) => {
  const lower = word.toLowerCase();
  if (ACRONYMS.has(lower)) return word.toUpperCase();
  return i === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
}).join(" ");

const captureLabel = (c) => (c?.running ? "Live"
  : CAPTURE_LABEL[String(c?.state || "").toLowerCase()] || "Off");

function evidenceOf(alert) {
  let evidence = alert?.evidence;
  if (typeof evidence === "string") {
    try { evidence = JSON.parse(evidence); } catch { return null; }
  }
  return (evidence && typeof evidence === "object") ? evidence : null;
}

/* Alerts carry no destination column; where one exists it is inside the
 * evidence the rule recorded. Never invent one -- a dash is the honest
 * answer for a finding that is about a source's behaviour, not a pair. */
function destinationOf(alert) {
  const e = evidenceOf(alert);
  if (!e) return "";
  if (e.destination) return String(e.destination);
  if (e.target) return String(e.target);
  for (const key of ["destinations", "internal_targets", "dns_destinations"]) {
    const list = e[key];
    if (Array.isArray(list) && list.length) {
      return list.length === 1 ? String(list[0])
        : `${list[0]} +${list.length - 1}`;
    }
  }
  return "";
}

/* Which layer produced a finding. Deterministic rules name an ATT&CK
 * technique; the statistical layers deliberately never do. */
function methodOf(alert) {
  if (alert?.attack?.mapped) return `Rule · ${alert.attack.technique_id}`;
  if (String(alert?.threat || "").startsWith("ML_")) return "ML anomaly model";
  if (String(alert?.threat || "").startsWith("BEHAVIORAL_")) return "Behavioural baseline";
  return "Detection rule";
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

/* Widths and heights arrive as custom properties, never as inline style
   attributes, which the page's own CSP would refuse. */
function setPct(el, pct) {
  if (el) el.style.setProperty("--pct", Math.max(0, Math.min(100, pct)));
}

/* ══ Transport ═════════════════════════════════════════════════════ */

const tokenKey = "nemos.token";
const getToken = () => { try { return localStorage.getItem(tokenKey) || ""; } catch { return ""; } };
const setToken = (v) => {
  try { v ? localStorage.setItem(tokenKey, v) : localStorage.removeItem(tokenKey); }
  catch { /* private mode */ }
};

async function api(path) {
  const headers = {};
  const token = getToken();
  // X-NEMOS-Token is the header the API documents and checks. Sending only
  // Authorization: Bearer meant the console could never authenticate against
  // a token-protected sensor.
  if (token) headers["X-NEMOS-Token"] = token;
  const response = await fetch(path, { headers, cache: "no-store" });
  if (response.status === 401) { $("authbar").hidden = false; throw new Error("unauthorized"); }
  // A disabled subsystem answers 503. That is a state to render, not a failure
  // to report: the sensor is working exactly as it was configured to.
  if (response.status === 503) return { unavailable: true };
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/* State-changing calls. Separate from api() because these carry a method and
 * must surface the server's own error text: "no Telegram chat is paired" is
 * something the operator can act on, and "HTTP 409" is not. */
async function apiSend(path, method) {
  const headers = {};
  const token = getToken();
  if (token) headers["X-NEMOS-Token"] = token;
  const response = await fetch(path, { method, headers, cache: "no-store" });
  let body = {};
  try { body = await response.json(); } catch { body = {}; }
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

/* ══ Grouping ══════════════════════════════════════════════════════
 * Forty hosts beaconing to one address is one campaign, not forty findings.
 * Listed individually it fills the first three pages and pushes a single
 * CRITICAL finding out of sight, which is how a console teaches its operator
 * to stop reading it. Identical findings collapse into one row carrying the
 * count and the addresses behind it. Nothing is discarded: opening a group
 * shows every member.
 */
function groupKey(a) {
  // Same detection, same severity, same technique, same score. The address is
  // what varies across a campaign, so it is deliberately not in the key.
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

function byTriage(a, b) {
  return (SEV_RANK[b.severity] ?? -1) - (SEV_RANK[a.severity] ?? -1)
    || (Number(b.risk_score ?? b.max_risk) || 0) - (Number(a.risk_score ?? a.max_risk) || 0)
    || String(b.timestamp ?? b.last_seen ?? "").localeCompare(String(a.timestamp ?? a.last_seen ?? ""));
}

/* Summarise a set of addresses without letting it overrun its column. */
function sourceSummary(sources) {
  const list = [...sources];
  if (list.length === 1) return esc(list[0]);
  return `${esc(list[0])} <span class="more">+${list.length - 1} more</span>`;
}

function matches(a, needle) {
  if (!needle) return true;
  return `${a.threat} ${a.source} ${a.reason} ${a.technique} ${destinationOf(a)}`
    .toLowerCase().includes(needle);
}

/* ══ Overview ══════════════════════════════════════════════════════ */

/* The single sentence that answers "what do I do now?" before any number is
 * shown. Derived entirely from findings the sensor recorded. */
function renderBanner(alerts, capture) {
  const open = alerts.filter((a) => !a.acknowledged);
  const critical = open.filter((a) => a.severity === "CRITICAL");
  const high = open.filter((a) => a.severity === "HIGH");

  let tone = "ok";
  let mark = "✓";
  let title = "Nothing needs your attention";
  let body = alerts.length
    ? "No critical or high-severity finding is open. Lower-severity findings are listed below."
    : "The sensor is running and nothing has crossed a detection threshold. On a quiet network that is the correct result, not a failure.";

  if (critical.length) {
    const where = new Set(critical.map((a) => a.source));
    tone = "crit"; mark = "▲";
    title = critical.length === 1
      ? "1 critical finding needs attention now"
      : `${critical.length} critical findings need attention now`;
    body = `Across ${plural(where.size, "address", "addresses")}. Start at the top of the priority queue below — it is ordered worst first.`;
  } else if (high.length) {
    const where = new Set(high.map((a) => a.source));
    tone = "high"; mark = "▲";
    title = high.length === 1
      ? "1 high-severity finding to review"
      : `${high.length} high-severity findings to review`;
    body = `Across ${plural(where.size, "address", "addresses")}. Nothing critical is open — worth working through today.`;
  }

  // A sensor that is not capturing outranks anything it did or did not find,
  // because an empty queue then means nothing at all.
  if (capture && !capture.running && capture.state !== "not_configured") {
    tone = "crit"; mark = "◉";
    title = "The sensor is not capturing traffic";
    body = `Capture state is "${String(capture.state || "unknown").replace(/_/g, " ")}"${
      capture.error ? `: ${capture.error}` : ""}. Until it recovers, an empty queue below means nothing was seen, not that nothing happened.`;
  }

  $("ov-banner").innerHTML = `
    <div class="banner ${tone}">
      <span class="banner-mark" aria-hidden="true">${mark}</span>
      <span class="banner-text"><b>${esc(title)}</b><p>${esc(body)}</p></span>
    </div>`;
}

/* The share of recorded packets by protocol, from the sensor's own counters.
   Zero traffic says so rather than printing 0%. */
function protocolMix(stats) {
  const total = Number(stats.packets) || 0;
  if (!total) return "nothing recorded yet";
  const parts = [["TCP", stats.tcp], ["UDP", stats.udp], ["ICMP", stats.icmp]]
    .map(([name, n]) => [name, Math.round(((Number(n) || 0) / total) * 100)])
    .filter(([, pct]) => pct >= 1)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 2)
    .map(([name, pct]) => `${pct}% ${name}`);
  return parts.length ? parts.join(", ") : "mixed protocols";
}

/* Rules and the baseline always run; the model is the one that may not be
   there. Counting them is how the Overview says "still protected" when the
   model is only warming up. */
function layersUp(analysis) {
  return 2 + (analysis?.model?.available ? 1 : 0);
}

function renderKpis(stats, capture) {
  // Triage metrics, not traffic volume. Packet counts say how busy the wire
  // is; they never say what to look at next, and they were occupying the most
  // valuable strip of the screen to say it.
  const alerts = state.alerts || [];
  const open = alerts.filter((a) => !a.acknowledged);
  const critical = open.filter((a) => a.severity === "CRITICAL");
  const high = open.filter((a) => a.severity === "HIGH");
  const sources = new Set(open.map((a) => a.source));
  const techniques = new Set(open.map((a) => a.technique).filter(Boolean));

  const analysis = state.status?.analysis || {};
  const health = analysis?.model?.health || {};
  const boot = analysis.bootstrap || {};
  const modelNote = health.drifted ? "drifted — retrain it"
    : health.stale ? "stale — retrain it"
    : health.score_inflated ? "calibration looks off"
    : analysis?.model?.available ? "model is healthy"
    : (ML_LABEL[boot.state] || "no model").toLowerCase();

  const cards = [
    { k: "Critical open", v: num(critical.length),
      s: critical.length ? "act on these now" : "nothing critical",
      alarm: critical.length > 0, good: critical.length === 0 },
    { k: "High open", v: num(high.length),
      s: high.length ? "review these today" : "none open",
      warn: high.length > 0 },
    { k: "Addresses involved", v: num(sources.size), s: "with an open finding" },
    { k: "Techniques seen", v: num(techniques.size), s: "distinct ATT&CK IDs" },
    { k: "Capture", v: captureLabel(capture),
      s: capture?.interface && capture.interface !== "default"
        ? `on ${capture.interface}` : String(capture?.state || "").replace(/_/g, " ") || "no interface",
      alarm: Boolean(capture?.error) || capture?.state === "failed" },
    { k: "Packets recorded", v: num(stats.packets), s: protocolMix(stats) },
    { k: "Detection layers", v: `${layersUp(analysis)} of 3`, s: modelNote,
      good: layersUp(analysis) === 3, warn: layersUp(analysis) < 3 },
  ];

  $("kpis").innerHTML = cards.map((c) => `
    <article class="kpi ${c.alarm ? "alarm" : c.warn ? "warn" : c.good ? "good" : ""}">
      <div class="kpi-k">${esc(c.k)}</div>
      <div class="kpi-v">${esc(c.v)}</div>
      <div class="kpi-s">${esc(c.s)}</div>
    </article>`).join("");
}

/* Buckets real alert timestamps into fixed slots. No slot is invented: an
 * empty stretch of time renders as an empty stretch of time. */
function renderTimeline(alerts) {
  const host = $("ov-timeline");
  if (!alerts.length) {
    host.innerHTML = emptyState("◌", "No findings to plot",
      "Nothing has been recorded yet, so there is no activity to chart.");
    return;
  }

  const times = alerts.map((a) => stamp(a.timestamp)).filter(Boolean);
  if (!times.length) {
    host.innerHTML = emptyState("◌", "No usable timestamps",
      "The recorded findings carry no timestamp this console can read.");
    return;
  }

  const now = Date.now();
  const minutes = Number(state.ovRange) || 0;
  const newest = Math.max(...times, minutes ? now : 0);
  const oldest = minutes ? newest - minutes * 60000 : Math.min(...times);
  const span = Math.max(1, newest - oldest);
  const SLOTS = 48;

  const buckets = Array.from({ length: SLOTS }, () => ({ n: 0, sev: "" }));
  for (const a of alerts) {
    const t = stamp(a.timestamp);
    if (!t || t < oldest || t > newest) continue;
    const i = Math.min(SLOTS - 1, Math.floor(((t - oldest) / span) * SLOTS));
    const b = buckets[i];
    b.n += 1;
    if ((SEV_RANK[a.severity] ?? -1) > (SEV_RANK[b.sev] ?? -1)) b.sev = a.severity;
  }

  const peak = Math.max(1, ...buckets.map((b) => b.n));
  const plotted = buckets.reduce((sum, b) => sum + b.n, 0);
  const fmt = (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  host.innerHTML = `
    <div class="timeline">
      <div class="tl-bars">${buckets.map((b) => `
        <i class="${b.n ? sevClass(b.sev) : "zero"}"></i>`).join("")}</div>
      <div class="tl-axis"><span>${esc(fmt(oldest))}</span><span>${esc(fmt(newest))}</span></div>
      <div class="tl-legend">
        <span><i class="tl-crit"></i>Critical</span>
        <span><i class="tl-high"></i>High</span>
        <span><i class="tl-med"></i>Medium</span>
        <span><i class="tl-low"></i>Low</span>
        <span>${plotted} of ${alerts.length} findings fall in this range</span>
      </div>
    </div>`;

  const bars = host.querySelectorAll(".tl-bars i");
  buckets.forEach((b, i) => setPct(bars[i], (b.n / peak) * 100));
  // Legend swatches take their colour from the same severity classes the bars
  // use, so the two can never drift apart.
  const swatches = host.querySelectorAll(".tl-legend i");
  ["sev-crit", "sev-high", "sev-med", "sev-low"].forEach((cls, i) => {
    if (swatches[i]) swatches[i].className = cls;
  });
}

function feedRows(alerts, limit) {
  if (!alerts.length) {
    return emptyState("◌", "Nothing in the queue",
      "No finding matches this filter. Clear the search, or widen the severity filter.");
  }
  return `<div class="feed">${groupFindings(alerts).slice(0, limit).map((g) => {
    const a = g.members[0];
    const spread = g.members.length > 1
      ? `<span class="count">${g.members.length} findings · ${g.sources.size} addresses</span>` : "";
    const who = g.members.length > 1
      ? `${esc([...g.sources][0])} and ${g.sources.size - 1} other address${g.sources.size === 2 ? "" : "es"}`
      : esc(a.source);
    return `
    <div class="feed-row ${sevClass(g.severity)}" data-alert="${esc(a.id)}" tabindex="0" role="button">
      <span class="feed-t">${esc(clock(g.latest))}</span>
      <span class="feed-main">
        <b title="${esc(g.threat)}">${esc(threatLabel(g.threat))}</b>${spread}
        <span>${who} · ${esc(a.reason)}</span>
      </span>
      <span class="score">${esc(g.risk_score)}</span>
    </div>`;
  }).join("")}</div>`;
}

function renderOverviewFeed() {
  const needle = state.ovFilter.text.trim().toLowerCase();
  const matched = state.alerts.filter((a) =>
    (state.ovFilter.severity === "ALL" || a.severity === state.ovFilter.severity)
    && matches(a, needle));
  $("ov-events").innerHTML = feedRows(matched, 12);
}

/* ══ Incidents ═════════════════════════════════════════════════════ */

/* /api/incidents returns arrays; /api/dashboard returns the same fields as
 * comma-joined strings. Normalise once so no renderer has to care which. */
const asList = (v) => (Array.isArray(v) ? v.filter(Boolean)
  : String(v || "").split(",").filter(Boolean));

/* Alerts carry `acknowledged`; incidents do not. Derive the incident's status
 * from its own findings rather than showing a field the backend has not got. */
function incidentStatus(incident) {
  const members = state.alerts.filter((a) => a.incident_id === incident.incident_id);
  if (!members.length) return { cls: "", word: "—" };
  return members.every((a) => a.acknowledged)
    ? { cls: "ack", word: "Acknowledged" }
    : { cls: "open", word: "Open" };
}

function renderIncidentRow(i) {
  // A raw comma-joined list of SCREAMING_SNAKE labels used to overrun its
  // column and paint over the risk beside it -- worst on the multi-stage
  // incidents, which are the ones that matter most. Show the leading few and
  // count the rest.
  const threats = asList(i.threats);
  const shown = threats.slice(0, 2)
    .map((t) => `<span class="tag" title="${esc(t)}">${esc(threatLabel(t))}</span>`).join("");
  const extra = threats.length > 2
    ? `<span class="more">+${threats.length - 2} more</span>` : "";
  const sources = asList(i.sources);
  const status = incidentStatus(i);
  return `
    <tr class="row ${sevClass(i.severity)}" data-incident="${esc(i.incident_id)}"
        title="Incident ${esc(i.incident_id)}">
      <td><span class="sev">${esc(sevWord(i.severity))}</span></td>
      <td>${shown}${extra}</td>
      <td class="mono">${sources.length > 1
        ? `${esc(sources[0])} <span class="more">+${sources.length - 1}</span>`
        : esc(sources[0] || "—")}</td>
      <td class="num score">${esc(i.max_risk ?? i.risk_score ?? "—")}</td>
      <td class="num dim">${i.confidence == null ? "—" : `${esc(i.confidence)}%`}</td>
      <td class="num">${num(i.alert_count)}</td>
      <td class="dim nowrap">${esc(clock(i.first_seen))}</td>
      <td class="dim nowrap">${esc(ago(i.last_seen))}</td>
      <td><span class="state ${status.cls}">${esc(status.word)}</span></td>
    </tr>`;
}

function renderIncidents(incidents) {
  const rows = [...incidents].sort(byTriage);
  $("inc-count").textContent = `${capped(rows.length, LIMITS.incidents)} open`;
  $("nav-incidents").textContent = rows.length
    ? capped(rows.length, LIMITS.incidents) : "";

  const body = $("inc-body");
  const empty = $("inc-empty");
  if (!rows.length) {
    body.innerHTML = "";
    empty.innerHTML = emptyState("◇", "No incidents have formed",
      "An incident groups everything one address did inside the correlation window. Nothing has met that bar yet.");
    return;
  }
  empty.innerHTML = "";
  body.innerHTML = rows.map(renderIncidentRow).join("");
}

function renderOverviewIncidents(incidents) {
  const rows = [...incidents].sort(byTriage).slice(0, 6);
  if (!rows.length) {
    $("ov-incidents").innerHTML = emptyState("◇", "No incidents have formed",
      "An incident groups everything one address did inside the correlation window. Nothing has met that bar yet.");
    return;
  }
  $("ov-incidents").innerHTML = `<div class="tablewrap"><table class="table"><tbody>${
    rows.map((i) => {
      const threats = asList(i.threats);
      const sources = asList(i.sources);
      return `
      <tr class="row ${sevClass(i.severity)}" data-incident="${esc(i.incident_id)}"
          title="Incident ${esc(i.incident_id)}">
        <td><span class="sev">${esc(sevWord(i.severity))}</span></td>
        <td class="mono nowrap">${esc(sources[0] || "—")}</td>
        <td>${esc(threatLabel(threats[0] || ""))}${
          threats.length > 1 ? ` <span class="more">+${threats.length - 1} more</span>` : ""}</td>
        <td class="num">${num(i.alert_count)} findings</td>
        <td class="num score">${esc(i.max_risk ?? "—")}</td>
        <td class="dim nowrap">${esc(ago(i.last_seen))}</td>
      </tr>`;
    }).join("")}</tbody></table></div>`;
}

/* ══ Detections ════════════════════════════════════════════════════ */

function filteredDetections() {
  const { text, severity, threat } = state.detFilter;
  const needle = text.trim().toLowerCase();
  return state.alerts.filter((a) => {
    if (severity !== "ALL" && a.severity !== severity) return false;
    if (threat !== "ALL" && a.threat !== threat) return false;
    return matches(a, needle);
  });
}

function detectionCells(a) {
  const destination = destinationOf(a);
  return `
      <td class="dim mono nowrap">${esc(clock(a.timestamp))}</td>
      <td><span class="sev">${esc(sevWord(a.severity))}</span></td>
      <td><b title="${esc(a.threat)}">${esc(threatLabel(a.threat))}</b>
          <br><span class="dim">${esc(a.reason)}</span></td>
      <td class="mono">${esc(a.source)}</td>
      <td class="mono dim">${destination ? esc(destination) : "—"}</td>
      <td class="num score">${esc(a.risk_score)}</td>
      <td class="num dim">${esc(a.confidence)}%</td>
      <td class="dim">${esc(methodOf(a))}</td>
      <td><span class="state ${a.acknowledged ? "ack" : "open"}">${
        a.acknowledged ? "Acknowledged" : "Open"}</span></td>`;
}

function renderDetections() {
  const matched = filteredDetections();
  // Group first, then paginate the groups. Paginating raw findings and
  // grouping only the visible page would still hand the operator a first page
  // made entirely of one repeated campaign.
  const rows = groupFindings(matched);
  if (state.detFilter.sort === "time") {
    rows.sort((x, y) => String(y.latest).localeCompare(String(x.latest)));
  } else if (state.detFilter.sort === "severity") {
    rows.sort(byTriage);
  }

  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  state.detPage = Math.min(state.detPage, pages - 1);
  const page = rows.slice(state.detPage * PAGE, state.detPage * PAGE + PAGE);

  const total = capped(state.alerts.length, LIMITS.alerts);
  $("det-count").textContent = rows.length === matched.length
    ? `${matched.length} of ${total}`
    : `${rows.length} groups · ${matched.length} of ${total} findings`;
  $("nav-detections").textContent = state.alerts.length
    ? capped(state.alerts.length, LIMITS.alerts) : "";

  const body = $("det-body");
  const empty = $("det-empty");
  if (!rows.length) {
    body.innerHTML = "";
    empty.innerHTML = state.alerts.length
      ? emptyState("⌕", "Nothing matches",
          "No finding matches this filter. Clear the search box or pick a different severity.")
      : emptyState("◌", "No findings yet",
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
      return `<tr class="row ${sevClass(a.severity)}" data-alert="${esc(a.id)}">${detectionCells(a)}</tr>`;
    }
    const expanded = state.expanded.has(g.key);
    const head = `
    <tr class="row grouped ${sevClass(g.severity)}" data-group="${esc(g.key)}"
        tabindex="0" role="button" aria-expanded="${expanded}">
      <td class="dim mono nowrap">${esc(clock(g.latest))}</td>
      <td><span class="sev">${esc(sevWord(g.severity))}</span></td>
      <td><b title="${esc(g.threat)}">${esc(threatLabel(g.threat))}</b>
          <span class="count">${g.members.length} findings · ${g.sources.size} addresses</span>
          <br><span class="dim">${esc(g.reason)}</span></td>
      <td class="mono">${sourceSummary(g.sources)}</td>
      <td class="mono dim">—</td>
      <td class="num score">${esc(g.risk_score)}</td>
      <td class="num dim">${esc(g.confidence)}%</td>
      <td class="dim">${esc(methodOf(g.members[0]))}</td>
      <td><span class="caret" aria-hidden="true">${expanded ? "▾" : "▸"}</span></td>
    </tr>`;
    if (!expanded) return head;
    return head + g.members.slice(0, 60).map((a) => `
      <tr class="row child ${sevClass(a.severity)}" data-alert="${esc(a.id)}">${detectionCells(a)}</tr>`
    ).join("");
  }).join("");
}

function refreshThreatFilter() {
  const select = $("det-threat");
  const threats = [...new Set(state.alerts.map((a) => a.threat).filter(Boolean))].sort();
  const current = state.detFilter.threat;
  select.innerHTML = `<option value="ALL">Every threat</option>${
    threats.map((t) => `<option value="${esc(t)}">${esc(threatLabel(t))}</option>`).join("")}`;
  select.value = threats.includes(current) ? current : "ALL";
  state.detFilter.threat = select.value;
}

/* ══ Hosts ═════════════════════════════════════════════════════════ */

/* The sensor records no hostname, MAC or open-port list, so this says where an
 * address sits rather than inventing an identity for it. */
function position(host) {
  const v = String(host || "");
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(v)) return "Internal";
  if (/^127\.|^::1$/.test(v)) return "This machine";
  if (/^(fe80:|fc|fd)/i.test(v)) return "Internal (IPv6)";
  if (v.includes(":")) return "External (IPv6)";
  return v ? "External" : "—";
}

function renderHosts(hosts) {
  const needle = state.hostFilter.trim().toLowerCase();
  const rows = hosts.filter((h) => !needle || String(h.host).toLowerCase().includes(needle));
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  state.hostPage = Math.min(state.hostPage, pages - 1);
  const page = rows.slice(state.hostPage * PAGE, state.hostPage * PAGE + PAGE);

  // hosts arrives already ordered by risk and cut at LIMITS.hosts, so a full
  // page is the worst 50 of an unknown total, not the whole inventory.
  $("host-count").textContent = needle
    ? `${plural(rows.length, "match", "matches")}`
    : atCap(hosts.length, LIMITS.hosts)
      ? `top ${hosts.length} by risk`
      : plural(rows.length, "address", "addresses");
  $("nav-hosts").textContent = hosts.length
    ? capped(hosts.length, LIMITS.hosts) : "";

  const body = $("host-body");
  const empty = $("host-empty");
  if (!rows.length) {
    body.innerHTML = "";
    empty.innerHTML = emptyState("▢", "No addresses yet",
      "No traffic has been attributed to an address. If capture is off, that is why.");
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
    return `
    <tr class="row ${sevClass(band)}" data-host="${esc(h.host)}">
      <td class="mono">${esc(h.host)}</td>
      <td class="dim">${esc(position(h.host))}</td>
      <td class="num score">${risk || "—"}</td>
      <td class="num">${num(h.alert_count)}</td>
      <td class="num">${num(h.critical_count)}</td>
      <td class="num dim">${num(h.packets)}</td>
      <td class="dim nowrap">${esc(h.last_alert ? ago(h.last_alert) : "none")}</td>
    </tr>`;
  }).join("");
}

/* ══ Network ═══════════════════════════════════════════════════════ */

/* Drawn from the flow rows the sensor recorded, and from nothing else. There
 * is no inferred topology here: every line is one observed flow direction. */
function renderNetwork(flows) {
  // This is the page the console requested, not the size of the flow table --
  // labelling it "flows" would state a total the console has not been told.
  $("net-count").textContent = atCap(flows.length, LIMITS.flows)
    ? `${flows.length} most recent flows` : plural(flows.length, "flow", "flows");

  const map = $("net-map");
  const body = $("net-body");
  const empty = $("net-empty");

  if (!flows.length) {
    map.innerHTML = emptyState("⇄", "No flows recorded",
      "Flow aggregation is either disabled or has not completed a window yet. Nothing is drawn that was not observed.");
    $("net-legend").innerHTML = "";
    body.innerHTML = "";
    empty.innerHTML = "";
    return;
  }

  const worst = new Map();
  for (const a of state.alerts) {
    if ((SEV_RANK[a.severity] ?? -1) > (SEV_RANK[worst.get(a.source)] ?? -1)) {
      worst.set(a.source, a.severity);
    }
  }

  const top = [...flows].sort((a, b) => (b.packets || 0) - (a.packets || 0)).slice(0, 14);
  const sources = [...new Set(top.map((f) => f.source))];
  const targets = [...new Set(top.map((f) => f.destination))];
  const rowH = 26;
  const height = Math.max(sources.length, targets.length) * rowH + 46;
  const peak = Math.max(1, ...top.map((f) => Number(f.packets) || 0));
  const yOf = (list, name, count) =>
    36 + (list.indexOf(name) * rowH) + ((Math.max(sources.length, targets.length) - count) * rowH) / 2;

  const edges = top.map((f) => {
    const y1 = yOf(sources, f.source, sources.length);
    const y2 = yOf(targets, f.destination, targets.length);
    const width = 1 + (Number(f.packets) || 0) / peak * 3;
    const cls = worst.get(f.source) ? sevClass(worst.get(f.source)) : "";
    return `<path class="edge ${cls}" d="M 190 ${y1} C 320 ${y1}, 360 ${y2}, 490 ${y2}"
             stroke-width="${width.toFixed(2)}" opacity="0.75"></path>`;
  }).join("");

  const node = (list, name, x, anchor) => {
    const y = yOf(list, name, list.length);
    const cls = worst.get(name) ? sevClass(worst.get(name)) : "";
    return `<circle class="node ${cls}" cx="${x}" cy="${y}" r="4" stroke-width="1.5"></circle>
            <text x="${anchor === "end" ? x - 10 : x + 10}" y="${y + 3.5}"
                  text-anchor="${anchor}">${esc(name)}</text>`;
  };

  map.innerHTML = `<div class="netmap">
    <svg viewBox="0 0 680 ${height}" role="img"
         aria-label="Observed flows from source addresses on the left to destinations on the right">
      <text class="head" x="10" y="18">FROM</text>
      <text class="head" x="670" y="18" text-anchor="end">TO</text>
      ${edges}
      ${sources.map((s) => node(sources, s, 190, "end")).join("")}
      ${targets.map((t) => node(targets, t, 490, "start")).join("")}
    </svg></div>`;

  $("net-legend").innerHTML = `<div class="legend">
    <span>Line thickness is packet count</span>
    <span>Colour is the worst finding recorded against that source</span>
    <span>Each line is one direction — A→B and B→A are counted separately and never merged</span>
    <span>Showing the ${top.length} busiest of the ${flows.length} most recent flows</span>
  </div>`;

  empty.innerHTML = "";
  body.innerHTML = top.map((f) => {
    const sev = worst.get(f.source);
    return `
    <tr class="row ${sev ? sevClass(sev) : ""}" data-host="${esc(f.source)}">
      <td class="mono">${esc(f.source)}</td>
      <td class="mono">${esc(f.destination)}</td>
      <td>${esc(f.protocol || "—")}</td>
      <td class="num mono">${f.destination_port ?? "—"}</td>
      <td class="num">${num(f.packets)}</td>
      <td class="num">${esc(bytes(f.bytes))}</td>
      <td class="num dim">${(Number(f.duration) || 0).toFixed(1)}s</td>
      <td class="dim">${sev
        ? `${esc(sevWord(sev))} finding against this source`
        : "no finding against this source"}</td>
    </tr>`;
  }).join("");
}

/* ══ ATT&CK ════════════════════════════════════════════════════════ */

function renderAttack(alerts, catalog, unmapped) {
  const seen = new Map();
  const severityOf = new Map();
  for (const a of alerts) {
    if (!a.technique) continue;
    seen.set(a.technique, (seen.get(a.technique) || 0) + 1);
    if ((SEV_RANK[a.severity] ?? -1) > (SEV_RANK[severityOf.get(a.technique)] ?? -1)) {
      severityOf.set(a.technique, a.severity);
    }
  }

  $("atk-count").textContent = `${seen.size} of ${catalog.length} observed`;
  $("nav-attack").textContent = seen.size || "";

  const byTactic = new Map();
  for (const t of catalog) {
    const tactic = t.tactic || "Other";
    if (!byTactic.has(tactic)) byTactic.set(tactic, []);
    byTactic.get(tactic).push(t);
  }

  // Order tactics the way an intrusion progresses, not alphabetically.
  const order = (tactic) => {
    const i = CHAIN.findIndex((s) => s.match.test(tactic));
    return i === -1 ? CHAIN.length : i;
  };
  const tactics = [...byTactic.entries()].sort((a, b) => order(a[0]) - order(b[0]));

  $("atk-tactics").innerHTML = `<div class="tactics">${tactics.map(([tactic, techs]) => {
    const hits = techs.filter((t) => seen.has(t.technique_id)).length;
    return `
    <div class="tactic ${hits ? "hit" : ""}">
      <div class="tactic-h"><b>${esc(tactic)}</b><span>${hits}/${techs.length}</span></div>
      ${techs.map((t) => {
        const count = seen.get(t.technique_id);
        const cls = count ? `seen ${sevClass(severityOf.get(t.technique_id))}` : "";
        return `
        <article class="tech ${cls}">
          ${count ? `<span class="tech-badge">${count}×</span>` : ""}
          <span class="tech-id">${esc(t.technique_id)}</span>
          <b>${esc(t.name)}</b>
          <p>${esc(t.description)}</p>
        </article>`;
      }).join("")}
    </div>`;
  }).join("")}</div>`;

  const host = $("atk-unmapped");
  if (!unmapped.length) {
    host.innerHTML = emptyState("○", "Nothing unmapped",
      "Every recorded finding either evidences a named technique or none have been recorded yet.");
    return;
  }
  host.innerHTML = `<dl class="facts">${unmapped.map((u) => `
    <div>
      <dt>${esc(threatLabel(u.threat))}${
        u.signal?.reason ? `<br><span class="more">${esc(u.signal.reason)}</span>` : ""}</dt>
      <dd>${num(u.count)}</dd>
    </div>`).join("")}</dl>`;
}

/* ══ Analytics ═════════════════════════════════════════════════════ */

const facts = (pairs) => pairs
  .map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");

/* All three detection layers and which of them is carrying the sensor right
 * now. NEMOS is deliberately not ML-dependent: rules and the statistical
 * baseline run whether or not a model exists, and saying so is the point --
 * "no model" must never be read as "no detection". */
function layerList(analysis) {
  const boot = analysis.bootstrap || {};
  const mlOn = Boolean(analysis.model?.available);
  const rows = [
    ["on", "Deterministic rules", "active"],
    ["on", "Behavioural baseline", analysis.enabled === false ? "inactive" : "active"],
    [mlOn ? "on" : "off", "ML anomaly model",
     mlOn ? "active" : (ML_LABEL[boot.state] || boot.state || "no model").toLowerCase()],
  ];
  return `<ul class="layers">${rows.map(([cls, name, note]) => `
    <li class="${cls}"><span class="tick" aria-hidden="true">${cls === "on" ? "✓" : "○"}</span>
      <b>${esc(name)}</b><span>${esc(note)}</span></li>`).join("")}</ul>`;
}

function renderModel(analysis) {
  const host = $("ml-summary");
  const boot = analysis.bootstrap || {};
  const modelState = boot.state || "NO_MODEL";
  const meta = analysis.model?.metadata || {};

  $("ml-state").textContent = ML_LABEL[modelState] || modelState;
  $("ml-state").className = `chip ${ML_TONE[modelState] || ""}`;

  if (analysis.enabled === false) {
    host.innerHTML = `<div class="notice warn"><b>Windowed analysis is switched off</b>
      <p>${esc(sentence(analysis.reason) || "Not enabled.")}
         Set <code>NEMOS_ANALYSIS=true</code> to turn on flow aggregation, feature
         extraction and model scoring. Deterministic rules are unaffected.</p>
      </div>${layerList(analysis)}`;
    return;
  }

  if (analysis.model?.available) {
    // Only ever reached when a real forest was fitted, validated and loaded.
    host.innerHTML = `<dl class="facts">${facts([
      ["Status", ML_LABEL[modelState] || modelState],
      ["Algorithm", boot.algorithm || "Isolation Forest"],
      ["Model file", "anomaly_model.joblib"],
      ["Trained", meta.trained_at ? ago(meta.trained_at) : "—"],
      ["Trained on", `${num(meta.samples)} windows`],
      ["Window length", `${analysis.window_seconds ?? "—"} seconds`],
      ["Feature schema", analysis.model.schema_version ?? "—"],
      ["Windows scored so far", num(analysis.model.scored_windows)],
      ["Where it came from", boot.auto_trained
        ? "trained automatically by this sensor" : "trained out of band"],
      ["scikit-learn", meta.sklearn_version || "—"],
    ])}</dl>
    <p class="card-note">A score says how unlike the learned traffic a window is.
       It is not a probability of compromise, and on its own it never raises a
       finding above the statistical ceiling.</p>
    ${layerList(analysis)}`;
    return;
  }

  if (modelState === "NO_MODEL") {
    host.innerHTML = `<div class="notice warn"><b>Automatic training is unavailable</b>
      <p>${esc(sentence(boot.reason) || sentence(analysis.model?.reason) || "No model is loaded.")}
         You can still train one yourself with
         <code>python tools/train_model.py --source database</code>.
         NEMOS ships no pretrained model on purpose: a model fitted on another
         network describes another network's normal.</p></div>${layerList(analysis)}`;
    return;
  }

  if (modelState === "FAILED") {
    host.innerHTML = `<div class="notice bad"><b>The last training run failed</b>
      <p>${esc(sentence(boot.last_error) || "The run did not complete.")}
         Collection carries on and NEMOS will try again. Detection is unaffected.</p>
      </div>${layerList(analysis)}`;
    return;
  }

  // Warming up, training or validating. Show measured progress and nothing else.
  const need = Number(boot.samples_required) || 0;
  const have = Number(boot.samples) || 0;
  const needSeconds = Number(boot.observed_seconds_required) || 0;
  const seen = Number(boot.observed_seconds) || 0;
  host.innerHTML = `
    <dl class="facts">${facts([
      ["Status", ML_LABEL[modelState] || modelState],
      ["Clean windows collected", `${num(have)} of ${num(need)}`],
      ["Time observed", needSeconds
        ? `${duration(seen)} of ${duration(needSeconds)}` : "no minimum set"],
      ["Window length", `${analysis.window_seconds ?? "—"} seconds`],
      ["Windows excluded so far", num(boot.samples_rejected)],
      ["Model", "not active yet"],
    ])}</dl>
    <div class="progress"><i></i></div>
    <p class="card-note">NEMOS is learning what ordinary traffic looks like here.
       It keeps only the windows every detection layer judged unremarkable, so
       traffic it flagged never becomes training data. Once both thresholds are
       met it fits an Isolation Forest in the background. Rules and the
       behavioural baseline are already protecting this network in the meantime.</p>
    ${layerList(analysis)}`;

  const bar = host.querySelector(".progress i");
  const byTime = needSeconds ? Math.min(1, seen / needSeconds) : 1;
  const byRows = need ? Math.min(1, have / need) : 1;
  setPct(bar, Math.min(byTime, byRows) * 100);
}

function renderModelHealth(analysis) {
  const host = $("ml-health");
  const health = analysis?.model?.health;
  if (!analysis.model?.available || !health) {
    host.innerHTML = `<div class="notice"><b>Nothing to report yet</b>
      <p>Model health is measured against traffic a loaded model has scored.
         There is no active model, so there is nothing to compare.</p></div>`;
    return;
  }

  const problems = [health.drifted && "drifted", health.stale && "stale",
                    health.score_inflated && "calibration suspect"].filter(Boolean);
  // drift_comparable stays null until the sensor has scored enough windows to
  // run the comparison at all. Saying "still describes the traffic" before
  // then would report a verdict nothing has reached.
  const assessed = health.drift_comparable !== null && health.drift_comparable !== undefined;
  const tone = problems.length ? "warn" : assessed ? "good" : "";
  const headline = problems.length
    ? `This model should be retrained (${problems.join(", ")})`
    : assessed
      ? "This model still describes the traffic it is scoring"
      : "Not enough scored traffic yet to judge this model";

  host.innerHTML = `
    <div class="notice ${tone}"><b>${esc(headline)}</b>
      <p>${health.reasons?.length
        ? esc(health.reasons.map(sentence).join(" "))
        : "No drift, staleness or calibration problem has been measured."}</p></div>
    <dl class="facts">${facts([
      ["Windows scored", num(health.scored_windows)],
      ["Model age", health.age_days == null ? "—" : `${health.age_days} days`],
      ["Trained on", `${num(health.training_samples)} windows`],
      ["Features that drifted", health.drifted_features?.length
        ? health.drifted_features.map((f) => f.feature ?? f).join(", ") : "none"],
      ["Share scored anomalous", health.anomalous_fraction == null
        ? "not enough data yet" : `${(health.anomalous_fraction * 100).toFixed(1)}%`],
      ["Drift comparable", health.drift_comparable === null
        ? "not yet assessed" : (health.drift_comparable ? "yes" : "no — feature widths differ")],
    ])}</dl>`;
}

function renderBaselines(baselines) {
  const host = $("ml-baselines");
  $("base-count").textContent = `${baselines.length} tracked`;
  if (!baselines.length) {
    host.innerHTML = emptyState("◍", "No baselines yet",
      "Each address needs several windows of its own history before it can be compared against itself.");
    return;
  }
  const peak = Math.max(1, ...baselines.map((b) => Number(b.strongest_sigma) || 0));
  host.innerHTML = `<ul class="bars">${baselines.slice(0, 25).map((b) => {
    const sigma = Number(b.strongest_sigma) || 0;
    const band = sigma >= 6 ? "CRITICAL" : sigma >= 4 ? "HIGH" : sigma >= 2 ? "MEDIUM" : "LOW";
    return `
    <li class="${sevClass(band)}" data-host="${esc(b.source)}">
      <span class="lbl mono">${esc(b.source)}</span>
      <span class="bar"><i></i></span>
      <span class="n">${sigma.toFixed(1)}σ</span>
    </li>`;
  }).join("")}</ul>
  <p class="card-note">Sigma is how far an address has moved from its own recent
     history. Two sigma is mildly unusual; six is far outside what that address
     normally does. It describes change, not intent.</p>`;

  const bars = host.querySelectorAll(".bars .bar i");
  baselines.slice(0, 25).forEach((b, i) =>
    setPct(bars[i], ((Number(b.strongest_sigma) || 0) / peak) * 100));
}

function renderAnomalies(anomalies) {
  const host = $("ml-anomalies");
  if (!anomalies.length) {
    host.innerHTML = emptyState("◌", "No scored windows yet",
      "Windows appear here once flow analysis has completed a cycle with traffic in it.");
    return;
  }
  host.innerHTML = `<div class="tablewrap"><table class="table"><thead><tr>
      <th>Address</th><th>Verdict</th><th class="num">Risk</th>
      <th class="num">Anomaly score</th><th>Baseline</th><th>Layers that agreed</th>
    </tr></thead><tbody>${anomalies.slice(0, 25).map((a) => `
      <tr class="${sevClass(a.severity)}">
        <td class="mono">${esc(a.source)}</td>
        <td>${esc(threatLabel(a.verdict))}</td>
        <td class="num score">${esc(a.risk_score)}</td>
        <td class="num dim">${a.anomaly_score == null ? "not scored" : esc(a.anomaly_score)}</td>
        <td class="dim">${esc(threatLabel(a.baseline_state))}</td>
        <td class="dim">${esc((a.detection_layers || []).join(", ") || "—")}</td>
      </tr>`).join("")}</tbody></table></div>`;
}

/* ══ Sensor ════════════════════════════════════════════════════════ */

function renderSensor(data, status) {
  const capture = status.capture || data.capture || {};
  const w = status.writer || {};
  const analysis = status.analysis || {};
  const flows = analysis.flows || {};

  $("sensor-grid").innerHTML = `<div class="panels">
    <section>
      <h3>Capture</h3>
      <dl class="facts">${facts([
        ["State", captureLabel(capture)],
        ["Running", capture.running ? "yes" : "no"],
        ["Interface", capture.interface || "auto-selected"],
        ["Packets seen", num(capture.packets_seen)],
        ["Last packet", capture.last_packet ? ago(capture.last_packet) : "—"],
        ["Error", capture.error || "none"],
      ])}</dl>
    </section>
    <section>
      <h3>Storage</h3>
      <dl class="facts">${facts([
        ["Writer thread alive", w.thread_alive ? "yes" : "no"],
        ["Queue", `${num(w.queue_depth)} of ${num(w.queue_capacity)}`],
        ["Queue high-water", num(w.queue_high_watermark)],
        ["Batches written", num(w.batches_written)],
        ["Dropped traffic rows", num(w.dropped_traffic)],
        ["Dropped findings", num(w.dropped_alerts)],
        ["Write errors", num(w.write_errors)],
      ])}</dl>
    </section>
    <section>
      <h3>Flow analysis</h3>
      ${analysis.enabled === false
        ? `<div class="notice"><b>Switched off</b><p>${
            esc(sentence(analysis.reason) || "Not enabled.")}</p></div>`
        : `<dl class="facts">${facts([
            ["Running", analysis.running ? "yes" : "no"],
            ["Window length", `${analysis.window_seconds ?? "—"} seconds`],
            ["Cycles completed", num(analysis.cycles)],
            ["Findings raised here", num(analysis.alerts_emitted)],
            ["Repeats suppressed", num(analysis.suppressed)],
            ["Open flows", `${num(flows.active_flows)} of ${num(flows.max_flows)}`],
            ["Flows evicted", num(flows.evicted)],
          ])}</dl>`}
    </section>
  </div>`;

  const n = status.notifications || {};
  const host = $("sensor-notify");
  if (!n.enabled || !n.active) {
    const configured = [n.telegram_configured && "Telegram",
                        n.webhook_configured && "a webhook"].filter(Boolean);
    host.innerHTML = `<div class="notice"><b>Nothing is being sent out</b>
      <p>${configured.length
        ? `${esc(configured.join(" and "))} ${configured.length > 1 ? "are" : "is"} configured, but delivery is not running.`
        : "No outbound channel is configured."}
         Findings are still recorded and shown here — only the outbound copy is
         affected. Set <code>TELEGRAM_BOT_TOKEN</code> and
         <code>TELEGRAM_CHAT_ID</code>, or <code>NEMOS_WEBHOOK_URL</code>.</p></div>`;
    return;
  }
  host.innerHTML = `<dl class="facts">${facts([
    ["Channels", Object.keys(n.channels || {}).join(", ") || "none"],
    ["Sending to chat", n.chat_id || "—"],
    ["Accepted", num(n.accepted)],
    ["Delivered", num(n.delivered)],
    ["Failed", num(n.failed)],
    ["Held back — below severity floor", num(n.suppressed_severity)],
    ["Held back — cooldown", num(n.suppressed_cooldown)],
    ["Held back — rate limit", num(n.suppressed_rate)],
    ["Waiting in queue", num(n.queue_depth)],
  ])}</dl>`;
}

/* ══ Settings ══════════════════════════════════════════════════════ */

/* ══ Telegram pairing ══════════════════════════════════════════════
 * The whole point of this panel is that the operator never handles a
 * credential. It shows the public t.me link as a QR code, a countdown to when
 * that code dies, and which chats are linked. The bot token is not in any
 * response this page reads.
 */
function renderTelegram(pairing) {
  const host = $("sensor-telegram");
  if (!host) return;
  state.pairing = pairing || null;
  const p = pairing || {};
  const parts = [];

  if (!p.available) {
    parts.push(`<div class="notice"><b>Telegram pairing is not configured</b>
      <p>${esc(p.error || "This deployment has not set up a Telegram bot.")}
         An administrator sets <code>TELEGRAM_BOT_TOKEN</code> and
         <code>TELEGRAM_BOT_USERNAME</code> once, on the server. You are never
         asked for either.</p></div>`);
  }

  const linked = p.linked || [];
  if (linked.length) {
    parts.push(`<div class="notice good"><b>Connected</b>
      <p>${linked.length} chat${linked.length === 1 ? "" : "s"} will receive
         security notifications: ${linked.map((l) =>
           esc(l.label ? `${l.label} (${l.chat_id})` : l.chat_id)).join(", ")}.</p></div>`);
  } else if (p.available) {
    parts.push(`<div class="notice"><b>No chat is linked yet</b>
      <p>Press “Generate code”, then scan the QR code with the Telegram app and
         press Start. Nothing is sent to Telegram until a chat is linked.</p></div>`);
  }

  if (state.pairCode) {
    parts.push(`<div class="qr-pair">
      <div class="qr-image">${state.pairCode.qr_svg}</div>
      <div class="qr-detail">
        <p class="lead">Scan with Telegram to connect NEMOS</p>
        <p class="mono">${esc(state.pairCode.link)}</p>
        <p>Expires in <span id="tg-countdown">—</span>. The code works once.</p>
      </div>
    </div>`);
  } else if (p.pending) {
    parts.push(`<div class="notice"><b>A pairing code is outstanding</b>
      <p>It was generated in another session, so it cannot be shown again.
         Press “Generate code” to replace it with one you can scan.</p></div>`);
  }

  host.innerHTML = parts.join("");
  updatePairCountdown();
}

function updatePairCountdown() {
  const el = $("tg-countdown");
  if (!el) return;
  if (!state.pairCode) { el.textContent = "—"; return; }
  const left = Math.max(0, Math.round(state.pairCode.expires_at * 1000 - Date.now()) / 1000);
  if (left <= 0) {
    // A dead code must stop looking scannable: the server will reject it.
    state.pairCode = null;
    renderTelegram(state.pairing);
    return;
  }
  const m = Math.floor(left / 60);
  const sec = Math.floor(left % 60);
  el.textContent = `${m}:${String(sec).padStart(2, "0")}`;
}

async function loadTelegram() {
  try {
    renderTelegram(await api("/api/telegram/pair"));
  } catch {
    renderTelegram({ available: false, error: "Could not read pairing state." });
  }
}

function renderSettings(status) {
  const analysis = status.analysis || {};
  const rate = status.rate_limit || {};

  $("settings-body").innerHTML = `<dl class="facts">${facts([
    ["Theme", document.documentElement.dataset.theme === "light" ? "Light" : "Dark"],
    ["Live refresh", state.live ? "on, every 5 seconds" : "paused"],
    ["API token", getToken() ? "saved in this browser" : "not set"],
    ["Rows per page", String(PAGE)],
  ])}</dl>
  <p class="card-note">Theme and token are kept in this browser's local storage
     and never sent anywhere except back to this sensor.</p>`;

  $("settings-config").innerHTML = `<dl class="facts">${facts([
    ["NEMOS version", status.version || "—"],
    ["Analysis window", analysis.window_seconds ? `${analysis.window_seconds} seconds` : "—"],
    ["Flow table limit", num(analysis.flows?.max_flows)],
    ["Automatic ML training", analysis.bootstrap?.enabled ? "on" : "off"],
    ["Clean windows before first fit", num(analysis.bootstrap?.samples_required)],
    ["Observation period required", analysis.bootstrap?.observed_seconds_required
      ? duration(analysis.bootstrap.observed_seconds_required) : "—"],
    ["Retrain every", analysis.bootstrap?.retrain_seconds
      ? duration(analysis.bootstrap.retrain_seconds) : "never"],
    ["Request limit", `${num(rate.general_per_minute)} per minute`],
    ["Failed-auth limit", `${num(rate.auth_failures_per_minute)} per minute`],
    ["AI analyst", status.analyst?.available ? "configured" : "not configured"],
  ])}</dl>`;
}

/* ══ Evidence drawer ═══════════════════════════════════════════════ */

function openDrawer(alert) {
  if (!alert) return;
  $("drawer-kicker").textContent = "Evidence";
  $("drawer-title").textContent = threatLabel(alert.threat);
  $("drawer-sub").textContent =
    `${alert.threat} · ${alert.source} · ${clock(alert.timestamp)}`;

  const evidence = evidenceOf(alert);
  const parts = [];

  parts.push(`<div class="sect"><h3>Why this fired</h3>
    <p class="reason">${esc(sentence(alert.reason))}</p></div>`);

  parts.push(`<div class="sect"><h3>Assessment</h3><dl class="kv">
    ${[["Severity", sevWord(alert.severity)],
       ["Risk score", `${alert.risk_score} out of 100`],
       ["Confidence", `${alert.confidence}%`],
       ["Category", threatLabel(alert.category)],
       ["Found by", methodOf(alert)],
       ["Source address", alert.source],
       ["Destination", destinationOf(alert) || "not applicable to this finding"],
       ["Incident", alert.incident_id || "—"],
       ["Status", alert.acknowledged ? "Acknowledged" : "Open"],
       ["Observed", alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "—"],
      ].map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}
    </dl></div>`);

  if (alert.attack?.mapped) {
    parts.push(`<div class="sect"><h3>ATT&amp;CK technique</h3><dl class="kv">
      <div><dt>Technique</dt><dd><a href="${esc(alert.attack.url)}" rel="noreferrer noopener">${esc(alert.attack.technique_id)}</a></dd></div>
      <div><dt>Name</dt><dd>${esc(alert.attack.name)}</dd></div>
      <div><dt>Tactic</dt><dd>${esc(alert.attack.tactic)}</dd></div>
      </dl><p class="reason">${esc(alert.attack.description)}</p></div>`);
  } else {
    parts.push(`<div class="sect"><h3>ATT&amp;CK technique</h3>
      <p class="reason">None. ${esc(alert.signal?.reason
        || "This finding evidences unusual behaviour but not one specific technique, so NEMOS deliberately does not name one.")}</p></div>`);
  }

  // Beaconing earns a plot: regularity *is* the finding, and it is far easier
  // to see than to read as a list of numbers.
  const gaps = evidence && Array.isArray(evidence.intervals_seconds) ? evidence.intervals_seconds : null;
  if (gaps && gaps.length) {
    parts.push(`<div class="sect"><h3>Time between contacts</h3>
      <div class="beacon">${gaps.map(() => "<i></i>").join("")}</div>
      <p class="beacon-cap">Each bar is the gap between two consecutive contacts.
         Mean ${esc(evidence.mean_interval_seconds)}s, jitter ratio
         ${esc(evidence.jitter_ratio)} against a threshold of ${esc(evidence.jitter_threshold)}.
         Bars of near-equal height are what makes this a beacon rather than
         ordinary traffic — software keeps time far more precisely than a person does.</p></div>`);
  }

  if (evidence) {
    parts.push(`<div class="sect"><h3>Raw evidence</h3>
      <pre class="json">${esc(JSON.stringify(evidence, null, 2))}</pre></div>`);
  }

  $("drawer-body").innerHTML = parts.join("");

  if (gaps && gaps.length) {
    const peak = Math.max(...gaps, 1);
    $("drawer-body").querySelectorAll(".beacon i")
      .forEach((bar, i) => setPct(bar, (gaps[i] / peak) * 100));
  }

  $("drawer").hidden = false;
  $("scrim").hidden = false;
  $("drawer-close").focus();
}

function closeDrawer() {
  $("drawer").hidden = true;
  $("scrim").hidden = true;
}

/* ══ Command palette ═══════════════════════════════════════════════ */

function paletteItems(query) {
  const q = query.trim().toLowerCase();
  const items = VIEWS.map((v) => ({ label: TITLES[v][0], hint: "view", action: () => go(v) }));

  for (const host of (state.data?.hosts || []).slice(0, 40)) {
    items.push({
      label: host.host, hint: "address",
      action: () => { state.hostFilter = host.host; $("host-search").value = host.host; go("hosts"); },
    });
  }
  for (const threat of [...new Set(state.alerts.map((a) => a.threat))]) {
    items.push({
      label: threatLabel(threat), hint: "threat",
      action: () => {
        state.detFilter.text = threat;
        $("det-search").value = threat;
        state.detPage = 0;
        go("detections");
        renderDetections();
      },
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
    </li>`).join("") || `<li class="dim">Nothing matches</li>`;
  renderPalette._items = items;
}

function togglePalette(open) {
  $("palette").hidden = !open;
  if (open) {
    $("palette-input").value = "";
    state.paletteIndex = 0;
    renderPalette();
    $("palette-input").focus();
  }
}

/* ══ Routing ═══════════════════════════════════════════════════════ */

function go(view) {
  if (!VIEWS.includes(view)) view = "overview";
  state.view = view;
  if (location.hash.slice(1) !== view) location.hash = view;

  for (const v of VIEWS) $(`view-${v}`).hidden = v !== view;
  for (const link of document.querySelectorAll(".nav-link")) {
    link.classList.toggle("on", link.dataset.view === view);
  }
  const [title, sub] = TITLES[view];
  $("view-title").textContent = title;
  $("view-sub").textContent = sub;
  window.scrollTo({ top: 0 });
}

/* ══ Paint ═════════════════════════════════════════════════════════ */

function paint() {
  const data = state.data;
  if (!data) return;
  const status = state.status || {};
  const analysis = status.analysis || {};
  const capture = status.capture || data.capture || {};

  renderBanner(state.alerts, capture);
  renderKpis(data.stats || {}, capture);
  renderTimeline(state.alerts);
  renderOverviewFeed();
  renderOverviewIncidents(state.incidents);

  renderIncidents(state.incidents);
  renderDetections();
  renderHosts(data.hosts || []);
  renderNetwork(state.flows);
  renderAttack(state.alerts, state.catalog, state.unmapped);

  renderModel(analysis);
  renderModelHealth(analysis);
  renderBaselines(state.baselines);
  renderAnomalies(state.anomalies);

  renderSensor(data, status);
  renderSettings(status);
  loadTelegram();

  // Rail footer: sensor status, capture interface, system health, last update.
  const dot = $("conn-dot");
  dot.className = `dot ${capture.running ? "ok" : capture.error ? "bad" : "warn"}`;
  $("conn-text").textContent = capture.running ? "Capturing"
    : captureLabel(capture) === "Off" ? "Not capturing" : captureLabel(capture);
  $("conn-sub").textContent = capture.interface || "no interface";
  $("foot-iface").textContent = capture.interface || "—";

  const writer = status.writer || {};
  const unhealthy = [
    Boolean(capture.error),
    writer.thread_alive === false,
    Number(writer.write_errors) > 0,
    Number(writer.dropped_alerts) > 0,
  ].filter(Boolean).length;
  $("foot-health").textContent = unhealthy
    ? `${unhealthy} problem${unhealthy === 1 ? "" : "s"}` : "all clear";
  $("foot-updated").textContent = new Date().toLocaleTimeString();
  $("updated-at").textContent = new Date().toLocaleTimeString();
}

async function refresh() {
  try {
    // Risk-ordered on the server: sorting a page the client already holds
    // cannot change which rows are on it, so the worst finding has to be put
    // on page one before it is sent.
    const [dash, alerts, incidents, catalog, status] = await Promise.all([
      api("/api/dashboard"),
      api("/api/alerts?limit=500&sort=risk"),
      api("/api/incidents?limit=200&sort=risk"),
      api("/api/techniques"),
      api("/api/status"),
    ]);
    state.data = dash;
    state.alerts = Array.isArray(alerts) ? alerts : [];
    state.incidents = Array.isArray(incidents) ? incidents : [];
    state.catalog = catalog.techniques || [];
    state.unmapped = catalog.unmapped || [];
    state.status = status;

    // These three back one view each, and two of them answer 503 when
    // analysis is off. Fetch them only when their view is on screen.
    if (state.view === "network") {
      const flows = await api("/api/flows?limit=200");
      state.flows = Array.isArray(flows) ? flows : [];
    }
    if (state.view === "analytics") {
      const [baselines, anomalies] = await Promise.all([
        api("/api/baselines?limit=50"),
        api("/api/anomalies?limit=50"),
      ]);
      state.baselines = Array.isArray(baselines) ? baselines : [];
      state.anomalies = Array.isArray(anomalies) ? anomalies : [];
    }

    refreshThreatFilter();
    $("authbar").hidden = true;
    $("live-status").className = state.live ? "livechip live" : "livechip paused";
    $("live-state").textContent = state.live ? "Live" : "Paused";
    paint();
  } catch (error) {
    if (String(error.message) !== "unauthorized") {
      $("conn-dot").className = "dot bad";
      $("conn-text").textContent = "Disconnected";
      $("conn-sub").textContent = "retrying";
      $("live-status").className = "livechip down";
      $("live-state").textContent = "Offline";
    }
  }
}

/* ══ Wiring ════════════════════════════════════════════════════════ */

const alertById = (id) => state.alerts.find((a) => String(a.id) === String(id));

function toggleGroup(key) {
  if (state.expanded.has(key)) state.expanded.delete(key);
  else state.expanded.add(key);
  renderDetections();
}

function bindSeverity(id, apply) {
  $(id).addEventListener("click", (e) => {
    const button = e.target.closest("[data-sev]");
    if (!button) return;
    for (const seg of $(id).children) seg.classList.toggle("on", seg === button);
    apply(button.dataset.sev);
  });
}

function init() {
  try {
    const saved = localStorage.getItem("nemos.theme");
    if (saved) document.documentElement.dataset.theme = saved;
  } catch { /* private mode */ }

  $("theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("nemos.theme", next); } catch { /* private mode */ }
    if (state.status) renderSettings(state.status);
  });

  window.addEventListener("hashchange", () => { go(location.hash.slice(1)); refresh(); });
  go(location.hash.slice(1) || "overview");

  $("live-toggle").addEventListener("click", () => {
    state.live = !state.live;
    $("live-toggle").setAttribute("aria-pressed", String(state.live));
    $("live-label").textContent = state.live ? "Pause" : "Resume";
    $("live-status").className = state.live ? "livechip live" : "livechip paused";
    $("live-state").textContent = state.live ? "Live" : "Paused";
    if (state.live) refresh();
  });
  $("refresh-now").addEventListener("click", refresh);

  $("tg-pair").addEventListener("click", async () => {
    const button = $("tg-pair");
    button.disabled = true;
    try {
      const result = await apiSend("/api/telegram/pair", "POST");
      state.pairCode = result;
      renderTelegram(state.pairing);
      toast("Scan the code with Telegram");
    } catch (err) {
      toast(err.message || "Could not generate a pairing code");
      await loadTelegram();
    } finally {
      button.disabled = false;
    }
  });

  $("tg-test").addEventListener("click", async () => {
    const button = $("tg-test");
    button.disabled = true;
    try {
      const result = await apiSend("/api/telegram/test", "POST");
      toast(`Test notification sent to ${result.sent} chat(s)`);
    } catch (err) {
      toast(err.message || "Could not send a test notification");
    } finally {
      button.disabled = false;
    }
  });

  // The countdown is the only thing on this page that has to tick on its own.
  setInterval(updatePairCountdown, 1000);

  $("token-save").addEventListener("click", () => {
    setToken($("token-input").value.trim());
    $("token-input").value = "";
    toast("Token saved");
    refresh();
  });
  $("token-clear").addEventListener("click", () => {
    setToken(""); toast("Token cleared"); refresh();
  });

  // Overview filters
  $("ov-search").addEventListener("input", (e) => {
    state.ovFilter.text = e.target.value; renderOverviewFeed();
  });
  bindSeverity("ov-severity", (sev) => { state.ovFilter.severity = sev; renderOverviewFeed(); });
  $("ov-range").addEventListener("click", (e) => {
    const button = e.target.closest("[data-range]");
    if (!button) return;
    for (const seg of $("ov-range").children) seg.classList.toggle("on", seg === button);
    state.ovRange = Number(button.dataset.range);
    renderTimeline(state.alerts);
  });

  // Detection filters
  $("det-search").addEventListener("input", (e) => {
    state.detFilter.text = e.target.value; state.detPage = 0; renderDetections();
  });
  $("det-threat").addEventListener("change", (e) => {
    state.detFilter.threat = e.target.value; state.detPage = 0; renderDetections();
  });
  $("det-sort").addEventListener("change", (e) => {
    state.detFilter.sort = e.target.value; state.detPage = 0; renderDetections();
  });
  bindSeverity("det-severity", (sev) => {
    state.detFilter.severity = sev; state.detPage = 0; renderDetections();
  });
  $("det-prev").addEventListener("click", () => {
    state.detPage = Math.max(0, state.detPage - 1); renderDetections();
  });
  $("det-next").addEventListener("click", () => { state.detPage += 1; renderDetections(); });

  // Host filters
  $("host-search").addEventListener("input", (e) => {
    state.hostFilter = e.target.value; state.hostPage = 0; renderHosts(state.data?.hosts || []);
  });
  $("host-prev").addEventListener("click", () => {
    state.hostPage = Math.max(0, state.hostPage - 1); renderHosts(state.data?.hosts || []);
  });
  $("host-next").addEventListener("click", () => {
    state.hostPage += 1; renderHosts(state.data?.hosts || []);
  });

  document.addEventListener("click", (e) => {
    // Group headers expand in place. Checked before [data-alert] so a click on
    // a collapsed campaign opens it rather than jumping into one member.
    const groupRow = e.target.closest("[data-group]");
    if (groupRow) { toggleGroup(groupRow.dataset.group); return; }

    const alertRow = e.target.closest("[data-alert]");
    if (alertRow) { openDrawer(alertById(alertRow.dataset.alert)); return; }

    const hostRow = e.target.closest("[data-host]");
    if (hostRow) {
      state.detFilter.text = hostRow.dataset.host;
      state.detFilter.severity = "ALL";
      $("det-search").value = hostRow.dataset.host;
      state.detPage = 0;
      go("detections");
      renderDetections();
      return;
    }

    const incidentRow = e.target.closest("[data-incident]");
    if (incidentRow) {
      const first = state.alerts.find((a) => a.incident_id === incidentRow.dataset.incident);
      if (first) openDrawer(first);
      else toast("No stored finding for that incident");
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const key = e.target.dataset?.group;
    if (key) { toggleGroup(key); return; }
    if (e.target.dataset?.alert) openDrawer(alertById(e.target.dataset.alert));
  });

  $("drawer-close").addEventListener("click", closeDrawer);
  $("scrim").addEventListener("click", closeDrawer);

  $("open-palette").addEventListener("click", () => togglePalette(true));
  $("palette-input").addEventListener("input", () => { state.paletteIndex = 0; renderPalette(); });
  $("palette-list").addEventListener("click", (e) => {
    const li = e.target.closest("[data-index]");
    if (!li) return;
    renderPalette._items[Number(li.dataset.index)].action();
    togglePalette(false);
  });
  $("palette").addEventListener("click", (e) => {
    if (e.target === $("palette")) togglePalette(false);
  });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault(); togglePalette($("palette").hidden); return;
    }
    if (e.key === "Escape") { togglePalette(false); closeDrawer(); return; }
    if ($("palette").hidden) return;
    const items = renderPalette._items || [];
    if (e.key === "ArrowDown") {
      e.preventDefault();
      state.paletteIndex = Math.min(items.length - 1, state.paletteIndex + 1);
      renderPalette();
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      state.paletteIndex = Math.max(0, state.paletteIndex - 1);
      renderPalette();
    }
    if (e.key === "Enter" && items[state.paletteIndex]) {
      items[state.paletteIndex].action();
      togglePalette(false);
    }
  });

  refresh();
  setInterval(() => { if (state.live && !document.hidden) refresh(); }, 5000);
}

document.addEventListener("DOMContentLoaded", init);
