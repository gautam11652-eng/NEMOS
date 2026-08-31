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
  if (token) headers.Authorization = `Bearer ${token}`;
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

function renderKpis(stats, capture) {
  const cards = [
    { k: "Packets", v: num(stats.packets), s: capture?.running ? "capturing" : "capture stopped" },
    { k: "TCP", v: num(stats.tcp), s: pct(stats.tcp, stats.packets) },
    { k: "UDP", v: num(stats.udp), s: pct(stats.udp, stats.packets) },
    { k: "DNS", v: num(stats.dns), s: pct(stats.dns, stats.packets) },
    { k: "Findings", v: num(stats.threats), s: "all severities" },
    { k: "Critical", v: num(stats.critical), s: "needs review", alarm: Number(stats.critical) > 0 },
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
  return `<div class="feed">${alerts.slice(0, limit).map((a) => `
    <div class="feed-row row ${sevClass(a.severity)}" data-alert="${esc(a.id)}" tabindex="0" role="button">
      <span class="feed-t">${esc(clock(a.timestamp))}</span>
      <span class="feed-main">
        <b>${esc(a.threat)}</b>
        <span>${esc(a.source)} · ${esc(a.reason)}</span>
      </span>
      <span class="score">${esc(a.risk_score)}</span>
    </div>`).join("")}</div>`;
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
  body.innerHTML = incidents.map((i) => `
    <tr class="row ${sevClass(i.severity)}" data-incident="${esc(i.incident_id)}">
      <td class="mono">${esc(i.incident_id)}</td>
      <td class="mono">${esc(i.sources)}</td>
      <td class="wrap dim">${esc(i.threats)}</td>
      <td class="num">${num(i.alert_count)}</td>
      <td class="num score">${esc(i.max_risk)}</td>
      <td><span class="sev">${esc(i.severity)}</span></td>
      <td class="dim">${esc(ago(i.last_seen))}</td>
    </tr>`).join("");
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
  const rows = filteredDetections();
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  state.detPage = Math.min(state.detPage, pages - 1);
  const page = rows.slice(state.detPage * PAGE, state.detPage * PAGE + PAGE);

  $("det-count").textContent = `${rows.length} of ${state.alerts.length}`;
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

  body.innerHTML = page.map((a) => `
    <tr class="row ${sevClass(a.severity)}" data-alert="${esc(a.id)}">
      <td class="dim mono">${esc(clock(a.timestamp))}</td>
      <td><b>${esc(a.threat)}</b><br><span class="dim">${esc(a.reason)}</span></td>
      <td class="mono">${esc(a.source)}</td>
      <td class="num score">${esc(a.risk_score)}</td>
      <td class="num dim">${esc(a.confidence)}%</td>
      <td class="mono dim">${esc(a.technique || "—")}</td>
      <td><span class="sev">${esc(a.severity)}</span></td>
    </tr>`).join("");
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

  // ML model. Each branch is a real state the sensor can be in, and says what
  // to do about it rather than rendering a row of dashes.
  const analysis = status.analysis || {};
  const model = $("sensor-model");
  if (analysis.enabled === false) {
    model.innerHTML = `<div class="notice"><b>Windowed analysis is disabled</b>
      <p>${esc(sentence(analysis.reason) || "Not enabled.")} Set <code>NEMOS_ANALYSIS=true</code>
         to enable flow aggregation, feature extraction and model scoring.
         Deterministic rules and the statistical baseline are unaffected.</p></div>`;
  } else if (!analysis.model?.available) {
    model.innerHTML = `<div class="notice"><b>No trained model</b>
      <p>${esc(sentence(analysis.model?.reason) || "No model is loaded.")}
         Train one with <code>python tools/train_model.py --source database</code>.
         NEMOS ships no pretrained model on purpose: a model fitted on another
         network describes another network's normal.</p></div>`;
  } else {
    const meta = analysis.model.metadata || {};
    model.innerHTML = `<dl class="facts">${facts([
      ["State", "loaded"],
      ["Schema version", analysis.model.schema_version ?? "—"],
      ["Trained", meta.trained_at ? ago(meta.trained_at) : "—"],
      ["Training samples", num(meta.samples)],
      ["Window", `${analysis.window_seconds ?? "—"}s`],
      ["Windows scored", num(analysis.model.scored_windows)],
      ["scikit-learn", meta.sklearn_version || "—"],
    ])}</dl>`;
  }

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
    ? `<div class="tablewrap"><table class="table"><tbody>${(data.incidents || []).slice(0, 6).map((i) => `
        <tr class="row ${sevClass(i.severity)}" data-incident="${esc(i.incident_id)}">
          <td class="mono">${esc(i.incident_id)}</td>
          <td class="mono dim">${esc(i.sources)}</td>
          <td class="num score">${esc(i.max_risk)}</td>
          <td><span class="sev">${esc(i.severity)}</span></td>
        </tr>`).join("")}</tbody></table></div>`
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
      api("/api/alerts?limit=500"),
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
    if (e.key === "Enter" && e.target.dataset?.alert) openDrawer(alertById(e.target.dataset.alert));
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
