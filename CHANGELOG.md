# Changelog

## Unreleased

### Fixed

- **Packet capture reported the wrong problem.** On Kali the sensor showed
  `Capture: Blocked` / `CAP_NET_RAW is required` / `Packets recorded: 0` for
  what could equally have been a misspelled interface name or an uninstalled
  backend -- three problems with three unrelated fixes, all reaching the
  operator as one message that named only the least likely of them. Capture now
  runs a preflight before starting a thread and distinguishes:
  - `BLOCKED` -- the OS refused a packet socket, checked by *opening* one rather
    than by reading a capability bit, since seccomp, AppArmor, a container's
    network mode and an unprivileged userns can each refuse a process that
    appears to hold `CAP_NET_RAW`. When the capability is held and the socket is
    still refused, the message says so, because `setcap` is then the wrong fix.
  - `NO INTERFACE` -- the configured interface does not exist, reported with the
    list of ones that do.
  - `ERROR` -- a missing backend, including a Windows host with no Npcap.
  - `NO TRAFFIC` -- bound, but nothing has arrived.
  - `ONLINE` -- bound **and packets have actually arrived**.
- **`ONLINE` now requires a packet.** It was previously set on a successful
  bind. A sensor pointed at the wrong interface binds perfectly and sees
  nothing, so that reported a blind deployment as a healthy one.
- Every failure state carries one actionable sentence for the current platform,
  in the log and on the Sensor page. On Linux that is `setcap cap_net_raw+eip`
  and not "run as root": `CAP_NET_RAW` alone was measured sufficient -- capture
  reaches `ONLINE` as an unprivileged user holding only that capability -- so
  the advice no longer asks for `CAP_NET_ADMIN` as most does.
- Interfaces are enumerated (scapy's list, then `/sys/class/net`, then
  `socket.if_nameindex`) instead of assumed. No interface name is hardcoded
  anywhere in the module, and a test asserts it.

### Added

- **Telegram QR pairing.** An operator no longer pastes a bot token anywhere.
  The token is a deployment secret (`TELEGRAM_BOT_TOKEN` plus the public
  `TELEGRAM_BOT_USERNAME`), set once by whoever deploys NEMOS; operators link
  their own chat by scanning a QR code on the Sensor page. Codes are 128 bits
  from `secrets.token_urlsafe`, stored only as SHA-256 hashes, single-use,
  five-minute-lived, and redeemed inside one `BEGIN IMMEDIATE` transaction so
  two concurrent `/start` messages cannot both win. Chat ids come only from
  Telegram's own update payload. Issuing a code retires the previous one.
- **`nemos/qr.py`**, a dependency-free QR encoder (byte mode, versions 1-10,
  all four error-correction levels). Its output is pinned against an
  independent reference implementation, and the SVG the dashboard renders has
  been decoded back to the exact pairing link with a third-party decoder.
  Written rather than pulled in because NEMOS needs exactly one QR code and the
  project rule is to avoid a dependency for a single screen.
- **Structured, severity-aware alerts.** LOW is two lines; CRITICAL is a full
  incident report with detection, confidence, risk, endpoints, reasoning,
  observed counters, summarised evidence, ATT&CK technique and tactic, incident
  id and a link back to the dashboard. A field NEMOS does not have produces no
  line — not a blank, not a zero. Evidence lists are summarised rather than
  dumped, so a port scan's hundred port numbers become a count and a preview.
- **Inline actions**: Investigate, Acknowledge, Open Dashboard. Authorisation is
  re-checked when the button is pressed rather than inherited from the message
  it was attached to, so a chat unlinked after an alert was sent cannot act on
  it. Every state-changing action is written to an audit log with actor, target,
  result and timestamp, readable at `GET /api/telegram/audit`.
- **Commands**: `/status`, `/incidents`, `/critical`, `/hosts`,
  `/incident <id>`, `/brief`, `/help`, all answered from live NEMOS state. An
  unlinked chat gets pairing instructions and nothing else — not a count, not a
  host, not an incident id. Per-chat token buckets bound a flood to its own
  sender.
- **Daily security brief**, off unless `NEMOS_TELEGRAM_BRIEF_HOUR` names a UTC
  hour. Only metrics with a query behind them are printed; a section with
  nothing behind it is omitted rather than shown as zero.
- **Delivery to every paired chat.** `TELEGRAM_CHAT_ID` still works and is
  merged with the paired audience, which is read fresh on every send so a chat
  paired a minute ago does not need a restart to be alerted. One chat failing
  no longer cancels the others; only a delivery that reached nobody is a
  failure.
- `NEMOS_DASHBOARD_URL` for alert deep links, and an optional lab-only
  `NEMOS_TELEGRAM_CONTAIN_HOOK`.
- **TLS handshake fingerprinting (JA3/JA3S)**, closing the blind spot every
  metadata-only sensor has. The handshake is sent in cleartext before a session
  key exists, and what it discloses — versions, ciphers, extensions, curves —
  identifies the client *software*. Application data is never parsed and
  nothing is decrypted, so the existing claim that encrypted payloads are not
  inspected remains exactly true; the README now states the distinction rather
  than leaving "metadata-only" to imply more than it should.
- GREASE (RFC 8701) is stripped before hashing. Without it Chrome produces a
  different fingerprint on every connection, which makes JA3 actively
  misleading rather than merely useless. A test pins the property because
  nothing else would catch its loss.
- Handshakes are recognised by the TLS record header rather than by port, so
  TLS on a port it has no business using is fingerprinted like any other.
- New finding `TLS_ON_UNEXPECTED_PORT` (T1571): confirmed handshakes to an
  external host on a non-TLS port. Unlike the port-volume rule beside it, this
  knows the traffic really is TLS.
- Fingerprints and SNI are attached as evidence to every command-and-control
  finding — a beaconing alert carrying a JA3 can be pivoted on, where a
  destination address cannot.
- New settings: `NEMOS_DETECT_TLS_HORIZON`, `NEMOS_DETECT_TLS_MAX_FINGERPRINTS`,
  `NEMOS_DETECT_TLS_ODD_PORT_HANDSHAKES`, `NEMOS_DETECT_TLS_MAX_TRACKED`.

### Fixed

- The Telegram poller backed off nothing on repeated failures. An invalid token
  fails identically forever, so it logged the same warning every five seconds
  and told the operator nothing new. The wait now doubles to a five-minute
  ceiling and only the first failures are logged at warning level.

### Deliberately not added

- **No built-in containment.** NEMOS is a passive sensor with no enforcement
  point, and a "Contain" button that shelled out to `iptables` would be both a
  command-injection surface and an offensive capability aimed at whatever
  address a detection happened to name. Where a controlled lab has a real
  action, `NEMOS_TELEGRAM_CONTAIN_HOOK` runs the operator's own executable in
  argv form with a validated incident id, no shell and a timeout. Absent that
  setting the button does not exist.
- **No per-user bot tokens.** Letting each operator supply one would multiply
  the number of credentials in play and put a secret in a web form. One
  deployment, one bot, many paired chats.
- **No list of known-malicious JA3 hashes.** They go stale, they collide with
  the stock Go and Python TLS stacks that legitimate software also uses, and
  shipping one would assert a detection quality that could not be validated
  here. The fingerprint is recorded so an analyst can pivot on it.
- **No standalone fingerprint-churn alert.** A host presenting many distinct
  TLS stacks is worth attention, but behind NAT one address aggregates every
  host behind it and reaches any threshold honestly. It could not earn a
  confidence above the detector's floor without inflating the number, so it is
  evidence on other findings instead of a finding of its own.

- **The ML anomaly model bootstraps itself.** A sensor with no model starts
  normally, reports `WARMING_UP`, and trains its own Isolation Forest once it
  has observed enough traffic. `python tools/train_model.py` is no longer
  required to get ML scoring, and still works unchanged. Before this, the ML
  layer was inert on every deployment where nobody ran it by hand.
- Training data is vetted, not collected blindly. A window enters the corpus
  only when `fusion.assess` returned `NO_FINDING` for that source — no rule
  fired, the baseline is not deviating, any loaded model scored it NORMAL — and
  a source is held out for several windows after any deterministic finding,
  because a rule firing late in a window is fused into the next one. The filter
  reads the existing detection layers rather than reimplementing them.
- Two independent thresholds gate the first fit (`NEMOS_ML_BOOTSTRAP_MIN_SAMPLES`
  and `NEMOS_ML_BOOTSTRAP_MIN_SECONDS`). A sample count alone is satisfied by one
  quiet minute repeated, which fits a cloud that genuinely unusual traffic can
  land inside.
- Bounded periodic retraining (`NEMOS_ML_RETRAIN_SECONDS`, daily by default, `0`
  to disable). The active model keeps scoring throughout and a replacement is
  promoted only after it validates; a failed refit leaves the working model
  untouched.
- New settings: `NEMOS_ML_AUTOTRAIN`, `NEMOS_ML_BOOTSTRAP_MIN_SECONDS`,
  `NEMOS_ML_BOOTSTRAP_MIN_SAMPLES`, `NEMOS_ML_RETRAIN_SECONDS`,
  `NEMOS_ML_MAX_SAMPLES`.
- The Sensor page shows the model lifecycle with measured progress — sample
  count, observation period, windows excluded — and lists all three detection
  layers, so "no model" cannot be misread as "no detection".

### Changed

- `AnomalyEngine.load` is split into `check` (pure validation: schema, feature
  names, aggregation window) and `install` (a single locked swap of estimator
  and calibration). Retraining validates a candidate before promoting it, so a
  rejected model cannot cost the sensor the one it is already scoring with.
- New `ml_training_samples` table in the existing database, scoped to the
  current window and feature schema. A restart resumes the observation period
  rather than discarding it; changing `NEMOS_ANALYSIS_WINDOW` invalidates the
  corpus rather than mixing incompatible feature scales.

### Fixed

- The bootstrap's cached sample count was not invalidated on write, so under a
  fast window cadence the training trigger could read a total that never grew —
  a bootstrap that silently never fires. Found by running it, not by reading it.

## 4.1.0

Detection coverage, a rebuilt interface, and two defects found by testing the
running system rather than the unit suite.

### Added

- **Seventeen new detections**, all derived from metadata NEMOS already
  captures. Beaconing (periodicity by coefficient of variation of contact
  intervals), lateral movement, credential brute force and password spraying,
  data exfiltration, stealth TCP flag scans, DNS and ICMP tunneling, endpoint
  denial of service, reflection amplification, ingress tool transfer,
  crypto-mining and Tor port heuristics, and non-standard port traffic.
  Detection rules: 10 -> 28.
- **ATT&CK coverage 5 -> 27 techniques**, spanning seven tactics where it
  previously spanned two. Coverage was expanded by adding detections, never by
  adding catalog entries: a test asserts the catalog contains no technique the
  detector cannot emit.
- **Exfiltration over an established C2 channel** (T1041) is distinguished from
  generic exfiltration (T1048) by correlation — bulk transfer to a host the
  same source was already beaconing to.
- **Rebuilt dashboard**: six routed views, an intrusion-progression view
  placing findings on the ATT&CK tactic they evidence, an evidence drawer, a
  beacon periodicity plot, filtering and pagination throughout, a command
  palette, and light/dark themes.
- **`tools/benchmark.py`**, a reproducible capture-path benchmark. Every
  performance number in the documentation now comes from it.
- **`tools/connect_telegram.py`** — chat-id auto-detection. Telegram has no
  anonymous send path, so a bot token is always required, but the chat id no
  longer has to be copied out of a raw `getUpdates` response. The tool
  validates the token with `getMe`, prints a `t.me` deep link carrying a
  one-time code, waits for Start, binds that chat and writes
  `TELEGRAM_CHAT_ID` to `.env` at 0600. The code is what makes this safe:
  without it the tool would bind whichever chat messaged the bot first. It is
  compared in constant time, the update backlog is drained first so an older
  Start cannot be replayed, and the token is never printed, never written by
  the tool and never accepted as a command-line argument, where other users
  could read it from the process table.
- **API request limiting.** Two independent per-client buckets: a general limit
  (`NEMOS_API_RATE`, 240/min) bounding resource use, and a much tighter one
  (`NEMOS_API_AUTH_RATE`, 10/min) bounding rejected credentials, incremented
  before the 401 so each guess at `NEMOS_API_TOKEN` costs the guesser. A single
  shared limit could not do both: anything loose enough for the dashboard's
  polling is far too loose to slow a token search. Exceeding either returns 429
  with `Retry-After`; `/api/health` is never limited so a liveness probe cannot
  exhaust a client's budget. Clients are keyed on peer address and never on
  `X-Forwarded-For`, which is attacker-controlled and would otherwise let one
  client mint unlimited identities. Both client tables are bounded with LRU
  eviction. Limits are clamped so a misconfigured low value cannot lock an
  operator out of their own sensor.
- **Every deterministic-rule threshold is now tunable**, named
  `NEMOS_DETECT_<FIELD>` after the `DetectionConfig` field it sets (34
  variables covering window size, every flood/scan/tunnel/exfiltration
  threshold, cooldown and correlation window). Previously only `NEMOS_MAX_EVENTS`
  and the adaptive-baseline settings were reachable without a code change; an
  operator whose network genuinely runs hotter or quieter than the defaults
  had no other way to say so. Every value is clamped on load, matching the
  discipline `NEMOS_API_RATE` already established, so a bad setting cannot
  silently disable a rule.
- **`nemos/watchdog.py`: a sensor watchdog.** Closes a real gap found this
  session -- a capture thread can die while the process keeps running and
  answering the dashboard, which is exactly the "starting forever" bug fixed
  below, and nothing else in NEMOS notices. The watchdog polls capture health
  on its own thread: the moment capture is reported unhealthy it submits a
  finding through the normal alert-delivery pipeline (always logged first, so
  the finding is never silent even when no notification channel is
  configured or reachable), and while capture is healthy it pings systemd's
  own watchdog (`sd_notify(WATCHDOG=1)`) so `WatchdogSec=` in the unit file
  lets systemd restart a hung process, which `Restart=on-failure` alone
  cannot do. A second, opt-in check (`NEMOS_HEARTBEAT_SECONDS`, off by
  default) can also alert on prolonged silence from a capture that is
  otherwise healthy; it defaults off because a quiet link and a cable pull
  are indistinguishable from packet volume alone, unlike capture death.
  `packaging/systemd/nemos.service` now sets `NotifyAccess=main` and
  `WatchdogSec=90`.
- **IPv6 detection.** Every rule now applies to v6 traffic, and NDP spoofing
  (`NDP_MAPPING_CHANGE`, T1557) is detected as the v6 form of ARP cache
  poisoning. Neighbour Discovery is classified as its own protocol rather than
  as ICMP: it is IPv6's ARP, constant on any healthy segment, and counting it
  as ICMP would have reported every dual-stack network as a permanent ping
  flood -- a false positive introduced by the fix itself. Duplicate-address
  detection (a solicitation from `::`) asserts no binding and is ignored.

- **Syslog/SIEM export** (`NEMOS_SYSLOG_HOST`). Findings are exported as CEF
  over RFC 5424 syslog, the format the widest range of collectors parse
  without a custom decoder, so NEMOS can be a component of an existing
  detection stack rather than a second console nobody watches. UDP by default
  because it cannot block delivery on an unreachable collector; TCP available
  where the collector requires it. Every field is escaped before it is
  written, which is a security boundary rather than formatting: alert fields
  quote evidence and evidence quotes the network, so a raw newline reaching a
  collector would let an attacker terminate the record and forge a separate
  entry after it -- adversary-controlled text inside a record a responder
  trusts. A test asserts a forged `CEF:0|Evil|...|All clear` embedded in a
  finding stays inside the `msg=` field instead of becoming its own event.

- **Low-and-slow reconnaissance** (`SLOW_PORT_SCAN`, `SLOW_HOST_SWEEP`). Every
  volumetric rule works over one short window, which is what makes them cheap
  and is also a published evasion: spread the same scan over hours and no
  single window crosses a threshold. Widening the window is not the fix --
  per-packet cost is linear in window size, so an hour-long packet window
  would cost ~360x more on the capture thread. `nemos/slowscan.py` keeps a
  much coarser record instead: recording is one dict write per packet, and
  the bounded walk that evaluates it is rate-limited per source. Measured
  overhead is 0.5 us/packet, 0.2%. Eviction deliberately does not use LRU --
  a slow scanner is by definition the least recently active thing tracked, so
  recency-based eviction would discard exactly what this exists to catch;
  expired sources go first, then the source with the fewest distinct
  endpoints. The sweep rule ignores common client ports (443, 53, 80 and
  similar) because a workstation browsing the web contacts hundreds of hosts
  an hour with the same shape and none of the meaning.

- **Model drift and staleness reporting** (`nemos/drift.py`, surfaced at
  `/api/status` under `analysis.model.health`). The Isolation Forest is
  trained once, by hand, and was then never mentioned again -- so both
  failure modes were silent: traffic moves away from the training
  distribution and ordinary work starts scoring anomalous until the operator
  learns to ignore the layer, or the network grows into what the model
  considers normal and it stops flagging what it should. Neither produces an
  error; the dashboard shows a model that is loaded and scoring, which is
  what it shows when all is well. Three independent signals are now reported
  from data the model already persists at training time: age since training,
  per-feature distance from the training distribution in training sigmas, and
  the share of windows landing in anomalous bands. None is asserted as "the
  model is wrong" -- they are the evidence for deciding whether to retrain,
  and the report says which fired. Statistics are accumulated with Welford's
  method on the analysis thread and reset on train and load, so a freshly
  trained model cannot report drift against its own training data.

- **The console leads with what matters.** Findings and incidents are ordered
  by risk rather than arrival, and repeated findings are grouped. Both halves
  are needed and neither works alone: ordering happens in SQL, because sorting
  the page a client already holds cannot change which rows are on it, and
  grouping happens before pagination, because grouping only the visible page
  still hands the operator a first page made of one repeated campaign. On the
  demonstration data this turns 68 findings across three pages into 14 groups
  on one screen, and 48 incident rows into 9. `/api/alerts` and
  `/api/incidents` keep their documented arrival order and take `sort=risk`;
  `/api/dashboard` is risk-ordered without asking, since it exists only to
  feed the console.
- **Triage metrics replace traffic volume** on the overview: critical open,
  high open, distinct sources, distinct techniques, capture state and model
  health. Packet counts describe how busy the wire is, never what to look at
  next, and they were occupying the most valuable strip of the screen to say
  it.

### Fixed

- **A campaign buried every critical finding.** Forty hosts beaconing to one
  address produced forty separate findings and forty single-alert incidents;
  listed chronologically they filled the first three pages and pushed a
  CRITICAL SYN flood out of sight. The behaviour was correct and the
  presentation made it useless -- a console that buries its worst finding
  under repetition trains its operator to stop reading it.
- **A multi-technique incident rendered on top of its own severity.** The
  threat column was a raw comma-joined list of `SCREAMING_SNAKE` labels with
  `max-width` set on a `td`, which does not constrain an auto-layout table.
  It overran into the risk and severity columns, and did so worst on
  multi-stage incidents -- the rows that matter most. The table now has a
  fixed layout and truncates with a count.
- **Threat identifiers were shown raw**, and a sentence helper meant for
  prose appended a full stop to them, rendering `C2_BEACONING.`. They are now
  humanised for display with the exact identifier kept on hover, since that
  is the value that appears in the API, in Telegram and in syslog.
- **Capture state was printed as a machine token**, so a sensor with capture
  disabled showed `not_configured` in 25px type overflowing its own card.
- **Feature drift was silently never assessed.** The engine keeps the
  training mean and spread in their own fields rather than in `_metadata`,
  and `status()` passed `_metadata` alone -- so the monitor had nothing to
  compare against and reported "not drifted" for traffic dozens of sigmas
  from training, which is indistinguishable from a healthy model. Found by
  running it against a real trained model rather than the hand-written
  metadata the unit tests used. The monitor now reports
  `drift_comparable: false` with a reason when it cannot compare, so a check
  that could not run can never again look like a check that passed.
- **A new source in the slow tier could evict itself.** `_evict_source` ran
  before `last_seen` was assigned, so a state still holding its `0.0` default
  looked infinitely stale and was the one selected for eviction. Once the
  source table filled, the slow tier silently stopped tracking anything new.
  Found by a bounding test, not by inspection.
- **The README described a benchmark configuration nobody could reproduce.**
  It documented 12,000 packets per profile while `tools/benchmark.py` had
  moved to a default of 20,000, so the published numbers were measured under
  settings that did not match the command printed beside them. A test now
  pins the documented sample size to the tool's actual default.

- **IPv6 was discarded before any detection ran.** `capture.py` gated on
  `haslayer(IP)`, so every v6 packet was dropped at the parse path. Nothing
  failed and nothing was logged: the sensor reported no findings for v6
  traffic, which is indistinguishable from a quiet network. On a dual-stack
  segment an attacker bypassed all 27 rules by preferring the other address
  family. Everything downstream was already family-agnostic -- the detector's
  internal ranges have always listed `::1/128`, `fc00::/7` and `fe80::/10` --
  so the blindness was confined to, and complete at, the capture path.
- **The parse path existed twice.** A `_parse` method that only the tests
  called, and a second copy inlined in the sniff callback that actually ran.
  They had already drifted, which is how a parse path acquires a defect no
  test can see: the fake packet the tests used could not represent an IPv6
  layer at all. There is now one implementation, and the capture thread calls
  the same one the tests do.

- **The dashboard could never authenticate.** The API reads `X-NEMOS-Token`;
  the rewritten script sent `Authorization: Bearer`. Against a token-protected
  sensor every request returned 401 and saving a token changed nothing. The
  dashboard now sends the documented header, and the API additionally accepts
  a standard bearer token because that is what scripts reach for by default.
- **Detection scanned the window once per rule.** Cost per packet was rules
  times window size: 130 -> 853 us/packet as rules were added. Detection runs
  inline on the capture thread, so this was dropped traffic. Every windowed
  statistic is now derived in one traversal; address parsing and TCP flag
  classification are memoised with bounded caches. 853 -> 256 us/packet on the
  same workload.
- `[hidden]` was overridden by component display rules, so every dashboard
  view, the drawer and the palette painted simultaneously.
- The favicon was a `data:` URI, which the page's own Content-Security-Policy
  refused; it is now a served file, which also fixes a 404 on every load.
- The dashboard fetched `/api/attack`, which is not a route.
- Port scanning from an external source is now reported as Reconnaissance
  (T1595) rather than Discovery (T1046); host sweeps as Remote System Discovery
  (T1018) rather than Network Service Discovery.

- **Telegram counted an undelivered message as sent.** The Bot API reports its
  outcome in the body, and can answer HTTP 200 with `{"ok": false}`. Only the
  status line was checked, so those were recorded as delivered: a silent failure
  in the alerting path. The response body is now authoritative. The test double
  had defaulted to an empty body, which the real API never returns -- a fake
  more permissive than the service it stood in for, which is why this survived.
- **Capture reported "starting" forever on a quiet link.** State only advanced
  to "running" when the first packet arrived, so a correctly bound sensor on an
  idle interface was indistinguishable from one that never came up. It now flips
  on a successful socket bind via Scapy's started_callback.
- **A dead capture thread reported no error at all.** A BaseException such as a
  native panic escapes `except Exception`, leaving the status stuck at
  "starting" with `error: null`. Status is now reconciled against whether the
  thread is alive, and reports "failed" with an actionable message.

### Changed

- **Corrected a published performance claim.** 4.0.0 reported 189,356
  packets/sec. That figure was measured on a benchmark whose event windows
  stayed nearly empty and did not represent a busy network; it should not have
  been published as a single headline number. Measured range is now 5,059
  packets/sec (50 sources, windows full) to 38,319 (5,000 sources), and the
  README documents why the slowest figure is the one to plan against.
- Per-packet cost remains linear in window size. This predates 4.1.0 and is
  documented as a known limitation rather than left implicit.

### Verified

- **Live packet capture now works and is tested.** Capture binds a real socket
  on loopback, and the TCP, UDP, DNS and ICMP parse paths were all exercised by
  self-generated traffic (490 packets through the full sensor: capture ->
  detector -> storage -> API -> dashboard), producing real findings. Covered by
  tests/test_capture_live.py, which skips where raw capture is unavailable.
- **Telegram delivery end to end, with real credentials.** Messages were
  delivered to a real chat and confirmed by Telegram. The full chain was
  exercised with nothing synthetic in it: live loopback capture produced three
  findings (PORT_SCAN, SERVICE_DENIAL_OF_SERVICE, ICMP_FLOOD_PATTERN), all
  three were accepted and delivered, none failed. Re-running identical traffic
  suppressed two repeats by cooldown, so a repeating detection cannot turn the
  channel into a flood. The credential appeared in no log line, no API response
  (`/api/telegram` reports the chat id as `****2654`) and no file on disk.
  The credentials used were the operator's and are not stored in this
  repository.

### Fixed (found by capturing on a physical interface)

Capture was run on a real Ethernet NIC (virtio_net, MTU 1400) carrying this
host's own routed traffic to real remote hosts — 186 packets, correct
link-layer parsing, real addresses. It exercised what loopback cannot: Ethernet
framing, genuine remote endpoints, and **both directions of every conversation**.
Two detection-quality bugs surfaced immediately, and both would have fired
continuously on any ordinary deployment.

- **Every busy server was reported as a port scanner.** NEMOS is designed
  around unidirectional flows, but most people point it at a normal interface,
  where replies are visible too. A web server answering several client
  connections sends to many *ephemeral* ports of this host, which the scan rule
  counted as scanned ports. The observed finding had all 8 ports ephemeral,
  `syn_ratio 0.0`, one source port (443) and one destination — the inverse of a
  scan in every dimension. Established-session return traffic (acknowledged,
  not initiating, from a service port to an ephemeral port) is now excluded
  from the scanned-port set. SYN probes are never excluded, so a real sweep
  from a service source port still fires.
- **SERVICE_CONNECTION_BURST counted packets, not connections.** The rule is
  named for connections and its threshold of 40 reads as a burst of them, but a
  single TLS session is dozens of packets — four ordinary HTTPS requests
  crossed it. It now counts connection attempts.

After both fixes the same live traffic produces no findings, and all 27 rules
still fire on the shapes they target.

### Fixed (found by an operator testing on Kali with real Nmap)

- **A port scan was also reported as a denial-of-service flood.**
  `sudo nmap -sS -p 1-1000` sends far more than the 150-SYN threshold, so
  SYN_FLOOD_PATTERN fired alongside PORT_SCAN and TCP_SYN_SCAN at risk 90 with
  T1498.001. Counting SYNs alone cannot tell enumeration from denial of
  service. A flood concentrates on a service to exhaust it; a scan spreads
  across ports to enumerate them. The rule now requires that a share of the
  SYNs (`syn_flood_concentration`, default 0.30) land on one destination port,
  and the evidence names that port and the measured concentration. Both flood
  shapes still fire — a single service on one host, and the same service across
  many hosts — because concentration is measured per port, not per host. The
  threshold is configurable, so the previous behaviour can be restored.
- **Files created under sudo were left owned by root.** Capture needs
  CAP_NET_RAW, so the sensor is usually started with `sudo python main.py`;
  `data/nemos.db` then came out root-owned and training, run without sudo,
  could not open it. NEMOS now hands the data directory, the database and its
  write-ahead log, and the trained model back to the user behind sudo. A root
  login or a systemd unit running as root sets no SUDO_UID and is deliberately
  left alone, since root ownership is intended there.

### Reviewed, not changed

- **Overlapping detections on one event are intentional.** A single Nmap run
  producing PORT_SCAN, TCP_SYN_SCAN and (previously) SYN_FLOOD_PATTERN is
  multi-label detection: each rule states a different observed fact, and each
  carries its own evidence. They are already correlated — every alert from a
  source inside the correlation window shares an `incident_id`, which the
  dashboard groups by and every Telegram message carries. Consolidating them
  into one finding would discard evidence, so the rules stay separate; the
  SYN-flood entry above was a misclassification, not redundancy.
- **Constant features in a small training set.** Training warned that
  `udp_ratio` and `icmp_ratio` were constant across 72 windows captured from
  TCP-only traffic. That warning is working as intended: a constant feature
  contributes nothing to an Isolation Forest, and the model is simply blind to
  those dimensions until the training data contains that traffic. It is a
  statement about the corpus, not a defect.

### Known limitations

- Capture is verified on loopback and on a physical Ethernet interface with
  real routed traffic. A production link under sustained high load, and a
  span/tap port carrying other hosts' traffic, have not been exercised.

## 4.0.0

Major release: NEMOS gains a genuine machine-learning detection layer alongside
the existing deterministic rules, built around an explicit unidirectional flow
model. The existing detector is unchanged in behaviour and remains the
authoritative layer.

### Added

- **Unidirectional flow aggregation** (`nemos/flows.py`). The five-tuple is used
  exactly as observed with no canonicalisation, so A->B and B->A are separate
  records that are never merged. A one-way tap is a first-class deployment, and
  no feature requires a response packet. `reverse_of()` correlates the opposite
  direction without merging either side.
- **Feature engineering** (`nemos/features.py`). 24 features per source per
  window: volume, rates, per-flow statistics, fan-out counts, Shannon entropy
  over destinations and ports, packet-size statistics, TCP flag ratios and
  protocol ratios. Free of any ML dependency so it is testable and reusable on
  its own. Ordered and schema-versioned.
- **Unsupervised ML anomaly detection** (`nemos/ml.py`). An Isolation Forest
  from scikit-learn, trained locally on the operator's own benign traffic. No
  labelled attack data, no cloud service and no internet access are required.
  Reproducible via a fixed seed; model, calibration and provenance metadata are
  persisted atomically.
- **Explainability.** The model exposes no per-feature attribution, so NEMOS
  reports which features are furthest from their training mean in standard
  deviations. Every assessment carries those alongside the score.
- **Hybrid risk fusion** (`nemos/fusion.py`). Deterministic rules set the risk
  floor and are the only source of an ATT&CK technique; statistical layers may
  raise a score but never lower it, and alone cannot reach CRITICAL. Every
  result carries the arithmetic that produced it.
- **Explicit baseline states**: `NO_BASELINE`, `NORMAL`, `DEVIATING`,
  `HIGHLY_DEVIATING`. A host without enough history is `NO_BASELINE` -- never
  "normal" and never "anomalous".
- **Windowed analysis engine** (`nemos/analysis.py`) on its own thread. The
  capture path does one dictionary operation per packet; expiry, feature
  extraction, batched inference and fusion happen off it.
- **Model lifecycle CLI** (`tools/train_model.py`): train from captured traffic
  or synthetic data, dry-run inspection, JSON output. Training is out-of-band by
  design -- a sensor that retrained itself on live traffic would learn to accept
  an intrusion in progress.
- **Controlled demonstration** (`tools/demo.py`, `tools/scenarios.py`) across
  nine traffic shapes, generated in memory using RFC 5737 documentation
  addresses. Nothing is transmitted and no host is contacted.
- **Optional LLM analyst** (`nemos/analyst.py`). Explains findings the other
  layers already made; performs no detection and is never in the packet path.
  Responses are verified against the evidence bundle and discarded if they
  reference an IP address or technique that is not in it. Hosted provider
  endpoints cannot be redirected by configuration; `ollama` must be loopback.
- **API**: `/api/flows`, `/api/analysis`, `/api/anomalies`, `/api/windows`,
  `/api/baselines`, `/api/baselines/<ip>`, `/api/analyst`, and
  `POST /api/analyst/ask`, which takes a target and never caller-supplied
  evidence so it cannot be used as an open LLM proxy.
- **Dashboard**: a ML Detection section showing model state and provenance,
  per-assessment anomaly score, baseline state, the hybrid arithmetic and the
  contributing features. A test pins that every field maps to a real backend
  value and forbids overstated wording.
- Flows are persisted through the existing batched writer as a third item kind,
  treated as telemetry for backpressure so they are dropped before findings.

### Fixed

- **Flow-table eviction was O(n) per packet.** It scanned for the oldest entry,
  so the bound that exists to survive a spoofing flood became the bottleneck
  exactly when full. Now an `OrderedDict` with O(1) LRU, matching the detector
  and profiler. A 200,000-packet benchmark did not finish before this fix; it
  now sustains a high ingest rate. A test pins the complexity.
  (Correction, 4.1.0: the figure originally published here was measured on a
  benchmark that kept event windows nearly empty and did not represent a busy
  network. See tools/benchmark.py and the Performance section of the README.)
- **The anomaly score anchored on the training minimum**, a single sample, so
  one unusual training window set the whole scale. Measured here the minimum was
  -0.255 against a 5th percentile of -0.030, stretching the band until a
  259-port SYN scan scored 65. The score now uses robust deviation units
  anchored on the median and 5th percentile, with bands from measured
  separation. Scenario scores moved from 64-69 to 84-100 with normal traffic
  still producing no finding.
- **The aggregation window was not part of the model contract.** Counts and
  rates scale with it, so a model fitted on 10s windows applied to 2s windows
  scored a distribution it had never seen. Training now records the window,
  mixed-window corpora are refused, and loading refuses a mismatch with a
  message naming both fixes.
- **Training accepted a degenerate corpus.** The minimum sample count counted
  rows, so many copies of one window passed while teaching the forest nothing --
  and a scan then scored *lower* than normal traffic. A distinct-sample minimum
  now applies, and constant features are reported.
- `ThreatDetector.process()` and `observe_arp()` accept an optional `now`.
  They previously always read the monotonic clock, so replaying an hour of
  traffic in a second placed every event in one window and manufactured
  findings. Live capture is unchanged.
- `/api/packet` now also feeds the windowed flow pipeline, so synthetic traffic
  exercises flow aggregation, features and ML rather than only reaching storage.
  It deliberately does not invoke the deterministic detector, whose per-source
  state is owned by the capture thread.

### Changed

- Version 3.3.0 -> 4.0.0.
- `scikit-learn` and `joblib` are runtime dependencies, but every import is
  guarded: without them NEMOS runs deterministic rules plus the statistical
  baseline exactly as before, and reports why ML is unavailable.
- Documentation rewritten to describe the three layers separately and to state
  plainly what each can and cannot evidence.

### Testing

278 -> 338 tests. Measured on this machine: feature extraction 52.76 ms for 20,000 flows into 50
source vectors, batched inference 15.08 ms for 50 vectors (0.302 ms per
source-window).

**Real Telegram delivery was not tested**: no credentials were present in this
environment. The delivery path is covered by tests using a recording transport,
which verify request shape, retry, redaction, suppression and non-blocking
behaviour, but no message was sent to Telegram.

## 3.3.0

### Added
- **Outbound alert delivery.** Telegram and generic-webhook channels now actually
  send findings. Previously the Telegram integration was documented and shown in
  the dashboard but had no delivery code path at all: `/api/telegram` only
  reported whether the credentials were set, and no alert was ever sent anywhere.
  Delivery runs on a worker thread and never blocks packet capture; storage
  happens first, so an unreachable channel cannot cost a recorded detection.
- Severity floor, per-finding cooldown and a global token-bucket rate limit, so a
  port scan cannot turn the sensor into a message flood. Suppressed alerts remain
  recorded and every suppression is counted.
- `.env` loading. The README and `.env.example` had instructed users to create a
  `.env` file, but nothing in the codebase ever read one, so file-based settings
  were silently ignored. Real environment variables still take precedence.
- `GET /api/notifications` and delivery metrics on `/api/status` and
  `/api/metrics`, so operators can tell "credentials present" from "alerts are
  actually arriving".
- Filtering on `GET /api/alerts`: `severity` (repeatable), `source`, `threat`,
  `technique`, `acknowledged` and `since`, all bound as parameters.
- Ruff lint configuration and a CI lint job; CI now also verifies that built
  artifacts carry the version from `nemos/version.py`.

### Fixed
- **Duplicate writes on shutdown.** The SQLite writer's sentinel-drain path
  flushed the final partial batch and then fell through to a `finally` clause
  that flushed the same still-populated list again. Any traffic and alerts
  pending at shutdown were written twice, and the cached telemetry counters were
  incremented twice with them. This hit every clean shutdown where the last
  batch had not already been flushed by the timeout path -- the common case for
  a busy sensor being stopped. Covered by a regression test.
- The dashboard's writer-queue health tile read `queue_size` from the dashboard
  payload, but the metric is named `queue_depth` and `/api/dashboard` never
  returned writer metrics at all, so the tile was permanently blank. It now reads
  live depth and capacity from `/api/status`.
- `TimeoutError` raised during writer shutdown lost its originating exception.

### Changed
- Packaging version is single-sourced from `nemos/version.py` via
  `dynamic = ["version"]`; it was previously duplicated by hand in
  `pyproject.toml` and could drift from the version `/api/health` reports.
- `/api/alerts` and `/api/traffic` select explicit columns instead of `SELECT *`.
- Telegram alert text is sent with no Markdown/HTML parse mode, so alert content
  cannot break rendering or inject formatting.
- Webhook URLs must be HTTPS unless loopback, and HTTP redirects are refused
  rather than followed.

### Documentation
- **Corrected an overstatement risk.** The README's "Detection Engine v3"
  heading described the behavioural baseline in terms that could be read as
  machine learning. It is an exponentially weighted mean/variance model with an
  explicit sigma threshold — a transparent statistical baseline, not a trained
  one. The README now says so directly in a "What NEMOS is not" section, and
  `CONTRIBUTING.md` makes not describing it as AI or ML a contribution rule.
  (`detector.py` already stated this correctly in a comment; only the docs
  overstated.)
- Resolved a version-label contradiction: the README called the detector
  "Detection Engine v3" while `docs/ARCHITECTURE.md` called the same component
  "v2". Both now describe it without a version label.
- Fixed the documented test command. `README.md`, `CONTRIBUTING.md` and
  `docs/RELEASE.md` told users to run `python -m unittest discover`, but the
  project uses pytest — which is what CI, the Makefile and `pyproject.toml`
  configure.
- Corrected the systemd instructions. The README implied a service could be set
  up by copying two files; the packaged unit expects a `nemos` account, a venv
  at `/opt/nemos` and `/var/lib/nemos`, all of which `install.sh` creates.
- Rewrote the README: removed a duplicated introduction, moved the License
  section out of the middle of the document, added status badges, an
  architecture diagram, full configuration tables, an API table and an explicit
  Limitations section.
- Rewrote `docs/ARCHITECTURE.md`, which predated `notify.py` and `env.py`, and
  `docs/RELEASE.md`, which contained stale release notes rather than a process.
- Expanded `CONTRIBUTING.md` and `SECURITY.md`; added `CODE_OF_CONDUCT.md`,
  issue and pull-request templates, `dependabot.yml` and `.editorconfig`.

### Removed
- `backup_before_final_ui/` and four committed `*.pre_polish` files.
- `FINAL_AUDIT.md`, `TEST_REPORT.md` and `TEST_REPORT_LOCAL.md`, consolidated
  into a single current `AUDIT_REPORT.md`.

## 3.2.7

- Optimized SQLite retention maintenance to avoid full-table telemetry and host-stat recounts after every prune.
- Retention now applies incremental telemetry/host deltas and repairs only hosts whose risk/latest-alert fields may have changed.
- Batched host-stat upserts with `executemany()` to reduce SQLite statement overhead inside writer batches.
- Added regression coverage for retained host risk/latest-alert correctness.


## 3.2.6

- Included capture state in dashboard ETags so sensor failures/recovery and packet-capture counters are visible even when SQLite telemetry is unchanged.
- Hardened the SQLite writer lifecycle so unexpected worker exits no longer leave submissions accepted or make shutdown hang; the writer can be restarted cleanly.
- Corrected the dashboard color-scheme metadata to match the intentionally clean light workspace.

## 3.2.5

- Fixed Linux systemd packet capture by allowing the AF_NETLINK and AF_PACKET address families required by Scapy.
- Made the dashboard report an unset capture interface as `default` instead of incorrectly implying that every interface is being captured.
- Fixed the Kali verification script to check the actual lowercase `nemos/static/app.js` path.
- Standardized the manual-install default database filename to `data/nemos.db`.

## 3.2.4

- Fixed the dashboard KPI refresh crash caused by a missing UDP DOM element.
- Removed CSP-incompatible inline risk-ring styling and replaced it with SVG progress rendering.
- Added a clipboard fallback for non-secure dashboard contexts.
- Made sidebar navigation highlight the section currently being viewed.
- Added deterministic host ordering for equal-risk hosts.
- Bounded incident evidence in SQL instead of loading unbounded incident rows into memory.
- Added accurate host top-protocol telemetry to host investigations.
- Added dashboard asset/syntax regression tests.

##  

- Fixed stale uppercase `NEMOS.*` imports left in the test suite after the package rename to lowercase `nemos`.
- Added package-import regression coverage so future renames cannot silently break the test suite.

- Hardened packet-capture lifecycle with explicit runtime status and a finite Scapy sniff timeout so idle captures stop deterministically.
- Fixed production server shutdown by managing the Waitress server object explicitly.
- Added protected `/api/status` and capture state to dashboard responses.
- Dashboard now distinguishes healthy capture, missing `CAP_NET_RAW`, capture errors, disabled capture, and startup state instead of displaying all-zero telemetry as if the sensor were healthy.
- Reduced systemd privileges to `CAP_NET_RAW` only.
- Removed the Flask development-server fallback from `main.py`; deployment now requires the pinned Waitress dependency.
- Added regression coverage for capture state and runtime status.


## 3.2.2

- Added conditional dashboard responses with ETags to avoid retransmitting unchanged telemetry.
- Dashboard polling now pauses while the browser tab is hidden and uses request timeouts.
- Added regression coverage for conditional dashboard requests.
- Preserved batched SQLite writes and bounded queue/backpressure behavior.

## 3.2.1 - Runtime hardening

- Fixed `DetectionConfig.from_env()` startup crash caused by `dataclass(slots=True)` member descriptors.
- Bounded detector cooldown state to prevent attacker-controlled source churn from causing unbounded memory growth.
- Preserved the pre-update behavioral baseline in anomaly evidence.
- Hardened non-finite environment float handling.
- Reduced `/api/incidents` N+1 database queries to a bounded batched query.
- Added safe zero-state handling for telemetry counters.
- Hardened SQLite writer startup failure handling and exposed writer thread health in protected metrics.
- Made packet-capture lifecycle idempotent.
- Added regression coverage for the runtime startup and memory-bound issues.

## 3.2.1 — Final Validation & Release Engineering

- Centralized the application version in `nemos/version.py`.
- Synchronized package metadata, API health reporting, tests and documentation to 3.2.1.
- Added a final offline detection validation workflow using RFC 5737 documentation addresses only.
- Added release validation documentation and clean-source packaging checks.
- Kept live Flask/Scapy integration explicitly marked as a target-environment validation step.

## 3.1.0 — SIH Validation & Release Polish

- Added offline synthetic detection validation using RFC 5737 documentation addresses.
- Added SIH demo plan, five-minute demo script, and presentation outline.
- Synchronized package/API/test version metadata to 3.1.0.
- Corrected stale API version expectation in the integration test.
- Added release notes and a documented validation workflow.

## 3.0.0

- Added GitHub Actions CI across supported Python versions.
- Added dependency vulnerability auditing with pip-audit.
- Added reproducible package-build workflow.
- Added hardened systemd service template with least-privilege capabilities for packet capture.
- Added release checklist and local security-audit script.
- Added Makefile developer commands.
- Bumped application/package version to 3.0.0.

## 2.9.1 — Security & Reliability Audit
- Added Flask trusted-host validation with explicit trusted-host configuration for wildcard remote binds.
- Added stricter API packet validation for boolean ports and oversized timestamps.
- Expanded CSP with `base-uri`, `object-src`, `frame-ancestors`, and `form-action` restrictions.
- Added traffic destination/source-destination indexes and alert source/severity indexing.
- Refused remote startup when Waitress is unavailable instead of falling back to Flask's development server.
- Added explicit process exit status handling.
- Updated remote deployment documentation and environment example.

## 2.9.0 — Adversarial Reliability & Backpressure
- Added priority-aware bounded SQLite backpressure with a reserved queue region for alerts.
- Traffic can be shed under sustained overload instead of allowing unbounded memory growth or blocking packet capture indefinitely.
- Alerts receive a short blocking window and reserved capacity so traffic bursts cannot starve security findings.
- Added writer operational metrics: queue depth, high-water mark, dropped traffic/alerts, write errors, and completed batches.
- Added authenticated `/api/metrics` for runtime writer health.
- Hardened shutdown draining so all queued work is processed before the writer exits.
- Added deterministic saturation/priority tests and a 50,000-event storage stress benchmark.

## 2.9.0 — Investigation Workflow

- Added host investigation endpoint and UI.
- Added alert detail endpoint.
- Added incident defensive guidance and evidence-focused investigation view.
- Added alert acknowledgement controls to the incident workflow.
- Added bounded host/incident investigation data.

## 2.9.0
- Added deterministic adaptive behavioral profiling with EMA mean/variance across packet rate, byte rate, destination diversity, and port diversity.
- Behavioral sampling is cadence-limited to prevent packet-by-packet baseline drift.
- Behavioral alerts include current values, baseline values, sigma deviations, and model metadata.


## 2.5.0 - Detection Engine v3

- Added evidence-driven UDP port-scan and ICMP sweep detections.
- Added explicit TCP SYN scan evidence and scan classification.
- Improved confidence calibration and minimum-confidence gating.
- Kept behavioural anomaly detection explainable and removed misleading ATT&CK mapping from generic anomalies.
- Added bounded ARP state eviction.
- Expanded detector tests for new reconnaissance signals.


## 2.9.0 - SOC Intelligence Layer
- Added explainable host-risk summaries and `/api/hosts`.
- Added bounded incident investigation endpoint `/api/incidents/<incident_id>`.
- Added host-risk panel to the SOC dashboard.
- Kept host risk as a triage score, not an automated attribution verdict.

## 2.1.0
- Added O(1) dashboard/stat counters with automatic migration/backfill for existing databases.
- Protected read-only API telemetry when an API token is configured.
- Added dashboard token entry with local-only browser storage.
- Added strict IP, port, protocol and packet-size validation for packet ingestion.
- Hardened SQLite writer lifecycle, shutdown draining, lock retries and error accounting.
- Added safer environment parsing and packaged `main.py` as the console entry point.
- Fixed the service-connection ATT&CK mapping to network service scanning (`T1046`).
- Expanded lifecycle, authentication, validation and configuration tests.


## 2.0.0
- Rebuilt architecture around one lifecycle entry point.
- Added real Scapy packet capture.
- Added bounded multi-signal detection engine.
- Added MITRE ATT&CK technique references.
- Added batched SQLite WAL writer.
- Added consolidated dashboard endpoint and 3-second polling.
- Added request validation, API token protection, security headers and loopback-safe defaults.
- Added SOC-style responsive dashboard.
- Added tests, packaging metadata, security policy and contributor guidance.
- Removed virtual environment, runtime databases, backups and caches from source distribution.

## 2.2.0 - Detection Engine v2

- Added source-level incident correlation with stable incident IDs.
- Added explainable behavioural traffic-baseline detection with bounded per-source state.
- Expanded evidence attached to network-scan and flood detections.
- Added `/api/incidents` and incident data to `/api/dashboard`.
- Added incident-aware SOC dashboard views.
- Added `incident_id` storage migration and index.
- Reworked telemetry statistics to use O(1) incremental updates during normal batches; full recounts occur only when retention pruning changes stored rows.
- Added retention/statistics regression tests.

## 2.6.0 — Incident Intelligence

- Added deterministic, explainable incident-level risk summarization.
- Added incident confidence, severity, threat/technique diversity and evidence metrics.
- `/api/incidents` now returns enriched incident triage summaries.
- `/api/incidents/<incident_id>` now returns an incident summary alongside alert evidence.
- Incident scoring is bounded to 0–100 and is explicitly a triage priority, not a probability of compromise.

## 2.9.0 — Adaptive Behavioural Intelligence
- Added deterministic EW mean/variance profiling for packet rate, byte rate, destination diversity, and port diversity.
- Added cadence-limited baseline sampling to reduce baseline drift during bursts.
- Added explainable sigma-deviation evidence to behavioural alerts.
- Added bounded profile storage and configurable behavioural settings.

## Dashboard polish — 2026-08-30

- Replaced the broken Risk Distribution board with a deterministic Security Posture panel.
- Reworked the dashboard into a restrained dark SOC interface with clearer hierarchy and denser operational information.
- Expanded the MITRE ATT&CK section to show the complete conservative NEMOS catalog, observed counts, tactics, descriptions, and unmapped behavioral signals.
- Added Telegram configuration/status visibility without exposing the bot token.
- Added a compact creator panel for Gautam with the NEMOS GitHub repository and contact email.
- Corrected NEMOS branding to `Network Exposure Monitoring & Operations System` throughout the dashboard.
- Preserved existing incident, host, network, acknowledgement, evidence-export, and polling workflows.
