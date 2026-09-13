# Configuration

NEMOS reads a `.env` file next to `main.py` at startup. Real environment
variables always take precedence, so a systemd unit or an explicit `export` is
never overridden by a stale file. Copy `.env.example` to `.env` to begin.

## Core

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEMOS_HOST` | `127.0.0.1` | Bind address |
| `NEMOS_PORT` | `5000` | Bind port |
| `NEMOS_INTERFACE` | *(all)* | Capture interface; unset captures on all of them |
| `NEMOS_CAPTURE` | `true` | Enable packet capture |
| `NEMOS_DB` | `data/nemos.db` | SQLite path |
| `NEMOS_API_TOKEN` | *(none)* | Required for any non-loopback bind |
| `NEMOS_API_RATE` | `240` | Requests per client per minute. Must stay above the dashboard's polling (~48/min) |
| `NEMOS_API_AUTH_RATE` | `10` | Rejected credentials per client per minute before 429 |
| `NEMOS_TRUSTED_HOSTS` | *(none)* | Required for wildcard binds |
| `NEMOS_LOG_LEVEL` | `INFO` | Logging level |

## Sensor watchdog

Detects a capture thread that has died without the process exiting — a real
failure mode found on a live deployment, and one `Restart=on-failure` alone
cannot catch. See [Deployment](DEPLOYMENT.md).

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEMOS_HEARTBEAT_SECONDS` | `0` (off) | Alert if capture goes this long with no packets. Off by default — a quiet link and a cable pull look identical from packet volume alone |
| `NEMOS_WATCHDOG_POLL_SECONDS` | `15` | How often the watchdog checks capture health and pings systemd |

## Retention and throughput

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEMOS_MAX_TRAFFIC` | `100000` | Traffic rows retained |
| `NEMOS_MAX_ALERTS` | `10000` | Alert rows retained |
| `NEMOS_DB_BATCH` | `250` | Rows per write batch |
| `NEMOS_DB_FLUSH_SECONDS` | `0.5` | Maximum flush interval |
| `NEMOS_DASHBOARD_LIMIT` | `100` | Default dashboard page size |

## Flow analysis and ML

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEMOS_ANALYSIS` | `true` | Enable windowed flow analysis and ML scoring |
| `NEMOS_ANALYSIS_WINDOW` | `10.0` | Aggregation window in seconds — **must match the model's training window** |
| `NEMOS_MAX_FLOWS` | `20000` | Bound on the in-memory flow table |
| `NEMOS_INTERNAL_NETWORKS` | RFC 1918 + loopback | Comma-separated CIDRs treated as internal |
| `NEMOS_MAX_EVENTS` | `1000` | Events retained per source for the rules. Detection cost per packet is linear in this — see [Performance](BENCHMARK.md#performance) |
| `NEMOS_PERSIST_FLOWS` | `true` | Store aggregated flows in SQLite |
| `NEMOS_MODEL_DIR` | `data/model` | Where the trained model is loaded from |
| `NEMOS_ML_AUTOTRAIN` | `true` | Let the sensor train its own model from vetted-normal traffic |
| `NEMOS_ML_BOOTSTRAP_MIN_SAMPLES` | `1000` | Clean windows required before the first fit (floor: 50) |
| `NEMOS_ML_BOOTSTRAP_MIN_SECONDS` | `600` | Observation period required before the first fit |
| `NEMOS_ML_RETRAIN_SECONDS` | `86400` | Refit cadence once a model is active; `0` disables retraining |
| `NEMOS_ML_MAX_SAMPLES` | `20000` | Bound on the stored training corpus |

## Optional LLM analyst

Off unless `NEMOS_LLM_PROVIDER` is set. Nothing is sent anywhere until it is.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEMOS_LLM_PROVIDER` | *(none)* | `anthropic`, `openai` or `ollama` (local) |
| `NEMOS_LLM_MODEL` | provider default | Model name |
| `NEMOS_LLM_URL` | provider default | Only overridable for `ollama`, and only to a loopback address |
| `NEMOS_LLM_TIMEOUT` | `30` | Request timeout in seconds |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | *(none)* | Required by the hosted providers |

For a fully offline deployment use `ollama`, which keeps the model on the same
machine. NEMOS refuses to redirect a hosted provider's endpoint, so evidence
about your network cannot be retargeted by a misconfigured variable.

## Baseline tuning

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEMOS_BEHAVIOR_ALPHA` | `0.15` | EMA smoothing factor |
| `NEMOS_BEHAVIOR_MIN_SAMPLES` | `8` | Warm-up before the baseline can alert |
| `NEMOS_BEHAVIOR_SIGMA` | `3.0` | Deviation threshold |
| `NEMOS_BEHAVIOR_SAMPLE_SECONDS` | `5.0` | Sampling cadence |

## Detection rule tuning

Every deterministic-rule threshold is overridable, named `NEMOS_DETECT_<FIELD>`
after the `DetectionConfig` field it sets. The defaults were tuned against
real traffic (including a live nmap sweep and SYN flood, see
[the benchmark](BENCHMARK.md)) and are the right starting point for most networks; these
exist for the network that genuinely runs hotter or quieter than that. Every
value is clamped on load, so a bad setting cannot silently disable a rule.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEMOS_DETECT_WINDOW` | `10` | Detection window, seconds |
| `NEMOS_DETECT_PORT_SCAN` | `8` | Distinct ports probed to flag a scan |
| `NEMOS_DETECT_SYN_FLOOD` | `150` | SYNs in the window to flag a flood |
| `NEMOS_DETECT_SYN_FLOOD_CONCENTRATION` | `0.30` | Share of SYNs on one port that separates a flood from a scan |
| `NEMOS_DETECT_ICMP_FLOOD` | `100` | ICMP packets to flag a flood |
| `NEMOS_DETECT_FANOUT` | `25` | Distinct destinations to flag network fan-out |
| `NEMOS_DETECT_DNS_BURST` | `80` | DNS queries to flag a burst |
| `NEMOS_DETECT_SERVICE_BURST` | `40` | Connections to one service to flag a burst |
| `NEMOS_DETECT_UDP_SCAN` | `12` | Distinct UDP ports to flag a scan |
| `NEMOS_DETECT_ICMP_SWEEP` | `12` | Distinct hosts pinged to flag a sweep |
| `NEMOS_DETECT_STEALTH_SCAN` | `6` | FIN/NULL/Xmas packets to flag a stealth scan |
| `NEMOS_DETECT_LATERAL_HOSTS` | `5` | Internal hosts touched to flag lateral movement |
| `NEMOS_DETECT_BRUTE_FORCE` | `20` | Auth attempts to flag brute forcing |
| `NEMOS_DETECT_EXFIL_BYTES` | `25000000` | Outbound bytes to flag exfiltration |
| `NEMOS_DETECT_DNS_TUNNEL_PACKETS` | `30` | DNS packets, combined with mean size, to flag tunneling |
| `NEMOS_DETECT_DNS_TUNNEL_MEAN_SIZE` | `180` | Mean DNS packet size (bytes) that flags tunneling |
| `NEMOS_DETECT_MINING_PACKETS` | `10` | Packets to known mining ports to flag mining |
| `NEMOS_DETECT_TOR_PACKETS` | `10` | Packets to known Tor ports to flag Tor use |
| `NEMOS_DETECT_SPRAY_HOSTS` | `8` | Hosts touched with repeated auth attempts to flag password spraying |
| `NEMOS_DETECT_SPRAY_MAX_ATTEMPTS` | `6` | Attempts per host before it counts toward spraying |
| `NEMOS_DETECT_ICMP_TUNNEL_PACKETS` | `12` | ICMP packets, combined with mean size, to flag tunneling |
| `NEMOS_DETECT_ICMP_TUNNEL_MEAN_SIZE` | `200` | Mean ICMP packet size (bytes) that flags tunneling |
| `NEMOS_DETECT_SERVICE_DOS` | `120` | Packets to one service endpoint to flag denial of service |
| `NEMOS_DETECT_AMPLIFICATION_PACKETS` | `60` | Packets from known amplifier ports to flag reflection abuse |
| `NEMOS_DETECT_INGRESS_BYTES` | `25000000` | Inbound bytes to flag an ingress transfer |
| `NEMOS_DETECT_NONSTANDARD_PACKETS` | `40` | Packets on high, unexpected ports to flag non-standard traffic |
| `NEMOS_DETECT_NONSTANDARD_MIN_PORT` | `10000` | Port floor for the rule above |
| `NEMOS_DETECT_BEACON_MIN_INTERVALS` | `5` | Timing samples required before beaconing can be flagged |
| `NEMOS_DETECT_BEACON_MAX_JITTER` | `0.15` | Maximum timing variance still counted as periodic |
| `NEMOS_DETECT_BEACON_MIN_PERIOD` | `2.0` | Shortest interval (seconds) considered beaconing, not chatter |
| `NEMOS_DETECT_BEACON_HORIZON` | `900.0` | How far back (seconds) beacon timing history is kept |
| `NEMOS_DETECT_SLOW_HORIZON` | `3600.0` | Long-horizon window, seconds, for scans paced below `NEMOS_DETECT_WINDOW` |
| `NEMOS_DETECT_SLOW_SCAN_PORTS` | `40` | Distinct ports on one host over the horizon to flag a slow vertical scan |
| `NEMOS_DETECT_SLOW_SWEEP_HOSTS` | `30` | Hosts on one uncommon port over the horizon to flag a slow sweep |
| `NEMOS_DETECT_SLOW_EVAL_SECONDS` | `30.0` | How often the slow tier is evaluated per source (recording is per packet and O(1)) |
| `NEMOS_DETECT_SLOW_MAX_SOURCES` | `1024` | Sources tracked in the slow tier |
| `NEMOS_DETECT_SLOW_MAX_TRACKED` | `256` | Endpoints remembered per source in the slow tier |
| `NEMOS_DETECT_COOLDOWN` | `30` | Seconds before the same rule can refire for the same source |
| `NEMOS_DETECT_CORRELATION_WINDOW` | `60` | Seconds findings from one source share an incident id |
| `NEMOS_DETECT_MAX_SOURCES` | `4096` | Distinct sources tracked at once, LRU-evicted beyond this |
| `NEMOS_DETECT_BASELINE_MULTIPLIER` | `3.0` | Deviation multiplier for the adaptive-baseline rules |
| `NEMOS_DETECT_BASELINE_MIN_EVENTS` | `20` | Minimum events before the adaptive baseline can flag a source |
| `NEMOS_DETECT_MIN_CONFIDENCE` | `55` | Confidence floor (0-100) below which a finding is dropped |
