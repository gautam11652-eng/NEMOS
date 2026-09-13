# API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Liveness (public even when a token is set) |
| `GET /api/dashboard` | Consolidated dashboard snapshot (ETag-cached) |
| `GET /api/stats` | Telemetry counters |
| `GET /api/alerts` | Recent alerts, filterable |
| `GET /api/alerts/<id>` | Single alert with evidence |
| `GET /api/incidents` | Correlated incidents |
| `GET /api/incidents/<incident_id>` | Incident detail and triage summary |
| `GET /api/telegram/pair` | Pairing state and linked chats (never the code) |
| `POST /api/telegram/pair` | Mint a single-use pairing code and its QR code |
| `DELETE /api/telegram/pair` | Revoke the outstanding pairing code |
| `DELETE /api/telegram/links/<chat_id>` | Unlink a paired chat |
| `POST /api/telegram/test` | Send the confirmation message to paired chats |
| `GET /api/telegram/audit` | Audit trail for chat-initiated actions |
| `GET /api/hosts` | Host risk index |
| `GET /api/hosts/<ip>` | Per-host investigation view |
| `GET /api/techniques` | ATT&CK catalog with observed counts |
| `GET /api/flows` | Unidirectional flows; `active=true` for the live table |
| `GET /api/analysis` | Windowed-analysis and ML model health |
| `GET /api/anomalies` | Recent fused assessments with full arithmetic |
| `GET /api/windows` | Recent completed analysis windows |
| `GET /api/baselines`, `GET /api/baselines/<ip>` | Per-host baseline state |
| `GET /api/analyst` | Optional LLM analyst status |
| `POST /api/analyst/ask` | Ask the analyst about an incident or host |
| `GET /api/traffic` | Recent traffic events |
| `GET /api/status` | Capture, writer and delivery health |
| `GET /api/metrics` | Writer and delivery metrics |
| `GET /api/notifications` | Alert-delivery configuration and health |
| `POST /api/packet` | Test/compatibility ingestion |
| `POST /api/alerts/<id>/ack` | Acknowledge an alert |
| `POST /api/alerts/clear` | Clear alerts |

## Filtering alerts

`GET /api/alerts` accepts `severity` (repeatable), `source`, `threat`,
`technique`, `acknowledged`, `since` and `limit`:

```bash
curl 'http://127.0.0.1:5000/api/alerts?severity=CRITICAL&severity=HIGH&acknowledged=false'
curl 'http://127.0.0.1:5000/api/alerts?source=192.0.2.10&since=2026-01-01'
```

Every filter is validated and passed as a bound parameter.

`GET /api/flows` accepts `source`, `destination`, `protocol`, `limit` and
`active`. Both directions of a conversation appear as separate rows:

```bash
curl 'http://127.0.0.1:5000/api/flows?source=192.0.2.10'
curl 'http://127.0.0.1:5000/api/flows?active=true'
```

`POST /api/analyst/ask` takes a **target**, never evidence — NEMOS assembles the
bundle from its own storage, so the endpoint cannot be used as a general-purpose
LLM proxy:

```bash
curl -X POST http://127.0.0.1:5000/api/analyst/ask \
  -H 'Content-Type: application/json' \
  -d '{"question":"why is this host suspicious?","host":"192.0.2.10"}'
```

When `NEMOS_API_TOKEN` is set, all `/api/*` endpoints except `/api/health`
require an `X-NEMOS-Token` header. The dashboard prompts for the token and keeps
it in `sessionStorage` only.

## Dashboard

A local SOC interface with a live detection timeline, security posture summary,
correlated-incident investigation with evidence and recommended next steps, a
host risk index, an ATT&CK coverage view, a connection graph, and sensor health
including capture state and writer backpressure.

The **ML Detection** section shows:

- **Model status** — loaded or not trained, version, training timestamp,
  training window count, windows scored, aggregation window
- **Per-assessment detail** — anomaly score, confidence, risk, baseline state
- **Hybrid verdict** — the fusion arithmetic, the layers that contributed, and
  the ATT&CK techniques (or an explicit note that statistical evidence does not
  name one)
- **Why this was flagged** — the contributing features and their deviations

Every displayed value maps to a real backend field; a test enforces that and
forbids overstated wording such as "AI detected attack".
