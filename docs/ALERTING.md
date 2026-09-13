# Alert delivery

NEMOS records findings locally by default. It can also push them to Telegram or
a webhook. Delivery is off until you configure a channel, and it never blocks
packet capture.

## Connecting a chat: scan a QR code

A bot token is a *deployment* secret. One NEMOS install needs exactly one, set
once by whoever deploys it, and no operator should ever be asked to paste one
into a web form. So they are not: they scan a QR code.

```bash
# .env, beside main.py -- one setting, set once, by the deployment
TELEGRAM_BOT_TOKEN=the_token_from_@BotFather
```

That is the whole configuration. `TELEGRAM_BOT_USERNAME` is optional: the token
already determines the username, so NEMOS asks Telegram once and caches the
answer rather than making you look it up and retype it — which was not just
extra work but the one setting whose typo failed *silently*, rendering a
perfectly valid QR code that pointed at a bot which did not exist.

The bot token cannot be eliminated. Telegram has no anonymous send path — a
token *is* the bot's identity. What NEMOS removes is everyone else having to
handle one: it is set once by whoever deploys the sensor, stays server-side, and
no operator is ever asked for a credential or a chat id.

Then, on the **Sensor** page, press **Connect Telegram**. NEMOS mints a single-use
pairing code, renders `https://t.me/<bot>?start=<code>` as a QR code, and counts
down its five-minute life. Scan it, press **Start**, and that chat is linked.
Alerts begin arriving immediately — no restart, no chat id to look up.

What the pairing code has to survive, and how:

| Attack | Defence |
| --- | --- |
| Guessing a code | 128 bits from `secrets.token_urlsafe` |
| Replaying a used code | Redemption flips `used` inside one `BEGIN IMMEDIATE` transaction, so concurrent `/start`s cannot both win |
| Waiting out and then using an expired code | Expiry is compared against the server clock at redemption; nothing the client sends is consulted |
| Linking someone else's chat | A code binds whichever chat redeems it and is then dead |
| Injecting a chat id | The chat id comes only from Telegram's own update payload, and must still parse as one |
| Reading codes out of a stolen database | Only SHA-256 hashes are stored, and a hash cannot be replayed as a start parameter |

Issuing a new code retires the previous one, so a link screenshotted an hour ago
is not still live alongside the one on screen.

The QR encoder is `nemos/qr.py` — about 400 lines, no new dependency. Its output
is pinned in the test suite against an independent reference implementation, and
the rendered SVG has been decoded back to the exact pairing link.

`python tools/connect_telegram.py` still works and still writes
`TELEGRAM_CHAT_ID`; QR pairing is the path that does not require shell access to
the sensor.

## What an alert looks like

Detail scales with severity, because a channel that sends the same wall of text
for everything trains its reader to ignore it. LOW is two lines. CRITICAL is the
full structured report:

```
🚨 NEMOS SECURITY INCIDENT
━━━━━━━━━━━━━━━━━━

Severity: HIGH

Detection:
PORT_SCAN

Confidence: 99%
Risk score: 89/100

Source:
192.0.2.10

Why this fired:
8 unique destination ports in 10s

Observed:
• 8 packets
• 1 unique destination
• 8 unique ports

Evidence:
• scan type: vertical
• ports: 8 — 20, 21, 22, 23, 24, 25, ...
• syn ratio: 1.0

ATT&CK:
T1595 — Active Scanning
Tactic: Reconnaissance

Incident: NEMOS-B956BF9FC040
Observed at: 2026-09-03T04:11:06+00:00

[ Investigate ] [ Acknowledge ] [ Open Dashboard ]
```

Every value there came out of the finding. A field NEMOS does not have produces
no line — not a blank, not a zero. Evidence lists are summarised rather than
dumped: a port scan legitimately carries a hundred port numbers, and sending all
of them helps nobody.

Messages are plain text with **no parse mode**. Alert fields carry
attacker-influenced content, and asking a chat client to parse that as Markdown
invites both delivery failures and formatting injection. Newlines are stripped
from every field so nothing can forge a second section.

## Commands

A linked chat can ask:

| Command | Answers with |
| --- | --- |
| `/status` | Capture, detection, ML, database and delivery state, plus live counters |
| `/incidents` | The most recent incidents, highest risk first |
| `/critical` | Only incidents carrying a critical finding |
| `/hosts` | Observed hosts ranked by risk |
| `/incident <id>` | One incident with its evidence timeline and ATT&CK mapping |
| `/brief` | The security summary on demand |

An unlinked chat gets pairing instructions and nothing else — not a count, not a
host, not an incident id. Authorisation is re-checked when an inline button is
pressed, so a chat unlinked after an alert was sent cannot still act on it.
Every state-changing action is recorded in an audit log with its actor, target,
result and timestamp, readable at `/api/telegram/audit`.

Set `NEMOS_TELEGRAM_BRIEF_HOUR` to send a daily summary at that UTC hour.

## Verifying delivery

NEMOS tests the delivery path against a mock Bot API, and the whole chain has
been exercised end to end against the live one -- live capture through to a
message arriving in a real chat. What it cannot test is *your* token and chat
id. Run:

```bash
python tools/verify_telegram.py
```

It sends one clearly-labelled test message and, on failure, names the likely
cause -- wrong token, unreachable chat, bot blocked, bot never started, missing
post rights, or no route to api.telegram.org. Credentials are read from the
environment or `.env`, never from arguments, and never printed.

## Telegram

1. Open Telegram and start a chat with **@BotFather**.
2. Create a bot with `/newbot` and copy the token. You do not need the username.
3. Add both to `.env` — this is the only Telegram configuration a deployment needs:

```env
TELEGRAM_BOT_TOKEN=your_bot_token
```

4. Open the **Sensor** page and press **Connect Telegram**, then scan the QR code.

`TELEGRAM_CHAT_ID` remains supported for a single fixed recipient, but is no
longer required: paired chats are the delivery audience.

## Phone alerts with no credentials at all

A Telegram bot token cannot be avoided — a token *is* the bot's identity, and
Telegram has no unauthenticated send path. If you want alerts on a phone and are
not willing to hold any credential, use a push service instead:

```env
NEMOS_WEBHOOK_URL=https://ntfy.sh/pick-something-long-and-unguessable
NEMOS_WEBHOOK_FORMAT=text
```

That is the entire configuration. No token, no chat id, no account, no signup.
Install the ntfy app, subscribe to that topic, and findings arrive as push
notifications carrying the same rendered report Telegram gets — severity,
evidence, ATT&CK technique, incident id — with the severity also set as the
notification's priority and tag.

What you give up, stated plainly:

| | Telegram | `text` webhook |
| --- | --- | --- |
| Credential to hold | one bot token, set once | **none** |
| Report format | full structured report | the same report |
| Inline actions (Investigate / Acknowledge) | yes | no |
| Commands (`/status`, `/incidents`, …) | yes | no |
| Who can read your alerts | only paired chats | **anyone who guesses the URL** |

That last row is the real cost. The topic name is the only thing protecting the
feed, so treat it as a password: long, random, never committed. A short or
guessable topic publishes your network's security findings to whoever tries it.

## Webhook

```env
NEMOS_WEBHOOK_URL=https://your-collector.example/hook
NEMOS_WEBHOOK_TOKEN=optional_bearer_token
NEMOS_WEBHOOK_FORMAT=json
```

The URL must be HTTPS unless it points at loopback: alert bodies describe your
network and are not sent in cleartext. Redirects are refused rather than
followed, so a redirect cannot downgrade the transport or retarget the payload.

## Syslog / SIEM

Findings can be exported as **CEF over RFC 5424 syslog**, the format Splunk,
QRadar, Elastic and Wazuh parse without a custom decoder — so NEMOS can be a
component of an existing detection stack rather than a second console nobody
watches.

```env
NEMOS_SYSLOG_HOST=10.0.0.9
NEMOS_SYSLOG_PORT=514
NEMOS_SYSLOG_PROTOCOL=udp      # or tcp
NEMOS_SYSLOG_FACILITY=13
```

A finding arrives looking like this:

```
<107>1 2026-01-01T00:00:00+00:00 sensor NEMOS - PORT_SCAN - CEF:0|NEMOS|NEMOS|4.1.0|PORT_SCAN|PORT_SCAN|7|src=203.0.113.9 dst=192.168.1.10 dpt=443 proto=TCP cn1=74 cn1Label=riskScore cs1=T1595 cs1Label=mitreTechnique cs2=NEMOS-ABC123 cs2Label=incidentId msg=20 distinct ports probed in 10s
```

UDP is the default because it cannot block delivery on an unreachable
collector; TCP is available where the collector requires it and losses matter
more than latency.

Every field is escaped before it is written. This is a security boundary, not
formatting: alert fields quote evidence, evidence quotes the network, and a
raw newline reaching a collector would let an attacker end the record and
forge a second one after it — putting adversary-controlled text into a record
a responder trusts. Newlines, pipes and equals signs are escaped, and a test
asserts a forged `CEF:0|Evil|...|All clear` inside a finding stays inside the
`msg=` field instead of becoming its own event.

## Tuning what gets sent

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEMOS_NOTIFY` | `true` | Master switch |
| `NEMOS_NOTIFY_MIN_SEVERITY` | `HIGH` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `NEMOS_NOTIFY_COOLDOWN` | `300` | Seconds before the same finding repeats |
| `NEMOS_NOTIFY_RATE` | `12` | Maximum messages per minute |
| `NEMOS_NOTIFY_TIMEOUT` | `5.0` | Per-request timeout |
| `NEMOS_NOTIFY_QUEUE` | `256` | Pending-delivery queue size |
| `NEMOS_WEBHOOK_FORMAT` | `json` | `text` posts the rendered report for push services |
| `TELEGRAM_BOT_TOKEN` | — | Deployment bot credential; never leaves the server |
| `TELEGRAM_BOT_USERNAME` | *(derived)* | Optional; resolved from the token via getMe when unset |
| `TELEGRAM_CHAT_ID` | — | Legacy fixed recipient; QR pairing replaces it |
| `NEMOS_DASHBOARD_URL` | — | Base URL alerts link back to; `https://` for a button |
| `NEMOS_TELEGRAM_BRIEF_HOUR` | — | UTC hour for the daily brief; unset is off |
| `NEMOS_TELEGRAM_CONTAIN_HOOK` | — | Lab-only containment executable (see below) |

The cooldown and rate limit exist so a port scan cannot turn the sensor into a
message flood. **Suppressed alerts are still recorded and still appear on the
dashboard** — only the outbound copy is dropped, and every suppression is
counted in `/api/notifications`.

The bot token is never returned by any endpoint and is redacted from logs and
error messages. A test asserts this against every Telegram route, against
`/api/status`, and against the rendered page.

## Containment

NEMOS is a passive sensor. It has no enforcement point, so it does not pretend
to have one: there is no built-in "block this host". Where a controlled lab has
a real containment action, point `NEMOS_TELEGRAM_CONTAIN_HOOK` at an executable
and a **Contain** button appears on alerts. Pressing it runs that executable
with the incident id as its only argument — argv form, no shell, a 20-second
timeout, and the id validated against the `NEMOS-<12 hex>` format NEMOS itself
mints, so nothing typed in a chat can become a command. Every attempt is
audited, and the button is absent unless the hook is configured.
