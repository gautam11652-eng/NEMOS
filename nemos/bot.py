"""The NEMOS Telegram bot: pairing, commands and inline actions.

This is the *inbound* half of the Telegram integration. ``nemos/notify.py``
pushes findings out; this module long-polls for what an operator sends back and
answers from live NEMOS state.

Boundaries that matter:

- **One bot, server-side.** The token lives in the deployment's environment.
  Operators pair a chat by scanning a QR code (see ``nemos/pairing.py``); they
  never see, paste or upload a credential.
- **Authorised or nothing.** Every command except ``/start <code>`` requires the
  sending chat to already be linked. An unlinked chat is told how to pair and is
  shown no telemetry at all -- not even a count.
- **Never fatal.** The poller runs on its own daemon thread inside a loop that
  catches everything. A Telegram outage, a malformed update or a rendering bug
  degrades to a logged warning; capture and detection keep running.
- **Bounded.** Per-chat token buckets, a cap on reply size, and hard limits on
  every query. A chat that floods the bot spends its own budget, not the
  sensor's.
- **Audited.** Every state-changing action records who did it, to what, and
  whether it worked, in the same durable store as the pairing state.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import shutil
import subprocess  # noqa: S404 - used only for an operator-supplied hook, argv form
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any
from collections.abc import Callable, Mapping

from .attack import enrich_alert
from .database import connect
from .intelligence import minted_incident_id, summarize_incident, valid_incident_id
from .notify import TELEGRAM_API_BASE, redact, telegram_api
from .pairing import PairingStore, valid_chat_id
from .telegram import (
    HELP_TEXT,
    PAIRED_NOTIFICATION,
    TEST_NOTIFICATION,
    UNAUTHORIZED_TEXT,
    render_brief,
    render_hosts,
    render_incident,
    render_incident_list,
    render_status,
)

log = logging.getLogger(__name__)

POLL_TIMEOUT = 25          # seconds Telegram holds a getUpdates call open
POLL_ERROR_BACKOFF = 5.0   # seconds to wait after the first failed poll
MAX_POLL_BACKOFF = 300.0   # ceiling for repeated failures
MAX_UPDATES = 20           # updates accepted per poll
COMMAND_RATE = 12          # commands per chat per minute
MAX_TRACKED_CHATS = 256
CONTAIN_TIMEOUT = 20.0     # seconds an operator containment hook may run

# Command replies are bounded independently of the alert cap: a list command
# answers from the database and must not be able to produce an unbounded reply.
LIST_LIMIT = 8


# -- live data collection ----------------------------------------------------


def collect_status(db_path: Path, *, capture: Any = None, notifier: Any = None,
                   analysis: Any = None, linked_chats: int = 0,
                   started_at: float | None = None) -> dict[str, Any]:
    """Assemble ``/status`` from real runtime state.

    Anything NEMOS cannot observe is reported as UNKNOWN. There is no default
    of "ONLINE" anywhere in here: a status message that guesses is worse than
    no status message.
    """
    state: dict[str, Any] = {
        "capture": "UNKNOWN",
        "detection": "UNKNOWN",
        "ml": "UNAVAILABLE",
        "database": "ERROR",
        "telegram": "CONNECTED" if linked_chats else "DISCONNECTED",
    }

    if capture is not None:
        try:
            status = capture.status()
            state["capture"] = str(status.get("display_state")
                                   or status.get("state") or "UNKNOWN").upper()
            state["interface"] = status.get("interface") or ""
            state["packets_captured"] = int(status.get("packets_seen") or 0)
        except Exception:  # pragma: no cover - defensive
            log.debug("could not read capture status for /status", exc_info=True)
            state["capture"] = "ERROR"

    try:
        c = connect(db_path)
        try:
            stats = c.execute(
                "SELECT packets, threats FROM telemetry_stats WHERE id = 1"
            ).fetchone()
            state["packets"] = int(stats["packets"] or 0) if stats else 0
            state["flows"] = int(
                c.execute("SELECT COUNT(*) AS n FROM flows").fetchone()["n"] or 0
            )
            state["hosts"] = int(
                c.execute("SELECT COUNT(*) AS n FROM host_stats").fetchone()["n"] or 0
            )
            state["incidents"] = int(
                c.execute(
                    "SELECT COUNT(DISTINCT incident_id) AS n FROM alerts "
                    "WHERE incident_id <> ''"
                ).fetchone()["n"] or 0
            )
            state["unacknowledged"] = int(
                c.execute(
                    "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged = 0"
                ).fetchone()["n"] or 0
            )
            state["database"] = "ONLINE"
            # The detector runs in this process, so the fact that this thread is
            # answering at all is the evidence for it. There is no separate
            # health signal to consult, and inventing one would be worse.
            state["detection"] = "ONLINE"
        finally:
            c.close()
    except Exception as exc:
        log.warning("could not read the database for /status: %s", exc)

    if analysis is not None:
        try:
            info = analysis.status()
            model = info.get("model") or {}
            if model.get("loaded"):
                state["ml"] = "AVAILABLE"
            elif info.get("bootstrap", {}).get("state") in {"TRAINING", "VALIDATING",
                                                            "WARMING_UP", "RETRAINING"}:
                state["ml"] = "LEARNING"
            elif model.get("error"):
                state["ml"] = "ERROR"
            else:
                state["ml"] = "FALLBACK"
            baseline = info.get("baseline_state") or info.get("baseline")
            if baseline:
                state["baseline"] = str(baseline)
        except Exception:  # pragma: no cover - defensive
            log.debug("could not read analysis status for /status", exc_info=True)
            state["ml"] = "ERROR"

    if notifier is not None:
        try:
            metrics = notifier.metrics()
            telegram = (metrics.get("channels") or {}).get("telegram") or {}
            if telegram.get("last_error"):
                state["note"] = f"Last delivery error: {telegram['last_error'][:120]}"
        except Exception:  # pragma: no cover - defensive
            log.debug("could not read notifier metrics for /status", exc_info=True)

    if started_at is not None:
        state["uptime_seconds"] = max(0.0, time.time() - started_at)
    return state


def _incident_rows(db_path: Path, limit: int, severities: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Return incident summaries built from stored alerts, highest risk first."""
    c = connect(db_path)
    try:
        clause = ""
        params: list[Any] = []
        if severities:
            # An incident qualifies when any of its detections has the severity
            # asked for -- an incident is not "critical" only when every one of
            # its findings is.
            marks = ",".join("?" for _ in severities)
            clause = (" AND incident_id IN (SELECT incident_id FROM alerts "
                      f"WHERE severity IN ({marks}) AND incident_id <> '')")
            params.extend(severities)
        ids = [
            row["incident_id"]
            for row in c.execute(
                "SELECT incident_id, MAX(id) AS last_id FROM alerts "
                f"WHERE incident_id <> ''{clause} "
                "GROUP BY incident_id ORDER BY last_id DESC LIMIT ?",
                (*params, max(1, min(50, int(limit) * 4))),
            )
        ]
        if not ids:
            return []
        marks = ",".join("?" for _ in ids)
        rows = [
            enrich_alert(dict(row))
            for row in c.execute(
                # `marks` is a run of `?` placeholders; the ids are bound.
                f"""SELECT id,timestamp,threat,category,source,severity,risk_score,
                           confidence,reason,technique,incident_id,evidence
                    FROM alerts WHERE incident_id IN ({marks})
                    ORDER BY id ASC LIMIT 500""",
                ids,
            )
        ]
    finally:
        c.close()

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["incident_id"], []).append(row)

    summaries = []
    for incident_id, alerts in grouped.items():
        summary = summarize_incident(incident_id, alerts).as_dict()
        summary["last_seen"] = max(str(a.get("timestamp") or "") for a in alerts)
        summaries.append(summary)
    # Highest risk first; most recent breaks a tie.
    summaries.sort(key=lambda item: (int(item["risk_score"]), item["last_seen"]), reverse=True)
    return summaries[:limit]


def collect_incidents(db_path: Path, limit: int = LIST_LIMIT) -> list[dict[str, Any]]:
    return _incident_rows(db_path, limit)


def collect_critical(db_path: Path, limit: int = LIST_LIMIT) -> list[dict[str, Any]]:
    return _incident_rows(db_path, limit, ("CRITICAL",))


def collect_hosts(db_path: Path, limit: int = LIST_LIMIT) -> list[dict[str, Any]]:
    c = connect(db_path)
    try:
        rows = c.execute(
            "SELECT host,packets,alert_count,critical_count,max_risk FROM host_stats "
            "ORDER BY max_risk DESC, critical_count DESC, packets DESC, host ASC LIMIT ?",
            (max(1, min(25, int(limit))),),
        ).fetchall()
    finally:
        c.close()
    result = []
    for row in rows:
        alert_count = int(row["alert_count"] or 0)
        critical = int(row["critical_count"] or 0)
        max_risk = int(row["max_risk"] or 0)
        # The same bounded, explainable host risk the API serves; kept identical
        # so chat and dashboard cannot disagree about a host.
        result.append({
            "host": row["host"],
            "packets": int(row["packets"] or 0),
            "alert_count": alert_count,
            "critical_count": critical,
            "risk_score": min(100, max_risk + min(20, alert_count * 4) + min(10, critical * 5)),
        })
    return result


def collect_incident(db_path: Path, incident_id: str) -> tuple[dict[str, Any] | None,
                                                               list[dict[str, Any]]]:
    if not valid_incident_id(incident_id):
        return None, []
    c = connect(db_path)
    try:
        rows = [
            enrich_alert(dict(row))
            for row in c.execute(
                """SELECT id,timestamp,threat,category,source,severity,risk_score,
                          confidence,reason,technique,incident_id,acknowledged,evidence
                   FROM alerts WHERE incident_id = ? ORDER BY id ASC LIMIT 200""",
                (incident_id,),
            )
        ]
    finally:
        c.close()
    if not rows:
        return None, []
    return summarize_incident(incident_id, rows).as_dict(), rows


def collect_brief(db_path: Path, hours: float = 24.0) -> dict[str, Any]:
    """Gather the daily brief from stored telemetry.

    Every figure is a query result. Where a figure has no query behind it the
    key is simply absent, and the renderer omits the line.
    """
    c = connect(db_path)
    try:
        stats = c.execute(
            "SELECT packets FROM telemetry_stats WHERE id = 1"
        ).fetchone()
        data: dict[str, Any] = {
            "period": f"Last {int(hours)}h of recorded telemetry",
            "packets": int(stats["packets"] or 0) if stats else 0,
            "flows": int(c.execute("SELECT COUNT(*) AS n FROM flows").fetchone()["n"] or 0),
            "hosts": int(c.execute("SELECT COUNT(*) AS n FROM host_stats").fetchone()["n"] or 0),
        }
        severity_counts = {
            str(row["severity"]).upper(): int(row["n"] or 0)
            for row in c.execute(
                "SELECT severity, COUNT(DISTINCT incident_id) AS n FROM alerts "
                "WHERE incident_id <> '' GROUP BY severity"
            )
        }
        if severity_counts:
            data["severity_counts"] = severity_counts
        data["top_detections"] = [
            {"threat": row["threat"], "count": int(row["n"] or 0)}
            for row in c.execute(
                "SELECT threat, COUNT(*) AS n FROM alerts GROUP BY threat "
                "ORDER BY n DESC, threat ASC LIMIT 5"
            )
        ]
        highest = c.execute("SELECT MAX(risk_score) AS r FROM alerts").fetchone()
        if highest is not None and highest["r"] is not None:
            data["highest_risk"] = int(highest["r"])
        data["unresolved"] = int(
            c.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged = 0"
            ).fetchone()["n"] or 0
        )
    finally:
        c.close()

    data["top_hosts"] = collect_hosts(db_path, 5)
    recommended = [
        f"{item['host']} — risk {item['risk_score']}/100"
        for item in data["top_hosts"] if item["risk_score"] >= 75
    ]
    if recommended:
        data["recommended"] = recommended[:5]
    return data


# -- the bot -----------------------------------------------------------------


class TelegramBot:
    """Long-polls Telegram and answers with live NEMOS data."""

    def __init__(self, token: str, store: PairingStore, db_path: Path, *,
                 capture: Any = None, notifier: Any = None, analysis: Any = None,
                 dashboard_url: str = "", bot_username: str = "",
                 contain_hook: str = "", api_base: str = TELEGRAM_API_BASE,
                 api: Callable[..., Any] | None = None,
                 started_at: float | None = None):
        self.token = token
        self.store = store
        self.db_path = Path(db_path)
        self.capture = capture
        self.notifier = notifier
        self.analysis = analysis
        self.dashboard_url = dashboard_url
        self.bot_username = bot_username
        self.contain_hook = contain_hook
        self.api_base = api_base
        self._api = api or telegram_api
        self.started_at = started_at if started_at is not None else time.time()

        self._offset = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self.handled = 0
        self.errors = 0
        self.last_error = ""

    # -- lifecycle -----------------------------------------------------------

    @property
    def active(self) -> bool:
        return bool(self.token)

    def start(self) -> None:
        if not self.active:
            log.info("Telegram bot idle: no TELEGRAM_BOT_TOKEN configured")
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="telegram-bot",
                                            daemon=True)
            self._thread.start()
        log.info("Telegram command bot started")

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(max(0.0, float(timeout)))
        with self._lock:
            self._thread = None

    def _run(self) -> None:
        failures = 0
        while not self._stop.is_set():
            try:
                updates = self._poll()
            except Exception as exc:
                self.errors += 1
                self.last_error = redact(str(exc), self.token)[:200]
                # An invalid token fails identically forever. Retrying it every
                # five seconds fills the log with the same line and tells the
                # operator nothing new, so the wait doubles up to a ceiling and
                # only the first few failures are logged at warning.
                if failures < 3:
                    log.warning("Telegram poll failed: %s", self.last_error)
                elif failures == 3:
                    log.warning(
                        "Telegram poll is still failing (%s); backing off and "
                        "logging further failures at debug level",
                        self.last_error,
                    )
                else:
                    log.debug("Telegram poll failed: %s", self.last_error)
                self._stop.wait(min(MAX_POLL_BACKOFF,
                                    POLL_ERROR_BACKOFF * (2 ** min(failures, 6))))
                failures += 1
                continue
            failures = 0
            for update in updates:
                if self._stop.is_set():
                    break
                try:
                    self.handle(update)
                except Exception as exc:  # a bad update must not kill the loop
                    self.errors += 1
                    self.last_error = redact(str(exc), self.token)[:200]
                    log.warning("Telegram update handling failed: %s", self.last_error)

    def _poll(self) -> list[dict[str, Any]]:
        result = self._api(
            self.token, "getUpdates",
            {
                "offset": self._offset or None,
                "timeout": POLL_TIMEOUT,
                "limit": MAX_UPDATES,
                "allowed_updates": json.dumps(["message", "callback_query"]),
            },
            timeout=POLL_TIMEOUT + 10,
            api_base=self.api_base,
        )
        updates = result if isinstance(result, list) else []
        for update in updates:
            if isinstance(update, Mapping):
                self._offset = max(self._offset, int(update.get("update_id", 0)) + 1)
        return [u for u in updates if isinstance(u, Mapping)]

    # -- outbound ------------------------------------------------------------

    def send(self, chat_id: Any, text: str, keyboard: Mapping[str, Any] | None = None) -> bool:
        """Send one message. Returns False instead of raising on failure."""
        params: dict[str, Any] = {
            "chat_id": str(chat_id),
            "text": text[:4096],
            "disable_web_page_preview": "true",
        }
        if keyboard:
            params["reply_markup"] = json.dumps(keyboard, separators=(",", ":"))
        try:
            self._api(self.token, "sendMessage", params, timeout=15.0,
                      api_base=self.api_base)
            return True
        except Exception as exc:
            self.errors += 1
            self.last_error = redact(str(exc), self.token)[:200]
            log.warning("Telegram reply failed: %s", self.last_error)
            return False

    def _answer_callback(self, callback_id: str, text: str = "") -> None:
        try:
            self._api(self.token, "answerCallbackQuery",
                      {"callback_query_id": callback_id, "text": text[:200]},
                      timeout=10.0, api_base=self.api_base)
        except Exception:
            # A missing acknowledgement leaves a spinner in the client. That is
            # cosmetic; the action itself already happened and was audited.
            log.debug("could not acknowledge a callback query", exc_info=True)

    # -- rate limiting -------------------------------------------------------

    def _allow(self, chat_id: str, now: float | None = None) -> bool:
        """Per-chat token bucket. A chatty chat spends only its own budget."""
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, updated = self._buckets.get(chat_id, (float(COMMAND_RATE), now))
            tokens = min(float(COMMAND_RATE),
                         tokens + max(0.0, now - updated) * (COMMAND_RATE / 60.0))
            if tokens < 1.0:
                self._buckets[chat_id] = (tokens, now)
                self._buckets.move_to_end(chat_id)
                return False
            self._buckets[chat_id] = (tokens - 1.0, now)
            self._buckets.move_to_end(chat_id)
            while len(self._buckets) > MAX_TRACKED_CHATS:
                self._buckets.popitem(last=False)
        return True

    # -- dispatch ------------------------------------------------------------

    def handle(self, update: Mapping[str, Any]) -> None:
        if "callback_query" in update:
            self._handle_callback(update["callback_query"])
            return
        message = update.get("message")
        if not isinstance(message, Mapping):
            return
        chat = message.get("chat")
        chat_id = (chat or {}).get("id") if isinstance(chat, Mapping) else None
        if not valid_chat_id(chat_id):
            return
        chat_id = str(chat_id)
        text = str(message.get("text") or "").strip()
        if not text.startswith("/"):
            return
        if not self._allow(chat_id):
            return
        self.handled += 1

        command, _, argument = text.partition(" ")
        # Telegram appends @botname in groups.
        command = command.split("@", 1)[0].lower()
        argument = argument.strip()[:64]

        if command == "/start":
            self._handle_start(chat_id, argument, message)
            return

        if not self.store.is_linked(chat_id):
            self.send(chat_id, UNAUTHORIZED_TEXT)
            return
        self.store.touch(chat_id)

        if command in ("/help", "/commands"):
            self.send(chat_id, HELP_TEXT)
        elif command == "/status":
            self.send(chat_id, render_status(collect_status(
                self.db_path, capture=self.capture, notifier=self.notifier,
                analysis=self.analysis, linked_chats=len(self.store.chat_ids()),
                started_at=self.started_at,
            )))
        elif command == "/incidents":
            self.send(chat_id, render_incident_list(
                collect_incidents(self.db_path), dashboard_url=self.dashboard_url))
        elif command == "/critical":
            self.send(chat_id, render_incident_list(
                collect_critical(self.db_path), title="CRITICAL INCIDENTS",
                empty="No critical incidents recorded.",
                dashboard_url=self.dashboard_url))
        elif command == "/hosts":
            self.send(chat_id, render_hosts(collect_hosts(self.db_path)))
        elif command == "/incident":
            self._handle_incident(chat_id, argument)
        elif command == "/brief":
            self.send(chat_id, render_brief(collect_brief(self.db_path),
                                            dashboard_url=self.dashboard_url))
        elif command == "/test":
            self.send(chat_id, TEST_NOTIFICATION)
        else:
            self.send(chat_id, HELP_TEXT)

    def _handle_start(self, chat_id: str, argument: str, message: Mapping[str, Any]) -> None:
        if not argument:
            if self.store.is_linked(chat_id):
                self.send(chat_id, HELP_TEXT)
            else:
                self.send(chat_id, UNAUTHORIZED_TEXT)
            return
        sender = message.get("from") if isinstance(message.get("from"), Mapping) else {}
        label = str(sender.get("username") or sender.get("first_name") or "")[:64]
        ok, reason = self.store.redeem(argument, chat_id, label)
        # The code itself is never logged or audited -- only the outcome.
        self.store.record(chat_id, "pair", "", "ok" if ok else "denied", reason)
        if ok:
            self.send(chat_id, PAIRED_NOTIFICATION)
        else:
            self.send(chat_id,
                      "That pairing code is not valid. Generate a new QR code in "
                      "the NEMOS dashboard and scan it again.")

    def _handle_incident(self, chat_id: str, argument: str) -> None:
        incident_id = argument.strip().upper()
        if not valid_incident_id(incident_id):
            self.send(chat_id, "Usage: /incident NEMOS-XXXXXXXXXXXX")
            return
        summary, alerts = collect_incident(self.db_path, incident_id)
        if summary is None:
            self.send(chat_id, f"No incident {incident_id} is recorded.")
            return
        self.send(chat_id, render_incident(summary, alerts,
                                           dashboard_url=self.dashboard_url))

    # -- inline actions ------------------------------------------------------

    def _handle_callback(self, callback: Mapping[str, Any]) -> None:
        callback_id = str(callback.get("id") or "")[:64]
        message = callback.get("message") if isinstance(callback.get("message"), Mapping) else {}
        chat = message.get("chat") if isinstance(message.get("chat"), Mapping) else {}
        chat_id = chat.get("id")
        if not valid_chat_id(chat_id):
            return
        chat_id = str(chat_id)

        # Authorisation is re-checked here, not inherited from the message the
        # button was attached to: a chat can be unlinked after an alert was sent.
        if not self.store.is_linked(chat_id):
            self.store.record(chat_id, "callback", "", "denied", "chat not linked")
            self._answer_callback(callback_id, "Not authorised.")
            return
        if not self._allow(chat_id):
            self._answer_callback(callback_id, "Too many requests.")
            return
        self.handled += 1

        data = str(callback.get("data") or "")[:64]
        action, _, target = data.partition(":")
        if action == "inv":
            self._handle_incident(chat_id, target)
            self.store.record(chat_id, "investigate", target, "ok")
            self._answer_callback(callback_id, "Incident detail sent.")
        elif action == "ack":
            ok = self._acknowledge_alert(target)
            self.store.record(chat_id, "acknowledge", f"alert:{target}",
                              "ok" if ok else "not_found")
            self._answer_callback(callback_id,
                                  "Acknowledged." if ok else "Nothing to acknowledge.")
        elif action == "acki":
            count = self._acknowledge_incident(target)
            self.store.record(chat_id, "acknowledge", target,
                              "ok" if count else "not_found", f"{count} detections")
            self._answer_callback(
                callback_id,
                f"Acknowledged {count} detection(s)." if count else "Nothing to acknowledge.")
        elif action == "con":
            self._handle_contain(chat_id, target, callback_id)
        else:
            self._answer_callback(callback_id, "Unknown action.")

    def _acknowledge_alert(self, target: str) -> bool:
        if not str(target).isdigit():
            return False
        c = connect(self.db_path)
        try:
            cursor = c.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ? AND acknowledged = 0",
                (int(target),),
            )
            c.commit()
            return bool(cursor.rowcount)
        finally:
            c.close()

    def _acknowledge_incident(self, incident_id: str) -> int:
        if not valid_incident_id(incident_id):
            return 0
        c = connect(self.db_path)
        try:
            cursor = c.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE incident_id = ? AND acknowledged = 0",
                (incident_id,),
            )
            c.commit()
            return int(cursor.rowcount or 0)
        finally:
            c.close()

    def _handle_contain(self, chat_id: str, incident_id: str, callback_id: str) -> None:
        """Run the operator's containment hook, if this deployment has one.

        NEMOS is a passive sensor: it has no enforcement point of its own, so it
        does not invent one. Containment happens only where the operator has
        supplied an executable via ``NEMOS_TELEGRAM_CONTAIN_HOOK``, and NEMOS
        does no more than run it with a validated incident id.

        The hook is executed as an argv list with no shell, so nothing in a chat
        message can be interpreted as a command; the incident id has already
        been matched against the format NEMOS itself mints; the call is bounded
        by a timeout; and the outcome is audited either way.
        """
        if not self.contain_hook:
            self.store.record(chat_id, "contain", incident_id, "unavailable",
                              "no containment hook configured")
            self._answer_callback(callback_id, "Containment is not configured.")
            return
        if not minted_incident_id(incident_id):
            self.store.record(chat_id, "contain", incident_id, "denied", "invalid id")
            self._answer_callback(callback_id, "Invalid incident.")
            return
        hook = shutil.which(self.contain_hook) or self.contain_hook
        if not Path(hook).is_file():
            self.store.record(chat_id, "contain", incident_id, "error", "hook not found")
            self._answer_callback(callback_id, "Containment hook is missing.")
            return
        try:
            completed = subprocess.run(  # noqa: S603 - argv form, no shell, validated id
                [hook, incident_id], capture_output=True, text=True,
                timeout=CONTAIN_TIMEOUT, check=False, shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self.store.record(chat_id, "contain", incident_id, "error", str(exc)[:200])
            self._answer_callback(callback_id, "Containment failed.")
            return
        ok = completed.returncode == 0
        self.store.record(chat_id, "contain", incident_id, "ok" if ok else "failed",
                          (completed.stdout or completed.stderr or "")[:200])
        self._answer_callback(callback_id,
                              "Containment hook ran." if ok else "Containment hook failed.")

    # -- health --------------------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        """Bot health. Never includes the token."""
        with self._lock:
            running = bool(self._thread is not None and self._thread.is_alive())
        return {
            "active": self.active,
            "running": running,
            "handled": self.handled,
            "errors": self.errors,
            "last_error": self.last_error,
            "linked_chats": len(self.store.chat_ids()),
            "contain_configured": bool(self.contain_hook),
        }


class DailyBrief:
    """Send the scheduled security summary once a day, at a configured UTC hour.

    Off unless ``NEMOS_TELEGRAM_BRIEF_HOUR`` is set. It runs on its own thread
    and shares the bot's send path, so a brief that fails is a logged warning
    like any other delivery -- never an exception on a detection thread.

    The "once a day" guarantee is a stored date rather than a sleep: a sensor
    that was suspended, or whose clock jumped, sends at most one brief per UTC
    day instead of a burst catching up.
    """

    def __init__(self, bot: TelegramBot, hour: int, *, interval: float = 60.0,
                 clock: Callable[[], dt.datetime] | None = None):
        self.bot = bot
        self.hour = max(0, min(23, int(hour)))
        self.interval = max(1.0, float(interval))
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_sent: dt.date | None = None
        self.sent = 0

    def due(self, now: dt.datetime) -> bool:
        return now.hour == self.hour and self._last_sent != now.date()

    def run_once(self, now: dt.datetime | None = None) -> bool:
        """Send the brief if it is due. Returns whether anything was sent."""
        now = now or self._clock()
        if not self.due(now):
            return False
        self._last_sent = now.date()
        chats = self.bot.store.chat_ids()
        if not chats:
            return False
        try:
            text = render_brief(collect_brief(self.bot.db_path),
                                dashboard_url=self.bot.dashboard_url)
        except Exception:
            log.warning("could not build the daily brief", exc_info=True)
            return False
        for chat_id in chats:
            self.bot.send(chat_id, text)
        self.sent += 1
        return True

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="telegram-brief",
                                        daemon=True)
        self._thread.start()
        log.info("daily Telegram brief scheduled for %02d:00 UTC", self.hour)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # pragma: no cover - the thread must never die
                log.exception("daily brief scheduler error")
            self._stop.wait(self.interval)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(max(0.0, float(timeout)))
        self._thread = None


__all__ = [
    "COMMAND_RATE",
    "DailyBrief",
    "LIST_LIMIT",
    "TelegramBot",
    "collect_brief",
    "collect_critical",
    "collect_hosts",
    "collect_incident",
    "collect_incidents",
    "collect_status",
]
