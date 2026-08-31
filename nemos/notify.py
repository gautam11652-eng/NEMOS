"""Outbound alert delivery for NEMOS.

NEMOS is a local-first sensor, but an alert nobody reads is not a detection.
This module delivers findings to an operator-configured channel (Telegram or a
generic webhook) without ever blocking the packet-capture path.

Design constraints, in priority order:

1. **Never block capture.** ``submit`` performs bounded, non-blocking work and
   returns immediately. All network I/O happens on a dedicated worker thread.
2. **Never amplify an attack.** A port scan can generate findings faster than
   any chat API accepts them. Severity filtering, per-finding cooldown and a
   global token bucket bound outbound volume; excess is counted, not queued.
3. **Never leak the credential.** The Telegram bot token appears in the request
   URL, so every log line and error string is redacted before it escapes.
4. **No new dependencies.** Delivery uses the standard library only.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any
from collections.abc import Callable, Mapping
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
DEFAULT_MIN_SEVERITY = "HIGH"

TELEGRAM_API_BASE = "https://api.telegram.org"
TELEGRAM_MAX_MESSAGE = 3500

# Bound the cooldown map: the key contains an attacker-influenceable source
# address, so it must not grow without limit.
MAX_COOLDOWN_ENTRIES = 4096

Transport = Callable[[str, str, Mapping[str, str], bytes, float], tuple[int, str]]


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _float_env(name: str, default: float, lo: float, hi: float) -> float:
    try:
        value = float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
    if value != value or value in (float("inf"), float("-inf")):  # NaN / Inf
        return default
    return max(lo, min(hi, value))


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(os.getenv(name, default))
    except (TypeError, ValueError):
        value = default
    return max(lo, min(hi, value))


def _is_loopback(host: str) -> bool:
    host = (host or "").strip("[]")
    if host in {"localhost", ""}:
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def valid_webhook_url(url: str) -> bool:
    """Accept only an HTTPS webhook, or plain HTTP to an explicit loopback host.

    Alert bodies describe the monitored network. Sending them in cleartext to a
    remote collector would leak exactly the telemetry NEMOS exists to protect.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme == "https":
        return bool(parts.hostname)
    if parts.scheme == "http":
        return bool(parts.hostname) and _is_loopback(parts.hostname)
    return False


@dataclass(frozen=True)
class NotifierConfig:
    """Delivery configuration resolved from the environment."""

    telegram_token: str = ""
    telegram_chat_id: str = ""
    webhook_url: str = ""
    webhook_token: str = ""
    min_severity: str = DEFAULT_MIN_SEVERITY
    cooldown_seconds: float = 300.0
    rate_per_minute: int = 12
    timeout_seconds: float = 5.0
    queue_size: int = 256
    enabled: bool = True

    @property
    def telegram_configured(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat_id)

    @property
    def webhook_configured(self) -> bool:
        return bool(self.webhook_url)

    @property
    def any_channel(self) -> bool:
        return self.telegram_configured or self.webhook_configured

    @property
    def active(self) -> bool:
        return self.enabled and self.any_channel

    @classmethod
    def from_env(cls) -> NotifierConfig:
        severity = os.getenv("NEMOS_NOTIFY_MIN_SEVERITY", DEFAULT_MIN_SEVERITY).strip().upper()
        if severity not in SEVERITY_ORDER:
            severity = DEFAULT_MIN_SEVERITY
        webhook = os.getenv("NEMOS_WEBHOOK_URL", "").strip()
        if webhook and not valid_webhook_url(webhook):
            log.error(
                "ignoring NEMOS_WEBHOOK_URL: an https:// URL is required "
                "(http:// is allowed only for a loopback address)"
            )
            webhook = ""
        return cls(
            telegram_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
            telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", "").strip(),
            webhook_url=webhook,
            webhook_token=os.getenv("NEMOS_WEBHOOK_TOKEN", "").strip(),
            min_severity=severity,
            cooldown_seconds=_float_env("NEMOS_NOTIFY_COOLDOWN", 300.0, 0.0, 86_400.0),
            rate_per_minute=_int_env("NEMOS_NOTIFY_RATE", 12, 1, 600),
            timeout_seconds=_float_env("NEMOS_NOTIFY_TIMEOUT", 5.0, 0.5, 60.0),
            queue_size=_int_env("NEMOS_NOTIFY_QUEUE", 256, 8, 10_000),
            enabled=_bool_env("NEMOS_NOTIFY", True),
        )


def redact(text: str, *secrets: str) -> str:
    """Remove credentials from text that may reach a log or an API response."""
    result = str(text)
    for secret in secrets:
        if secret and len(secret) >= 4:
            result = result.replace(secret, "***")
    return result


# urllib follows redirects by default. A redirect on an alert POST could
# silently downgrade the transport or retarget the payload at another host, so
# redirects are refused outright rather than followed.
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_post(method: str, url: str, headers: Mapping[str, str], body: bytes,
              timeout: float) -> tuple[int, str]:
    """Perform one bounded HTTP request and return ``(status, body_text)``."""
    # Schemes are constrained upstream: the Telegram base URL is a fixed https
    # constant, and webhook URLs must pass valid_webhook_url before reaching here.
    request = urllib.request.Request(url, data=body, method=method)  # noqa: S310
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with _OPENER.open(request, timeout=timeout) as response:  # noqa: S310
            # Responses are only used for diagnostics; cap what we read.
            return int(response.status), response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(4096).decode("utf-8", "replace")
        except Exception:  # pragma: no cover - diagnostic path only
            # The status code is what the caller acts on; an unreadable error
            # body is not itself worth surfacing or failing over.
            log.debug("could not read error body from %s", urlsplit(url).hostname)
        return int(exc.code), detail


def telegram_api(token: str, method: str, params: Mapping[str, Any] | None = None,
                 timeout: float = 15.0, api_base: str = TELEGRAM_API_BASE) -> dict[str, Any]:
    """Call one Bot API method and return its ``result``.

    Used by setup tooling for the read-only methods (getMe, getUpdates) that
    delivery itself never needs. It goes through the same non-redirecting
    opener as delivery, and raises DeliveryError with the token redacted, so
    setup cannot become the one path that leaks the credential.
    """
    query = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{api_base.rstrip('/')}/bot{token}/{method}"
    if query:
        url = f"{url}?{query}"
    request = urllib.request.Request(url, method="GET")  # noqa: S310
    try:
        with _OPENER.open(request, timeout=timeout) as response:  # noqa: S310
            status, raw = int(response.status), response.read(1_000_000)
    except urllib.error.HTTPError as exc:
        status, raw = int(exc.code), exc.read(64_000)
    except urllib.error.URLError as exc:
        raise DeliveryError(f"could not reach Telegram: {redact(str(exc.reason), token)}") from exc

    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise DeliveryError(
            f"{method} returned {status} with an unparseable body: "
            f"{redact(text, token)[:200]}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        description = ""
        if isinstance(payload, dict):
            description = str(payload.get("description") or "")
        raise DeliveryError(
            f"{method} failed ({status}): {redact(description, token)[:200] or status}"
        )
    return payload.get("result")


def format_alert_text(alert: Mapping[str, Any]) -> str:
    """Render a plain-text alert summary.

    No Markdown/HTML parse mode is used. Alert fields describe observed network
    activity, and asking a chat client to parse that as markup invites both
    rendering failures and formatting injection.
    """
    severity = str(alert.get("severity") or "UNKNOWN").upper()
    lines = [
        f"NEMOS {severity}: {alert.get('threat') or 'DETECTION'}",
        f"source: {alert.get('source') or 'unknown'}",
        f"risk: {alert.get('risk_score', 0)}/100  confidence: {alert.get('confidence', 0)}%",
    ]
    reason = str(alert.get("reason") or "").strip()
    if reason:
        lines.append(f"reason: {reason}")
    technique = str(alert.get("technique") or "").strip()
    if technique:
        lines.append(f"ATT&CK: {technique}")
    incident = str(alert.get("incident_id") or "").strip()
    if incident:
        lines.append(f"incident: {incident}")
    timestamp = str(alert.get("timestamp") or "").strip()
    if timestamp:
        lines.append(f"time: {timestamp}")
    text = "\n".join(lines)
    if len(text) > TELEGRAM_MAX_MESSAGE:
        text = text[: TELEGRAM_MAX_MESSAGE - 3] + "..."
    return text


@dataclass
class _ChannelState:
    name: str
    sent: int = 0
    failed: int = 0
    last_error: str = ""
    last_success: float = 0.0


class _Channel:
    name = "channel"

    def send(self, alert: Mapping[str, Any], transport: Transport, timeout: float) -> None:
        raise NotImplementedError


class TelegramChannel(_Channel):
    name = "telegram"

    def __init__(self, token: str, chat_id: str, api_base: str = TELEGRAM_API_BASE):
        self.token = token
        self.chat_id = chat_id
        self.api_base = api_base.rstrip("/")

    def send(self, alert: Mapping[str, Any], transport: Transport, timeout: float) -> None:
        url = f"{self.api_base}/bot{self.token}/sendMessage"
        body = json.dumps(
            {
                "chat_id": self.chat_id,
                "text": format_alert_text(alert),
                "disable_web_page_preview": True,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        status, detail = transport(
            "POST", url, {"Content-Type": "application/json"}, body, timeout
        )
        safe = redact(detail, self.token)[:200]
        if status != 200:
            # The token is embedded in the URL and echoed by some errors.
            raise DeliveryError(f"telegram responded {status}: {safe}")

        # A 200 is not proof of delivery. The Bot API carries its outcome in the
        # `ok` field of a JSON body, and can answer 200 with `"ok": false`.
        # Trusting the status code alone reported those as delivered, so the
        # operator saw a success for a message that was never sent -- the worst
        # possible failure for an alerting path. The API always answers JSON, so
        # a body that will not parse is also treated as a failure rather than
        # assumed good.
        try:
            payload = json.loads(detail)
        except (ValueError, TypeError) as exc:
            raise DeliveryError(
                f"telegram returned {status} with an unparseable body: {safe}"
            ) from exc
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            description = ""
            if isinstance(payload, dict):
                description = str(payload.get("description") or "")
            raise DeliveryError(
                "telegram accepted the request but reported failure: "
                f"{redact(description, self.token)[:200] or safe}"
            )


class WebhookChannel(_Channel):
    name = "webhook"

    def __init__(self, url: str, token: str = ""):
        self.url = url
        self.token = token

    def send(self, alert: Mapping[str, Any], transport: Transport, timeout: float) -> None:
        headers = {"Content-Type": "application/json", "User-Agent": "NEMOS"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = json.dumps(
            {"source": "NEMOS", "alert": dict(alert)}, separators=(",", ":"), default=str
        ).encode("utf-8")
        status, detail = transport("POST", self.url, headers, body, timeout)
        if not 200 <= status < 300:
            raise DeliveryError(
                f"webhook responded {status}: {redact(detail, self.token)[:200]}"
            )


class DeliveryError(RuntimeError):
    """Raised by a channel when a single delivery attempt fails."""


@dataclass
class _Counters:
    accepted: int = 0
    delivered: int = 0
    failed: int = 0
    dropped_queue_full: int = 0
    suppressed_severity: int = 0
    suppressed_cooldown: int = 0
    suppressed_rate: int = 0
    channels: dict[str, _ChannelState] = field(default_factory=dict)


class AlertNotifier:
    """Bounded, non-blocking alert delivery.

    ``submit`` is safe to call from the packet-capture thread: it applies the
    severity floor, the per-finding cooldown and the global rate limit under a
    short lock, then hands the alert to a worker thread. It never performs I/O
    and never blocks.
    """

    def __init__(self, config: NotifierConfig | None = None, *,
                 transport: Transport | None = None,
                 channels: list[_Channel] | None = None):
        self.config = config or NotifierConfig()
        self._transport = transport or http_post
        if channels is None:
            channels = []
            if self.config.telegram_configured:
                channels.append(
                    TelegramChannel(self.config.telegram_token, self.config.telegram_chat_id)
                )
            if self.config.webhook_configured:
                channels.append(
                    WebhookChannel(self.config.webhook_url, self.config.webhook_token)
                )
        self.channels = channels

        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(
            maxsize=self.config.queue_size
        )
        self._lock = threading.Lock()
        self._counters = _Counters(
            channels={channel.name: _ChannelState(channel.name) for channel in self.channels}
        )
        self._cooldown: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._tokens = float(self.config.rate_per_minute)
        self._tokens_updated = time.monotonic()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started = False
        self._floor = SEVERITY_ORDER.get(self.config.min_severity, SEVERITY_ORDER[DEFAULT_MIN_SEVERITY])

    @property
    def active(self) -> bool:
        return bool(self.config.enabled and self.channels)

    def start(self) -> None:
        if not self.active:
            if self.config.enabled and not self.channels:
                log.info("alert delivery idle: no Telegram or webhook channel configured")
            else:
                log.info("alert delivery disabled by configuration")
            return
        with self._lock:
            if self._started and self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._started = True
            self._thread = threading.Thread(
                target=self._run, name="alert-notifier", daemon=True
            )
            self._thread.start()
        log.info(
            "alert delivery enabled: channels=%s min_severity=%s rate=%s/min",
            ",".join(channel.name for channel in self.channels),
            self.config.min_severity,
            self.config.rate_per_minute,
        )

    def _allow(self, alert: Mapping[str, Any], now: float) -> bool:
        """Apply severity, cooldown and rate limits. Caller must hold the lock."""
        severity = str(alert.get("severity") or "").upper()
        if SEVERITY_ORDER.get(severity, -1) < self._floor:
            self._counters.suppressed_severity += 1
            return False

        key = (str(alert.get("source") or ""), str(alert.get("threat") or ""))
        if self.config.cooldown_seconds > 0:
            previous = self._cooldown.get(key)
            if previous is not None and now - previous < self.config.cooldown_seconds:
                self._cooldown.move_to_end(key)
                self._counters.suppressed_cooldown += 1
                return False

        # Token bucket, refilled continuously. A scan that produces distinct
        # findings must not be able to flood the channel even though each
        # individual finding passes the cooldown.
        elapsed = max(0.0, now - self._tokens_updated)
        self._tokens_updated = now
        self._tokens = min(
            float(self.config.rate_per_minute),
            self._tokens + elapsed * (self.config.rate_per_minute / 60.0),
        )
        if self._tokens < 1.0:
            self._counters.suppressed_rate += 1
            return False
        self._tokens -= 1.0

        if self.config.cooldown_seconds > 0:
            self._cooldown[key] = now
            self._cooldown.move_to_end(key)
            while len(self._cooldown) > MAX_COOLDOWN_ENTRIES:
                self._cooldown.popitem(last=False)
        return True

    def submit(self, alert: Mapping[str, Any]) -> bool:
        """Queue an alert for delivery. Returns True if it was accepted."""
        if not self.active or not self._started:
            return False
        payload = dict(alert)
        now = time.monotonic()
        with self._lock:
            if not self._allow(payload, now):
                return False
            try:
                self._queue.put_nowait(payload)
            except queue.Full:
                # Delivery is best-effort by design; the alert is already
                # durably stored in SQLite regardless of channel health.
                self._counters.dropped_queue_full += 1
                return False
            self._counters.accepted += 1
        return True

    def _deliver(self, alert: Mapping[str, Any]) -> None:
        delivered_any = False
        for channel in self.channels:
            error: Exception | None = None
            for attempt in range(2):
                try:
                    channel.send(alert, self._transport, self.config.timeout_seconds)
                    error = None
                    break
                except Exception as exc:  # network, HTTP, or serialization failure
                    error = exc
                    if attempt == 0:
                        if self._stop.is_set():
                            # Shutting down: do not spend another network
                            # attempt. The alert is already stored.
                            break
                        # One short retry absorbs a transient hiccup without
                        # turning a sustained outage into a busy loop.
                        self._stop.wait(1.0)
            with self._lock:
                state = self._counters.channels.setdefault(
                    channel.name, _ChannelState(channel.name)
                )
                if error is None:
                    state.sent += 1
                    state.last_success = time.time()
                    state.last_error = ""
                    delivered_any = True
                else:
                    state.failed += 1
                    state.last_error = redact(
                        str(error), self.config.telegram_token, self.config.webhook_token
                    )[:200]
            if error is not None:
                log.warning(
                    "alert delivery failed on %s: %s",
                    channel.name,
                    redact(str(error), self.config.telegram_token, self.config.webhook_token)[:200],
                )
        with self._lock:
            if delivered_any:
                self._counters.delivered += 1
            else:
                self._counters.failed += 1

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                if self._stop.is_set():
                    break
                continue
            if item is None:
                break
            try:
                self._deliver(item)
            except Exception:  # pragma: no cover - worker must never die
                log.exception("unexpected error while delivering an alert")

    def shutdown(self, timeout: float = 5.0) -> None:
        with self._lock:
            if not self._started:
                return
            thread = self._thread
            self._started = False
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if thread is not None:
            thread.join(max(0.0, float(timeout)))
        with self._lock:
            self._thread = None

    def metrics(self) -> dict[str, Any]:
        """Return delivery health. Never includes a credential."""
        with self._lock:
            counters = self._counters
            channels = {
                name: {
                    "sent": state.sent,
                    "failed": state.failed,
                    "last_error": state.last_error,
                    "last_success": state.last_success or None,
                }
                for name, state in counters.channels.items()
            }
            return {
                "enabled": self.config.enabled,
                "active": self.active,
                "min_severity": self.config.min_severity,
                "rate_per_minute": self.config.rate_per_minute,
                "cooldown_seconds": self.config.cooldown_seconds,
                "queue_depth": self._queue.qsize(),
                "queue_capacity": self._queue.maxsize,
                "accepted": counters.accepted,
                "delivered": counters.delivered,
                "failed": counters.failed,
                "dropped_queue_full": counters.dropped_queue_full,
                "suppressed_severity": counters.suppressed_severity,
                "suppressed_cooldown": counters.suppressed_cooldown,
                "suppressed_rate": counters.suppressed_rate,
                "channels": channels,
            }


__all__ = [
    "telegram_api",
    "AlertNotifier",
    "DeliveryError",
    "NotifierConfig",
    "SEVERITY_ORDER",
    "TelegramChannel",
    "WebhookChannel",
    "format_alert_text",
    "http_post",
    "redact",
    "valid_webhook_url",
]
