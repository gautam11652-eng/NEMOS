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

import hashlib
import json
import logging
import os
import queue
import socket
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

from .telegram import TELEGRAM_MAX_MESSAGE, alert_keyboard, render_alert  # noqa: F401
from .version import VERSION

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
DEFAULT_MIN_SEVERITY = "HIGH"

TELEGRAM_API_BASE = "https://api.telegram.org"

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
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_protocol: str = "udp"
    syslog_facility: int = 13
    # Deployment-level Telegram settings. The token is the only credential and
    # it never leaves the server; the username is public (it is in the t.me
    # link) and the dashboard URL is what an alert links back to.
    telegram_bot_username: str = ""
    dashboard_url: str = ""
    webhook_format: str = "json"

    @property
    def telegram_token_configured(self) -> bool:
        """A deployment token is present. Pairing can proceed on this alone."""
        return bool(self.telegram_token)

    @property
    def telegram_configured(self) -> bool:
        """A token *and* a statically configured chat id.

        Kept as-is for the API response shape that predates QR pairing. It
        answers "is TELEGRAM_CHAT_ID set", not "can NEMOS deliver" -- with
        pairing, a sensor with no chat id can still have an audience.
        """
        return bool(self.telegram_token and self.telegram_chat_id)

    @property
    def webhook_configured(self) -> bool:
        return bool(self.webhook_url)

    @property
    def syslog_configured(self) -> bool:
        return bool(self.syslog_host)

    @property
    def any_channel(self) -> bool:
        return self.telegram_configured or self.webhook_configured or self.syslog_configured

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
            syslog_host=_syslog_sanitize(os.getenv("NEMOS_SYSLOG_HOST", "").strip())[:255],
            syslog_port=_int_env("NEMOS_SYSLOG_PORT", 514, 1, 65_535),
            syslog_protocol=(
                "tcp" if os.getenv("NEMOS_SYSLOG_PROTOCOL", "udp").strip().lower() == "tcp"
                else "udp"
            ),
            syslog_facility=_int_env("NEMOS_SYSLOG_FACILITY", 13, 0, 23),
            telegram_bot_username=_bot_username(os.getenv("TELEGRAM_BOT_USERNAME", "")),
            dashboard_url=_dashboard_url(os.getenv("NEMOS_DASHBOARD_URL", "")),
            webhook_format=(
                "text" if os.getenv("NEMOS_WEBHOOK_FORMAT", "json").strip().lower() == "text"
                else "json"
            ),
        )


def _header_safe(value: str) -> str:
    """Flatten a value so it is legal in an HTTP header.

    Threat names are derived from observed traffic, so this is a boundary, not
    cosmetics: a newline here would let a finding inject a header of its own,
    and a non-latin-1 byte makes the request unsendable rather than merely ugly.
    """
    text = " ".join(str(value).replace("\r", " ").replace("\n", " ").split())
    return text.encode("latin-1", "replace").decode("latin-1")[:120]


def _bot_username(value: str) -> str:
    """Normalise TELEGRAM_BOT_USERNAME into the bare username.

    Operators paste it with a leading @ or as a whole t.me URL. Everything that
    is not a Telegram username character is rejected rather than escaped,
    because this value is interpolated into the pairing link a QR code encodes.
    """
    text = str(value or "").strip()
    for prefix in ("https://t.me/", "http://t.me/", "t.me/"):
        if text.lower().startswith(prefix):
            # A pasted link legitimately carries a path or query after the
            # username; a bare value does not, and truncating one instead of
            # rejecting it would silently accept "nemos/../evil" as "nemos".
            text = text[len(prefix):].split("?", 1)[0].split("/", 1)[0]
            break
    else:
        text = text[1:] if text.startswith("@") else text
    if not text or len(text) > 32:
        return ""
    return text if all(ch.isalnum() or ch == "_" for ch in text) else ""


def _dashboard_url(value: str) -> str:
    """Accept an http(s) base URL for deep links, or nothing at all."""
    text = str(value or "").strip().rstrip("/")
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname:
        log.error("ignoring NEMOS_DASHBOARD_URL: an http:// or https:// URL is required")
        return ""
    return text


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


# Resolved bot usernames, keyed by a hash of the token rather than the token, so
# a heap dump or a stray repr cannot yield the credential. Bounded because the
# key is configuration rather than traffic, but bounded anyway on principle.
_USERNAME_CACHE: OrderedDict[str, tuple[str, float]] = OrderedDict()
_USERNAME_LOCK = threading.Lock()
_USERNAME_CACHE_MAX = 8
# A success is cached for the process's life; a failure only briefly, so a
# transient outage does not pin "unavailable" until the next restart.
_USERNAME_FAILURE_TTL = 60.0


def resolve_bot_username(token: str, *, api: Callable[..., Any] | None = None,
                         now: float | None = None) -> tuple[str, str]:
    """Ask Telegram what this bot is called. Returns ``(username, error)``.

    ``TELEGRAM_BOT_USERNAME`` exists so an operator *can* pin the value, but
    requiring it was redundant: the token already determines it, and getMe will
    say so. Worse, it was the one setting a typo in which fails silently --
    NEMOS would render a perfectly valid QR code pointing at a bot that does
    not exist, and the operator would find out by scanning it.

    One network call per token per process. The token is never logged, never
    returned, and never used as a cache key in plaintext.
    """
    token = str(token or "").strip()
    if not token:
        return "", "no bot token is configured"
    now = time.time() if now is None else now
    key = hashlib.sha256(token.encode("utf-8")).hexdigest()

    with _USERNAME_LOCK:
        cached = _USERNAME_CACHE.get(key)
        if cached is not None:
            username, expires = cached
            if username or expires > now:
                _USERNAME_CACHE.move_to_end(key)
                return username, "" if username else "Telegram did not identify this bot"

    call = api or telegram_api
    try:
        me = call(token, "getMe", timeout=10.0)
    except Exception as exc:
        # Deliberately not cached as a success: a network blip must not pin the
        # dashboard to "unavailable" for the rest of the process's life.
        message = redact(str(exc), token)[:200]
        with _USERNAME_LOCK:
            _USERNAME_CACHE[key] = ("", now + _USERNAME_FAILURE_TTL)
            while len(_USERNAME_CACHE) > _USERNAME_CACHE_MAX:
                _USERNAME_CACHE.popitem(last=False)
        return "", f"could not ask Telegram for the bot username: {message}"

    username = _bot_username(str((me or {}).get("username") or ""))
    with _USERNAME_LOCK:
        _USERNAME_CACHE[key] = (username, now + _USERNAME_FAILURE_TTL)
        _USERNAME_CACHE.move_to_end(key)
        while len(_USERNAME_CACHE) > _USERNAME_CACHE_MAX:
            _USERNAME_CACHE.popitem(last=False)
    if not username:
        return "", "Telegram accepted the token but returned no usable bot username"
    return username, ""


def forget_bot_username(token: str = "") -> None:
    """Drop cached usernames. Used by tests and after a credential change."""
    with _USERNAME_LOCK:
        if token:
            _USERNAME_CACHE.pop(hashlib.sha256(token.encode("utf-8")).hexdigest(), None)
        else:
            _USERNAME_CACHE.clear()


def format_alert_text(alert: Mapping[str, Any], *, detail: str = "",
                      dashboard_url: str = "") -> str:
    """Render an alert for Telegram.

    The rendering itself lives in nemos/telegram.py, which has no I/O and no
    delivery state, so the exact text an operator receives is unit-testable.
    This wrapper is the delivery path's entry point and keeps the name that
    callers outside this module already import.

    No Markdown/HTML parse mode is used. Alert fields describe observed network
    activity, and asking a chat client to parse that as markup invites both
    rendering failures and formatting injection.
    """
    return render_alert(alert, detail=detail, dashboard_url=dashboard_url)


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
    """Deliver a finding to every chat this sensor is paired with.

    The audience comes from two places: the legacy ``TELEGRAM_CHAT_ID`` setting,
    and whatever chats have paired themselves by QR code. ``chat_ids`` is a
    callable rather than a list because pairing happens while the sensor runs --
    a chat linked a minute ago must receive the next alert without a restart.

    A send failure to one chat does not cancel the others. Only a delivery that
    reached nobody is reported as a failure, because that is the only case where
    the operator has genuinely not been told.
    """

    name = "telegram"

    def __init__(self, token: str, chat_id: str = "", api_base: str = TELEGRAM_API_BASE,
                 *, chat_ids: Callable[[], list[str]] | None = None,
                 dashboard_url: str = "", allow_contain: bool = False):
        self.token = token
        self.chat_id = chat_id
        self.api_base = api_base.rstrip("/")
        self._chat_ids = chat_ids
        self.dashboard_url = dashboard_url
        self.allow_contain = allow_contain

    def audience(self) -> list[str]:
        """Every chat that should receive this alert, de-duplicated, in order."""
        targets: list[str] = []
        if self.chat_id:
            targets.append(str(self.chat_id))
        if self._chat_ids is not None:
            try:
                targets.extend(str(chat) for chat in self._chat_ids())
            except Exception:
                # A failing pairing store must not silence a configured chat id.
                log.warning("could not read paired Telegram chats", exc_info=True)
        seen: set[str] = set()
        return [chat for chat in targets if chat and not (chat in seen or seen.add(chat))]

    def _send_one(self, chat_id: str, alert: Mapping[str, Any],
                  transport: Transport, timeout: float) -> None:
        url = f"{self.api_base}/bot{self.token}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": format_alert_text(alert, dashboard_url=self.dashboard_url),
            "disable_web_page_preview": True,
        }
        keyboard = alert_keyboard(alert, dashboard_url=self.dashboard_url,
                                  allow_contain=self.allow_contain)
        if keyboard:
            payload["reply_markup"] = keyboard
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
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
            parsed = json.loads(detail)
        except (ValueError, TypeError) as exc:
            raise DeliveryError(
                f"telegram returned {status} with an unparseable body: {safe}"
            ) from exc
        if not isinstance(parsed, dict) or parsed.get("ok") is not True:
            description = ""
            if isinstance(parsed, dict):
                description = str(parsed.get("description") or "")
            raise DeliveryError(
                "telegram accepted the request but reported failure: "
                f"{redact(description, self.token)[:200] or safe}"
            )

    def send(self, alert: Mapping[str, Any], transport: Transport, timeout: float) -> None:
        targets = self.audience()
        if not targets:
            raise DeliveryError("no Telegram chat is paired with this sensor")
        errors: list[str] = []
        delivered = 0
        for chat_id in targets:
            try:
                self._send_one(chat_id, alert, transport, timeout)
                delivered += 1
            except DeliveryError as exc:
                errors.append(str(exc))
        if delivered == 0:
            raise DeliveryError("; ".join(errors)[:200] or "telegram delivery failed")
        if errors:
            log.warning("telegram delivery reached %d of %d chats: %s",
                        delivered, len(targets), errors[0][:160])


# Push services that turn a plain POST body into a phone notification -- ntfy
# being the common one -- read these headers if they are present and ignore
# them otherwise, so sending them costs nothing on a collector that does not.
# Priority is ntfy's 1-5 scale.
PUSH_PRIORITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}
PUSH_TAGS = {
    "CRITICAL": "rotating_light",
    "HIGH": "warning",
    "MEDIUM": "yellow_circle",
    "LOW": "blue_circle",
}


class WebhookChannel(_Channel):
    """Deliver a finding to an arbitrary HTTP collector.

    Two body formats, because two very different things are on the other end.

    ``json`` (the default) posts a machine-readable envelope, for a SIEM, a
    Lambda, or anything that parses.

    ``text`` posts the same rendered report Telegram receives, as ``text/plain``.
    That exists for the push services that treat the body as the notification --
    and it is the one path in NEMOS that reaches a phone with **no credential of
    any kind**: no bot token, no chat id, no account. The URL is the whole
    configuration, which is also its weakness, so the topic in it has to be long
    and unguessable.
    """

    name = "webhook"

    def __init__(self, url: str, token: str = "", body_format: str = "json",
                 dashboard_url: str = ""):
        self.url = url
        self.token = token
        self.body_format = "text" if str(body_format).lower() == "text" else "json"
        self.dashboard_url = dashboard_url

    def _payload(self, alert: Mapping[str, Any]) -> tuple[dict[str, str], bytes]:
        headers = {"User-Agent": "NEMOS"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.body_format == "text":
            severity = str(alert.get("severity") or "LOW").upper()
            headers["Content-Type"] = "text/plain; charset=utf-8"
            # X- prefixed so a collector that does not know them treats them as
            # ordinary unknown headers rather than as its own metadata.
            headers["X-Title"] = _header_safe(
                f"NEMOS {severity}: {alert.get('threat') or 'DETECTION'}")
            headers["X-Priority"] = str(PUSH_PRIORITY.get(severity, 3))
            headers["X-Tags"] = PUSH_TAGS.get(severity, "blue_circle")
            body = format_alert_text(
                alert, dashboard_url=self.dashboard_url).encode("utf-8")
            return headers, body
        headers["Content-Type"] = "application/json"
        body = json.dumps(
            {"source": "NEMOS", "alert": dict(alert)}, separators=(",", ":"), default=str
        ).encode("utf-8")
        return headers, body

    def send(self, alert: Mapping[str, Any], transport: Transport, timeout: float) -> None:
        headers, body = self._payload(alert)
        status, detail = transport("POST", self.url, headers, body, timeout)
        if not 200 <= status < 300:
            raise DeliveryError(
                f"webhook responded {status}: {redact(detail, self.token)[:200]}"
            )


class DeliveryError(RuntimeError):
    """Raised by a channel when a single delivery attempt fails."""


# CEF severity is 0-10. NEMOS severities map onto the bands SIEMs conventionally
# treat as low / medium / high / very high.
CEF_SEVERITY = {"LOW": 3, "MEDIUM": 5, "HIGH": 7, "CRITICAL": 9}

SYSLOG_MAX_BYTES = 8192


def _cef_header_escape(value: str) -> str:
    r"""Escape a CEF header field, where ``\`` and ``|`` are structural."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_extension_escape(value: str) -> str:
    r"""Escape a CEF extension value, where ``\`` and ``=`` are structural.

    Newlines are escaped rather than passed through. This is a security
    boundary, not cosmetics: alert fields carry attacker-influenced content,
    and a raw newline reaching a syslog collector lets an attacker terminate
    the record and forge an entirely separate log entry after it.
    """
    text = str(value).replace("\\", "\\\\").replace("=", "\\=")
    return text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")


def _syslog_sanitize(value: str) -> str:
    """Strip characters that would break out of a syslog record."""
    return "".join(ch for ch in str(value) if ch not in "\r\n\x00")


def format_cef(alert: Mapping[str, Any], version: str) -> str:
    """Render one finding as ArcSight CEF.

    CEF is the format the widest range of collectors (Splunk, QRadar, Elastic,
    Wazuh) parse without a custom decoder, which is the point of exporting at
    all: a finding that only exists in NEMOS's own dashboard is not part of
    anyone's detection stack.
    """
    severity = str(alert.get("severity") or "LOW").upper()
    header = "|".join([
        "CEF:0",
        "NEMOS",
        "NEMOS",
        _cef_header_escape(version),
        _cef_header_escape(alert.get("threat") or "FINDING"),
        _cef_header_escape(alert.get("threat") or "Finding"),
        str(CEF_SEVERITY.get(severity, 3)),
    ])
    # A custom field carries its label only when it carries a value: a bare
    # cs1Label with no cs1 is noise a SIEM has to filter back out.
    fields: list[tuple[str, Any, str]] = [
        ("src", alert.get("source"), ""),
        ("dst", alert.get("destination"), ""),
        ("dpt", alert.get("destination_port"), ""),
        ("proto", alert.get("protocol"), ""),
        ("cat", alert.get("category"), ""),
        ("cn1", alert.get("risk_score"), "riskScore"),
        ("cn2", alert.get("confidence"), "confidence"),
        ("cs1", alert.get("technique"), "mitreTechnique"),
        ("cs2", alert.get("incident_id"), "incidentId"),
        ("rt", alert.get("timestamp"), ""),
        ("msg", alert.get("reason"), ""),
    ]
    parts: list[str] = []
    for key, value, label in fields:
        if value in (None, ""):
            continue
        parts.append(f"{key}={_cef_extension_escape(value)}")
        if label:
            parts.append(f"{key}Label={label}")
    extension = " ".join(parts)
    return f"{header}|{extension}" if extension else header


class SyslogChannel(_Channel):
    """Export findings to a SIEM over syslog.

    Deliberately not built on the HTTP ``transport``: syslog is a datagram or
    stream protocol, so this channel owns its socket. UDP is the default
    because it cannot block the delivery worker on an unreachable collector;
    TCP is available where the collector requires it and losses matter more
    than latency.
    """

    name = "syslog"

    def __init__(self, host: str, port: int = 514, protocol: str = "udp",
                 facility: int = 13, hostname: str = "", socket_factory=None):
        self.host = host
        self.port = int(port)
        self.protocol = protocol.lower().strip()
        self.facility = int(facility)
        self.hostname = _syslog_sanitize(hostname or socket.gethostname())[:255] or "-"
        self._socket_factory = socket_factory or socket.socket

    def _priority(self, severity: str) -> int:
        # Syslog PRI = facility * 8 + severity, where syslog severity counts
        # down: 3 is Error, 4 Warning, 5 Notice.
        level = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 5}.get(severity.upper(), 5)
        return self.facility * 8 + level

    def render(self, alert: Mapping[str, Any]) -> str:
        """RFC 5424 framing around a CEF payload."""
        severity = str(alert.get("severity") or "LOW").upper()
        timestamp = _syslog_sanitize(alert.get("timestamp") or "")[:64] or "-"
        message = format_cef(alert, VERSION)
        line = (
            f"<{self._priority(severity)}>1 {timestamp} {self.hostname} NEMOS - "
            f"{_syslog_sanitize(alert.get('threat') or 'FINDING')[:32]} - {message}"
        )
        return _syslog_sanitize(line)

    def send(self, alert: Mapping[str, Any], transport: Transport, timeout: float) -> None:
        payload = self.render(alert).encode("utf-8", "replace")[:SYSLOG_MAX_BYTES]
        try:
            if self.protocol == "tcp":
                sock = self._socket_factory(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sock.settimeout(timeout)
                    sock.connect((self.host, self.port))
                    # RFC 6587 non-transparent framing: collectors delimit on
                    # the newline, which is why the payload can never contain
                    # one of its own.
                    sock.sendall(payload + b"\n")
                finally:
                    sock.close()
            else:
                sock = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.settimeout(timeout)
                    sock.sendto(payload, (self.host, self.port))
                finally:
                    sock.close()
        except OSError as exc:
            raise DeliveryError(f"syslog delivery to {self.host}:{self.port} failed: {exc}") from exc


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
                 channels: list[_Channel] | None = None,
                 chat_ids: Callable[[], list[str]] | None = None,
                 allow_contain: bool = False):
        self.config = config or NotifierConfig()
        self._transport = transport or http_post
        if channels is None:
            channels = []
            # With QR pairing a token alone is enough to have an audience: the
            # chats come from the pairing store via ``chat_ids``. Requiring
            # TELEGRAM_CHAT_ID here would have left a freshly paired sensor with
            # no Telegram channel at all until it was restarted.
            if self.config.telegram_configured or (
                    self.config.telegram_token_configured and chat_ids is not None):
                channels.append(
                    TelegramChannel(
                        self.config.telegram_token, self.config.telegram_chat_id,
                        chat_ids=chat_ids, dashboard_url=self.config.dashboard_url,
                        allow_contain=allow_contain,
                    )
                )
            if self.config.webhook_configured:
                channels.append(
                    WebhookChannel(
                        self.config.webhook_url, self.config.webhook_token,
                        body_format=self.config.webhook_format,
                        dashboard_url=self.config.dashboard_url,
                    )
                )
            if self.config.syslog_configured:
                channels.append(
                    SyslogChannel(
                        self.config.syslog_host,
                        self.config.syslog_port,
                        self.config.syslog_protocol,
                        self.config.syslog_facility,
                    )
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
    "SyslogChannel",
    "format_cef",
    "format_alert_text",
    "http_post",
    "redact",
    "valid_webhook_url",
]
