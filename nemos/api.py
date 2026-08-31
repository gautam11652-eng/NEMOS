from __future__ import annotations

import hashlib
import hmac
import os
import threading
import ipaddress
import json
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request

from .config import Settings
from .database import connect
from .models import TrafficEvent
from .intelligence import summarize_incident
from .analyst import collect_evidence
from .attack import catalog as attack_catalog, enrich_alert

from .version import VERSION
_ALLOWED_PROTOCOLS = {"TCP", "UDP", "DNS", "ICMP", "ARP", "NDP", "IP", "OTHER"}
_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_BOOLEANS = {"1": True, "true": True, "yes": True, "0": False, "false": False, "no": False}


def _bounded_limit(value: Any, default: int, minimum: int = 1, maximum: int = 500) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, minimum), maximum)


def _port(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("port must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = int(value.strip(), 10)
        except ValueError as exc:
            raise ValueError("port must be an integer") from exc
    else:
        raise ValueError("port must be an integer")
    if not 0 < parsed <= 65535:
        raise ValueError("port out of range")
    return parsed


def _packet_size(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("packet size must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = int(value.strip(), 10)
        except ValueError as exc:
            raise ValueError("packet size must be an integer") from exc
    else:
        raise ValueError("packet size must be an integer")
    if not 0 <= parsed <= 65535:
        raise ValueError("packet size out of range")
    return parsed


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _host(value: str) -> bool:
    return isinstance(value, str) and len(value) <= 64 and _valid_ip(value)


_INCIDENT_ID_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _valid_incident_id(value: str) -> bool:
    return bool(value) and len(value) <= 64 and all(ch in _INCIDENT_ID_CHARS for ch in value)


def _dashboard_etag(c, limit: int, capture_state: dict[str, Any] | None = None) -> str:
    """Build a stable change token for both telemetry and sensor state.

    Database writes advance ``revision``. Capture state is included as well so
    a sensor failure/recovery (or a dropped-packet counter change) is visible
    to a dashboard even when SQLite telemetry has not changed.
    """
    row = c.execute("SELECT revision FROM telemetry_stats WHERE id=1").fetchone()
    revision = int(row[0] or 0) if row else 0
    state = {
        "revision": revision,
        "limit": limit,
        "capture": {
            "state": (capture_state or {}).get("state"),
            "running": bool((capture_state or {}).get("running")),
            "packets_seen": int((capture_state or {}).get("packets_seen") or 0),
            "error": (capture_state or {}).get("error"),
        },
    }
    digest = hashlib.sha256(
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f'"{digest}"'


def _read_stats(c) -> dict[str, int]:
    """Read cached telemetry counters with a safe zero-state fallback."""
    row = c.execute(
        "SELECT packets,tcp,udp,icmp,dns,threats,critical FROM telemetry_stats WHERE id=1"
    ).fetchone()
    if row is None:
        return {
            "packets": 0, "tcp": 0, "udp": 0, "icmp": 0,
            "dns": 0, "threats": 0, "critical": 0,
        }
    return {key: int(row[key] or 0) for key in row.keys()}


def _enrich_alert_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [enrich_alert(row) for row in rows]


class RateLimiter:
    """Fixed-window request limiting, bounded in the number of clients tracked.

    A fixed window rather than a token bucket: the window boundary allows a
    brief burst of at most one window's budget, which is harmless here, and the
    state is a single counter and timestamp per client instead of a float
    balance that has to be decayed on every read.

    The client map is keyed by peer address, which an attacker on a local
    segment can vary, so it is bounded and evicted least-recently-used like
    every other attacker-keyed structure in NEMOS. Eviction under a spoofing
    flood costs an attacker their own history, never another client's.
    """

    __slots__ = ("general", "auth_failures", "window", "_general", "_auth", "_max_clients", "_lock")

    def __init__(self, general_per_minute: int = 240, auth_failures_per_minute: int = 10,
                 window: float = 60.0, max_clients: int = 4096):
        self.general = max(1, int(general_per_minute))
        self.auth_failures = max(1, int(auth_failures_per_minute))
        self.window = float(window)
        self._general: OrderedDict[str, list[float]] = OrderedDict()
        self._auth: OrderedDict[str, list[float]] = OrderedDict()
        self._max_clients = max_clients
        self._lock = threading.Lock()

    def _hit(self, table: OrderedDict[str, list[float]], key: str,
             limit: int, now: float) -> tuple[bool, int]:
        entry = table.get(key)
        if entry is None or now - entry[0] >= self.window:
            if entry is None:
                if len(table) >= self._max_clients:
                    table.popitem(last=False)
            else:
                table.move_to_end(key)
            table[key] = [now, 1.0]
            return True, 0
        table.move_to_end(key)
        entry[1] += 1
        if entry[1] > limit:
            return False, max(1, int(self.window - (now - entry[0])) + 1)
        return True, 0

    def check(self, key: str) -> tuple[bool, int]:
        """Count one request. Returns (allowed, retry_after_seconds)."""
        with self._lock:
            return self._hit(self._general, key, self.general, time.monotonic())

    def record_auth_failure(self, key: str) -> tuple[bool, int]:
        """Count one rejected credential. Returns (blocked, retry_after)."""
        with self._lock:
            allowed, retry = self._hit(self._auth, key, self.auth_failures, time.monotonic())
            return (not allowed), retry

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "general_per_minute": self.general,
                "auth_failures_per_minute": self.auth_failures,
                "tracked_clients": len(self._general),
                "clients_with_auth_failures": len(self._auth),
            }


def create_app(settings: Settings, writer, capture=None, notifier=None, analysis=None,
               analyst=None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024
    # Flask 3.x trusted-host protection. Keep local aliases usable for the
    # default loopback deployment while rejecting arbitrary Host headers.
    trusted = set(settings.trusted_hosts)
    if not settings.remote:
        trusted.update({"127.0.0.1", "localhost", "[::1]", "::1"})
    elif not trusted and settings.host not in {"0.0.0.0", "::", "*"}:
        trusted.add(settings.host)
    if trusted:
        app.config["TRUSTED_HOSTS"] = sorted(trusted)
    token = settings.api_token

    # Small in-process cache for the assembled dashboard snapshot. The
    # telemetry revision is the authoritative invalidation signal; the cache
    # therefore removes repeated SQLite reads when multiple browser clients
    # request the same unchanged dashboard state. Keep it tiny because the
    # payload contains recent telemetry and can be moderately large.
    dashboard_cache: dict[tuple[str, int], dict[str, Any]] = {}
    dashboard_cache_lock = threading.Lock()
    dashboard_cache_limit = 4

    def _notification_state() -> dict[str, Any]:
        """Summarize alert delivery for the dashboard.

        Works with or without a live notifier so the endpoint stays useful when
        the app is created standalone (tests, or a read-only inspection).
        The bot token is never read into the response; only whether it is set.
        """
        chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        telegram_configured = bool(os.getenv("TELEGRAM_BOT_TOKEN", "").strip() and chat_id)
        # Show only the tail of the chat id: enough to confirm the right chat is
        # targeted, not enough to be a useful identifier on a shared screen.
        masked = ("••••" + chat_id[-4:]) if len(chat_id) > 4 else (chat_id or "")
        state: dict[str, Any] = {
            "telegram_configured": telegram_configured,
            "chat_id": masked,
            "webhook_configured": bool(os.getenv("NEMOS_WEBHOOK_URL", "").strip()),
            "channels": {},
        }
        if notifier is not None:
            metrics = notifier.metrics()
            state.update(metrics)
            state["telegram_configured"] = telegram_configured
            state["chat_id"] = masked
            state["webhook_configured"] = "webhook" in metrics.get("channels", {})
        else:
            state.update({
                "enabled": False, "active": False, "accepted": 0, "delivered": 0,
                "failed": 0, "queue_depth": 0, "dropped_queue_full": 0,
                "suppressed_severity": 0, "suppressed_cooldown": 0, "suppressed_rate": 0,
            })
        return state

    def auth() -> bool:
        """Accept the NEMOS header or a standard bearer token.

        X-NEMOS-Token is the documented form. Authorization: Bearer is accepted
        too because it is what scripts, curl and HTTP clients reach for by
        default, and rejecting it produced a 401 that looked like a wrong
        credential rather than a wrong header name.

        Both comparisons are constant-time. Note that compare_digest is only
        constant-time over equal-length inputs, which is unavoidable here and
        leaks length, not content.
        """
        if not token:
            return True
        supplied = request.headers.get("X-NEMOS-Token", "")
        if not supplied:
            header = request.headers.get("Authorization", "")
            scheme, _, value = header.partition(" ")
            if scheme.lower() == "bearer":
                supplied = value.strip()
        return hmac.compare_digest(supplied, token)

    def same_origin_state_change() -> bool:
        """Reject browser cross-site writes when no API token is configured.

        Local mode intentionally has no credential prompt, but mutating localhost
        endpoints should not be writable by an unrelated web page. Non-browser
        clients generally omit these headers and remain compatible.
        """
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return True
        if token:
            return True
        fetch_site = request.headers.get("Sec-Fetch-Site", "").lower()
        if fetch_site == "cross-site":
            return False
        origin = request.headers.get("Origin")
        if not origin:
            return True
        try:
            parsed = urlsplit(origin)
            request_origin = urlsplit(request.host_url)
            return (parsed.scheme, parsed.netloc) == (request_origin.scheme, request_origin.netloc)
        except ValueError:
            return False

    # ---- Rate limiting -------------------------------------------------
    # Two buckets per client, because the two risks are different sizes. The
    # general one bounds resource use; the auth one bounds guesses at the API
    # token, which is the only credential NEMOS has. A shared limit would have
    # to be loose enough for the dashboard's polling, which is far too loose to
    # slow a token search.
    limiter = RateLimiter(
        general_per_minute=settings.api_rate_limit,
        auth_failures_per_minute=settings.api_auth_rate_limit,
    )
    app.extensions["nemos_rate_limiter"] = limiter

    def client_key() -> str:
        """Identify the caller for rate limiting.

        Deliberately the peer address, never X-Forwarded-For: that header is
        attacker-controlled, so honouring it by default would let one client
        mint unlimited identities and bypass the limit entirely. Behind a
        trusted reverse proxy, have the proxy do the limiting.
        """
        return request.remote_addr or "unknown"

    @app.before_request
    def guard():
        # Health is intentionally public so service monitors can check liveness,
        # and unmetered so a monitor cannot exhaust a client's budget.
        if not request.path.startswith("/api/") or request.path == "/api/health":
            return None

        who = client_key()
        allowed, retry_after = limiter.check(who)
        if not allowed:
            response = jsonify(ok=False, error="rate limit exceeded")
            response.status_code = 429
            response.headers["Retry-After"] = str(retry_after)
            return response

        if not auth():
            # Count the failure before answering, so a token search is slowed
            # by the attempt rather than only by the eventual success.
            blocked, retry_after = limiter.record_auth_failure(who)
            if blocked:
                response = jsonify(ok=False, error="too many failed attempts")
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                return response
            return jsonify(ok=False, error="authentication required"), 401

        if not same_origin_state_change():
            return jsonify(ok=False, error="cross-site request blocked"), 403
        return None

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(),microphone=(),geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'self'; object-src 'none'; "
            "frame-ancestors 'self'; form-action 'self'; style-src 'self'; "
            "script-src 'self'; connect-src 'self'"
        )
        # API responses must not be cached because they can contain live
        # telemetry or authenticated data. Static dashboard assets are safe to
        # cache briefly and are intentionally kept separate from API caching.
        if request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=300"
        else:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return render_template("index.html", version=VERSION, token_configured=bool(token))

    @app.get("/api/health")
    def health():
        response = jsonify(status="online", service="NEMOS", version=VERSION, timestamp=time.time())
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/dashboard")
    def dashboard():
        limit = _bounded_limit(request.args.get("limit"), settings.dashboard_limit, 10, 500)
        c = connect(settings.db_path)
        try:
            capture_state = capture.status() if capture is not None else {
                "state": "not_configured",
                "running": False,
                "interface": settings.interface or "default",
                "packets_seen": 0,
                "last_packet": None,
                "error": None,
            }
            etag = _dashboard_etag(c, limit, capture_state)
            if request.headers.get("If-None-Match") == etag:
                return ("", 304, {"ETag": etag, "Cache-Control": "no-store"})

            cache_key = (etag, limit)
            with dashboard_cache_lock:
                cached = dashboard_cache.get(cache_key)
            if cached is not None:
                response = jsonify(**cached)
                response.set_etag(etag.strip('"'))
                return response

            stats = _read_stats(c)
            alerts = _enrich_alert_rows([
                dict(row)
                for row in c.execute(
                    """SELECT id,timestamp,threat,category,source,severity,risk_score,
                              confidence,reason,technique,incident_id,acknowledged
                       FROM alerts ORDER BY id DESC LIMIT ?""",
                    (limit,),
                )
            ])
            traffic = [
                dict(row)
                for row in c.execute(
                    """SELECT id,timestamp,source,destination,source_port,destination_port,
                              protocol,packet_size,flags
                       FROM traffic ORDER BY id DESC LIMIT ?""",
                    (limit,),
                )
            ]
            incidents = [
                dict(row)
                for row in c.execute(
                    """SELECT incident_id, MAX(id) last_id, MIN(timestamp) first_seen,
                              MAX(timestamp) last_seen, COUNT(*) alert_count,
                              MAX(risk_score) max_risk,
                          CASE
                              WHEN SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) > 0 THEN 'CRITICAL'
                              WHEN SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) > 0 THEN 'HIGH'
                              WHEN SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) > 0 THEN 'MEDIUM'
                              ELSE 'LOW'
                          END severity,
                              GROUP_CONCAT(DISTINCT threat) threats,
                              GROUP_CONCAT(DISTINCT source) sources
                       FROM alerts WHERE incident_id <> ''
                       GROUP BY incident_id ORDER BY last_id DESC LIMIT ?""",
                    (min(limit, 50),),
                )
            ]
            # Host summaries are maintained incrementally by the writer, avoiding
            # full-table GROUP BY scans on every dashboard poll.
            host_rows = c.execute(
                "SELECT host,packets,alert_count,critical_count,max_risk,last_alert FROM host_stats ORDER BY max_risk DESC, critical_count DESC, packets DESC, host ASC LIMIT ?",
                (min(limit, 50),),
            ).fetchall()
            hosts = []
            for row in host_rows:
                ac = int(row["alert_count"] or 0)
                mr = int(row["max_risk"] or 0)
                cc = int(row["critical_count"] or 0)
                hosts.append({"host": row["host"], "packets": int(row["packets"] or 0), "alert_count": ac,
                              "critical_count": cc, "max_risk": mr,
                              "risk_score": min(100, mr + min(20, ac * 4) + min(10, cc * 5)),
                              "last_alert": row["last_alert"]})
            payload = {
                "stats": stats,
                "alerts": alerts,
                "traffic": traffic,
                "incidents": incidents,
                "hosts": hosts[:min(limit, 50)],
                "capture": capture_state,
            }
            with dashboard_cache_lock:
                dashboard_cache[cache_key] = payload
                while len(dashboard_cache) > dashboard_cache_limit:
                    dashboard_cache.pop(next(iter(dashboard_cache)))
            response = jsonify(**payload)
            response.set_etag(etag.strip('"'))
            return response
        finally:
            c.close()

    @app.get("/api/status")
    def status():
        capture_state = capture.status() if capture is not None else {"state": "not_configured", "running": False, "interface": settings.interface or "default", "packets_seen": 0, "last_packet": None, "error": None}
        return jsonify(
            ok=True, version=VERSION, capture=capture_state,
            writer=writer.metrics(), notifications=_notification_state(),
            rate_limit=limiter.metrics(),
            analysis=(analysis.status() if analysis is not None else {
                "enabled": False,
                "reason": "windowed flow analysis is disabled",
            }),
            analyst=(analyst.status() if analyst is not None else {"available": False}),
        )

    @app.get("/api/metrics")
    def metrics():
        """Return writer/delivery health metrics; protected by API auth."""
        return jsonify(writer=writer.metrics(), notifications=_notification_state())

    @app.get("/api/stats")
    def stats():
        c = connect(settings.db_path)
        try:
            return jsonify(_read_stats(c))
        finally:
            c.close()

    @app.get("/api/alerts")
    def alerts():
        """Return recent alerts, optionally filtered.

        Supported filters: ``severity`` (repeatable), ``source``, ``threat``,
        ``technique``, ``acknowledged`` and ``since`` (ISO timestamp prefix).
        Every filter is bound as a parameter and validated against a known set
        or a length cap; none of them reach the SQL text.
        """
        limit = _bounded_limit(request.args.get("limit"), 100)
        clauses: list[str] = []
        params: list[Any] = []

        severities = [
            value.strip().upper()
            for value in request.args.getlist("severity")
            if value.strip()
        ]
        if severities:
            if any(value not in _SEVERITIES for value in severities):
                return jsonify(ok=False, error="invalid severity"), 400
            unique = sorted(set(severities))
            clauses.append(f"severity IN ({','.join('?' for _ in unique)})")
            params.extend(unique)

        source = request.args.get("source", "").strip()
        if source:
            if not _host(source):
                return jsonify(ok=False, error="source must be a valid IP address"), 400
            clauses.append("source = ?")
            params.append(source)

        for name, column in (("threat", "threat"), ("technique", "technique")):
            value = request.args.get(name, "").strip()
            if value:
                if len(value) > 64:
                    return jsonify(ok=False, error=f"{name} too long"), 400
                clauses.append(f"{column} = ?")
                params.append(value.upper() if name == "threat" else value)

        acknowledged = request.args.get("acknowledged", "").strip().lower()
        if acknowledged:
            if acknowledged not in _BOOLEANS:
                return jsonify(ok=False, error="acknowledged must be true or false"), 400
            clauses.append("acknowledged = ?")
            params.append(1 if _BOOLEANS[acknowledged] else 0)

        since = request.args.get("since", "").strip()
        if since:
            if len(since) > 64:
                return jsonify(ok=False, error="since too long"), 400
            # Timestamps are stored as ISO-8601 strings, so a lexical
            # comparison is also a chronological one.
            clauses.append("timestamp >= ?")
            params.append(since)

        # Every element of `clauses` is a literal fragment written above; the
        # only interpolated characters are `?` placeholders. All user-supplied
        # values travel in `params` as bound parameters.
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        c = connect(settings.db_path)
        try:
            return jsonify(_enrich_alert_rows([
                dict(row) for row in c.execute(
                    f"""SELECT id,timestamp,threat,category,source,severity,risk_score,
                               confidence,reason,technique,incident_id,acknowledged,evidence
                        FROM alerts{where} ORDER BY id DESC LIMIT ?""",
                    params,
                )
            ]))
        finally:
            c.close()

    @app.get("/api/incidents")
    def incidents():
        limit = _bounded_limit(request.args.get("limit"), 50, 1, 200)
        c = connect(settings.db_path)
        try:
            rows = c.execute(
                """SELECT incident_id, MAX(id) last_id, MIN(timestamp) first_seen,
                          MAX(timestamp) last_seen, COUNT(*) alert_count,
                          MAX(risk_score) max_risk,
                          GROUP_CONCAT(DISTINCT threat) threats,
                          GROUP_CONCAT(DISTINCT source) sources
                   FROM alerts WHERE incident_id <> ''
                   GROUP BY incident_id ORDER BY last_id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            if not rows:
                return jsonify([])

            # Fetch the selected incident evidence in one bounded query instead
            # of issuing one SQL query per incident (N+1 query pattern).
            incident_ids = [row["incident_id"] for row in rows]
            placeholders = ",".join("?" for _ in incident_ids)
            evidence_rows = c.execute(
                # `placeholders` is a run of `?` markers; ids are bound below.
                f"""WITH ranked AS (
                       SELECT id,incident_id,threat,source,severity,risk_score,confidence,
                              technique,evidence,
                              ROW_NUMBER() OVER (PARTITION BY incident_id ORDER BY id ASC) AS rn
                       FROM alerts
                       WHERE incident_id IN ({placeholders})
                   )
                   SELECT id,incident_id,threat,source,severity,risk_score,confidence,technique,evidence
                   FROM ranked
                   WHERE rn <= 200
                   ORDER BY id ASC""",
                incident_ids,
            ).fetchall()
            grouped: dict[str, list[dict[str, Any]]] = {incident_id: [] for incident_id in incident_ids}
            for evidence in evidence_rows:
                bucket = grouped.get(evidence["incident_id"])
                if bucket is not None and len(bucket) < 200:
                    bucket.append(enrich_alert(dict(evidence)))

            result = []
            for row in rows:
                incident_id = row["incident_id"]
                detail_rows = grouped.get(incident_id, [])
                if not detail_rows:
                    continue
                summary = summarize_incident(incident_id, detail_rows)
                item = dict(row)
                item.update(summary.as_dict())
                item.pop("incident_id", None)
                item["incident_id"] = summary.incident_id
                result.append(item)
            return jsonify(result)
        finally:
            c.close()

    @app.get("/api/hosts")
    def hosts():
        """Return bounded host risk summaries from the maintained host index."""
        limit = _bounded_limit(request.args.get("limit"), 25, 1, 100)
        c = connect(settings.db_path)
        try:
            rows = c.execute(
                """SELECT host,packets,alert_count,critical_count,max_risk,last_alert
                   FROM host_stats
                   ORDER BY max_risk DESC, critical_count DESC, packets DESC, host ASC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
            result = []
            for row in rows:
                alert_count = int(row["alert_count"] or 0)
                max_risk = int(row["max_risk"] or 0)
                critical = int(row["critical_count"] or 0)
                # Explainable bounded host risk; this is triage priority, not a verdict.
                risk = min(100, max_risk + min(20, alert_count * 4) + min(10, critical * 5))
                result.append({
                    "host": row["host"],
                    "packets": int(row["packets"] or 0),
                    "alert_count": alert_count,
                    "critical_count": critical,
                    "max_risk": max_risk,
                    "risk_score": risk,
                    "last_alert": row["last_alert"],
                })
            return jsonify(result)
        finally:
            c.close()

    @app.get("/api/incidents/<incident_id>")
    def incident_detail(incident_id: str):
        if not _valid_incident_id(incident_id):
            return jsonify(ok=False, error="invalid incident id"), 400
        c = connect(settings.db_path)
        try:
            rows = _enrich_alert_rows([dict(row) for row in c.execute(
                """SELECT id,timestamp,threat,category,source,severity,risk_score,confidence,
                          reason,technique,incident_id,acknowledged,evidence
                   FROM alerts WHERE incident_id=? ORDER BY id ASC LIMIT 200""",
                (incident_id,),
            )])
            if not rows:
                return jsonify(ok=False, error="incident not found"), 404
            summary = summarize_incident(incident_id, rows)
            # Keep the enriched object used by the dashboard while also exposing
            # the summary fields at the top level for API clients that consumed
            # the original incident-detail response shape.
            summary_data = summary.as_dict()
            return jsonify(**summary_data, incident=summary_data, alerts=rows)
        finally:
            c.close()

    @app.get("/api/hosts/<host>")
    def host_detail(host: str):
        """Return a bounded investigation view for one validated IP host."""
        if not _host(host):
            return jsonify(ok=False, error="invalid host"), 400
        c = connect(settings.db_path)
        try:
            alerts_rows = _enrich_alert_rows([dict(row) for row in c.execute(
                """SELECT id,timestamp,threat,category,source,severity,risk_score,confidence,
                          reason,technique,incident_id,acknowledged,evidence
                   FROM alerts WHERE source=? ORDER BY id DESC LIMIT 100""", (host,)
            )])
            traffic_rows = [dict(row) for row in c.execute(
                """SELECT id,timestamp,source,destination,source_port,destination_port,
                          protocol,packet_size,flags FROM traffic
                   WHERE source=? OR destination=? ORDER BY id DESC LIMIT 100""", (host, host)
            )]
            if not alerts_rows and not traffic_rows:
                return jsonify(ok=False, error="host not found"), 404
            summary = summarize_incident(
                f"HOST-{host}", alerts_rows
            ) if alerts_rows else None
            incidents = sorted({r["incident_id"] for r in alerts_rows if r.get("incident_id")})
            protocol_counts: dict[str, int] = {}
            for event in traffic_rows:
                protocol = str(event.get("protocol") or "OTHER")
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            top_protocol = max(protocol_counts, key=protocol_counts.get) if protocol_counts else None
            return jsonify(
                host=host,
                triage=(summary.as_dict() if summary else {"risk_score": 0, "severity": "LOW", "confidence": 0, "recommendations": []}),
                incidents=incidents[:50],
                alerts=alerts_rows,
                traffic=traffic_rows,
                top_protocol=top_protocol,
            )
        finally:
            c.close()


    @app.get("/api/alerts/<int:alert_id>")
    def alert_detail(alert_id: int):
        c = connect(settings.db_path)
        try:
            row = c.execute(
                """SELECT id,timestamp,threat,category,source,severity,risk_score,confidence,
                          reason,technique,incident_id,acknowledged,evidence
                   FROM alerts WHERE id=?""", (alert_id,)
            ).fetchone()
            if not row:
                return jsonify(ok=False, error="alert not found"), 404
            return jsonify(alert=enrich_alert(dict(row)))
        finally:
            c.close()


    def _analysis_unavailable():
        return jsonify(
            ok=False,
            error="windowed flow analysis is not enabled",
            hint="set NEMOS_ANALYSIS=true and restart",
        ), 503

    @app.get("/api/flows")
    def flows():
        """Recent unidirectional flows.

        ``active=true`` returns the in-memory table (flows still open in the
        current window); the default reads completed flows from storage.
        Direction is preserved: a row is one direction of a conversation.
        """
        limit = _bounded_limit(request.args.get("limit"), 100, 1, 500)
        if request.args.get("active", "").lower() in ("1", "true", "yes"):
            if analysis is None:
                return _analysis_unavailable()
            return jsonify(analysis.active_flows(limit))

        clauses: list[str] = []
        params: list[Any] = []
        source = request.args.get("source", "").strip()
        if source:
            if not _host(source):
                return jsonify(ok=False, error="source must be a valid IP address"), 400
            clauses.append("source = ?")
            params.append(source)
        destination = request.args.get("destination", "").strip()
        if destination:
            if not _host(destination):
                return jsonify(ok=False, error="destination must be a valid IP address"), 400
            clauses.append("destination = ?")
            params.append(destination)
        protocol = request.args.get("protocol", "").strip().upper()
        if protocol:
            if protocol not in _ALLOWED_PROTOCOLS:
                return jsonify(ok=False, error="unsupported protocol"), 400
            clauses.append("protocol = ?")
            params.append(protocol)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        c = connect(settings.db_path)
        try:
            return jsonify([dict(row) for row in c.execute(
                f"""SELECT id,first_timestamp,last_timestamp,source,destination,
                           source_port,destination_port,protocol,packets,bytes,
                           duration,packets_per_second,bytes_per_second,
                           mean_packet_size,stddev_packet_size,syn,ack,fin,rst,interface
                    FROM flows{where} ORDER BY id DESC LIMIT ?""",
                params,
            )])
        finally:
            c.close()

    @app.get("/api/analysis")
    def analysis_status():
        """Windowed-analysis and model health."""
        if analysis is None:
            return _analysis_unavailable()
        return jsonify(analysis.status())

    @app.get("/api/anomalies")
    def anomalies():
        """Recent fused assessments, each with the arithmetic behind its score."""
        if analysis is None:
            return _analysis_unavailable()
        limit = _bounded_limit(request.args.get("limit"), 50, 1, 200)
        return jsonify(analysis.recent_assessments(limit))

    @app.get("/api/windows")
    def windows():
        """Recent completed analysis windows."""
        if analysis is None:
            return _analysis_unavailable()
        limit = _bounded_limit(request.args.get("limit"), 10, 1, 50)
        return jsonify(analysis.recent_windows(limit))

    @app.get("/api/baselines")
    def baselines():
        """Per-host statistical baseline states."""
        if analysis is None:
            return _analysis_unavailable()
        limit = _bounded_limit(request.args.get("limit"), 50, 1, 200)
        return jsonify(analysis.baselines(limit))

    @app.get("/api/baselines/<host>")
    def baseline_detail(host: str):
        if not _host(host):
            return jsonify(ok=False, error="invalid host"), 400
        if analysis is None:
            return _analysis_unavailable()
        return jsonify(analysis.baseline_for(host))

    @app.get("/api/analyst")
    def analyst_status():
        """Optional AI analyst status. Absence is a normal state, not an error."""
        if analyst is None:
            return jsonify({
                "available": False,
                "reason": "no LLM provider configured (set NEMOS_LLM_PROVIDER); "
                          "NEMOS detection is unaffected",
                "role": "Explains findings NEMOS has already made. It performs no detection.",
            })
        return jsonify(analyst.status())

    @app.post("/api/analyst/ask")
    def analyst_ask():
        """Ask the optional AI analyst about an incident or host.

        The caller names *what* to explain; it never supplies the evidence.
        NEMOS assembles the bundle from its own stored findings, so this
        endpoint cannot be used as a general-purpose LLM proxy, and the model
        can only ever see facts NEMOS produced.
        """
        if analyst is None or not analyst.available:
            return jsonify(
                ok=False,
                error="the AI analyst is not configured",
                detail="set NEMOS_LLM_PROVIDER and the provider API key to enable it",
                note="NEMOS detection and alerting do not require it.",
            ), 503

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(ok=False, error="JSON object required"), 400

        question = str(data.get("question") or "").strip()
        if not question:
            return jsonify(ok=False, error="question required"), 400
        if len(question) > 500:
            return jsonify(ok=False, error="question too long"), 400

        incident_id = str(data.get("incident_id") or "").strip()
        host = str(data.get("host") or "").strip()
        if not incident_id and not host:
            return jsonify(ok=False, error="incident_id or host required"), 400

        c = connect(settings.db_path)
        try:
            if incident_id:
                if not _valid_incident_id(incident_id):
                    return jsonify(ok=False, error="invalid incident id"), 400
                rows = _enrich_alert_rows([dict(row) for row in c.execute(
                    """SELECT id,timestamp,threat,category,source,severity,risk_score,
                              confidence,reason,technique,incident_id,evidence
                       FROM alerts WHERE incident_id=? ORDER BY id ASC LIMIT 50""",
                    (incident_id,),
                )])
                if not rows:
                    return jsonify(ok=False, error="incident not found"), 404
                summary = summarize_incident(incident_id, rows)
                bundle = collect_evidence(incident=summary.as_dict(), alerts=rows)
            else:
                if not _host(host):
                    return jsonify(ok=False, error="invalid host"), 400
                rows = _enrich_alert_rows([dict(row) for row in c.execute(
                    """SELECT id,timestamp,threat,category,source,severity,risk_score,
                              confidence,reason,technique,incident_id,evidence
                       FROM alerts WHERE source=? ORDER BY id DESC LIMIT 50""",
                    (host,),
                )])
                flows = [dict(row) for row in c.execute(
                    """SELECT first_timestamp,last_timestamp,source,destination,
                              source_port,destination_port,protocol,packets,bytes,duration
                       FROM flows WHERE source=? ORDER BY id DESC LIMIT 40""",
                    (host,),
                )]
                if not rows and not flows:
                    return jsonify(ok=False, error="host not found"), 404
                bundle = collect_evidence(
                    alerts=rows, flows=flows,
                    baseline=(analysis.baseline_for(host) if analysis is not None else None),
                )
        finally:
            c.close()

        result = analyst.explain(question, bundle)
        return (jsonify(result), 200 if result.get("ok") else 502)

    @app.get("/api/notifications")
    def notification_status():
        """Report alert-delivery configuration and health without secrets."""
        return jsonify(_notification_state())

    @app.get("/api/telegram")
    def telegram_status():
        """Telegram delivery status.

        Retains the original ``configured``/``chat_id`` response shape for
        existing clients and adds live delivery counters so the dashboard can
        distinguish "credentials present" from "alerts are actually arriving".
        """
        state = _notification_state()
        telegram = state["channels"].get("telegram", {})
        return jsonify(
            configured=bool(state["telegram_configured"]),
            chat_id=state["chat_id"],
            delivery=state,
            sent=telegram.get("sent", 0),
            failed=telegram.get("failed", 0),
            last_error=telegram.get("last_error", ""),
        )

    @app.get("/api/techniques")
    def techniques():
        """Return the detector's conservative ATT&CK catalog plus observed counts."""
        c = connect(settings.db_path)
        try:
            rows = c.execute(
                "SELECT technique, COUNT(*) AS count FROM alerts WHERE technique <> '' GROUP BY technique"
            ).fetchall()
            counts = {str(row["technique"]): int(row["count"] or 0) for row in rows}
            observed = []
            for item in attack_catalog():
                item = dict(item)
                item["count"] = counts.get(item["technique_id"], 0)
                observed.append(item)

            unmapped_rows = c.execute(
                "SELECT threat, COUNT(*) AS count FROM alerts WHERE technique = '' GROUP BY threat ORDER BY count DESC, threat ASC"
            ).fetchall()
            unmapped = [
                {
                    "threat": row["threat"],
                    "count": int(row["count"] or 0),
                    "signal": enrich_alert({"threat": row["threat"], "technique": ""})["signal"],
                }
                for row in unmapped_rows
            ]
            return jsonify(techniques=observed, unmapped=unmapped)
        finally:
            c.close()

    @app.get("/api/traffic")
    def traffic():
        limit = _bounded_limit(request.args.get("limit"), 100)
        c = connect(settings.db_path)
        try:
            return jsonify([dict(row) for row in c.execute(
                """SELECT id,timestamp,source,destination,source_port,destination_port,
                          protocol,packet_size,flags,interface,direction
                   FROM traffic ORDER BY id DESC LIMIT ?""",
                (limit,),
            )])
        finally:
            c.close()

    @app.post("/api/packet")
    def packet():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(ok=False, error="JSON object required"), 400

        try:
            source = str(data.get("source") or data.get("src_ip") or "").strip()
            destination = str(data.get("destination") or data.get("dst_ip") or "").strip()
            protocol = str(data.get("protocol") or "OTHER").upper().strip()
            if not source or not destination:
                return jsonify(ok=False, error="source and destination required"), 400
            if not _valid_ip(source) or not _valid_ip(destination):
                return jsonify(ok=False, error="source and destination must be valid IP addresses"), 400
            if protocol not in _ALLOWED_PROTOCOLS:
                return jsonify(ok=False, error="unsupported protocol"), 400

            timestamp = str(data.get("timestamp") or data.get("time") or "").strip()
            if not timestamp:
                from .models import utc_now
                timestamp = utc_now()
            if len(timestamp) > 64:
                return jsonify(ok=False, error="timestamp too long"), 400
            flags = str(data.get("flags", ""))[:32]
            event = TrafficEvent(
                timestamp, source, destination, protocol,
                _port(data.get("source_port")),
                _port(data.get("destination_port")),
                _packet_size(data.get("packet_size", 0)), flags,
            )
        except (TypeError, ValueError):
            return jsonify(ok=False, error="invalid packet fields"), 400

        accepted = writer.submit_traffic(event)
        if analysis is not None:
            # Feed the same windowed flow pipeline live capture uses, so
            # synthetic traffic exercises flow aggregation, feature extraction
            # and ML scoring rather than only reaching storage.
            #
            # The deterministic detector is deliberately NOT called here: it
            # holds unsynchronised per-source state and is owned by the single
            # capture thread, whereas this runs on any of the WSGI worker
            # threads. analysis.observe() takes a lock and is safe to share.
            analysis.observe(event)
        return (jsonify(ok=True), 202) if accepted else (
            jsonify(ok=False, error="write queue full"),
            503,
        )

    @app.post("/api/alerts/<int:alert_id>/ack")
    def ack(alert_id: int):
        c = connect(settings.db_path)
        try:
            with c:
                if c.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,)).rowcount == 0:
                    return jsonify(ok=False, error="not found"), 404
                c.execute("UPDATE telemetry_stats SET revision=revision+1 WHERE id=1")
            return jsonify(ok=True)
        finally:
            c.close()

    @app.post("/api/alerts/clear")
    def clear():
        c = connect(settings.db_path)
        try:
            with c:
                c.execute("DELETE FROM alerts")
                c.execute("UPDATE telemetry_stats SET threats=0, critical=0, revision=revision+1 WHERE id=1")
                c.execute("UPDATE host_stats SET alert_count=0, critical_count=0, max_risk=0, last_alert=NULL")
            return jsonify(ok=True)
        finally:
            c.close()

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(ok=False, error="request too large"), 413

    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return jsonify(ok=False, error="not found"), 404
        return "Not found", 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return jsonify(ok=False, error="method not allowed"), 405

    @app.errorhandler(500)
    def internal_error(_):
        return jsonify(ok=False, error="internal server error"), 500

    return app
