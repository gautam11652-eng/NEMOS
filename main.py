from __future__ import annotations

import logging
import os
import signal
import threading
from pathlib import Path

from nemos.analysis import AnalysisEngine
from nemos.analyst import Analyst, AnalystConfig
from nemos.api import create_app
from nemos.bot import DailyBrief, TelegramBot
from nemos.capture import (
    STATE_BLOCKED as CAPTURE_BLOCKED,
    STATE_ERROR as CAPTURE_ERROR,
    STATE_NO_INTERFACE as CAPTURE_NO_INTERFACE,
    PacketCapture,
)
from nemos.config import load_settings
from nemos.database import initialize
from nemos.detector import DetectionConfig, ThreatDetector
from nemos.env import load_dotenv
from nemos.models import TrafficEvent
from nemos.notify import AlertNotifier, NotifierConfig
from nemos.pairing import PairingStore
from nemos.storage import BatchWriter
from nemos.watchdog import SensorWatchdog


class ShutdownRequested(Exception):
    """Internal control-flow exception raised by SIGINT/SIGTERM handlers."""



def main() -> int:
    # Resolve the default data/config base from the application location rather
    # than the caller's working directory. This keeps manual launches and the
    # systemd service consistent; NEMOS_DB still overrides the database path.
    app_dir = Path(__file__).resolve().parent
    # A local .env is a documented convenience for operators. Real environment
    # variables always win, so a systemd unit or an explicit export is never
    # overridden by a stale file on disk. This must happen before settings are
    # read, which means it happens before logging is configured -- so report
    # what was applied once handlers exist.
    dotenv_applied = load_dotenv(app_dir / ".env")
    settings = load_settings(app_dir)
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    log = logging.getLogger("NEMOS")
    if dotenv_applied:
        # Names only. These values are secrets by design.
        log.info(
            "loaded %d setting(s) from .env: %s",
            len(dotenv_applied), ", ".join(sorted(dotenv_applied)),
        )

    initialize(settings.db_path)
    writer = BatchWriter(
        settings.db_path,
        settings.batch_size,
        settings.flush_seconds,
        max_traffic=settings.max_traffic,
        max_alerts=settings.max_alerts,
    )
    writer.start()

    detector = ThreatDetector(DetectionConfig.from_env())

    # Telegram: one deployment bot, many paired chats. The token stays in the
    # environment; operators link a chat by scanning a QR code the dashboard
    # renders, and the pairing store is the delivery audience from then on.
    notify_config = NotifierConfig.from_env()
    pairing = PairingStore(settings.db_path)
    notifier = AlertNotifier(
        notify_config,
        chat_ids=pairing.chat_ids,
        allow_contain=bool(os.getenv("NEMOS_TELEGRAM_CONTAIN_HOOK", "").strip()),
    )
    notifier.start()

    def record(alert) -> None:
        """Persist a finding, then hand it to alert delivery.

        Storage comes first and delivery is best-effort: an unreachable chat
        API must never cost the sensor a recorded detection.
        """
        writer.submit_alert(alert)
        notifier.submit(alert.as_dict())

    # Windowed flow analysis and ML anomaly detection. All of its work happens
    # on its own thread; the capture path below only appends to a flow table.
    analysis = None
    if settings.analysis_enabled:
        def persist_flows(flows) -> None:
            if settings.persist_flows:
                for flow in flows:
                    writer.submit_flow(flow.as_dict())

        analysis = AnalysisEngine(
            model_dir=settings.model_dir,
            window_seconds=settings.analysis_window,
            max_flows=settings.max_flows,
            on_alert=record,
            on_flows=persist_flows,
            # Automatic ML bootstrap. The corpus of vetted-normal windows lives
            # in the sensor's own database, so a restart resumes collection
            # rather than beginning the observation period again.
            db_path=settings.db_path,
            autotrain=settings.ml_autotrain,
            bootstrap_min_seconds=settings.ml_bootstrap_min_seconds,
            bootstrap_min_samples=settings.ml_bootstrap_min_samples,
            retrain_seconds=settings.ml_retrain_seconds,
            max_training_samples=settings.ml_max_samples,
        )
        analysis.start()
    else:
        log.info("windowed flow analysis disabled")

    # Optional LLM explanation layer. It performs no detection; when it is not
    # configured every other layer behaves identically.
    analyst = Analyst(AnalystConfig.from_env())
    if analyst.available:
        log.info("AI analyst enabled: provider=%s model=%s",
                 analyst.config.provider, analyst.config.model)

    def event(event: TrafficEvent, packet_type: str) -> None:
        writer.submit_traffic(event)
        if analysis is not None:
            # Cheap: one dict operation under a short lock. Feature extraction
            # and model inference happen on the analysis thread.
            analysis.observe(event)
        alerts = detector.process(event, packet_type)
        for alert in alerts:
            log.warning(
                "THREAT %s source=%s score=%s severity=%s",
                alert.threat,
                alert.source,
                alert.risk_score,
                alert.severity,
            )
            record(alert)
        if alerts and analysis is not None:
            # Hand deterministic findings to the analysis engine so the next
            # window can fuse them with the statistical layers.
            analysis.record_rule_alerts(event.source, alerts)
        if packet_type == "ARP" and event.metadata:
            alert = detector.observe_arp(
                event.source,
                str(event.metadata.get("mac", "")),
            )
            if alert:
                record(alert)
        elif packet_type == "NDP" and event.metadata.get("mac"):
            # Neighbour Discovery asserts a binding for the address it names,
            # which is not necessarily the packet's own source -- an
            # advertisement speaks for its target.
            alert = detector.observe_ndp(
                str(event.metadata.get("claimed") or event.source),
                str(event.metadata.get("mac", "")),
            )
            if alert:
                record(alert)

    def watchdog_notify(alert: dict) -> bool:
        """Log a sensor-health finding before attempting delivery.

        notifier.submit() is a no-op with no channel configured or an
        unreachable one -- exactly the condition a "sensor is blind" alert
        most needs to survive. The log line is unconditional so the finding
        is never silent even when delivery is.
        """
        log.error("SENSOR HEALTH %s: %s", alert.get("threat"), alert.get("reason"))
        return notifier.submit(alert)

    capture = PacketCapture(settings.interface, event) if settings.capture_enabled else None
    watchdog = SensorWatchdog(
        capture_status=capture.status if capture is not None else None,
        notify=watchdog_notify,
        heartbeat_seconds=settings.heartbeat_seconds,
        poll_seconds=settings.watchdog_poll_seconds,
    )
    server = None
    stopped = threading.Event()

    def request_shutdown(*_args) -> None:
        if stopped.is_set():
            return
        stopped.set()
        log.info("shutdown requested")
        if server is not None:
            try:
                server.close()
            except Exception:
                log.exception("failed to close HTTP server")
        # Raise a dedicated internal exception so the blocking Waitress loop
        # unwinds without printing a misleading KeyboardInterrupt traceback.
        raise ShutdownRequested

    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)

    bot = None
    brief = None
    try:
        if capture is not None:
            capture.start()
            state = capture.status()
            if state["display_state"] in (CAPTURE_BLOCKED, CAPTURE_NO_INTERFACE,
                                          CAPTURE_ERROR):
                # start() has already logged the reason and the fix. Repeat the
                # headline so an operator scrolling a busy startup log cannot
                # miss that nothing is being captured.
                log.error("capture is %s -- NEMOS will record no packets",
                          state["display_state"])
            else:
                log.info(
                    "capture started on %s (interfaces found: %s)",
                    settings.interface or "all interfaces",
                    ", ".join(state.get("interfaces") or []) or "unknown",
                )
        else:
            log.info("capture disabled")
        watchdog.start()

        # The command bot is started only once the pieces it reports on exist,
        # so /status can never answer about a half-built sensor.
        bot = TelegramBot(
            notify_config.telegram_token, pairing, settings.db_path,
            capture=capture, notifier=notifier, analysis=analysis,
            dashboard_url=notify_config.dashboard_url,
            bot_username=notify_config.telegram_bot_username,
            contain_hook=os.getenv("NEMOS_TELEGRAM_CONTAIN_HOOK", "").strip(),
        )
        bot.start()
        brief_hour = os.getenv("NEMOS_TELEGRAM_BRIEF_HOUR", "").strip()
        if brief_hour.isdigit() and bot.active:
            brief = DailyBrief(bot, int(brief_hour))
            brief.start()
        else:
            brief = None

        app = create_app(settings, writer, capture, notifier, analysis, analyst,
                         pairing=pairing, bot=bot)

        try:
            from waitress import create_server
        except ImportError:
            log.error("Waitress is required; install requirements.txt before starting NEMOS")
            return 2

        log.info("dashboard http://%s:%s", settings.host, settings.port)
        server = create_server(
            app,
            host=settings.host,
            port=settings.port,
            threads=8,
            connection_limit=100,
            max_request_body_size=32 * 1024,
            expose_tracebacks=False,
            ident="NEMOS",
        )
        if stopped.is_set():
            server.close()
            return 0

        try:
            server.run()
        except ShutdownRequested:
            log.info("HTTP server stopped")
        return 0
    except ShutdownRequested:
        log.info("shutdown requested during startup")
        return 0
    finally:
        try:
            # Before capture.stop(): a stopped capture thread looks identical
            # to a dead one, and the watchdog must not alert on a shutdown it
            # was asked to perform.
            watchdog.stop(timeout=5)
        except Exception:
            log.exception("failed to stop sensor watchdog")
        if capture is not None:
            try:
                capture.stop(timeout=5)
            except Exception:
                log.exception("failed to stop packet capture")
        if analysis is not None:
            try:
                # Capture has stopped, so drain the remaining flows: a final
                # window's worth of traffic should still be analysed and stored.
                analysis.run_cycle(force=True)
                analysis.stop(timeout=5)
            except Exception:
                log.exception("failed to stop flow analysis")
        for component, label in ((brief, "the daily Telegram brief"),
                                 (bot, "the Telegram command bot")):
            if component is None:
                continue
            try:
                component.stop(timeout=5)
            except Exception:
                log.exception("failed to stop %s", label)
        try:
            notifier.shutdown(timeout=5)
        except Exception:
            log.exception("failed to stop alert delivery")
        try:
            writer.shutdown(timeout=10)
        except Exception:
            log.exception("failed to stop SQLite writer")


if __name__ == "__main__":
    raise SystemExit(main())
