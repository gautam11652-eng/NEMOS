from __future__ import annotations

import logging
import signal
import threading
from pathlib import Path

from nemos.api import create_app
from nemos.capture import PacketCapture
from nemos.config import load_settings
from nemos.database import initialize
from nemos.detector import DetectionConfig, ThreatDetector
from nemos.env import load_dotenv
from nemos.models import TrafficEvent
from nemos.notify import AlertNotifier, NotifierConfig
from nemos.storage import BatchWriter


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
    notifier = AlertNotifier(NotifierConfig.from_env())
    notifier.start()

    def record(alert) -> None:
        """Persist a finding, then hand it to alert delivery.

        Storage comes first and delivery is best-effort: an unreachable chat
        API must never cost the sensor a recorded detection.
        """
        writer.submit_alert(alert)
        notifier.submit(alert.as_dict())

    def event(event: TrafficEvent, packet_type: str) -> None:
        writer.submit_traffic(event)
        for alert in detector.process(event, packet_type):
            log.warning(
                "THREAT %s source=%s score=%s severity=%s",
                alert.threat,
                alert.source,
                alert.risk_score,
                alert.severity,
            )
            record(alert)
        if packet_type == "ARP" and event.metadata:
            alert = detector.observe_arp(
                event.source,
                str(event.metadata.get("mac", "")),
            )
            if alert:
                record(alert)

    capture = PacketCapture(settings.interface, event) if settings.capture_enabled else None
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

    try:
        if capture is not None:
            capture.start()
            log.info(
                "capture enabled%s",
                f" on {settings.interface}" if settings.interface else "",
            )
        else:
            log.info("capture disabled")

        app = create_app(settings, writer, capture, notifier)

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
        if capture is not None:
            try:
                capture.stop(timeout=5)
            except Exception:
                log.exception("failed to stop packet capture")
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
