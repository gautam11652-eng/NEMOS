"""Notice a sensor that has gone quiet without crashing.

A dead capture thread does not raise anywhere the rest of NEMOS would see it.
That was confirmed on a real deployment: the Flask/waitress process kept
running and answering the dashboard while the capture thread underneath it
had already exited, so ``/api/status`` reported "starting" forever
(``nemos/capture.py``'s ``status()`` reconciliation exists because of that
exact bug). systemd's ``Restart=on-failure`` only helps a process that
actually exits -- this failure mode leaves the process alive.

This module closes that gap two ways:

1. It polls ``PacketCapture.status()`` and, the moment capture is reported
   dead, submits a notification through the same delivery pipeline as every
   other finding -- so the operator's phone tells them the sensor is blind,
   instead of the dashboard quietly saying nothing is wrong.
2. When run under systemd with ``WatchdogSec=`` configured, it pings
   systemd's own watchdog (``sd_notify(WATCHDOG=1)``) on every healthy check
   and *stops* pinging the moment capture is unhealthy. systemd then restarts
   the process on its own, which a passive polling loop cannot do.

Outside systemd, ``NOTIFY_SOCKET`` is unset and every ``sd_notify`` call is a
silent no-op -- this module changes nothing about a manual ``python main.py``
launch.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from collections.abc import Callable
from datetime import datetime

log = logging.getLogger(__name__)

CaptureStatus = Callable[[], dict]
Notify = Callable[[dict], bool]
Clock = Callable[[], float]

UNHEALTHY_STATES = {"failed", "error", "permission_denied", "unavailable"}


def _parse_watchdog_usec(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        usec = int(raw)
    except (TypeError, ValueError):
        return None
    return usec / 1_000_000 if usec > 0 else None


def _seconds_since(timestamp: str | None, now: datetime) -> float | None:
    """Age of an ISO-8601 timestamp in seconds, or None if there isn't one."""
    if not timestamp:
        return None
    try:
        then = datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    return max(0.0, (now - then).total_seconds())


class SensorWatchdog:
    """Poll capture health; alert on death, optionally on silence, ping systemd.

    ``heartbeat_seconds`` is off by default (0). Whether a quiet interface
    means "the network is quiet" or "something is wrong" cannot be told apart
    from packet volume alone without a false-positive cost on genuinely
    bursty or idle links -- unlike capture death, which is unambiguous. An
    operator who knows their link should never truly go silent can opt in.
    """

    def __init__(
        self,
        *,
        capture_status: CaptureStatus | None,
        notify: Notify,
        heartbeat_seconds: float = 0.0,
        poll_seconds: float = 15.0,
        clock: Clock = time.monotonic,
        now: Callable[[], datetime] | None = None,
        environ: dict | None = None,
    ) -> None:
        self._capture_status = capture_status
        self._notify = notify
        self._heartbeat_seconds = max(0.0, heartbeat_seconds)
        self._clock = clock
        self._now = now or (lambda: datetime.now().astimezone())
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._alerted_down = False
        self._alerted_silent = False
        self._started_at = self._clock()

        env = os.environ if environ is None else environ
        self._notify_socket = env.get("NOTIFY_SOCKET")
        watchdog_usec = _parse_watchdog_usec(env.get("WATCHDOG_USEC"))
        # systemd recommends pinging at less than half the configured
        # interval, so a single missed cycle cannot trip a restart.
        self._poll_seconds = (
            min(poll_seconds, watchdog_usec / 2) if watchdog_usec else poll_seconds
        )
        self._sock: socket.socket | None = None
        if self._notify_socket:
            try:
                self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            except OSError:
                log.debug("could not open sd_notify socket", exc_info=True)
                self._sock = None

    def start(self) -> None:
        self._sd_notify("READY=1")
        self._thread = threading.Thread(target=self._run, name="nemos-watchdog", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _run(self) -> None:
        while not self._stop.wait(self._poll_seconds):
            try:
                self._check()
            except Exception:
                # A watchdog that can crash its own thread is worse than
                # none: it stops pinging systemd and the process gets
                # restarted for a bug in monitoring code, not a real failure.
                log.exception("watchdog check failed")

    def _check(self) -> None:
        status = self._capture_status() if self._capture_status else None
        healthy = status is None or status.get("state") not in UNHEALTHY_STATES

        if not healthy:
            if not self._alerted_down:
                self._alerted_down = True
                self._notify({
                    "severity": "CRITICAL",
                    "threat": "CAPTURE_THREAD_DOWN",
                    "category": "sensor_health",
                    "source": "nemos-sensor",
                    "risk_score": 100,
                    "confidence": 100,
                    "reason": (
                        f"Packet capture has stopped ({status.get('error') or 'no reason reported'}). "
                        "The sensor is not seeing traffic."
                    ),
                    "incident_id": "WATCHDOG-CAPTURE-DOWN",
                })
            # Stop pinging: under systemd this lets WatchdogSec restart the
            # process. A dead capture thread pinging "I'm fine" would defeat
            # the one thing that can actually recover it.
            return

        self._alerted_down = False

        if self._heartbeat_seconds > 0 and status is not None:
            idle = _seconds_since(status.get("last_packet"), self._now())
            if idle is None:
                idle = self._clock() - self._started_at
            silent = idle > self._heartbeat_seconds
            if silent and not self._alerted_silent:
                self._alerted_silent = True
                self._notify({
                    "severity": "HIGH",
                    "threat": "SENSOR_SILENT",
                    "category": "sensor_health",
                    "source": "nemos-sensor",
                    "risk_score": 70,
                    "confidence": 60,
                    "reason": (
                        f"No packets observed in over {int(idle)}s on "
                        f"{status.get('interface', 'the capture interface')}, "
                        f"exceeding the configured {int(self._heartbeat_seconds)}s heartbeat."
                    ),
                    "incident_id": "WATCHDOG-SILENT",
                })
            elif not silent:
                self._alerted_silent = False

        self._sd_notify("WATCHDOG=1")

    def _sd_notify(self, message: str) -> None:
        if self._sock is None or not self._notify_socket:
            return
        addr = self._notify_socket
        if addr.startswith("@"):
            addr = "\0" + addr[1:]
        try:
            self._sock.sendto(message.encode(), addr)
        except OSError:
            log.debug("sd_notify(%s) failed", message, exc_info=True)


__all__ = ["SensorWatchdog"]
