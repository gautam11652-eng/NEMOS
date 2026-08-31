from __future__ import annotations

import logging
import threading

from .models import TrafficEvent, utc_now

log = logging.getLogger(__name__)


class PacketCapture:
    def __init__(self, interface, on_event):
        self.interface = interface
        self.on_event = on_event
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self.thread = None
        self._state = "stopped"
        self._packets_seen = 0
        self._last_packet = None
        self._error = None

    def start(self):
        with self._lock:
            if self.thread is not None and self.thread.is_alive():
                return
            self.stop_event.clear()
            self._state = "starting"
            self._error = None
            self.thread = threading.Thread(target=self._run, name="packet-capture", daemon=True)
            self.thread.start()

    def status(self) -> dict:
        """Report capture state, reconciled against whether the thread is alive.

        The worker sets its own state on the paths it can see, but a thread can
        die in ways it cannot catch -- a BaseException such as a native panic
        escapes ``except Exception`` entirely. Without this reconciliation the
        sensor reported ``starting`` with no error indefinitely after the
        capture thread had already exited, which is a silent failure: the
        dashboard shows a sensor that looks like it is still coming up.
        """
        with self._lock:
            alive = bool(self.thread is not None and self.thread.is_alive())
            state = self._state
            error = self._error
            if not alive and state in {"starting", "running"}:
                state = "failed"
                error = error or (
                    "capture thread exited without reporting a reason; check "
                    "privileges (CAP_NET_RAW) and the interface name"
                )
            return {
                "state": state,
                "running": alive,
                "interface": self.interface or "default",
                "packets_seen": self._packets_seen,
                "last_packet": self._last_packet,
                "error": error,
            }

    def stop(self, timeout=5):
        self.stop_event.set()
        with self._lock:
            thread = self.thread
        if thread is not None:
            thread.join(max(0.0, float(timeout)))
        with self._lock:
            if self.thread is thread and (thread is None or not thread.is_alive()):
                self.thread = None
                self._state = "stopped"

    def _run(self):
        try:
            from scapy.all import ARP, DNS, IP, ICMP, TCP, UDP, sniff
        except ImportError:
            with self._lock:
                self._state = "unavailable"
                self._error = "Scapy is not installed"
            log.error("Scapy unavailable; capture disabled.")
            return

        def handle(p):
            if self.stop_event.is_set():
                return
            try:
                now = utc_now()
                with self._lock:
                    self._packets_seen += 1
                    self._last_packet = now
                    self._state = "running"
                if p.haslayer(ARP):
                    a = p[ARP]
                    if a.psrc and a.hwsrc:
                        self.on_event(
                            TrafficEvent(
                                utc_now(), str(a.psrc), str(a.pdst), "ARP",
                                packet_size=len(p), interface=self.interface or "",
                                metadata={"mac": str(a.hwsrc)},
                            ),
                            "ARP",
                        )
                if not p.haslayer(IP):
                    return
                ip = p[IP]
                proto = "IP"
                sp = dp = None
                flags = ""
                ptype = "IP"
                if p.haslayer(TCP):
                    t = p[TCP]
                    proto = ptype = "TCP"
                    sp, dp = int(t.sport), int(t.dport)
                    flags = str(t.flags)
                elif p.haslayer(UDP):
                    u = p[UDP]
                    proto = ptype = "DNS" if p.haslayer(DNS) else "UDP"
                    sp, dp = int(u.sport), int(u.dport)
                elif p.haslayer(ICMP):
                    proto = ptype = "ICMP"
                self.on_event(
                    TrafficEvent(
                        utc_now(), str(ip.src), str(ip.dst), proto, sp, dp, len(p),
                        flags, self.interface or "", metadata={},
                    ),
                    ptype,
                )
            except Exception:
                log.exception("packet parse error")

        def started():
            """Scapy calls this once the capture socket is open.

            State must flip to "running" on a successful bind, not on the first
            packet. Keying it to traffic meant a correctly-running sensor on a
            quiet link reported "starting" forever, which is indistinguishable
            from a capture that never came up.
            """
            with self._lock:
                if self._state == "starting":
                    self._state = "running"

        try:
            with self._lock:
                self._state = "starting"
            while not self.stop_event.is_set():
                # A finite timeout makes stop() deterministic even when the
                # interface is completely idle; stop_filter alone can block
                # forever waiting for the next packet.
                sniff(
                    iface=self.interface, prn=handle, store=False, timeout=1,
                    started_callback=started,
                )
            with self._lock:
                self._state = "stopped"
        except PermissionError:
            with self._lock:
                self._state = "permission_denied"
                self._error = "CAP_NET_RAW is required for packet capture"
            log.error("Capture requires CAP_NET_RAW/root privileges.")
        except Exception as exc:
            with self._lock:
                self._state = "error"
                self._error = str(exc)[:240]
            log.exception("capture stopped")
        except BaseException as exc:
            # A native panic or an injected exception is still a dead capture
            # thread, and the operator must be told rather than left looking at
            # a sensor stuck in "starting". Re-raised after recording it.
            with self._lock:
                self._state = "error"
                self._error = f"{type(exc).__name__}: {exc}"[:240]
            log.critical("capture thread terminated: %s", type(exc).__name__)
            raise

    @staticmethod
    def _parse(packet, IP, TCP, UDP, ICMP, DNS, interface=""):
        if not packet.haslayer(IP):
            return None, ""
        ip = packet[IP]
        proto = "IP"
        ptype = "IP"
        sp = dp = None
        flags = ""
        if packet.haslayer(TCP):
            layer = packet[TCP]
            proto = ptype = "TCP"
            sp, dp = int(layer.sport), int(layer.dport)
            flags = str(layer.flags)
        elif packet.haslayer(UDP):
            layer = packet[UDP]
            proto = ptype = "DNS" if packet.haslayer(DNS) else "UDP"
            sp, dp = int(layer.sport), int(layer.dport)
        elif packet.haslayer(ICMP):
            proto = ptype = "ICMP"
        return TrafficEvent(
            utc_now(), str(ip.src), str(ip.dst), proto, sp, dp, len(packet),
            flags, interface, metadata={},
        ), ptype
