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
        with self._lock:
            return {
                "state": self._state,
                "running": bool(self.thread and self.thread.is_alive()),
                "interface": self.interface or "default",
                "packets_seen": self._packets_seen,
                "last_packet": self._last_packet,
                "error": self._error,
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

        try:
            with self._lock:
                self._state = "starting"
            while not self.stop_event.is_set():
                # A finite timeout makes stop() deterministic even when the
                # interface is completely idle; stop_filter alone can block
                # forever waiting for the next packet.
                sniff(
                    iface=self.interface, prn=handle, store=False, timeout=1,
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
