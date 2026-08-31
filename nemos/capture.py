from __future__ import annotations

import logging
import threading

from .models import TrafficEvent, utc_now

log = logging.getLogger(__name__)

# ICMPv6 types that are Neighbour Discovery: router/neighbour solicitation and
# advertisement, and redirect. These are IPv6's replacement for ARP -- constant,
# benign link-local control traffic on any healthy v6 segment. Counting them as
# ICMP would report every dual-stack network as a permanent ping flood, so they
# are recorded under their own protocol and kept out of the ICMP rules.
NDP_TYPES = frozenset({133, 134, 135, 136, 137})

# Bound on how far the layer walk will descend. A crafted packet with a long
# chain of extension headers must not turn one packet into unbounded work on
# the capture thread.
MAX_LAYER_DEPTH = 16


def ndp_binding(ip_layer, icmp6):
    """Extract the address-to-MAC claim an NDP message makes, if any.

    IPv6 has no ARP; Neighbour Discovery does the same job, and can be abused
    the same way. An unsolicited Neighbour Advertisement claiming someone
    else's address is the v6 form of ARP cache poisoning (what parasite6 and
    similar tools send), so the binding it asserts is worth the same scrutiny.

    Returns ``(claimed_address, mac)``, or ``(None, None)`` when the message
    asserts no usable binding:

    - Neighbour Advertisement (136) claims its ``tgt`` field is at the
      link-layer address carried in its option.
    - Neighbour Solicitation (135) claims its *own* source address is, which
      is only meaningful when that source is a real address -- a solicitation
      from ``::`` is duplicate-address detection and binds nothing.
    """
    icmp_type = int(getattr(icmp6, "type", -1))
    if icmp_type not in (135, 136):
        return None, None

    mac = None
    node = icmp6
    for _ in range(MAX_LAYER_DEPTH):
        node = getattr(node, "payload", None)
        if node is None or not node:
            break
        candidate = getattr(node, "lladdr", None)
        if candidate:
            mac = str(candidate)
            break
    if not mac:
        return None, None

    if icmp_type == 136:
        claimed = getattr(icmp6, "tgt", None) or getattr(ip_layer, "src", None)
    else:
        source = str(getattr(ip_layer, "src", "") or "")
        if source in ("", "::"):
            return None, None
        claimed = source
    return (str(claimed) if claimed else None), mac


def icmpv6_layer(packet):
    """Return the ICMPv6 layer of a packet, or None if it carries none.

    Found by walking the dissected layer chain and matching on class name
    rather than importing scapy's several dozen concrete ICMPv6 classes or its
    private ``_ICMPv6`` base. That keeps this working across scapy versions,
    and it handles IPv6 extension headers for free: scapy has already
    dissected them into the chain, so a hop-by-hop or fragment header between
    the IPv6 header and the ICMPv6 message is simply another link to step past.
    """
    layer = packet
    for _ in range(MAX_LAYER_DEPTH):
        if layer is None:
            return None
        if type(layer).__name__.startswith("ICMPv6"):
            return layer
        payload = getattr(layer, "payload", None)
        # scapy terminates a chain with NoPayload, which is falsy.
        if payload is None or not payload:
            return None
        layer = payload
    return None


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
            from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, sniff
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
                event, ptype = self._parse(
                    p, IP, TCP, UDP, ICMP, DNS, self.interface or "", IPv6,
                )
                if event is not None:
                    self.on_event(event, ptype)
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
    def _parse(packet, IP, TCP, UDP, ICMP, DNS, interface="", IPv6=None):
        """Translate one dissected packet into a TrafficEvent.

        This is the only parse implementation, and the capture thread calls it
        directly, so what the tests exercise is what actually runs. There was
        previously a second copy inlined in the sniff callback; the two had
        already drifted, which is precisely how a parse path acquires a bug
        that no test can see.

        Returns ``(None, "")`` for anything that is not IPv4 or IPv6.
        """
        if packet.haslayer(IP):
            ip = packet[IP]
            family = 4
        elif IPv6 is not None and packet.haslayer(IPv6):
            # Dropping v6 here left every detection rule blind to it, so an
            # attacker on a dual-stack network bypassed the sensor by simply
            # preferring the other address family.
            ip = packet[IPv6]
            family = 6
        else:
            return None, ""
        proto = "IP"
        ptype = "IP"
        sp = dp = None
        flags = ""
        ndp_claim = ndp_mac = None
        # TCP and UDP are the same scapy layers over either family, so every
        # port-based rule applies to v6 without change.
        if packet.haslayer(TCP):
            layer = packet[TCP]
            proto = ptype = "TCP"
            sp, dp = int(layer.sport), int(layer.dport)
            flags = str(layer.flags)
        elif packet.haslayer(UDP):
            layer = packet[UDP]
            proto = ptype = "DNS" if packet.haslayer(DNS) else "UDP"
            sp, dp = int(layer.sport), int(layer.dport)
        elif family == 4 and packet.haslayer(ICMP):
            proto = ptype = "ICMP"
        elif family == 6 and (icmp6 := icmpv6_layer(packet)) is not None:
            # Echo and error messages are what the ICMP rules exist for, so
            # they share the type. Neighbour Discovery is not: see NDP_TYPES.
            if int(getattr(icmp6, "type", -1)) in NDP_TYPES:
                proto = ptype = "NDP"
                ndp_claim, ndp_mac = ndp_binding(ip, icmp6)
            else:
                proto = ptype = "ICMP"
        metadata: dict = {} if family == 4 else {"ip_version": 6}
        if ndp_claim and ndp_mac:
            metadata["claimed"] = ndp_claim
            metadata["mac"] = ndp_mac
        return TrafficEvent(
            utc_now(), str(ip.src), str(ip.dst), proto, sp, dp, len(packet),
            flags, interface, metadata=metadata,
        ), ptype
