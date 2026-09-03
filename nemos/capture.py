from __future__ import annotations

import logging
import socket
import sys
import threading
import time
from pathlib import Path

from .models import TrafficEvent, utc_now
from .tls import MAX_HANDSHAKE_BYTES, parse_hello

log = logging.getLogger(__name__)

# The states an operator sees. These are deliberately coarser than the internal
# lifecycle below, because what an operator needs to know is not "which branch
# of _run are we in" but "is traffic reaching the detector, and if not, whose
# problem is it".
#
#   ONLINE        the socket is bound and packets have actually arrived
#   NO TRAFFIC    the socket is bound but nothing has arrived yet
#   BLOCKED       the OS refused the capture socket -- a privilege problem
#   NO INTERFACE  the configured interface does not exist, or none is usable
#   ERROR         anything else, including a missing capture backend
#   STARTING      the thread is up but has not bound yet
#   OFF           capture is disabled by configuration
#
# ONLINE is the important one. It is never set on a successful bind alone: a
# sensor that opened a socket on the wrong interface binds perfectly and sees
# nothing, and reporting that as ONLINE is precisely the failure that lets a
# deployment sit blind for a week. ONLINE requires a packet.
STATE_ONLINE = "ONLINE"
STATE_NO_TRAFFIC = "NO TRAFFIC"
STATE_BLOCKED = "BLOCKED"
STATE_NO_INTERFACE = "NO INTERFACE"
STATE_ERROR = "ERROR"
STATE_STARTING = "STARTING"
STATE_OFF = "OFF"

# Linux capability bit for opening a packet socket. Checked so the sensor can
# say *why* it was refused rather than only that it was.
CAP_NET_RAW = 13

# ETH_P_ALL, in host byte order, for the probe socket.
_ETH_P_ALL = 3

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


def _scapy_interfaces() -> list[str]:
    """Interface names scapy will accept, or [] when it cannot say.

    On Windows this matters more than it looks: scapy addresses adapters by its
    own names, which are not the names Windows or ``socket`` use. Asking scapy
    is the only way to get a name that ``sniff(iface=...)`` will take.
    """
    try:
        from scapy.arch import get_if_list
    except Exception:
        return []
    try:
        return [str(name) for name in get_if_list() if str(name)]
    except Exception:
        # A missing capture driver surfaces here on Windows rather than at
        # import; an empty list is the honest answer, and the backend check
        # below turns it into an actionable message.
        log.debug("scapy could not enumerate interfaces", exc_info=True)
        return []


def _system_interfaces() -> list[str]:
    """Interface names from the OS, without needing scapy."""
    names: list[str] = []
    sysfs = Path("/sys/class/net")
    if sysfs.is_dir():
        try:
            names = sorted(entry.name for entry in sysfs.iterdir())
        except OSError:
            names = []
    if not names:
        try:
            names = sorted({name for _, name in socket.if_nameindex() if name})
        except (OSError, AttributeError):
            names = []
    return names


def list_interfaces() -> list[str]:
    """Every interface NEMOS could capture on, best effort, never raising.

    Deliberately enumerated rather than assumed. Guessing ``eth0`` is wrong on
    a laptop, ``wlan0`` is wrong on a server, and both are wrong inside a
    container -- and a hardcoded guess fails as "0 packets" rather than as
    "that interface does not exist", which is the harder failure to diagnose.
    """
    seen: dict[str, None] = {}
    for name in _scapy_interfaces() + _system_interfaces():
        seen.setdefault(name, None)
    return list(seen)


def interface_is_up(name: str) -> bool | None:
    """Whether an interface is administratively up. None when unknowable."""
    state = Path("/sys/class/net") / str(name) / "operstate"
    try:
        value = state.read_text().strip().lower()
    except OSError:
        return None
    # "unknown" is what loopback and many virtual interfaces report; it is not
    # a failure, and treating it as down would hide a perfectly good capture.
    return value in ("up", "unknown")


def effective_capabilities() -> int | None:
    """The process's effective Linux capability set, or None off Linux."""
    try:
        with open("/proc/self/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    return int(line.split(":", 1)[1].strip(), 16)
    except (OSError, ValueError):
        return None
    return None


def has_cap_net_raw() -> bool | None:
    """Whether this process holds CAP_NET_RAW. None when it cannot be read."""
    caps = effective_capabilities()
    if caps is None:
        return None
    return bool(caps & (1 << CAP_NET_RAW))


def raw_socket_permitted() -> tuple[bool, str]:
    """Actually try to open a capture socket. Returns ``(ok, reason)``.

    A capability bit is a claim; a socket is proof. Opening one costs
    microseconds and answers the question the capability check only estimates
    -- seccomp, AppArmor, a container's network mode and an unprivileged
    userns can each refuse a process that appears to hold CAP_NET_RAW.

    The socket is closed immediately. Nothing is read from it.
    """
    if not hasattr(socket, "AF_PACKET"):
        # Not Linux. Other platforms have no equivalent cheap probe, so the
        # honest answer is "unknown", and the bind attempt itself will tell us.
        return True, ""
    try:
        probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
    except PermissionError:
        return False, "the operating system refused a packet socket"
    except OSError as exc:
        return False, f"a packet socket could not be opened: {exc}"
    probe.close()
    return True, ""


def backend_available() -> tuple[bool, str]:
    """Whether a usable capture backend is installed. ``(ok, reason)``."""
    try:
        import scapy  # noqa: F401
    except ImportError:
        return False, "Scapy is not installed"
    if sys.platform == "win32" and not _scapy_interfaces():
        # On Windows scapy imports cleanly without a capture driver and then
        # fails at sniff time with a raw traceback. Catching it here turns that
        # into the one sentence the operator can act on.
        return False, "Npcap is not installed, or its driver is not running"
    return True, ""


def remedy(state: str) -> str:
    """A single actionable sentence for a capture problem, by platform.

    Root is deliberately not the first suggestion on Linux. Running the whole
    sensor as root to read packets grants it every other privilege too, when
    the one capability it actually needs can be granted on its own.
    """
    if state == STATE_BLOCKED:
        if sys.platform == "win32":
            return ("Run NEMOS from an Administrator prompt, or install Npcap "
                    "with 'Restrict Npcap driver's access to Administrators only' "
                    "unchecked.")
        if sys.platform == "darwin":
            return ("Grant access to the BPF devices (/dev/bpf*), for example "
                    "with the ChmodBPF helper that ships with Wireshark.")
        # CAP_NET_RAW alone, deliberately. It was measured: capture reaches
        # ONLINE as an unprivileged user holding only that capability, so
        # asking for CAP_NET_ADMIN as well -- as most advice does -- would
        # widen the grant past what the sensor actually uses, and running the
        # whole process as root would widen it very much further.
        return (
            "Grant only the one capability capture needs, rather than running "
            "the whole sensor as root: "
            "sudo setcap cap_net_raw+eip $(readlink -f $(which python3)) "
            "-- or, under systemd, AmbientCapabilities=CAP_NET_RAW in the unit "
            "file (packaging/systemd/nemos.service already does this)."
        )
    if state == STATE_NO_INTERFACE:
        return ("Set NEMOS_INTERFACE to one of the interfaces listed above, or "
                "leave it unset to capture on all of them.")
    if state == STATE_ERROR and sys.platform == "win32":
        return ("Install Npcap from https://npcap.com with WinPcap API-compatible "
                "mode enabled, then restart NEMOS.")
    if state == STATE_ERROR:
        return "Install the capture dependencies: pip install -r requirements.txt"
    if state == STATE_NO_TRAFFIC:
        return ("The socket is open but nothing has arrived. Check that "
                "NEMOS_INTERFACE names the interface carrying traffic, and that "
                "the link is up.")
    return ""


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


def tcp_payload(layer) -> bytes:
    """The bytes a TCP segment carries, or b"" if it carries none.

    Bounded at the handshake cap: NEMOS reads the front of a segment to
    recognise a TLS handshake and never more, so a large transfer costs the
    same as a small one here.
    """
    payload = getattr(layer, "payload", None)
    if payload is None or not payload:
        return b""
    try:
        return bytes(payload)[:MAX_HANDSHAKE_BYTES]
    except Exception:
        # A layer scapy could not serialise is not worth an exception on the
        # capture thread.
        return b""


def tls_metadata(layer) -> dict:
    """Fingerprint a TLS handshake carried by this segment, if it is one.

    Deliberately keyed on the TLS record header rather than on port 443. TLS
    speaking on a port it has no business speaking on is exactly the traffic
    worth fingerprinting, and a port test would miss all of it.

    Only the ClientHello/ServerHello is read. Everything after the handshake
    is ciphertext and is never touched.
    """
    payload = tcp_payload(layer)
    if not payload:
        return {}
    hello = parse_hello(payload)
    return hello.as_dict() if hello is not None else {}


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


# How long a bound socket may see nothing before that is worth reporting as
# NO TRAFFIC rather than as still starting. Long enough that a genuinely quiet
# link at 3am is not a five-second alarm, short enough to catch a sensor
# watching the wrong interface during a demo.
DEFAULT_TRAFFIC_GRACE = 20.0


class PacketCapture:
    """Reads packets off an interface and hands each one to ``on_event``.

    The lifecycle is deliberately explicit about *why* it is not capturing.
    An earlier revision reported a bare "failed" with the same message for a
    misspelled interface name, a missing capability and an uninstalled Scapy --
    three problems with three completely different fixes.
    """

    def __init__(self, interface, on_event, traffic_grace: float = DEFAULT_TRAFFIC_GRACE):
        self.interface = interface
        self.on_event = on_event
        self.traffic_grace = max(0.0, float(traffic_grace))
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self.thread = None
        self._state = "stopped"
        self._packets_seen = 0
        self._last_packet = None
        self._error = None
        self._remedy = ""
        self._bound_at = None
        self._interfaces: list[str] = []

    def preflight(self) -> tuple[str, str, str]:
        """Check what capture needs before starting. ``(state, error, remedy)``.

        Returns ``("", "", "")`` when nothing is wrong. Run before the thread
        starts so a hopeless configuration is reported as itself instead of as
        a thread that dies a moment later for reasons nobody can see.
        """
        ok, reason = backend_available()
        if not ok:
            return STATE_ERROR, reason, remedy(STATE_ERROR)

        interfaces = list_interfaces()
        with self._lock:
            self._interfaces = list(interfaces)
        if self.interface:
            if interfaces and self.interface not in interfaces:
                available = ", ".join(interfaces[:12]) or "none"
                return (
                    STATE_NO_INTERFACE,
                    f"interface {self.interface!r} does not exist; available: {available}",
                    remedy(STATE_NO_INTERFACE),
                )
            if interface_is_up(self.interface) is False:
                # Not fatal: an interface can come up after the sensor does, and
                # refusing to start would make that unrecoverable without a
                # restart. Recorded so the dashboard can say so.
                log.warning("interface %s is down; capture will see nothing "
                            "until it comes up", self.interface)
        elif not interfaces:
            return (STATE_NO_INTERFACE, "no network interfaces were found",
                    remedy(STATE_NO_INTERFACE))

        permitted, reason = raw_socket_permitted()
        if not permitted:
            capability = has_cap_net_raw()
            if capability is False:
                reason = f"{reason} (this process does not hold CAP_NET_RAW)"
            elif capability is True:
                # Worth saying: the capability is present and the socket was
                # still refused, which points at seccomp, AppArmor or a
                # container network mode rather than at setcap.
                reason = (f"{reason} despite holding CAP_NET_RAW; a sandbox "
                          f"(seccomp, AppArmor, or the container's network mode) "
                          f"is refusing it")
            return STATE_BLOCKED, reason, remedy(STATE_BLOCKED)
        return "", "", ""

    def start(self):
        with self._lock:
            if self.thread is not None and self.thread.is_alive():
                return
        state, error, fix = self.preflight()
        if state:
            with self._lock:
                self._state = state
                self._error = error
                self._remedy = fix
            log.error("packet capture cannot start: %s", error)
            if fix:
                log.error("to fix: %s", fix)
            return
        with self._lock:
            self.stop_event.clear()
            self._state = "starting"
            self._error = None
            self._remedy = ""
            self._bound_at = None
            self.thread = threading.Thread(target=self._run, name="packet-capture", daemon=True)
            self.thread.start()

    def display_state(self, state: str, alive: bool, packets: int,
                      bound_at: float | None, now: float | None = None) -> str:
        """Map the internal lifecycle onto what an operator is shown.

        The one rule worth stating: ONLINE requires a packet, not a successful
        bind. A sensor watching the wrong interface binds perfectly and sees
        nothing forever, and calling that ONLINE is how a deployment sits blind
        without anyone noticing.
        """
        if state in ("permission_denied", STATE_BLOCKED):
            return STATE_BLOCKED
        if state == STATE_NO_INTERFACE:
            return STATE_NO_INTERFACE
        if state in ("unavailable", "error", "failed", STATE_ERROR):
            return STATE_ERROR
        if state in ("stopped", "not_configured"):
            return STATE_OFF
        if state == "running" and alive:
            if packets > 0:
                return STATE_ONLINE
            now = time.monotonic() if now is None else now
            if bound_at is not None and now - bound_at >= self.traffic_grace:
                return STATE_NO_TRAFFIC
            return STATE_STARTING
        if state == "starting":
            return STATE_STARTING
        return STATE_ERROR

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
            fix = self._remedy
            packets = self._packets_seen
            bound_at = self._bound_at
            interfaces = list(self._interfaces)
            if not alive and state in {"starting", "running"}:
                state = "failed"
                error = error or (
                    "capture thread exited without reporting a reason; check "
                    "privileges (CAP_NET_RAW) and the interface name"
                )
        shown = self.display_state(state, alive, packets, bound_at)
        if not fix:
            fix = remedy(shown)
        return {
            "state": state,
            "display_state": shown,
            "running": alive,
            "interface": self.interface or "default",
            "interfaces": interfaces,
            "packets_seen": packets,
            "last_packet": self._last_packet,
            "error": error,
            # Never a bare "it failed": every failure state carries the one
            # sentence that fixes it on this platform.
            "remedy": fix,
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
                self._state = STATE_ERROR
                self._error = "Scapy is not installed"
                self._remedy = remedy(STATE_ERROR)
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

            The internal state flips to "running" on a successful bind, not on
            the first packet: keying it to traffic meant a correctly-running
            sensor on a quiet link reported "starting" forever, which is
            indistinguishable from a capture that never came up.

            What an operator is *shown* is a separate question -- see
            display_state. A bind proves the socket opened; only a packet
            proves NEMOS can see the network.
            """
            with self._lock:
                if self._bound_at is None:
                    self._bound_at = time.monotonic()
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
                self._state = STATE_BLOCKED
                self._error = "the operating system refused the capture socket"
                self._remedy = remedy(STATE_BLOCKED)
            log.error("packet capture was refused: %s", remedy(STATE_BLOCKED))
        except Exception as exc:
            message = str(exc)
            lowered = message.lower()
            with self._lock:
                # scapy reports a bad interface name and a missing driver as the
                # same generic exception class. The text is the only thing that
                # separates "you typed the wrong name" from "install Npcap", and
                # those have nothing in common as fixes.
                if any(token in lowered for token in
                       ("npcap", "winpcap", "wpcap", "libpcap", "pcap library")):
                    self._state = STATE_ERROR
                    self._error = f"the capture backend is unavailable: {message[:200]}"
                    self._remedy = remedy(STATE_ERROR)
                elif any(token in lowered for token in
                         ("no such device", "unknown interface", "device not found",
                          "not found", "no such file or directory")):
                    available = ", ".join(list_interfaces()[:12]) or "none"
                    self._state = STATE_NO_INTERFACE
                    self._error = (f"interface {self.interface or 'default'!r} could not "
                                   f"be opened: {message[:160]}; available: {available}")
                    self._remedy = remedy(STATE_NO_INTERFACE)
                else:
                    self._state = STATE_ERROR
                    self._error = message[:240]
                    self._remedy = ""
            log.exception("capture stopped")
        except BaseException as exc:
            # A native panic or an injected exception is still a dead capture
            # thread, and the operator must be told rather than left looking at
            # a sensor stuck in "starting". Re-raised after recording it.
            with self._lock:
                self._state = STATE_ERROR
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
        tls: dict = {}
        if packet.haslayer(TCP):
            layer = packet[TCP]
            proto = ptype = "TCP"
            sp, dp = int(layer.sport), int(layer.dport)
            flags = str(layer.flags)
            tls = tls_metadata(layer)
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
        metadata.update(tls)
        return TrafficEvent(
            utc_now(), str(ip.src), str(ip.dst), proto, sp, dp, len(packet),
            flags, interface, metadata=metadata,
        ), ptype
