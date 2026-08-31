from __future__ import annotations

import ipaddress
import os
import time
import uuid
from math import isfinite
from collections import OrderedDict, deque
from functools import lru_cache
from itertools import pairwise
from dataclasses import dataclass
from typing import Any

from .behavioral import AdaptiveBehaviorProfiler, BehaviorObservation
from .models import Alert, TrafficEvent, utc_now


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    window: int = 10
    port_scan: int = 8
    syn_flood: int = 150
    # A flood concentrates on a service; a scan spreads across ports. Without
    # this, an nmap -sS sweep -- which sends far more than syn_flood SYNs -- was
    # reported as a denial-of-service flood as well as a scan.
    syn_flood_concentration: float = 0.30
    icmp_flood: int = 100
    fanout: int = 25
    dns_burst: int = 80
    service_burst: int = 40
    udp_scan: int = 12
    icmp_sweep: int = 12
    stealth_scan: int = 6
    lateral_hosts: int = 5
    brute_force: int = 20
    exfil_bytes: int = 25_000_000
    dns_tunnel_packets: int = 30
    dns_tunnel_mean_size: int = 180
    mining_packets: int = 10
    tor_packets: int = 10
    spray_hosts: int = 8
    spray_max_attempts: int = 6
    icmp_tunnel_packets: int = 12
    icmp_tunnel_mean_size: int = 200
    service_dos: int = 120
    amplification_packets: int = 60
    ingress_bytes: int = 25_000_000
    nonstandard_packets: int = 40
    nonstandard_min_port: int = 10_000
    # Beaconing is periodicity, which a 10s window cannot see. These govern a
    # separate per-pair timing history with its own horizon.
    beacon_min_intervals: int = 5
    beacon_max_jitter: float = 0.15
    beacon_min_period: float = 2.0
    beacon_horizon: float = 900.0
    cooldown: int = 30
    correlation_window: int = 60
    max_sources: int = 4096
    max_events: int = 1000
    baseline_alpha: float = 0.15
    baseline_min_samples: int = 8
    baseline_multiplier: float = 3.0
    baseline_min_events: int = 20
    baseline_sigma_threshold: float = 3.0
    baseline_sample_interval: float = 5.0
    baseline_extreme_sigma: float = 6.0
    min_confidence: int = 55

    @classmethod
    def from_env(cls) -> DetectionConfig:
        defaults = cls()

        def integer(name: str, default: int, lo: int, hi: int) -> int:
            try:
                value = int(os.getenv(name, default))
            except (TypeError, ValueError):
                value = default
            return max(lo, min(hi, value))

        def real(name: str, default: float, lo: float, hi: float) -> float:
            try:
                value = float(os.getenv(name, default))
            except (TypeError, ValueError):
                value = default
            return max(lo, min(hi, value)) if isfinite(value) else default

        return cls(
            # Every rule threshold below is tunable so an operator whose
            # network genuinely runs hotter or quieter than the defaults can
            # adjust detection without a code change and a rebuild. The
            # defaults themselves are unchanged; each clamp only bounds what
            # an operator can set them to, the same discipline NEMOS_API_RATE
            # and NEMOS_MAX_EVENTS already follow.
            window=integer("NEMOS_DETECT_WINDOW", defaults.window, 2, 300),
            port_scan=integer("NEMOS_DETECT_PORT_SCAN", defaults.port_scan, 2, 10_000),
            syn_flood=integer("NEMOS_DETECT_SYN_FLOOD", defaults.syn_flood, 10, 1_000_000),
            syn_flood_concentration=real(
                "NEMOS_DETECT_SYN_FLOOD_CONCENTRATION", defaults.syn_flood_concentration, 0.05, 1.0),
            icmp_flood=integer("NEMOS_DETECT_ICMP_FLOOD", defaults.icmp_flood, 10, 1_000_000),
            fanout=integer("NEMOS_DETECT_FANOUT", defaults.fanout, 2, 100_000),
            dns_burst=integer("NEMOS_DETECT_DNS_BURST", defaults.dns_burst, 5, 1_000_000),
            service_burst=integer("NEMOS_DETECT_SERVICE_BURST", defaults.service_burst, 2, 1_000_000),
            udp_scan=integer("NEMOS_DETECT_UDP_SCAN", defaults.udp_scan, 2, 100_000),
            icmp_sweep=integer("NEMOS_DETECT_ICMP_SWEEP", defaults.icmp_sweep, 2, 100_000),
            stealth_scan=integer("NEMOS_DETECT_STEALTH_SCAN", defaults.stealth_scan, 1, 100_000),
            lateral_hosts=integer("NEMOS_DETECT_LATERAL_HOSTS", defaults.lateral_hosts, 2, 100_000),
            brute_force=integer("NEMOS_DETECT_BRUTE_FORCE", defaults.brute_force, 2, 1_000_000),
            exfil_bytes=integer(
                "NEMOS_DETECT_EXFIL_BYTES", defaults.exfil_bytes, 1_000_000, 10_000_000_000),
            dns_tunnel_packets=integer(
                "NEMOS_DETECT_DNS_TUNNEL_PACKETS", defaults.dns_tunnel_packets, 5, 1_000_000),
            dns_tunnel_mean_size=integer(
                "NEMOS_DETECT_DNS_TUNNEL_MEAN_SIZE", defaults.dns_tunnel_mean_size, 50, 65_535),
            mining_packets=integer("NEMOS_DETECT_MINING_PACKETS", defaults.mining_packets, 1, 1_000_000),
            tor_packets=integer("NEMOS_DETECT_TOR_PACKETS", defaults.tor_packets, 1, 1_000_000),
            spray_hosts=integer("NEMOS_DETECT_SPRAY_HOSTS", defaults.spray_hosts, 2, 100_000),
            spray_max_attempts=integer(
                "NEMOS_DETECT_SPRAY_MAX_ATTEMPTS", defaults.spray_max_attempts, 1, 100_000),
            icmp_tunnel_packets=integer(
                "NEMOS_DETECT_ICMP_TUNNEL_PACKETS", defaults.icmp_tunnel_packets, 2, 1_000_000),
            icmp_tunnel_mean_size=integer(
                "NEMOS_DETECT_ICMP_TUNNEL_MEAN_SIZE", defaults.icmp_tunnel_mean_size, 50, 65_535),
            service_dos=integer("NEMOS_DETECT_SERVICE_DOS", defaults.service_dos, 10, 1_000_000),
            amplification_packets=integer(
                "NEMOS_DETECT_AMPLIFICATION_PACKETS", defaults.amplification_packets, 5, 1_000_000),
            ingress_bytes=integer(
                "NEMOS_DETECT_INGRESS_BYTES", defaults.ingress_bytes, 1_000_000, 10_000_000_000),
            nonstandard_packets=integer(
                "NEMOS_DETECT_NONSTANDARD_PACKETS", defaults.nonstandard_packets, 5, 1_000_000),
            nonstandard_min_port=integer(
                "NEMOS_DETECT_NONSTANDARD_MIN_PORT", defaults.nonstandard_min_port, 1024, 65_535),
            beacon_min_intervals=integer(
                "NEMOS_DETECT_BEACON_MIN_INTERVALS", defaults.beacon_min_intervals, 3, 1000),
            beacon_max_jitter=real(
                "NEMOS_DETECT_BEACON_MAX_JITTER", defaults.beacon_max_jitter, 0.01, 1.0),
            beacon_min_period=real(
                "NEMOS_DETECT_BEACON_MIN_PERIOD", defaults.beacon_min_period, 0.5, 3600.0),
            beacon_horizon=real(
                "NEMOS_DETECT_BEACON_HORIZON", defaults.beacon_horizon, 60.0, 86_400.0),
            cooldown=integer("NEMOS_DETECT_COOLDOWN", defaults.cooldown, 0, 3600),
            correlation_window=integer(
                "NEMOS_DETECT_CORRELATION_WINDOW", defaults.correlation_window, 5, 3600),
            max_sources=integer("NEMOS_DETECT_MAX_SOURCES", defaults.max_sources, 64, 1_000_000),
            # Per-packet detection cost is linear in how many events a window
            # holds, so this is the dial for trading detection depth against
            # capture-path throughput. The floor stays above the largest rule
            # threshold (syn_flood at 150) so lowering it cannot silently
            # disable a rule by starving it of evidence. Raising syn_flood
            # above the default means raising this too, or the flood rule
            # loses evidence to the eviction it competes against.
            max_events=integer("NEMOS_MAX_EVENTS", defaults.max_events, 200, 100_000),
            baseline_alpha=real("NEMOS_BEHAVIOR_ALPHA", defaults.baseline_alpha, 0.01, 1.0),
            baseline_min_samples=integer("NEMOS_BEHAVIOR_MIN_SAMPLES", defaults.baseline_min_samples, 2, 1000),
            baseline_multiplier=real(
                "NEMOS_DETECT_BASELINE_MULTIPLIER", defaults.baseline_multiplier, 1.0, 20.0),
            baseline_min_events=integer(
                "NEMOS_DETECT_BASELINE_MIN_EVENTS", defaults.baseline_min_events, 2, 100_000),
            baseline_sigma_threshold=real("NEMOS_BEHAVIOR_SIGMA", defaults.baseline_sigma_threshold, 1.0, 10.0),
            baseline_sample_interval=real(
                "NEMOS_BEHAVIOR_SAMPLE_SECONDS", defaults.baseline_sample_interval, 0.0, 300.0),
            baseline_extreme_sigma=real(
                "NEMOS_BEHAVIOR_EXTREME_SIGMA", defaults.baseline_extreme_sigma, 3.0, 15.0),
            min_confidence=integer("NEMOS_DETECT_MIN_CONFIDENCE", defaults.min_confidence, 0, 100),
        )


@lru_cache(maxsize=512)
def _flag_class(flags: str) -> str | None:
    """Classify a TCP flag string as a stealth-probe type, or None.

    Cached because a link carries only a handful of distinct flag combinations
    while carrying millions of packets, and this runs per record per packet.
    """
    marks = set(flags) - {"E", "C", "N"}
    if not marks:
        return "null"
    if marks == {"F"}:
        return "fin"
    if {"F", "P", "U"} <= marks and "S" not in marks and "A" not in marks:
        return "xmas"
    return None


class ThreatDetector:
    """Bounded, explainable network-behaviour detector.

    Detection v3 uses several independent signals and reports the evidence
    behind a finding. It deliberately avoids pretending that a small packet
    sample is machine learning: the behavioural component is an EMA baseline
    over observed source rates and is deterministic/offline by design.
    """

    COMMON_SERVICE_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 587,
        993, 995, 1433, 3306, 3389, 5432, 6379, 8080,
    }

    # Remote-administration and file-sharing services. Internal-to-internal
    # traffic across many of these hosts is the shape lateral movement takes.
    ADMIN_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986, 5900}

    # Services that accept credentials. Repeated attempts against one of these
    # on a single host is the shape a brute-force attempt takes.
    AUTH_PORTS = {
        21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900, 6379,
    }

    # Default ports for common mining pool protocols (Stratum and variants).
    # Port-based identification is a heuristic, not proof: the evidence records
    # the port so an analyst can confirm.
    MINING_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45560}

    # Default Tor OR/dir/SOCKS ports. Same caveat as mining: heuristic.
    TOR_PORTS = {9001, 9030, 9050, 9051, 9150}

    # Remote-administration ports mapped to the ATT&CK sub-technique for that
    # service. The port is observed directly, so naming the sub-technique is
    # evidence-backed rather than a guess about what the traffic carried.
    REMOTE_SERVICE_TECHNIQUES = {
        3389: "T1021.001",   # Remote Desktop Protocol
        445: "T1021.002",    # SMB / Windows Admin Shares
        22: "T1021.004",     # SSH
        5900: "T1021.005",   # VNC
        5985: "T1021.006",   # Windows Remote Management
        5986: "T1021.006",
    }

    # Services routinely abused for reflection/amplification floods. Seen as a
    # *source* port in high volume toward one destination, this is the sensor
    # observing the reflected leg of an amplification attack.
    AMPLIFIER_PORTS = {19, 53, 123, 161, 389, 1900, 5353, 11211}

    # Linux allocates ephemeral client ports from 32768 upward. A packet
    # arriving at one of these is almost always a reply to a connection this
    # host opened, not a probe of a listening service.
    EPHEMERAL_PORT_FLOOR = 32768

    # Periodic by design. Excluded from beacon analysis because NTP sync, DNS
    # refresh and DHCP renewal are textbook low-jitter timers -- flagging them
    # would bury real callbacks in known-benign noise.
    BENIGN_PERIODIC_PORTS = {53, 67, 68, 123, 5353}

    # What counts as "inside" for lateral-movement and exfiltration decisions.
    # RFC 1918, loopback, link-local and IPv6 unique-local -- deliberately not
    # the RFC 5737 documentation ranges. Override with NEMOS_INTERNAL_NETWORKS
    # when a deployment routes public address space internally, which would
    # otherwise make its own east-west traffic look like exfiltration.
    DEFAULT_INTERNAL_NETWORKS = (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16",
        "::1/128", "fc00::/7", "fe80::/10",
    )

    def __init__(self, cfg: DetectionConfig | None = None):
        self.cfg = cfg or DetectionConfig()
        self.events: OrderedDict[str, deque[dict[str, Any]]] = OrderedDict()
        self.last: OrderedDict[tuple[str, str], float] = OrderedDict()
        self.arp: OrderedDict[str, str] = OrderedDict()
        self.behavior = AdaptiveBehaviorProfiler(
            alpha=self.cfg.baseline_alpha,
            min_samples=self.cfg.baseline_min_samples,
            sample_interval=self.cfg.baseline_sample_interval,
            sigma_threshold=self.cfg.baseline_sigma_threshold,
            max_sources=self.cfg.max_sources,
        )
        self.incidents: OrderedDict[str, tuple[str, float]] = OrderedDict()
        # Beaconing is a property of the interval between contacts, so it needs
        # a horizon far longer than the detection window. Keyed by
        # (source, destination, port) -- every component of which an attacker
        # influences -- so it is bounded and evicted least-recently-used like
        # every other map in this class.
        self.contacts: OrderedDict[tuple[str, str, int | None], deque[float]] = OrderedDict()
        # Destinations already judged to be beacon targets for a source.
        # Bounded for the same reason as every other attacker-keyed map.
        self.beacon_targets: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._private_cache: OrderedDict[str, bool] = OrderedDict()
        self.internal_networks = self._parse_networks(
            os.getenv("NEMOS_INTERNAL_NETWORKS", "")
        ) or [ipaddress.ip_network(n) for n in self.DEFAULT_INTERNAL_NETWORKS]

    @staticmethod
    def _parse_networks(raw: str) -> list[Any]:
        """Parse a comma-separated CIDR list, skipping anything unparseable.

        A malformed entry is dropped rather than raising: a typo in one CIDR
        must not stop the sensor from starting.
        """
        networks = []
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
        return networks

    def process(self, e: TrafficEvent, ptype: str = "", now: float | None = None) -> list[Alert]:
        """Evaluate one event against the deterministic rules.

        ``now`` overrides the monotonic clock. Live capture leaves it unset;
        replay and tests pass the event's own timeline so a window means
        simulated seconds rather than wall-clock ones. Without it, replaying an
        hour of traffic in a second puts every event inside a single window and
        manufactures findings.
        """
        if not self._ip(e.source) or not self._ip(e.destination):
            return []

        now = time.monotonic() if now is None else now
        bucket = self._bucket(e.source)
        bucket.append({
            "t": now,
            "dst": e.destination,
            "port": e.destination_port,
            "sport": e.source_port,
            "proto": e.protocol.upper(),
            "flags": e.flags,
            "type": ptype.upper(),
            "size": max(0, int(e.packet_size or 0)),
        })
        cutoff = now - self.cfg.window
        while bucket and bucket[0]["t"] < cutoff:
            bucket.popleft()

        # One pass over the window computes every aggregate the rules below
        # need. Each rule used to scan the bucket itself, which made the cost
        # per packet the number of rules times the window size -- measured at
        # 160us/packet, against 5us before the rules were added. Detection runs
        # inline on the capture thread, so that is dropped traffic, not just a
        # slow dashboard.
        agg = self._aggregate(bucket, e.source)
        ports = agg["ports"]
        scan_ports = agg["scan_ports"]
        destinations = agg["destinations"]
        tcp_syn = agg["tcp_syn"]
        tcp_syn_ports = agg["tcp_syn_ports"]
        udp_ports = agg["udp_ports"]
        icmp_destinations = agg["icmp_destinations"]
        service_ports = agg["service_ports"]
        service_count = agg["service_count"]
        dns_count = agg["dns_count"]
        icmp_count = agg["icmp_count"]
        out: list[Alert] = []

        def add(threat: str, category: str, score: int, reason: str,
                technique: str = "", confidence: int | None = None, **kw: Any) -> None:
            alert = self._emit(
                e.source, threat, category, score, reason, technique,
                confidence=confidence, now=now, **kw,
            )
            if alert:
                out.append(alert)

        # Vertical scan: many ports on one or a few hosts. SYN evidence raises
        # confidence because a SYN-only burst is a stronger scan indicator.
        if len(scan_ports) >= self.cfg.port_scan:
            syn_ratio = len(tcp_syn) / max(1, len(bucket))
            # ATT&CK separates pre-compromise scanning from the inside from
            # post-compromise service discovery. The source address decides
            # which one the evidence actually supports.
            external = not self._private(e.source)
            scan_technique = "T1595" if external else "T1046"
            scan_score = min(96, 50 + len(scan_ports) * 3 + (15 if syn_ratio >= 0.5 else 0))
            scan_conf = min(99, 58 + len(scan_ports) * 3 + (18 if syn_ratio >= 0.5 else 0))
            add(
                "PORT_SCAN", "NETWORK_RECONNAISSANCE", scan_score,
                f"{len(scan_ports)} unique destination ports in {self.cfg.window}s",
                scan_technique, confidence=scan_conf,
                ports_scanned=len(scan_ports), packets=len(bucket),
                destinations=len(destinations), ports=len(scan_ports),
                evidence={
                    "scan_type": "vertical",
                    "source_position": "external" if external else "internal",
                    "ports": sorted(scan_ports)[:100],
                    "syn_packets": len(tcp_syn),
                    "syn_ratio": round(syn_ratio, 3),
                    "unique_destinations": len(destinations),
                },
            )

        # SYN-only vertical scanning gets an explicit finding when the port
        # count is high enough, while cooldown prevents duplicate noise.
        if len(tcp_syn_ports) >= self.cfg.port_scan and len(tcp_syn_ports) == len(ports):
            add(
                "TCP_SYN_SCAN", "NETWORK_RECONNAISSANCE",
                min(94, 58 + len(tcp_syn_ports) * 3),
                f"SYN probes targeted {len(tcp_syn_ports)} ports without ACK evidence",
                "T1046", confidence=min(99, 65 + len(tcp_syn_ports) * 3),
                packets=len(tcp_syn), ports=len(tcp_syn_ports),
                evidence={"scan_type": "tcp_syn", "ports": sorted(tcp_syn_ports)[:100]},
            )

        # Horizontal UDP scan: many UDP service ports from one source is
        # distinct from a TCP SYN scan and remains evidence-based.
        if len(udp_ports) >= self.cfg.udp_scan:
            add(
                "UDP_PORT_SCAN", "NETWORK_RECONNAISSANCE",
                min(90, 55 + len(udp_ports) * 2),
                f"{len(udp_ports)} unique UDP destination ports in {self.cfg.window}s",
                "T1046", confidence=min(96, 62 + len(udp_ports) * 2),
                packets=agg["udp_count"],
                ports=len(udp_ports), destinations=len(destinations),
                evidence={"scan_type": "udp", "ports": sorted(udp_ports)[:100]},
            )

        if len(destinations) >= self.cfg.fanout:
            add(
                "NETWORK_FANOUT", "NETWORK_DISCOVERY", 70,
                f"{len(destinations)} unique destinations in {self.cfg.window}s",
                "T1018", confidence=min(95, 60 + len(destinations)),
                packets=len(bucket), destinations=len(destinations), ports=len(ports),
                evidence={"unique_destinations": len(destinations)},
            )

        if len(icmp_destinations) >= self.cfg.icmp_sweep:
            add(
                "ICMP_SWEEP", "NETWORK_RECONNAISSANCE",
                min(88, 56 + len(icmp_destinations) * 2),
                f"ICMP traffic targeted {len(icmp_destinations)} destinations in {self.cfg.window}s",
                "T1018", confidence=min(95, 62 + len(icmp_destinations) * 2),
                packets=icmp_count, destinations=len(icmp_destinations),
                evidence={"scan_type": "icmp_sweep", "destinations": sorted(icmp_destinations)[:100]},
            )

        # A denial-of-service flood and a port sweep both emit a great many
        # SYNs; what separates them is where those SYNs land. A flood
        # concentrates on a service in order to exhaust it, while a scan spreads
        # across ports in order to enumerate them. Counting SYNs alone reported
        # `nmap -sS -p 1-1000` as a flood -- observed on a real deployment --
        # which both overstates the finding and misnames the technique.
        syn_per_port = agg["syn_per_port"]
        busiest_port_syns = max(syn_per_port.values(), default=0)
        concentration = busiest_port_syns / max(1, len(tcp_syn))
        if (len(tcp_syn) >= self.cfg.syn_flood
                and concentration >= self.cfg.syn_flood_concentration):
            targeted = max(syn_per_port, key=lambda k: syn_per_port[k])
            add(
                "SYN_FLOOD_PATTERN", "NETWORK_DENIAL_OF_SERVICE", 90,
                f"{busiest_port_syns} of {len(tcp_syn)} SYN packets targeted port "
                f"{targeted} in {self.cfg.window}s",
                "T1498.001", confidence=min(99, 75 + min(24, len(tcp_syn) // 10)),
                packets=len(tcp_syn), destinations=len(destinations), ports=len(ports),
                evidence={
                    "syn_ratio": round(len(tcp_syn) / max(1, len(bucket)), 3),
                    "syn_packets": len(tcp_syn),
                    "targeted_port": targeted,
                    "syns_to_targeted_port": busiest_port_syns,
                    "port_concentration": round(concentration, 3),
                    "concentration_threshold": self.cfg.syn_flood_concentration,
                    "note": "concentration separates a flood from a port sweep; "
                            "a sweep of comparable volume is reported as a scan",
                },
            )

        if icmp_count >= self.cfg.icmp_flood:
            add(
                "ICMP_FLOOD_PATTERN", "NETWORK_DENIAL_OF_SERVICE", 82,
                f"{icmp_count} ICMP packets in {self.cfg.window}s", "T1498",
                confidence=min(98, 70 + min(28, icmp_count // 10)),
                packets=icmp_count, destinations=len(destinations),
                evidence={"icmp_packets": icmp_count, "unique_destinations": len(icmp_destinations)},
            )

        if dns_count >= self.cfg.dns_burst:
            dns_destinations = agg["dns_destinations"]
            add(
                "DNS_BURST", "DNS_ANOMALY", 65,
                f"{dns_count} DNS packets in {self.cfg.window}s", "T1071.004",
                confidence=min(95, 60 + min(35, dns_count // 5)),
                packets=dns_count, destinations=len(dns_destinations),
                evidence={"dns_packets": dns_count, "dns_destinations": len(dns_destinations)},
            )

        if service_count >= self.cfg.service_burst:
            add(
                "SERVICE_CONNECTION_BURST", "SUSPICIOUS_ACTIVITY", 60,
                f"{service_count} connections to common service ports in {self.cfg.window}s",
                "T1046", confidence=min(94, 60 + min(34, service_count // 3)),
                packets=service_count, destinations=len(destinations), ports=len(service_ports),
                evidence={"service_ports": sorted(service_ports), "service_connections": service_count},
            )

        # --- Stealth scans -------------------------------------------------
        # NULL, FIN and Xmas probes exist to elicit a response from a closed
        # port without completing a handshake. They are defined entirely by
        # their flag combination, which capture already records.
        for kind, scanned in agg["stealth"].items():
            if len(scanned) >= self.cfg.stealth_scan:
                add(
                    f"TCP_{kind.upper()}_SCAN", "NETWORK_RECONNAISSANCE",
                    min(92, 60 + len(scanned) * 3),
                    f"{len(scanned)} ports probed with {kind.upper()} TCP flags "
                    f"in {self.cfg.window}s",
                    "T1046", confidence=min(97, 68 + len(scanned) * 3),
                    packets=len(bucket), ports=len(scanned),
                    destinations=len(destinations),
                    evidence={
                        "scan_type": f"tcp_{kind}",
                        "ports": sorted(scanned)[:100],
                        "note": "stealth probe: no handshake is completed",
                    },
                )

        # --- Lateral movement ----------------------------------------------
        # Internal source reaching many internal hosts on remote-administration
        # ports. Restricted to private-to-private traffic: a public scanner
        # hitting these ports is reconnaissance, already covered above, and
        # calling it lateral movement would misrepresent where the actor is.
        if agg["source_internal"]:
            lateral_targets = agg["lateral_targets"]
            if len(lateral_targets) >= self.cfg.lateral_hosts:
                admin_hits = agg["admin_hits"]
                lateral_ports = sorted(admin_hits)
                # The dominant service names the sub-technique. Falling back to
                # the parent when no port dominates keeps the claim honest.
                dominant = max(admin_hits, key=lambda k: admin_hits[k]) if admin_hits else None
                lateral_technique = self.REMOTE_SERVICE_TECHNIQUES.get(dominant, "T1021")
                add(
                    "LATERAL_MOVEMENT", "LATERAL_MOVEMENT",
                    min(93, 62 + len(lateral_targets) * 4),
                    f"internal host contacted {len(lateral_targets)} internal hosts "
                    f"on remote-administration ports in {self.cfg.window}s",
                    lateral_technique, confidence=min(96, 66 + len(lateral_targets) * 4),
                    packets=len(bucket), destinations=len(lateral_targets),
                    ports=len(lateral_ports),
                    evidence={
                        "internal_targets": sorted(lateral_targets)[:50],
                        "admin_ports": lateral_ports,
                        "dominant_port": dominant,
                        "service": {
                            3389: "RDP", 445: "SMB", 22: "SSH",
                            5900: "VNC", 5985: "WinRM", 5986: "WinRM",
                        }.get(dominant, "unknown"),
                    },
                )

        # --- Credential brute force -----------------------------------------
        # Many attempts against one authentication service on one host. Keyed
        # per (destination, port) so spraying one credential across many hosts
        # does not average away into a below-threshold count.
        for (dst, port), count in agg["auth_attempts"].items():
            if count >= self.cfg.brute_force:
                add(
                    "CREDENTIAL_BRUTE_FORCE", "CREDENTIAL_ACCESS",
                    min(91, 60 + count // 2),
                    f"{count} connection attempts to {dst}:{port} in {self.cfg.window}s",
                    "T1110.001", confidence=min(95, 64 + count // 2),
                    packets=count, destinations=1, ports=1,
                    evidence={
                        "target": dst,
                        "service_port": port,
                        "attempts": count,
                        "note": "attempt volume only; success cannot be "
                                "determined from metadata",
                    },
                )

        # --- Data exfiltration ------------------------------------------------
        # Sustained outbound volume to a single external destination. The
        # threshold is bytes observed in one window, so it scales with the
        # window rather than assuming a fixed session length.
        for dst, total in agg["external_bytes"].items():
            if total >= self.cfg.exfil_bytes:
                # If this destination was already judged a beacon target, the
                # transfer is leaving over the channel the implant established.
                over_c2 = (e.source, dst) in self.beacon_targets
                add(
                    "DATA_EXFILTRATION_OVER_C2" if over_c2 else "DATA_EXFILTRATION_VOLUME",
                    "EXFILTRATION",
                    min(90, 62 + int(total / max(1, self.cfg.exfil_bytes)) * 5),
                    f"{total / 1_000_000:.1f} MB sent to external host {dst} "
                    f"in {self.cfg.window}s",
                    "T1041" if over_c2 else "T1048",
                    confidence=88 if over_c2 else 78,
                    packets=agg["per_destination"].get(dst, 0),
                    destinations=1,
                    evidence={
                        "destination": dst,
                        "bytes": total,
                        "threshold_bytes": self.cfg.exfil_bytes,
                        "over_beacon_channel": over_c2,
                        "note": ("bulk transfer to a host this source was already "
                                 "beaconing to" if over_c2 else
                                 "volume only; a legitimate backup or upload "
                                 "has the same shape"),
                    },
                )

        # --- DNS tunneling ----------------------------------------------------
        # Ordinary DNS packets are small. A sustained stream of large ones
        # carries something other than routine name resolution. This is
        # separate from DNS_BURST, which counts volume alone.
        if dns_count >= self.cfg.dns_tunnel_packets:
            mean_dns = agg["dns_bytes"] / dns_count
            if mean_dns >= self.cfg.dns_tunnel_mean_size:
                add(
                    "DNS_TUNNELING_PATTERN", "COMMAND_AND_CONTROL",
                    min(88, 64 + int(mean_dns // 50)),
                    f"{dns_count} DNS packets averaging {mean_dns:.0f} bytes "
                    f"in {self.cfg.window}s",
                    "T1071.004", confidence=76,
                    packets=dns_count,
                    destinations=len(agg["dns_destinations"]),
                    evidence={
                        "dns_packets": dns_count,
                        "mean_packet_bytes": round(mean_dns, 1),
                        "size_threshold": self.cfg.dns_tunnel_mean_size,
                        "note": "payloads are not inspected; size is the signal",
                    },
                )

        # --- Known-suspicious destination ports -------------------------------
        # Port-based identification is a heuristic and says so in the evidence.
        # The port sets themselves are applied during aggregation; this table
        # only carries how each match is reported.
        for label, key, threat, technique, category, score in (
            ("mining pool", "mining", "CRYPTO_MINING_PATTERN",
             "T1496", "RESOURCE_HIJACKING", 72),
            ("Tor", "tor", "TOR_CONNECTION_PATTERN",
             "T1090.003", "COMMAND_AND_CONTROL", 68),
        ):
            threshold = (self.cfg.mining_packets if "MINING" in threat
                         else self.cfg.tor_packets)
            hits = agg[key]
            if len(hits) >= threshold:
                targets = sorted({x["dst"] for x in hits})
                add(
                    threat, category, score,
                    f"{len(hits)} connections to {label} ports in {self.cfg.window}s",
                    technique, confidence=64,
                    packets=len(hits), destinations=len(targets),
                    ports=len({x["port"] for x in hits}),
                    evidence={
                        "ports": sorted({x["port"] for x in hits}),
                        "destinations": targets[:50],
                        "note": f"port-based heuristic: these are default {label} "
                                "ports, not confirmation of the protocol",
                    },
                )

        # --- Beaconing --------------------------------------------------------
        # Evaluated on the event itself, not the window, because periodicity
        # lives on a longer horizon than the detection window.
        beacon = self._record_contact(bucket[-1], e.source, now)
        if beacon:
            key = (e.source, beacon["destination"])
            if key in self.beacon_targets:
                self.beacon_targets.move_to_end(key)
            elif len(self.beacon_targets) >= self.cfg.max_sources * 4:
                self.beacon_targets.popitem(last=False)
            self.beacon_targets[key] = now
            add(
                "C2_BEACONING", "COMMAND_AND_CONTROL",
                min(89, 66 + int((1 - beacon["jitter_ratio"] /
                                  self.cfg.beacon_max_jitter) * 20)),
                f"{beacon['contacts']} contacts with {beacon['destination']} at a "
                f"regular {beacon['mean_interval_seconds']}s interval",
                "T1071", confidence=80,
                packets=beacon["contacts"], destinations=1,
                evidence=beacon,
            )

        # --- Password spraying -------------------------------------------------
        # The inverse shape of brute force: few attempts each, across many
        # hosts, on one service. Counting per target (as brute force does)
        # never sees it, which is why it needs its own rule.
        for port, targets in agg["spray"].items():
            spread = len(targets)
            heaviest = max(targets.values(), default=0)
            if spread >= self.cfg.spray_hosts and heaviest <= self.cfg.spray_max_attempts:
                add(
                    "PASSWORD_SPRAYING", "CREDENTIAL_ACCESS",
                    min(90, 62 + spread * 2),
                    f"{spread} hosts probed on port {port} with at most "
                    f"{heaviest} attempts each in {self.cfg.window}s",
                    "T1110.003", confidence=min(94, 66 + spread * 2),
                    packets=sum(targets.values()), destinations=spread, ports=1,
                    evidence={
                        "service_port": port,
                        "hosts_targeted": spread,
                        "max_attempts_per_host": heaviest,
                        "note": "low attempts per host across many hosts is the "
                                "shape that evades per-account lockout",
                    },
                )

        # --- ICMP tunneling ----------------------------------------------------
        # Echo payloads are small and fixed by the OS. A sustained stream of
        # large ones is carrying something the protocol was not meant to carry.
        if icmp_count >= self.cfg.icmp_tunnel_packets:
            mean_icmp = agg["icmp_bytes"] / icmp_count
            if mean_icmp >= self.cfg.icmp_tunnel_mean_size:
                add(
                    "ICMP_TUNNELING_PATTERN", "COMMAND_AND_CONTROL",
                    min(88, 64 + int(mean_icmp // 100)),
                    f"{icmp_count} ICMP packets averaging {mean_icmp:.0f} bytes "
                    f"in {self.cfg.window}s",
                    "T1095", confidence=74,
                    packets=icmp_count,
                    destinations=len(icmp_destinations),
                    evidence={
                        "icmp_packets": icmp_count,
                        "mean_packet_bytes": round(mean_icmp, 1),
                        "size_threshold": self.cfg.icmp_tunnel_mean_size,
                        "note": "payloads are not inspected; packet size is the signal",
                    },
                )

        # --- Endpoint denial of service ----------------------------------------
        # Distinct from a network flood: volume concentrated on one service of
        # one host exhausts that service rather than the link.
        for (dst, port), count in agg["endpoint"].items():
            if count >= self.cfg.service_dos:
                add(
                    "SERVICE_DENIAL_OF_SERVICE", "NETWORK_DENIAL_OF_SERVICE",
                    min(92, 70 + count // 40),
                    f"{count} connections to {dst}:{port} in {self.cfg.window}s",
                    "T1499", confidence=min(96, 72 + count // 40),
                    packets=count, destinations=1, ports=1,
                    evidence={"target": dst, "service_port": port, "connections": count},
                )

        # --- Reflection amplification ------------------------------------------
        # Seen from the reflector side: high-volume traffic sourced from an
        # amplifiable service toward a single victim.
        for (dst, sport), count in agg["amplification"].items():
            if count >= self.cfg.amplification_packets:
                add(
                    "REFLECTION_AMPLIFICATION", "NETWORK_DENIAL_OF_SERVICE",
                    min(93, 72 + count // 50),
                    f"{count} packets from amplifiable service port {sport} "
                    f"toward {dst} in {self.cfg.window}s",
                    "T1498.002", confidence=76,
                    packets=count, destinations=1,
                    evidence={
                        "victim": dst,
                        "reflector_service_port": sport,
                        "packets": count,
                        "note": "the source address of reflected traffic is "
                                "typically spoofed to the victim",
                    },
                )

        # --- Ingress tool transfer ---------------------------------------------
        # Bulk data arriving from outside onto an internal host. The mirror of
        # exfiltration, and the stage that usually precedes it.
        if not agg["source_internal"] and self._private(e.destination):
            for dst, total in agg["internal_bytes"].items():
                if total >= self.cfg.ingress_bytes:
                    add(
                        "INGRESS_TOOL_TRANSFER", "COMMAND_AND_CONTROL",
                        min(88, 64 + int(total / max(1, self.cfg.ingress_bytes)) * 5),
                        f"{total / 1_000_000:.1f} MB delivered from external host "
                        f"to {dst} in {self.cfg.window}s",
                        "T1105", confidence=72,
                        packets=len(bucket), destinations=1,
                        evidence={
                            "internal_destination": dst,
                            "bytes": total,
                            "threshold_bytes": self.cfg.ingress_bytes,
                            "note": "volume and direction only; a software "
                                    "update has the same shape",
                        },
                    )

        # --- Non-standard port communication -----------------------------------
        # Sustained traffic to one external host on a high, unregistered port.
        # Weak alone, which is why its confidence is low and it names the port.
        for (dst, port), count in agg["nonstandard"].items():
            if count >= self.cfg.nonstandard_packets:
                add(
                    "NON_STANDARD_PORT_TRAFFIC", "COMMAND_AND_CONTROL",
                    62, f"{count} packets to {dst} on non-standard port {port} "
                        f"in {self.cfg.window}s",
                    "T1571", confidence=58,
                    packets=count, destinations=1, ports=1,
                    evidence={
                        "destination": dst,
                        "port": port,
                        "packets": count,
                        "note": "a high port is not itself suspicious; this is "
                                "corroboration for other findings, not a "
                                "conclusion on its own",
                    },
                )

        rate = len(bucket) / max(1, self.cfg.window)

        # Adaptive behavioral profile. Unlike the old per-packet EMA, this
        # samples at a fixed cadence and compares several independent host
        # features. The result is deterministic and fully explainable.
        bytes_total = agg["bytes_total"]
        behavior = self.behavior.observe(
            e.source, now,
            BehaviorObservation(
                rate=rate,
                bytes_rate=bytes_total / max(1, self.cfg.window),
                unique_destinations=len(destinations),
                unique_ports=len(ports),
            ),
        )
        if (
            behavior
            and behavior.ready
            and len(bucket) >= self.cfg.baseline_min_events
            and behavior.anomaly_score >= 55
            and (
                max(behavior.deviations.values(), default=0.0) >= self.cfg.baseline_sigma_threshold
            )
        ):
            strongest = max(behavior.deviations.values(), default=0.0)
            add(
                "BEHAVIORAL_TRAFFIC_ANOMALY", "ANOMALOUS_BEHAVIOR",
                behavior.anomaly_score,
                f"host behaviour deviated {strongest:.1f} sigma from its baseline",
                confidence=behavior.confidence,
                packets=len(bucket), destinations=len(destinations), ports=len(ports),
                evidence={
                    "model": "adaptive_ew_baseline",
                    "current": {
                        "rate": round(rate, 3),
                        "bytes_rate": round(bytes_total / max(1, self.cfg.window), 2),
                        "unique_destinations": len(destinations),
                        "unique_ports": len(ports),
                    },
                    "baseline": behavior.baseline,
                    "deviations_sigma": behavior.deviations,
                    "threshold_sigma": self.cfg.baseline_sigma_threshold,
                },
            )

        return out

    def observe_arp(self, ip: str, mac: str, now: float | None = None) -> Alert | None:
        if not self._ip(ip) or not mac:
            return None
        mac = mac.lower().strip()
        old = self.arp.get(ip)
        self.arp[ip] = mac
        self.arp.move_to_end(ip)
        if len(self.arp) > self.cfg.max_sources:
            self.arp.popitem(last=False)
        if old and old != mac:
            return self._emit(
                ip, "ARP_MAPPING_CHANGE", "NETWORK_MANIPULATION", 75,
                f"ARP mapping changed {old} -> {mac}", "T1557.002",
                evidence={"old_mac": old, "new_mac": mac},
                confidence=88, now=now,
            )
        return None

    def _aggregate(self, bucket: deque[dict[str, Any]], source: str) -> dict[str, Any]:
        """Derive every windowed statistic the rules need in one traversal.

        Returning a plain dict rather than a dataclass keeps this cheap: it is
        built once per packet on the capture thread.
        """
        cfg = self.cfg
        source_internal = self._private(source)

        ports: set[int] = set()
        # Ports that could plausibly be a scan target. On a bidirectional
        # interface -- which is what most deployments actually have, whatever
        # the one-way-tap design assumes -- a busy server's replies land on many
        # ephemeral ports of this host. Counting those made every server that
        # answered several client connections look like a vertical scan.
        scan_ports: set[int] = set()
        destinations: set[str] = set()
        tcp_syn: list[dict[str, Any]] = []
        tcp_syn_ports: set[int] = set()
        syn_per_port: dict[int, int] = {}
        udp_ports: set[int] = set()
        udp_count = 0
        icmp_destinations: set[str] = set()
        icmp_count = 0
        icmp_bytes = 0
        service_ports: set[int] = set()
        service_count = 0
        dns_count = 0
        dns_bytes = 0
        dns_destinations: set[str] = set()
        bytes_total = 0

        stealth: dict[str, set[int]] = {"null": set(), "fin": set(), "xmas": set()}
        lateral_targets: set[str] = set()
        admin_hits: dict[int, int] = {}
        auth_attempts: dict[tuple[str, int], int] = {}
        spray: dict[int, dict[str, int]] = {}
        external_bytes: dict[str, int] = {}
        internal_bytes: dict[str, int] = {}
        per_destination: dict[str, int] = {}
        endpoint: dict[tuple[str, int], int] = {}
        amplification: dict[tuple[str, int], int] = {}
        nonstandard: dict[tuple[str, int], int] = {}
        mining: list[dict[str, Any]] = []
        tor: list[dict[str, Any]] = []

        for x in bucket:
            proto = x["proto"]
            port = x["port"]
            dst = x["dst"]
            size = x["size"]
            bytes_total += size

            if port is not None:
                ports.add(port)
            if dst:
                destinations.add(dst)
                per_destination[dst] = per_destination.get(dst, 0) + 1
                if self._private(dst):
                    internal_bytes[dst] = internal_bytes.get(dst, 0) + size
                else:
                    external_bytes[dst] = external_bytes.get(dst, 0) + size

            if proto == "TCP":
                flags = x["flags"]
                initiating = "S" in flags and "A" not in flags
                if initiating:
                    tcp_syn.append(x)
                    if port is not None:
                        tcp_syn_ports.add(port)
                        syn_per_port[port] = syn_per_port.get(port, 0) + 1
                # Established-session return traffic: acknowledged, not
                # initiating, sent from a service port to one of our ephemeral
                # ports. That is a reply, and replies are not probes.
                reply = (
                    not initiating
                    and "A" in flags
                    and port is not None
                    and port >= self.EPHEMERAL_PORT_FLOOR
                    and x.get("sport") is not None
                    and (x["sport"] < 1024 or x["sport"] in self.COMMON_SERVICE_PORTS)
                )
                if port is not None and not reply:
                    scan_ports.add(port)
                if port in self.COMMON_SERVICE_PORTS:
                    service_ports.add(port)
                    # Count connection attempts, not packets. The rule is named
                    # for connections and a single TLS session is dozens of
                    # packets, so counting packets made ordinary browsing trip
                    # a threshold meant to describe a burst of connections.
                    if initiating:
                        service_count += 1
                if port is not None:
                    endpoint[(dst, port)] = endpoint.get((dst, port), 0) + 1
                    # Stealth probes are defined purely by flag combination.
                    kind = _flag_class(flags)
                    if kind is not None:
                        stealth[kind].add(port)
                    if port in self.MINING_PORTS:
                        mining.append(x)
                    elif port >= cfg.nonstandard_min_port and not self._private(dst):
                        nonstandard[(dst, port)] = nonstandard.get((dst, port), 0) + 1
                    if port in self.TOR_PORTS:
                        tor.append(x)
                    if port in self.AUTH_PORTS:
                        auth_attempts[(dst, port)] = auth_attempts.get((dst, port), 0) + 1
                        by_host = spray.setdefault(port, {})
                        by_host[dst] = by_host.get(dst, 0) + 1
                    if (source_internal and port in self.ADMIN_PORTS
                            and self._private(dst)):
                        admin_hits[port] = admin_hits.get(port, 0) + 1
                        if dst != source:
                            lateral_targets.add(dst)
            elif proto == "UDP":
                udp_count += 1
                if port is not None:
                    udp_ports.add(port)
                    scan_ports.add(port)
            elif proto == "ICMP":
                icmp_count += 1
                icmp_bytes += size
                icmp_destinations.add(dst)

            if proto == "DNS":
                dns_count += 1
                dns_bytes += size
                dns_destinations.add(dst)

            sport = x.get("sport")
            if sport in self.AMPLIFIER_PORTS and proto in {"UDP", "DNS"}:
                amplification[(dst, sport)] = amplification.get((dst, sport), 0) + 1

        return {
            "source_internal": source_internal,
            "ports": ports, "scan_ports": scan_ports, "destinations": destinations,
            "tcp_syn": tcp_syn, "tcp_syn_ports": tcp_syn_ports,
            "syn_per_port": syn_per_port,
            "udp_ports": udp_ports, "udp_count": udp_count,
            "icmp_destinations": icmp_destinations,
            "icmp_count": icmp_count, "icmp_bytes": icmp_bytes,
            "service_ports": service_ports, "service_count": service_count,
            "dns_count": dns_count, "dns_bytes": dns_bytes,
            "dns_destinations": dns_destinations,
            "bytes_total": bytes_total,
            "stealth": stealth,
            "lateral_targets": lateral_targets, "admin_hits": admin_hits,
            "auth_attempts": auth_attempts, "spray": spray,
            "external_bytes": external_bytes, "internal_bytes": internal_bytes,
            "per_destination": per_destination,
            "endpoint": endpoint, "amplification": amplification,
            "nonstandard": nonstandard, "mining": mining, "tor": tor,
        }

    def _record_contact(self, event: dict[str, Any], source: str,
                        now: float) -> dict[str, Any] | None:
        """Track contact times for one (source, destination, port) pair.

        Returns beacon evidence when the intervals between contacts are regular
        enough to look like a scheduled callback rather than human-driven or
        bursty traffic.

        Periodicity is measured with the coefficient of variation of the
        intervals -- standard deviation over mean. That ratio is scale-free, so
        a 5-second beacon and a 5-minute beacon are judged by the same
        criterion, which a fixed jitter tolerance in seconds could not do.
        """
        port = event["port"]
        if port in self.BENIGN_PERIODIC_PORTS:
            return None
        key = (source, event["dst"], port)
        history = self.contacts.get(key)
        if history is None:
            if len(self.contacts) >= self.cfg.max_sources * 4:
                self.contacts.popitem(last=False)
            history = deque(maxlen=self.cfg.beacon_min_intervals + 8)
            self.contacts[key] = history
        else:
            self.contacts.move_to_end(key)
        if history and now - history[-1] < self.cfg.beacon_min_period:
            # Packets belonging to the same contact, not a new one. Without
            # this every packet of a single transfer would look like a
            # perfectly regular beacon at line rate.
            return None
        history.append(now)
        while history and now - history[0] > self.cfg.beacon_horizon:
            history.popleft()
        if len(history) < self.cfg.beacon_min_intervals + 1:
            return None
        intervals = [b - a for a, b in pairwise(history)]
        mean = sum(intervals) / len(intervals)
        if mean < self.cfg.beacon_min_period:
            return None
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        jitter = (variance ** 0.5) / mean
        if jitter > self.cfg.beacon_max_jitter:
            return None
        return {
            "destination": event["dst"],
            "port": port,
            "contacts": len(history),
            "mean_interval_seconds": round(mean, 2),
            "jitter_ratio": round(jitter, 4),
            "jitter_threshold": self.cfg.beacon_max_jitter,
            "intervals_seconds": [round(x, 2) for x in intervals][-12:],
        }

    def _bucket(self, source: str) -> deque[dict[str, Any]]:
        bucket = self.events.get(source)
        if bucket is None:
            if len(self.events) >= self.cfg.max_sources:
                self.events.popitem(last=False)
            bucket = deque(maxlen=self.cfg.max_events)
            self.events[source] = bucket
        else:
            self.events.move_to_end(source)
        return bucket

    def _emit(self, source: str, threat: str, category: str, score: int,
              reason: str, technique: str = "", confidence: int | None = None,
              now: float | None = None, **kw: Any) -> Alert | None:
        key = (source, threat)
        now = time.monotonic() if now is None else now
        previous = self.last.get(key)
        if previous is not None and now - previous < self.cfg.cooldown:
            self.last.move_to_end(key)
            return None
        if key in self.last:
            self.last.move_to_end(key)
        else:
            # A source can be attacker-controlled. Bound cooldown state too,
            # otherwise many spoofed source addresses can grow this map without
            # bound even though the event/profile state is bounded.
            max_entries = max(16, self.cfg.max_sources * 16)
            if len(self.last) >= max_entries:
                self.last.popitem(last=False)
        self.last[key] = now
        score = max(0, min(100, int(score)))
        severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 75 else "MEDIUM" if score >= 50 else "LOW"
        if confidence is None:
            confidence = min(99, max(self.cfg.min_confidence, score + 5))
        confidence = max(0, min(100, int(confidence)))
        if confidence < self.cfg.min_confidence:
            return None
        incident_id = self._incident_for(source, now)
        return Alert(
            utc_now(), threat, category, source, severity, score, confidence, reason,
            window_seconds=self.cfg.window, technique=technique,
            incident_id=incident_id, **kw,
        )

    def _incident_for(self, source: str, now: float) -> str:
        current = self.incidents.get(source)
        if current and now - current[1] <= self.cfg.correlation_window:
            incident_id = current[0]
            self.incidents[source] = (incident_id, now)
            self.incidents.move_to_end(source)
            return incident_id
        incident_id = f"NEMOS-{uuid.uuid4().hex[:12].upper()}"
        if len(self.incidents) >= self.cfg.max_sources:
            self.incidents.popitem(last=False)
        self.incidents[source] = (incident_id, now)
        return incident_id

    def _private(self, value: str) -> bool:
        """Membership test with a bounded memo.

        Called for nearly every record in the window, and each miss walks the
        configured network list. Destinations repeat heavily, so memoising is
        the difference between one comparison and eight per packet. The cache is
        keyed by an attacker-influenced value, so it is bounded like every other
        map here.
        """
        cached = self._private_cache.get(value)
        if cached is not None:
            self._private_cache.move_to_end(value)
            return cached
        result = self._classify(value)
        if len(self._private_cache) >= 8192:
            self._private_cache.popitem(last=False)
        self._private_cache[value] = result
        return result

    def _classify(self, value: str) -> bool:
        """True when an address belongs to this deployment's internal ranges.

        Deliberately does not use ``ipaddress.is_private`` or ``is_global``.
        Both classify the RFC 5737 documentation ranges (192.0.2.0/24,
        198.51.100.0/24, 203.0.113.0/24) as non-global, and those are exactly
        the addresses NEMOS's synthetic traffic uses to stand in for the public
        internet. Relying on the stdlib predicate made every synthetic external
        host look internal, which silently disabled exfiltration detection and
        reported an external scanner as lateral movement -- and it did so only
        in the traffic used to demonstrate the sensor, where it was least
        likely to be noticed.

        An unparseable address counts as external, so a malformed value cannot
        suppress an exfiltration finding.
        """
        try:
            address = ipaddress.ip_address(value)
        except (TypeError, ValueError):
            return False
        return any(address in network for network in self.internal_networks)

    @staticmethod
    @lru_cache(maxsize=8192)
    def _ip(value: str) -> bool:
        """Validity check, memoised.

        Called for both endpoints of every packet, and ipaddress parsing was
        17% of detector runtime under profiling. Addresses repeat heavily, so
        the cache hit rate is high; it is bounded so a spoofing flood cannot
        grow it without limit.
        """
        try:
            ipaddress.ip_address(value)
            return True
        except (TypeError, ValueError):
            return False
