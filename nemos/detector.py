from __future__ import annotations

import ipaddress
import os
import time
import uuid
from math import isfinite
from collections import OrderedDict, deque
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
            baseline_alpha=real("NEMOS_BEHAVIOR_ALPHA", defaults.baseline_alpha, 0.01, 1.0),
            baseline_min_samples=integer("NEMOS_BEHAVIOR_MIN_SAMPLES", defaults.baseline_min_samples, 2, 1000),
            baseline_sigma_threshold=real("NEMOS_BEHAVIOR_SIGMA", defaults.baseline_sigma_threshold, 1.0, 10.0),
            baseline_sample_interval=real("NEMOS_BEHAVIOR_SAMPLE_SECONDS", defaults.baseline_sample_interval, 0.0, 300.0),
            baseline_extreme_sigma=real("NEMOS_BEHAVIOR_EXTREME_SIGMA", defaults.baseline_extreme_sigma, 3.0, 15.0),
        )


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
            "proto": e.protocol.upper(),
            "flags": e.flags,
            "type": ptype.upper(),
            "size": max(0, int(e.packet_size or 0)),
        })
        cutoff = now - self.cfg.window
        while bucket and bucket[0]["t"] < cutoff:
            bucket.popleft()

        ports = {x["port"] for x in bucket if x["port"] is not None}
        destinations = {x["dst"] for x in bucket if x["dst"]}
        tcp_syn = [
            x for x in bucket
            if x["proto"] == "TCP" and "S" in x["flags"] and "A" not in x["flags"]
        ]
        tcp_syn_ports = {x["port"] for x in tcp_syn if x["port"] is not None}
        udp_ports = {x["port"] for x in bucket if x["proto"] == "UDP" and x["port"] is not None}
        icmp_destinations = {x["dst"] for x in bucket if x["proto"] == "ICMP"}
        service_ports = {
            x["port"] for x in bucket
            if x["proto"] == "TCP" and x["port"] in self.COMMON_SERVICE_PORTS
        }
        service_count = sum(
            1 for x in bucket
            if x["proto"] == "TCP" and x["port"] in self.COMMON_SERVICE_PORTS
        )
        dns_count = sum(1 for x in bucket if x["proto"] == "DNS")
        icmp_count = sum(1 for x in bucket if x["proto"] == "ICMP")
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
        if len(ports) >= self.cfg.port_scan:
            syn_ratio = len(tcp_syn) / max(1, len(bucket))
            scan_score = min(96, 50 + len(ports) * 3 + (15 if syn_ratio >= 0.5 else 0))
            scan_conf = min(99, 58 + len(ports) * 3 + (18 if syn_ratio >= 0.5 else 0))
            add(
                "PORT_SCAN", "NETWORK_RECONNAISSANCE", scan_score,
                f"{len(ports)} unique destination ports in {self.cfg.window}s",
                "T1046", confidence=scan_conf,
                ports_scanned=len(ports), packets=len(bucket),
                destinations=len(destinations), ports=len(ports),
                evidence={
                    "scan_type": "vertical",
                    "ports": sorted(ports)[:100],
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
                packets=sum(1 for x in bucket if x["proto"] == "UDP"),
                ports=len(udp_ports), destinations=len(destinations),
                evidence={"scan_type": "udp", "ports": sorted(udp_ports)[:100]},
            )

        if len(destinations) >= self.cfg.fanout:
            add(
                "NETWORK_FANOUT", "NETWORK_DISCOVERY", 70,
                f"{len(destinations)} unique destinations in {self.cfg.window}s",
                "T1046", confidence=min(95, 60 + len(destinations)),
                packets=len(bucket), destinations=len(destinations), ports=len(ports),
                evidence={"unique_destinations": len(destinations)},
            )

        if len(icmp_destinations) >= self.cfg.icmp_sweep:
            add(
                "ICMP_SWEEP", "NETWORK_RECONNAISSANCE",
                min(88, 56 + len(icmp_destinations) * 2),
                f"ICMP traffic targeted {len(icmp_destinations)} destinations in {self.cfg.window}s",
                "T1046", confidence=min(95, 62 + len(icmp_destinations) * 2),
                packets=icmp_count, destinations=len(icmp_destinations),
                evidence={"scan_type": "icmp_sweep", "destinations": sorted(icmp_destinations)[:100]},
            )

        if len(tcp_syn) >= self.cfg.syn_flood:
            add(
                "SYN_FLOOD_PATTERN", "NETWORK_DENIAL_OF_SERVICE", 90,
                f"{len(tcp_syn)} SYN packets in {self.cfg.window}s",
                "T1498.001", confidence=min(99, 75 + min(24, len(tcp_syn) // 10)),
                packets=len(tcp_syn), destinations=len(destinations), ports=len(ports),
                evidence={"syn_ratio": round(len(tcp_syn) / max(1, len(bucket)), 3)},
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
            dns_destinations = {x["dst"] for x in bucket if x["proto"] == "DNS"}
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
        stealth: dict[str, set[int]] = {"null": set(), "fin": set(), "xmas": set()}
        for x in bucket:
            if x["proto"] != "TCP" or x["port"] is None:
                continue
            flags = set(x["flags"]) - {"E", "C", "N"}
            if not flags:
                stealth["null"].add(x["port"])
            elif flags == {"F"}:
                stealth["fin"].add(x["port"])
            elif {"F", "P", "U"} <= flags and "S" not in flags and "A" not in flags:
                stealth["xmas"].add(x["port"])
        for kind, scanned in stealth.items():
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
        if self._private(e.source):
            lateral_targets = {
                x["dst"] for x in bucket
                if x["proto"] == "TCP" and x["port"] in self.ADMIN_PORTS
                and self._private(x["dst"]) and x["dst"] != e.source
            }
            if len(lateral_targets) >= self.cfg.lateral_hosts:
                lateral_ports = sorted({
                    x["port"] for x in bucket
                    if x["port"] in self.ADMIN_PORTS and self._private(x["dst"])
                })
                add(
                    "LATERAL_MOVEMENT", "LATERAL_MOVEMENT",
                    min(93, 62 + len(lateral_targets) * 4),
                    f"internal host contacted {len(lateral_targets)} internal hosts "
                    f"on remote-administration ports in {self.cfg.window}s",
                    "T1021", confidence=min(96, 66 + len(lateral_targets) * 4),
                    packets=len(bucket), destinations=len(lateral_targets),
                    ports=len(lateral_ports),
                    evidence={
                        "internal_targets": sorted(lateral_targets)[:50],
                        "admin_ports": lateral_ports,
                    },
                )

        # --- Credential brute force -----------------------------------------
        # Many attempts against one authentication service on one host. Keyed
        # per (destination, port) so spraying one credential across many hosts
        # does not average away into a below-threshold count.
        attempts: dict[tuple[str, int], int] = {}
        for x in bucket:
            if x["proto"] == "TCP" and x["port"] in self.AUTH_PORTS:
                pair = (x["dst"], x["port"])
                attempts[pair] = attempts.get(pair, 0) + 1
        for (dst, port), count in attempts.items():
            if count >= self.cfg.brute_force:
                add(
                    "CREDENTIAL_BRUTE_FORCE", "CREDENTIAL_ACCESS",
                    min(91, 60 + count // 2),
                    f"{count} connection attempts to {dst}:{port} in {self.cfg.window}s",
                    "T1110", confidence=min(95, 64 + count // 2),
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
        volumes: dict[str, int] = {}
        for x in bucket:
            if x["dst"] and not self._private(x["dst"]):
                volumes[x["dst"]] = volumes.get(x["dst"], 0) + x["size"]
        for dst, total in volumes.items():
            if total >= self.cfg.exfil_bytes:
                add(
                    "DATA_EXFILTRATION_VOLUME", "EXFILTRATION",
                    min(90, 62 + int(total / max(1, self.cfg.exfil_bytes)) * 5),
                    f"{total / 1_000_000:.1f} MB sent to external host {dst} "
                    f"in {self.cfg.window}s",
                    "T1048", confidence=78,
                    packets=sum(1 for x in bucket if x["dst"] == dst),
                    destinations=1,
                    evidence={
                        "destination": dst,
                        "bytes": total,
                        "threshold_bytes": self.cfg.exfil_bytes,
                        "note": "volume only; a legitimate backup or upload "
                                "has the same shape",
                    },
                )

        # --- DNS tunneling ----------------------------------------------------
        # Ordinary DNS packets are small. A sustained stream of large ones
        # carries something other than routine name resolution. This is
        # separate from DNS_BURST, which counts volume alone.
        dns_packets = [x for x in bucket if x["proto"] == "DNS"]
        if len(dns_packets) >= self.cfg.dns_tunnel_packets:
            mean_dns = sum(x["size"] for x in dns_packets) / len(dns_packets)
            if mean_dns >= self.cfg.dns_tunnel_mean_size:
                add(
                    "DNS_TUNNELING_PATTERN", "COMMAND_AND_CONTROL",
                    min(88, 64 + int(mean_dns // 50)),
                    f"{len(dns_packets)} DNS packets averaging {mean_dns:.0f} bytes "
                    f"in {self.cfg.window}s",
                    "T1071.004", confidence=76,
                    packets=len(dns_packets),
                    destinations=len({x["dst"] for x in dns_packets}),
                    evidence={
                        "dns_packets": len(dns_packets),
                        "mean_packet_bytes": round(mean_dns, 1),
                        "size_threshold": self.cfg.dns_tunnel_mean_size,
                        "note": "payloads are not inspected; size is the signal",
                    },
                )

        # --- Known-suspicious destination ports -------------------------------
        # Port-based identification is a heuristic and says so in the evidence.
        for label, portset, threat, technique, category, score in (
            ("mining pool", self.MINING_PORTS, "CRYPTO_MINING_PATTERN",
             "T1496", "RESOURCE_HIJACKING", 72),
            ("Tor", self.TOR_PORTS, "TOR_CONNECTION_PATTERN",
             "T1090.003", "COMMAND_AND_CONTROL", 68),
        ):
            threshold = (self.cfg.mining_packets if "MINING" in threat
                         else self.cfg.tor_packets)
            hits = [x for x in bucket if x["proto"] == "TCP" and x["port"] in portset]
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

        rate = len(bucket) / max(1, self.cfg.window)

        # Adaptive behavioral profile. Unlike the old per-packet EMA, this
        # samples at a fixed cadence and compares several independent host
        # features. The result is deterministic and fully explainable.
        bytes_total = sum(x["size"] for x in bucket)
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
    def _ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except (TypeError, ValueError):
            return False
