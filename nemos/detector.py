from __future__ import annotations

import ipaddress
import os
import time
import uuid
from math import isfinite
from collections import OrderedDict, deque
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

    @staticmethod
    def _ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except (TypeError, ValueError):
            return False
