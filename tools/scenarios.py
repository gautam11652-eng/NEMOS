"""Synthetic traffic scenarios for training, testing and demonstration.

Everything here is generated in memory. No packet is transmitted, no host is
contacted and no interface is touched. All addresses come from the RFC 5737
documentation ranges (``192.0.2.0/24``, ``198.51.100.0/24``, ``203.0.113.0/24``),
which are reserved for documentation and are not routable on the public
internet, so a mistake here cannot reach a real system.

The generators are seeded, so a demonstration produces the same traffic every
time and a result can be reproduced.

These scenarios describe *traffic shapes*, not exploits. Nothing here is an
attack tool: a port scan here is a list of synthetic metadata records that never
leave the process.
"""

from __future__ import annotations

import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__ in (None, ""):  # allow direct execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nemos.models import TrafficEvent

# RFC 5737 documentation ranges.
INTERNAL = "192.0.2"
SERVERS = "198.51.100"
EXTERNAL = "203.0.113"

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@dataclass
class Scenario:
    """One named traffic pattern and what NEMOS is expected to make of it."""

    name: str
    description: str
    expectation: str
    events: list[tuple[float, TrafficEvent]] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max((t for t, _ in self.events), default=0.0)

    def __len__(self) -> int:
        return len(self.events)


def _ts(offset: float) -> str:
    return (BASE_TIME + timedelta(seconds=offset)).isoformat(timespec="seconds")


def _event(offset: float, source: str, destination: str, protocol: str,
           sport: int | None, dport: int | None, size: int, flags: str = "") -> tuple[float, TrafficEvent]:
    return offset, TrafficEvent(
        _ts(offset), source, destination, protocol, sport, dport, size, flags, "synthetic",
    )


def normal_traffic(seed: int = 1, hosts: int = 6, seconds: float = 60.0) -> Scenario:
    """Ordinary workstation behaviour: a few servers, common ports, mixed sizes."""
    rng = random.Random(seed)
    events: list[tuple[float, TrafficEvent]] = []
    for host_index in range(hosts):
        source = f"{INTERNAL}.{10 + host_index}"
        t = rng.uniform(0, 2)
        while t < seconds:
            destination = f"{SERVERS}.{rng.choice([10, 11, 12, 20])}"
            dport = rng.choice([443, 443, 443, 80, 22, 53])
            if dport == 53:
                events.append(_event(t, source, f"{SERVERS}.53", "DNS",
                                     rng.randint(30000, 60000), 53, rng.randint(70, 300)))
            else:
                sport = rng.randint(30000, 60000)
                events.append(_event(t, source, destination, "TCP", sport, dport,
                                     rng.randint(200, 1400), rng.choice(["PA", "A", "PA"])))
            t += rng.uniform(0.05, 0.6)
    events.sort(key=lambda item: item[0])
    return Scenario(
        "normal_traffic",
        "Six workstations using a small set of internal servers on common ports.",
        "No detection. This is the baseline the model is trained on.",
        events,
    )


def connection_burst(seed: int = 2) -> Scenario:
    """A sharp rise in connection rate to one service."""
    rng = random.Random(seed)
    source = f"{INTERNAL}.66"
    events = [
        _event(rng.uniform(0, 10), source, f"{SERVERS}.10", "TCP",
               rng.randint(30000, 60000), 443, rng.randint(60, 120), "S")
        for _ in range(400)
    ]
    events.sort(key=lambda item: item[0])
    return Scenario(
        "connection_burst",
        "400 connection attempts to a single service in ten seconds.",
        "Elevated packet rate and SYN ratio against the host baseline.",
        events,
    )


def destination_fanout(seed: int = 3) -> Scenario:
    """One host contacting many hosts on the same port -- a horizontal sweep."""
    rng = random.Random(seed)
    source = f"{INTERNAL}.77"
    events = [
        _event(rng.uniform(0, 10), source, f"{SERVERS}.{i}", "TCP",
               44444, 445, 60, "S")
        for i in range(1, 200)
    ]
    events.sort(key=lambda item: item[0])
    return Scenario(
        "destination_fanout",
        "One host probing 199 destinations on port 445.",
        "NETWORK_FANOUT; high destination entropy, low port entropy.",
        events,
    )


def port_sweep(seed: int = 4) -> Scenario:
    """One host, many ports -- a vertical scan."""
    rng = random.Random(seed)
    source = f"{INTERNAL}.88"
    events = [
        _event(rng.uniform(0, 10), source, f"{SERVERS}.50", "TCP", 44444, port, 60, "S")
        for port in range(1, 260)
    ]
    events.sort(key=lambda item: item[0])
    return Scenario(
        "port_sweep",
        "259 distinct destination ports on a single host.",
        "PORT_SCAN / TCP_SYN_SCAN; high port entropy, SYN ratio near 1.0.",
        events,
    )


def abnormal_tcp(seed: int = 5) -> Scenario:
    """SYN without completion, plus resets -- connections that never establish."""
    rng = random.Random(seed)
    source = f"{EXTERNAL}.99"
    events = []
    for i in range(500):
        t = rng.uniform(0, 10)
        events.append(_event(t, source, f"{SERVERS}.10", "TCP",
                             rng.randint(1024, 65535), 80, 60, "S"))
        if i % 4 == 0:
            events.append(_event(t + 0.01, source, f"{SERVERS}.10", "TCP",
                                 rng.randint(1024, 65535), 80, 60, "R"))
    events.sort(key=lambda item: item[0])
    return Scenario(
        "abnormal_tcp",
        "A SYN flood pattern with resets and no established sessions.",
        "SYN_FLOOD_PATTERN; SYN ratio high, ACK ratio near zero.",
        events,
    )


def unusual_udp(seed: int = 6) -> Scenario:
    """UDP across many ports -- a UDP service sweep."""
    rng = random.Random(seed)
    source = f"{INTERNAL}.55"
    events = [
        _event(rng.uniform(0, 10), source, f"{SERVERS}.60", "UDP", 40000, port, 80)
        for port in range(1, 120)
    ]
    events.sort(key=lambda item: item[0])
    return Scenario(
        "unusual_udp",
        "119 distinct UDP destination ports on one host.",
        "UDP_PORT_SCAN; udp_ratio 1.0 with high port entropy.",
        events,
    )


def dns_deviation(seed: int = 7) -> Scenario:
    """A large volume of DNS queries from one host."""
    rng = random.Random(seed)
    source = f"{INTERNAL}.44"
    events = [
        _event(rng.uniform(0, 10), source, f"{SERVERS}.53", "DNS",
               rng.randint(30000, 60000), 53, rng.randint(60, 200))
        for _ in range(300)
    ]
    events.sort(key=lambda item: item[0])
    return Scenario(
        "dns_deviation",
        "300 DNS queries from a single host in ten seconds.",
        "DNS_BURST; dns_ratio 1.0 well above the host baseline.",
        events,
    )


def rate_deviation(seed: int = 8) -> Scenario:
    """A host that behaves normally, then abruptly transfers at high volume."""
    rng = random.Random(seed)
    source = f"{INTERNAL}.33"
    events = []
    t = 0.0
    while t < 40.0:  # settled, ordinary behaviour first
        events.append(_event(t, source, f"{SERVERS}.11", "TCP",
                             rng.randint(30000, 60000), 443, rng.randint(200, 900), "PA"))
        t += rng.uniform(0.4, 1.0)
    t = 40.0
    while t < 55.0:  # then a sustained high-volume transfer
        events.append(_event(t, source, f"{EXTERNAL}.200", "TCP",
                             rng.randint(30000, 60000), 443, rng.randint(1200, 1500), "PA"))
        t += rng.uniform(0.005, 0.02)
    events.sort(key=lambda item: item[0])
    return Scenario(
        "rate_deviation",
        "A host with a settled profile that abruptly transfers at high volume.",
        "Behavioural deviation once the baseline has warmed up.",
        events,
    )


def icmp_sweep(seed: int = 9) -> Scenario:
    """ICMP to many destinations -- host discovery."""
    rng = random.Random(seed)
    source = f"{INTERNAL}.22"
    events = [
        _event(rng.uniform(0, 10), source, f"{SERVERS}.{i}", "ICMP", None, None, 84)
        for i in range(1, 120)
    ]
    events.sort(key=lambda item: item[0])
    return Scenario(
        "icmp_sweep",
        "ICMP echo to 119 destinations.",
        "ICMP_SWEEP; icmp_ratio 1.0 with high destination entropy.",
        events,
    )


#: Scenario A is the baseline; B-I are the abnormal shapes from the detection
#: requirements. Order is stable so demo output is comparable across runs.
SCENARIOS = {
    "normal": normal_traffic,
    "connection_burst": connection_burst,
    "destination_fanout": destination_fanout,
    "port_sweep": port_sweep,
    "abnormal_tcp": abnormal_tcp,
    "unusual_udp": unusual_udp,
    "dns_deviation": dns_deviation,
    "rate_deviation": rate_deviation,
    "icmp_sweep": icmp_sweep,
}

ATTACK_SCENARIOS = tuple(name for name in SCENARIOS if name != "normal")


def build(name: str, **kwargs) -> Scenario:
    """Build one scenario by name."""
    try:
        generator = SCENARIOS[name]
    except KeyError as exc:
        raise KeyError(f"unknown scenario '{name}'; known: {', '.join(SCENARIOS)}") from exc
    return generator(**kwargs)


def training_corpus(windows: int = 240, window_seconds: float = 10.0,
                    seed: int = 100) -> list[Scenario]:
    """A corpus of normal-traffic scenarios for training.

    Each scenario is one window's worth of ordinary activity, varied by seed so
    the model sees a realistic spread rather than one repeated pattern.
    """
    return [
        normal_traffic(seed=seed + i, hosts=3, seconds=window_seconds)
        for i in range(windows)
    ]


__all__ = [
    "ATTACK_SCENARIOS",
    "BASE_TIME",
    "EXTERNAL",
    "INTERNAL",
    "SCENARIOS",
    "SERVERS",
    "Scenario",
    "build",
    "training_corpus",
]
