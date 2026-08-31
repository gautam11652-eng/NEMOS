"""Unidirectional IP flow aggregation.

NEMOS observes packets, but detection reasons about *flows*. This module turns
a stream of ``TrafficEvent`` objects into aggregated flow records.

**Flows here are strictly unidirectional.** The flow key is

    (source, destination, source_port, destination_port, protocol)

used exactly as observed, with no canonicalisation or address ordering. Traffic
from A to B and traffic from B to A produce two independent records that are
never merged. This is deliberate:

* A unidirectional sensor may only ever see one side of a conversation. A
  representation that assumes both directions are available would silently
  misreport in exactly that deployment.
* Direction carries the signal. One host opening connections to two hundred
  destinations is reconnaissance; two hundred hosts answering it is not. Merging
  the two directions destroys the asymmetry the detector depends on.

Where reverse traffic matters, correlate the two directional records rather than
collapsing them -- :func:`FlowTable.reverse_of` exists for that and returns the
opposite record without modifying either.

The table is bounded. A flow key contains attacker-controlled addresses and
ports, so an unbounded table would be a denial-of-service vector; eviction is by
least-recent activity.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from math import sqrt
from typing import Any
from collections.abc import Iterable, Iterator

from .models import TrafficEvent

# Sensible ceilings. A flow key is attacker-influenceable, so both the table and
# any per-flow accumulation must be bounded.
DEFAULT_MAX_FLOWS = 20_000
DEFAULT_IDLE_TIMEOUT = 30.0
DEFAULT_MAX_DURATION = 300.0

TCP_FLAG_NAMES = ("S", "A", "F", "R", "P", "U")


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Directional five-tuple. Never normalised -- see the module docstring."""

    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    protocol: str

    def reversed(self) -> FlowKey:
        """The key for traffic in the opposite direction.

        Used for correlation only. It never merges records; the two directions
        remain separate rows.
        """
        return FlowKey(
            source=self.destination,
            destination=self.source,
            source_port=self.destination_port,
            destination_port=self.source_port,
            protocol=self.protocol,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "destination": self.destination,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
        }


@dataclass(slots=True)
class Flow:
    """One unidirectional flow, aggregated incrementally.

    Packet sizes are summarised with running count/sum/sum-of-squares rather
    than a retained list, so memory per flow is constant regardless of how many
    packets it carries.
    """

    key: FlowKey
    first_seen: float
    last_seen: float
    first_timestamp: str = ""
    last_timestamp: str = ""
    packets: int = 0
    bytes: int = 0
    size_min: int = 0
    size_max: int = 0
    _size_sum_squares: float = 0.0
    flags: dict[str, int] = field(default_factory=lambda: dict.fromkeys(TCP_FLAG_NAMES, 0))
    interface: str = ""

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def mean_packet_size(self) -> float:
        return (self.bytes / self.packets) if self.packets else 0.0

    @property
    def stddev_packet_size(self) -> float:
        """Population standard deviation of packet size within this flow."""
        if self.packets < 2:
            return 0.0
        mean = self.mean_packet_size
        variance = (self._size_sum_squares / self.packets) - (mean * mean)
        # Floating-point cancellation can push a mathematically non-negative
        # variance just below zero.
        return sqrt(variance) if variance > 0.0 else 0.0

    @property
    def packets_per_second(self) -> float:
        duration = self.duration
        return self.packets / duration if duration > 0 else float(self.packets)

    @property
    def bytes_per_second(self) -> float:
        duration = self.duration
        return self.bytes / duration if duration > 0 else float(self.bytes)

    def observe(self, event: TrafficEvent, now: float) -> None:
        size = max(0, int(event.packet_size or 0))
        if self.packets == 0:
            self.size_min = size
            self.size_max = size
            self.first_timestamp = event.timestamp
        else:
            self.size_min = min(self.size_min, size)
            self.size_max = max(self.size_max, size)
        self.packets += 1
        self.bytes += size
        self._size_sum_squares += float(size) * float(size)
        self.last_seen = now
        self.last_timestamp = event.timestamp
        if event.interface and not self.interface:
            self.interface = event.interface
        for flag in str(event.flags or ""):
            if flag in self.flags:
                self.flags[flag] += 1

    def as_dict(self) -> dict[str, Any]:
        data = self.key.as_dict()
        data.update({
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "duration": round(self.duration, 6),
            "packets": self.packets,
            "bytes": self.bytes,
            "packets_per_second": round(self.packets_per_second, 4),
            "bytes_per_second": round(self.bytes_per_second, 4),
            "mean_packet_size": round(self.mean_packet_size, 2),
            "stddev_packet_size": round(self.stddev_packet_size, 2),
            "size_min": self.size_min,
            "size_max": self.size_max,
            "syn": self.flags.get("S", 0),
            "ack": self.flags.get("A", 0),
            "fin": self.flags.get("F", 0),
            "rst": self.flags.get("R", 0),
            "psh": self.flags.get("P", 0),
            "urg": self.flags.get("U", 0),
            "interface": self.interface,
        })
        return data


class FlowTable:
    """Bounded table of active unidirectional flows.

    Not thread-safe by itself. The capture thread calls :meth:`observe` and the
    analysis thread calls :meth:`expire`, so the owner (``analysis.py``) holds a
    lock around both. Keeping the lock outside this class avoids acquiring it
    twice per packet.
    """

    def __init__(self, *, max_flows: int = DEFAULT_MAX_FLOWS,
                 idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
                 max_duration: float = DEFAULT_MAX_DURATION):
        self.max_flows = max(1, int(max_flows))
        self.idle_timeout = max(0.1, float(idle_timeout))
        self.max_duration = max(1.0, float(max_duration))
        # OrderedDict, not dict: eviction is least-recently-observed, and a
        # linear scan for the oldest entry would make eviction O(n) per packet
        # exactly when the table is full -- turning the bound that exists to
        # survive a spoofing flood into the bottleneck it was meant to prevent.
        self._flows: OrderedDict[FlowKey, Flow] = OrderedDict()
        self.evicted = 0
        self.observed_packets = 0

    def __len__(self) -> int:
        return len(self._flows)

    def __iter__(self) -> Iterator[Flow]:
        return iter(self._flows.values())

    @staticmethod
    def key_for(event: TrafficEvent) -> FlowKey:
        """Build the directional key. Note the absence of any ordering step."""
        return FlowKey(
            source=event.source,
            destination=event.destination,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=(event.protocol or "OTHER").upper(),
        )

    def observe(self, event: TrafficEvent, now: float | None = None) -> Flow:
        """Record one packet against its directional flow."""
        now = time.monotonic() if now is None else now
        key = self.key_for(event)
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= self.max_flows:
                self._evict_oldest()
            flow = Flow(key=key, first_seen=now, last_seen=now)
            self._flows[key] = flow
        else:
            # Refresh recency so eviction targets genuinely idle flows.
            self._flows.move_to_end(key)
        flow.observe(event, now)
        self.observed_packets += 1
        return flow

    def reverse_of(self, key: FlowKey) -> Flow | None:
        """Return the opposite-direction flow if it is also being observed.

        For correlation only. The two records stay independent.
        """
        return self._flows.get(key.reversed())

    def _evict_oldest(self) -> None:
        """Drop the least recently observed flow. O(1)."""
        if self._flows:
            self._flows.popitem(last=False)
            self.evicted += 1

    def expire(self, now: float | None = None, *, force: bool = False) -> list[Flow]:
        """Remove and return flows that are idle, over-long, or all of them.

        ``force`` drains the table, which is what shutdown needs so in-flight
        flows are still accounted for.
        """
        now = time.monotonic() if now is None else now
        if force:
            expired = list(self._flows.values())
            self._flows.clear()
            return expired
        expired = [
            flow for flow in self._flows.values()
            if (now - flow.last_seen) >= self.idle_timeout
            or (now - flow.first_seen) >= self.max_duration
        ]
        for flow in expired:
            self._flows.pop(flow.key, None)
        return expired

    def snapshot(self) -> list[Flow]:
        """Currently active flows, without removing them."""
        return list(self._flows.values())

    def metrics(self) -> dict[str, int]:
        return {
            "active_flows": len(self._flows),
            "max_flows": self.max_flows,
            "evicted": self.evicted,
            "observed_packets": self.observed_packets,
        }


def group_by_source(flows: Iterable[Flow]) -> dict[str, list[Flow]]:
    """Group flows by their originating host.

    Grouping is by ``key.source`` -- the sending side -- which is the entity a
    per-source baseline and the ML model reason about.
    """
    grouped: dict[str, list[Flow]] = {}
    for flow in flows:
        grouped.setdefault(flow.key.source, []).append(flow)
    return grouped


__all__ = [
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_MAX_DURATION",
    "DEFAULT_MAX_FLOWS",
    "Flow",
    "FlowKey",
    "FlowTable",
    "TCP_FLAG_NAMES",
    "group_by_source",
]
