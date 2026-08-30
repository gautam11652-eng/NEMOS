"""Per-source feature extraction over a window of unidirectional flows.

This module is deliberately free of any machine-learning dependency. It turns a
window of flows into a fixed-length numeric vector and nothing else, so it can
be unit-tested on its own and reused by the statistical baseline, the ML model
and the API without any of them depending on each other.

Every feature here is derivable from what ``capture.py`` actually observes:
addresses, ports, protocol, packet size and TCP flags. Nothing is inferred from
payload, and nothing is invented. If a value cannot be computed from the
observed window it is zero, not a guess.

``FEATURE_NAMES`` is ordered and versioned. A trained model records the schema
version it was fitted against and refuses to score a vector built by a different
one -- silently scoring a reordered vector would produce confident nonsense.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import log2, sqrt
from typing import Any
from collections.abc import Iterable, Mapping, Sequence

from .flows import Flow

# Increment when FEATURE_NAMES changes in any way: order, membership or meaning.
FEATURE_SCHEMA_VERSION = 1

FEATURE_NAMES: tuple[str, ...] = (
    "packets",
    "bytes",
    "packets_per_second",
    "bytes_per_second",
    "flow_count",
    "unique_destinations",
    "unique_destination_ports",
    "unique_source_ports",
    "destination_entropy",
    "destination_port_entropy",
    "mean_packet_size",
    "stddev_packet_size",
    "mean_flow_duration",
    "mean_packets_per_flow",
    "mean_bytes_per_flow",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "dns_ratio",
    "small_packet_ratio",
)

# A packet at or below this size carries little or no payload. A high proportion
# of them is characteristic of scanning and control traffic rather than data
# transfer.
SMALL_PACKET_BYTES = 100


def shannon_entropy(counts: Iterable[int]) -> float:
    """Shannon entropy in bits over a distribution of counts.

    Used to separate "many packets to one destination" from "many packets spread
    evenly across destinations" -- a distinction a plain unique count cannot
    make. Returns 0.0 for an empty or single-valued distribution.
    """
    values = [c for c in counts if c > 0]
    total = sum(values)
    if total <= 0 or len(values) < 2:
        return 0.0
    entropy = 0.0
    for count in values:
        p = count / total
        entropy -= p * log2(p)
    return entropy


@dataclass(frozen=True, slots=True)
class FeatureVector:
    """A window of one source's behaviour, as an ordered numeric vector."""

    source: str
    window_seconds: float
    values: tuple[float, ...]
    schema_version: int = FEATURE_SCHEMA_VERSION

    def as_dict(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.values, strict=True))

    def as_row(self) -> list[float]:
        return list(self.values)

    def describe(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "window_seconds": self.window_seconds,
            "schema_version": self.schema_version,
            "features": {k: round(v, 4) for k, v in self.as_dict().items()},
        }

    def get(self, name: str) -> float:
        try:
            return self.values[FEATURE_NAMES.index(name)]
        except ValueError as exc:
            raise KeyError(f"unknown feature: {name}") from exc


def _ratio(numerator: float, denominator: float) -> float:
    return (numerator / denominator) if denominator else 0.0


def extract(source: str, flows: Sequence[Flow], window_seconds: float) -> FeatureVector:
    """Build the feature vector for one source over one window.

    ``flows`` should be the flows *originating* from ``source`` within the
    window. An empty window yields an all-zero vector rather than an error, so
    callers can treat a silent host uniformly.
    """
    window = max(1e-6, float(window_seconds))
    if not flows:
        return FeatureVector(source, window, tuple(0.0 for _ in FEATURE_NAMES))

    packets = sum(f.packets for f in flows)
    total_bytes = sum(f.bytes for f in flows)
    flow_count = len(flows)

    destination_counts: dict[str, int] = {}
    destination_port_counts: dict[int, int] = {}
    source_ports: set[int] = set()
    for flow in flows:
        destination_counts[flow.key.destination] = (
            destination_counts.get(flow.key.destination, 0) + flow.packets
        )
        if flow.key.destination_port is not None:
            destination_port_counts[flow.key.destination_port] = (
                destination_port_counts.get(flow.key.destination_port, 0) + flow.packets
            )
        if flow.key.source_port is not None:
            source_ports.add(flow.key.source_port)

    syn = sum(f.flags.get("S", 0) for f in flows)
    ack = sum(f.flags.get("A", 0) for f in flows)
    rst = sum(f.flags.get("R", 0) for f in flows)
    fin = sum(f.flags.get("F", 0) for f in flows)

    tcp_packets = sum(f.packets for f in flows if f.key.protocol == "TCP")
    udp_packets = sum(f.packets for f in flows if f.key.protocol == "UDP")
    icmp_packets = sum(f.packets for f in flows if f.key.protocol == "ICMP")
    dns_packets = sum(f.packets for f in flows if f.key.protocol == "DNS")

    mean_packet_size = _ratio(total_bytes, packets)
    # Pool the per-flow variances and means back into a window-level standard
    # deviation, so the value describes the whole window rather than one flow.
    if packets > 1:
        pooled = 0.0
        for flow in flows:
            if flow.packets:
                delta = flow.mean_packet_size - mean_packet_size
                sd = flow.stddev_packet_size
                pooled += flow.packets * (sd * sd + delta * delta)
        variance = pooled / packets
        stddev_packet_size = sqrt(variance) if variance > 0 else 0.0
    else:
        stddev_packet_size = 0.0

    # A flow whose packets are all small carries little payload. Without
    # per-packet sizes, a flow counts as small-packet when its mean is at or
    # below the threshold -- an approximation, and labelled as one.
    small_packets = sum(
        f.packets for f in flows if f.packets and f.mean_packet_size <= SMALL_PACKET_BYTES
    )

    values = (
        float(packets),
        float(total_bytes),
        packets / window,
        total_bytes / window,
        float(flow_count),
        float(len(destination_counts)),
        float(len(destination_port_counts)),
        float(len(source_ports)),
        shannon_entropy(destination_counts.values()),
        shannon_entropy(destination_port_counts.values()),
        mean_packet_size,
        stddev_packet_size,
        _ratio(sum(f.duration for f in flows), flow_count),
        _ratio(packets, flow_count),
        _ratio(total_bytes, flow_count),
        _ratio(syn, packets),
        _ratio(ack, packets),
        _ratio(rst, packets),
        _ratio(fin, packets),
        _ratio(tcp_packets, packets),
        _ratio(udp_packets, packets),
        _ratio(icmp_packets, packets),
        _ratio(dns_packets, packets),
        _ratio(small_packets, packets),
    )
    assert len(values) == len(FEATURE_NAMES), "feature vector length must match schema"
    return FeatureVector(source, window, values)


def extract_all(grouped: Mapping[str, Sequence[Flow]], window_seconds: float) -> list[FeatureVector]:
    """Extract one vector per source, ordered by source for reproducibility."""
    return [extract(source, grouped[source], window_seconds) for source in sorted(grouped)]


def to_matrix(vectors: Sequence[FeatureVector]) -> list[list[float]]:
    """Feature vectors as a plain row-major matrix, for a model to consume."""
    return [vector.as_row() for vector in vectors]


__all__ = [
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "SMALL_PACKET_BYTES",
    "FeatureVector",
    "extract",
    "extract_all",
    "shannon_entropy",
    "to_matrix",
]
