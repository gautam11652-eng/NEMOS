from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any

def utc_now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

@dataclass(slots=True)
class TrafficEvent:
    timestamp: str
    source: str
    destination: str
    protocol: str
    source_port: int | None = None
    destination_port: int | None = None
    packet_size: int = 0
    flags: str = ""
    interface: str = ""
    direction: str = "unknown"
    metadata: dict[str,Any] | None = None
    def as_dict(self):
        d=asdict(self); d["metadata"]=self.metadata or {}; return d

@dataclass(slots=True)
class Alert:
    timestamp: str
    threat: str
    category: str
    source: str
    severity: str
    risk_score: int
    confidence: int
    reason: str
    ports_scanned: int=0
    packets: int=0
    destinations: int=0
    ports: int=0
    window_seconds: int=0
    technique: str=""
    incident_id: str=""
    evidence: dict[str,Any] | None=None
    def as_dict(self):
        d=asdict(self); d["evidence"]=self.evidence or {}; return d
