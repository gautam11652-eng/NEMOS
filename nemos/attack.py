from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    """Small, versioned ATT&CK catalog used by the NEMOS UI.

    NEMOS stores the technique ID on the alert. Names/tactics live here so
    presentation metadata can be corrected without rewriting historical alerts.
    """

    technique_id: str
    name: str
    tactic: str
    description: str
    url: str


# Only techniques actually emitted by the detector are included.  Keep this
# catalog conservative: a generic anomaly is not automatically an ATT&CK
# technique merely because it is suspicious.
TECHNIQUES: dict[str, AttackTechnique] = {
    "T1046": AttackTechnique(
        "T1046",
        "Network Service Discovery",
        "Discovery",
        "Identifying services running on remote hosts through port or service scanning.",
        "https://attack.mitre.org/techniques/T1046/",
    ),
    "T1021": AttackTechnique(
        "T1021",
        "Remote Services",
        "Lateral Movement",
        "Using valid accounts over remote services such as SMB, RDP or SSH to move between hosts.",
        "https://attack.mitre.org/techniques/T1021/",
    ),
    "T1048": AttackTechnique(
        "T1048",
        "Exfiltration Over Alternative Protocol",
        "Exfiltration",
        "Transferring data out of the network over a protocol other than the primary command channel.",
        "https://attack.mitre.org/techniques/T1048/",
    ),
    "T1071": AttackTechnique(
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
        "Communicating with a controller over an application-layer protocol to blend with normal traffic.",
        "https://attack.mitre.org/techniques/T1071/",
    ),
    "T1071.004": AttackTechnique(
        "T1071.004",
        "Application Layer Protocol: DNS",
        "Command and Control",
        "Using DNS as an application-layer communication protocol.",
        "https://attack.mitre.org/techniques/T1071/004/",
    ),
    "T1090.003": AttackTechnique(
        "T1090.003",
        "Proxy: Multi-hop Proxy",
        "Command and Control",
        "Routing traffic through a multi-hop proxy network such as Tor to obscure its destination.",
        "https://attack.mitre.org/techniques/T1090/003/",
    ),
    "T1110": AttackTechnique(
        "T1110",
        "Brute Force",
        "Credential Access",
        "Repeatedly attempting authentication against a service to guess valid credentials.",
        "https://attack.mitre.org/techniques/T1110/",
    ),
    "T1496": AttackTechnique(
        "T1496",
        "Resource Hijacking",
        "Impact",
        "Consuming system or network resources for the adversary's benefit, such as cryptocurrency mining.",
        "https://attack.mitre.org/techniques/T1496/",
    ),
    "T1498": AttackTechnique(
        "T1498",
        "Network Denial of Service",
        "Impact",
        "Attempting to degrade or block availability through network denial-of-service activity.",
        "https://attack.mitre.org/techniques/T1498/",
    ),
    "T1498.001": AttackTechnique(
        "T1498.001",
        "Network Denial of Service: Direct Network Flood",
        "Impact",
        "Generating high-volume network traffic directly against a target.",
        "https://attack.mitre.org/techniques/T1498/001/",
    ),
    "T1557.002": AttackTechnique(
        "T1557.002",
        "Adversary-in-the-Middle: ARP Cache Poisoning",
        "Credential Access / Collection",
        "Manipulating ARP mappings to position an adversary between networked devices.",
        "https://attack.mitre.org/techniques/T1557/002/",
    ),
}

# Signals that are intentionally not forced into ATT&CK.  This distinction is
# important for analyst trust: suspicious does not automatically mean a mapped
# adversary technique has been established.
NON_ATTACK_SIGNALS: dict[str, dict[str, str]] = {
    "BEHAVIORAL_TRAFFIC_ANOMALY": {
        "name": "Behavioral Traffic Anomaly",
        "type": "behavioral-signal",
        "reason": "Adaptive baseline detected statistically unusual host traffic; the observed network evidence is insufficient to assert a specific ATT&CK technique.",
    },
}


def technique_metadata(technique_id: str | None) -> dict[str, Any]:
    tid = str(technique_id or "").strip()
    item = TECHNIQUES.get(tid)
    if item:
        data = asdict(item)
        data["mapped"] = True
        data["type"] = "attack-technique"
        return data
    return {
        "technique_id": tid,
        "name": "",
        "tactic": "",
        "description": "",
        "url": "",
        "mapped": False,
        "type": "unmapped",
    }


def signal_metadata(threat: str | None) -> dict[str, Any]:
    item = NON_ATTACK_SIGNALS.get(str(threat or "").strip())
    if not item:
        return {
            "name": "",
            "type": "unmapped",
            "reason": "",
        }
    return dict(item)


def enrich_alert(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Add presentation-only ATT&CK metadata without changing stored schema."""
    result = dict(alert)
    tid = str(result.get("technique") or "").strip()
    result["attack"] = technique_metadata(tid)
    result["signal"] = signal_metadata(result.get("threat"))
    return result


def catalog() -> list[dict[str, Any]]:
    return [technique_metadata(tid) for tid in sorted(TECHNIQUES)]


__all__ = [
    "AttackTechnique",
    "TECHNIQUES",
    "NON_ATTACK_SIGNALS",
    "catalog",
    "enrich_alert",
    "signal_metadata",
    "technique_metadata",
]
