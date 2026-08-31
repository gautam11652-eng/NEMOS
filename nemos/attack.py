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


# Only techniques the detector actually emits are included, plus any it emitted
# in an earlier release (marked below) so stored alerts keep their names. Keep
# this catalog conservative: a generic anomaly is not automatically an ATT&CK
# technique merely because it is suspicious. Adding an aspirational entry here
# would misrepresent what NEMOS can evidence.
LEGACY_TECHNIQUES = frozenset({"T1110"})
TECHNIQUES: dict[str, AttackTechnique] = {
    "T1046": AttackTechnique(
        "T1046",
        "Network Service Discovery",
        "Discovery",
        "Identifying services running on remote hosts through port or service scanning.",
        "https://attack.mitre.org/techniques/T1046/",
    ),
    "T1018": AttackTechnique(
        "T1018",
        "Remote System Discovery",
        "Discovery",
        "Enumerating other hosts on the network by address, sweep or broadcast.",
        "https://attack.mitre.org/techniques/T1018/",
    ),
    "T1021": AttackTechnique(
        "T1021",
        "Remote Services",
        "Lateral Movement",
        "Using valid accounts over remote services such as SMB, RDP or SSH to move between hosts.",
        "https://attack.mitre.org/techniques/T1021/",
    ),
    "T1021.001": AttackTechnique(
        "T1021.001",
        "Remote Services: Remote Desktop Protocol",
        "Lateral Movement",
        "Moving between hosts over RDP using valid accounts.",
        "https://attack.mitre.org/techniques/T1021/001/",
    ),
    "T1021.002": AttackTechnique(
        "T1021.002",
        "Remote Services: SMB / Windows Admin Shares",
        "Lateral Movement",
        "Moving between hosts over SMB administrative shares using valid accounts.",
        "https://attack.mitre.org/techniques/T1021/002/",
    ),
    "T1021.004": AttackTechnique(
        "T1021.004",
        "Remote Services: SSH",
        "Lateral Movement",
        "Moving between hosts over SSH using valid accounts or keys.",
        "https://attack.mitre.org/techniques/T1021/004/",
    ),
    "T1021.005": AttackTechnique(
        "T1021.005",
        "Remote Services: VNC",
        "Lateral Movement",
        "Moving between hosts over VNC using valid credentials.",
        "https://attack.mitre.org/techniques/T1021/005/",
    ),
    "T1021.006": AttackTechnique(
        "T1021.006",
        "Remote Services: Windows Remote Management",
        "Lateral Movement",
        "Moving between hosts over WinRM using valid accounts.",
        "https://attack.mitre.org/techniques/T1021/006/",
    ),
    "T1041": AttackTechnique(
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration",
        "Sending collected data out over the same channel the implant uses for command and control.",
        "https://attack.mitre.org/techniques/T1041/",
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
    "T1095": AttackTechnique(
        "T1095",
        "Non-Application Layer Protocol",
        "Command and Control",
        "Using a non-application-layer protocol such as ICMP to carry command-and-control traffic.",
        "https://attack.mitre.org/techniques/T1095/",
    ),
    "T1105": AttackTechnique(
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
        "Transferring tools or files from an external system into the target network.",
        "https://attack.mitre.org/techniques/T1105/",
    ),
    "T1090.003": AttackTechnique(
        "T1090.003",
        "Proxy: Multi-hop Proxy",
        "Command and Control",
        "Routing traffic through a multi-hop proxy network such as Tor to obscure its destination.",
        "https://attack.mitre.org/techniques/T1090/003/",
    ),
    # Retained for alerts stored by 4.0/4.1, which emitted the parent before
    # the guessing/spraying sub-techniques existed. The detector no longer
    # emits it; removing it would leave those historical alerts unnamed.
    "T1110": AttackTechnique(
        "T1110",
        "Brute Force",
        "Credential Access",
        "Repeatedly attempting authentication against a service to guess valid credentials.",
        "https://attack.mitre.org/techniques/T1110/",
    ),
    "T1110.001": AttackTechnique(
        "T1110.001",
        "Brute Force: Password Guessing",
        "Credential Access",
        "Repeatedly guessing passwords against one account or service without prior knowledge.",
        "https://attack.mitre.org/techniques/T1110/001/",
    ),
    "T1110.003": AttackTechnique(
        "T1110.003",
        "Brute Force: Password Spraying",
        "Credential Access",
        "Trying a small number of common passwords across many accounts to avoid lockout.",
        "https://attack.mitre.org/techniques/T1110/003/",
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
    "T1498.002": AttackTechnique(
        "T1498.002",
        "Network Denial of Service: Reflection Amplification",
        "Impact",
        "Using an amplifiable third-party service to direct magnified traffic at a victim.",
        "https://attack.mitre.org/techniques/T1498/002/",
    ),
    "T1499": AttackTechnique(
        "T1499",
        "Endpoint Denial of Service",
        "Impact",
        "Exhausting the resources of a specific service or host rather than the network link.",
        "https://attack.mitre.org/techniques/T1499/",
    ),
    "T1571": AttackTechnique(
        "T1571",
        "Non-Standard Port",
        "Command and Control",
        "Communicating over a port that does not match the expected service, to evade filtering.",
        "https://attack.mitre.org/techniques/T1571/",
    ),
    "T1595": AttackTechnique(
        "T1595",
        "Active Scanning",
        "Reconnaissance",
        "Probing a target's infrastructure from outside before compromise.",
        "https://attack.mitre.org/techniques/T1595/",
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
