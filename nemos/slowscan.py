"""Catch reconnaissance that is deliberately too slow for the detection window.

Every volumetric rule in ``detector.py`` works over one short window (10s by
default). That is what makes them cheap, and it is also a published evasion:
an attacker who knows the window spreads the same scan across hours and never
puts enough packets in any single one. Forty ports probed in ten seconds is a
scan; the same forty probed one a minute apart is invisible, and identical in
intent.

Widening the window is not the fix. Per-packet detection cost is linear in how
many events a window holds, so an hour-long packet window would cost roughly
360x more per packet -- on the capture thread, where that becomes dropped
traffic. This module keeps a far coarser record instead:

- **Insert is O(1).** One dict write per packet, no scanning.
- **Evaluation is rate-limited per source**, so the bounded walk over a
  source's tracked set happens every ``eval_interval`` seconds rather than
  every packet.
- **Everything is bounded**, keyed by attacker-influenced values, like every
  other map in NEMOS.

What it deliberately does not do is treat every widely-contacting host as a
sweeper. A workstation browsing the web contacts hundreds of destinations an
hour on port 443, which has the same shape as a horizontal sweep and none of
the meaning. The sweep rule therefore only considers internal destinations on
uncommon ports; the vertical-scan rule, which has no such benign analogue, is
the stronger of the two.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

# Ports where contacting many hosts is ordinary client behaviour rather than a
# sweep: web, DNS, mail submission, time. Including these would report a
# browser as a scanner.
BENIGN_SWEEP_PORTS = frozenset({
    53, 80, 123, 443, 465, 587, 993, 995, 8080, 8443, 5353,
})


@dataclass
class _SourceState:
    """What is remembered about one source over the long horizon."""

    # (destination, port) -> last time it was contacted. Ordered so eviction
    # is O(1); capped so one source cannot grow without limit.
    seen: OrderedDict[tuple[str, int], float] = field(default_factory=OrderedDict)
    last_seen: float = 0.0
    last_eval: float = 0.0
    # Set when a fast rule already reported this source, so the slow tier does
    # not raise a second finding for behaviour that was caught in real time.
    quiet_until: float = 0.0


class SlowHorizonTracker:
    """Long-horizon, low-resolution companion to the windowed rules."""

    def __init__(
        self,
        horizon: float = 3600.0,
        scan_ports: int = 40,
        sweep_hosts: int = 30,
        eval_interval: float = 30.0,
        max_sources: int = 1024,
        max_tracked: int = 256,
    ) -> None:
        self.horizon = float(horizon)
        self.scan_ports = int(scan_ports)
        self.sweep_hosts = int(sweep_hosts)
        self.eval_interval = float(eval_interval)
        self.max_sources = int(max_sources)
        self.max_tracked = int(max_tracked)
        self.sources: OrderedDict[str, _SourceState] = OrderedDict()

    # -- recording ---------------------------------------------------------

    def observe(self, source: str, destination: str, port: int | None, now: float) -> None:
        """Record one contact. O(1); called for every packet."""
        if port is None or not source or not destination:
            return
        state = self.sources.get(source)
        if state is None:
            # last_seen must be set before eviction runs, not after: a state
            # still holding its 0.0 default looks infinitely stale, so the
            # source being created would be the one selected and discarded.
            # Once the table was full that silently stopped this tier from
            # tracking anything new.
            state = _SourceState(last_seen=now)
            self.sources[source] = state
            if len(self.sources) > self.max_sources:
                self._evict_source(now)
        state.seen[(destination, int(port))] = now
        state.seen.move_to_end((destination, int(port)))
        state.last_seen = now
        if len(state.seen) > self.max_tracked:
            state.seen.popitem(last=False)

    def note_fast_finding(self, source: str, now: float) -> None:
        """Silence the slow tier for a source a windowed rule already caught.

        Without this, a fast scanner accumulates slow-tier state too and is
        reported twice for one behaviour -- the sort of duplicate that makes
        an operator stop reading findings.
        """
        state = self.sources.get(source)
        if state is not None:
            state.quiet_until = now + self.horizon

    # -- evaluation --------------------------------------------------------

    def evaluate(self, source: str, now: float) -> list[dict]:
        """Report slow reconnaissance by this source, at most periodically.

        Returns a list of ``{"threat", "reason", "evidence"}`` dicts, empty
        almost always: the bounded walk below runs once per
        ``eval_interval`` per source, not once per packet.
        """
        state = self.sources.get(source)
        if state is None:
            return []
        if now - state.last_eval < self.eval_interval:
            return []
        state.last_eval = now

        cutoff = now - self.horizon
        # Expire in the same pass that reads, so nothing walks this twice.
        expired = [key for key, seen in state.seen.items() if seen < cutoff]
        for key in expired:
            del state.seen[key]
        if not state.seen or now < state.quiet_until:
            return []

        ports_per_destination: dict[str, set[int]] = {}
        hosts_per_port: dict[int, set[str]] = {}
        for destination, port in state.seen:
            ports_per_destination.setdefault(destination, set()).add(port)
            hosts_per_port.setdefault(port, set()).add(destination)

        findings: list[dict] = []

        target, ports = max(
            ports_per_destination.items(), key=lambda item: len(item[1]), default=("", set()))
        if len(ports) >= self.scan_ports:
            findings.append({
                "threat": "SLOW_PORT_SCAN",
                "reason": (
                    f"{len(ports)} distinct ports probed on {target} over "
                    f"{int(self.horizon)}s -- below the windowed threshold at every "
                    "instant, and a scan in aggregate"
                ),
                "evidence": {
                    "target": target,
                    "distinct_ports": len(ports),
                    "horizon_seconds": int(self.horizon),
                    "lowest_port": min(ports),
                    "highest_port": max(ports),
                },
            })

        candidates = {
            port: hosts for port, hosts in hosts_per_port.items()
            if port not in BENIGN_SWEEP_PORTS
        }
        swept_port, hosts = max(
            candidates.items(), key=lambda item: len(item[1]), default=(0, set()))
        if len(hosts) >= self.sweep_hosts:
            findings.append({
                "threat": "SLOW_HOST_SWEEP",
                "reason": (
                    f"{len(hosts)} hosts contacted on port {swept_port} over "
                    f"{int(self.horizon)}s at a rate below the windowed threshold"
                ),
                "evidence": {
                    "port": swept_port,
                    "distinct_hosts": len(hosts),
                    "horizon_seconds": int(self.horizon),
                },
            })

        if findings:
            # One report per horizon per source: the state that produced this
            # persists for an hour, and re-reporting it every interval would
            # bury the operator in the same finding.
            state.quiet_until = now + self.horizon
        return findings

    # -- bounding ----------------------------------------------------------

    def _evict_source(self, now: float) -> None:
        """Make room, preferring to forget the least interesting source.

        Plain LRU would be exactly wrong here: a slow scanner is, by
        definition, the least recently active thing being tracked, so
        recency-based eviction would discard the sources this module exists
        to catch. Fully expired sources go first, then whichever source has
        seen the fewest distinct endpoints.
        """
        cutoff = now - self.horizon
        stale = [key for key, state in self.sources.items() if state.last_seen < cutoff]
        for key in stale:
            del self.sources[key]
        if len(self.sources) <= self.max_sources:
            return
        least = min(self.sources.items(), key=lambda item: len(item[1].seen))[0]
        del self.sources[least]

    def metrics(self) -> dict:
        return {
            "tracked_sources": len(self.sources),
            "horizon_seconds": int(self.horizon),
            "scan_ports": self.scan_ports,
            "sweep_hosts": self.sweep_hosts,
        }


__all__ = ["SlowHorizonTracker", "BENIGN_SWEEP_PORTS"]
