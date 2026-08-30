from __future__ import annotations

import json
import logging
import queue
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .database import connect, initialize
from .models import Alert, TrafficEvent

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Item:
    kind: str
    payload: dict


class BatchWriter:
    """Single-owner SQLite writer with bounded, priority-aware backpressure.

    Traffic is lossy under sustained overload, because packet capture must not be
    blocked indefinitely. Alerts get a reserved portion of the queue and a short
    blocking window so telemetry pressure cannot starve security findings.
    """

    def __init__(
        self,
        path: Path,
        batch_size: int = 250,
        flush_seconds: float = 0.5,
        max_queue: int = 50_000,
        max_traffic: int = 100_000,
        max_alerts: int = 10_000,
        alert_reserve: int | None = None,
        alert_submit_timeout: float = 0.05,
    ):
        if batch_size < 1 or flush_seconds <= 0:
            raise ValueError("batch_size must be >= 1 and flush_seconds must be > 0")
        if max_queue < 1:
            raise ValueError("max_queue must be >= 1")
        if alert_submit_timeout < 0:
            raise ValueError("alert_submit_timeout must be >= 0")
        self.path = Path(path)
        self.batch_size = batch_size
        self.flush_seconds = flush_seconds
        self.max_traffic = max_traffic
        self.max_alerts = max_alerts
        self.alert_submit_timeout = alert_submit_timeout
        reserve_default = max(1, min(max_queue // 10, 2048))
        self.alert_reserve = reserve_default if alert_reserve is None else alert_reserve
        if max_queue == 1:
            self.alert_reserve = 0
        elif not 1 <= self.alert_reserve < max_queue:
            raise ValueError("alert_reserve must be >= 1 and < max_queue")

        self.q: queue.Queue[Item | None] = queue.Queue(maxsize=max_queue)
        self.stop = threading.Event()
        self._state_lock = threading.Lock()
        self._accepting = False
        self.started = False
        self.write_errors = 0
        self.dropped_events = 0
        self.dropped_traffic = 0
        self.dropped_alerts = 0
        self.batches_written = 0
        self.queue_high_watermark = 0
        self.thread: threading.Thread | None = None

    @property
    def queue_depth(self) -> int:
        return self.q.qsize()

    def metrics(self) -> dict[str, int | bool]:
        with self._state_lock:
            return {
                "queue_depth": self.q.qsize(),
                "queue_capacity": self.q.maxsize,
                "queue_high_watermark": self.queue_high_watermark,
                "dropped_events": self.dropped_events,
                "dropped_traffic": self.dropped_traffic,
                "dropped_alerts": self.dropped_alerts,
                "write_errors": self.write_errors,
                "batches_written": self.batches_written,
                "accepting": self._accepting,
                "thread_alive": bool(self.thread and self.thread.is_alive()),
            }

    def start(self):
        with self._state_lock:
            if self.started and self.thread is not None and self.thread.is_alive():
                return
            # Allow a clean retry after a writer thread died during startup or
            # after an unexpected runtime exception.
            self.started = False
            self.thread = None
            initialize(self.path)
            self.stop.clear()
            self._accepting = True
            self.thread = threading.Thread(target=self._run, name="sqlite-writer", daemon=True)
            self.started = True
            self.thread.start()

    def submit_traffic(self, event: TrafficEvent) -> bool:
        return self._submit(Item("traffic", event.as_dict()), is_alert=False)

    def submit_alert(self, alert: Alert) -> bool:
        return self._submit(Item("alert", alert.as_dict()), is_alert=True)

    def _record_drop(self, is_alert: bool) -> None:
        self.dropped_events += 1
        if is_alert:
            self.dropped_alerts += 1
        else:
            self.dropped_traffic += 1

    def _submit(self, item: Item, *, is_alert: bool) -> bool:
        with self._state_lock:
            if not self.started or not self._accepting:
                self._record_drop(is_alert)
                return False

            # Reserve capacity for alerts so packet bursts cannot consume every
            # queue slot. Traffic is rejected once the reserved region is reached.
            if not is_alert and self.alert_reserve and self.q.qsize() >= self.q.maxsize - self.alert_reserve:
                self._record_drop(False)
                return False

            try:
                if is_alert and self.alert_submit_timeout:
                    self.q.put(item, timeout=self.alert_submit_timeout)
                else:
                    self.q.put_nowait(item)
            except queue.Full:
                self._record_drop(is_alert)
                log.warning("write queue full; dropping %s", item.kind)
                return False

            self.queue_high_watermark = max(self.queue_high_watermark, self.q.qsize())
            return True

    def shutdown(self, timeout: float = 10):
        with self._state_lock:
            if not self.started:
                return
            self._accepting = False
            thread = self.thread

        self.stop.set()
        deadline = time.monotonic() + timeout

        # If the worker already died, there is nobody left to consume a
        # sentinel. Count queued items as dropped and reset the lifecycle so a
        # later start() can recover instead of hanging in shutdown().
        if thread is None or not thread.is_alive():
            dropped = 0
            while True:
                try:
                    self.q.get_nowait()
                    dropped += 1
                except queue.Empty:
                    break
            if dropped:
                with self._state_lock:
                    self.dropped_events += dropped
            with self._state_lock:
                self.started = False
                self.thread = None
            return

        while True:
            try:
                self.q.put_nowait(None)
                break
            except queue.Full as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError("SQLite writer queue did not drain") from exc
                time.sleep(0.01)

        remaining = max(0.0, deadline - time.monotonic())
        thread.join(remaining)
        if thread.is_alive():
            raise TimeoutError("SQLite writer did not stop")
        with self._state_lock:
            self.started = False
            self.thread = None

    def _run(self):
        try:
            c = connect(self.path)
        except Exception:
            with self._state_lock:
                self.write_errors += 1
                self._accepting = False
            log.exception("SQLite writer failed to open database")
            return

        pending: list[Item] = []
        last_flush = time.monotonic()
        try:
            while True:
                timeout = max(0.01, self.flush_seconds - (time.monotonic() - last_flush))
                try:
                    item = self.q.get(timeout=timeout)
                except queue.Empty:
                    if pending:
                        self._flush(c, pending)
                        pending = []
                    last_flush = time.monotonic()
                    continue

                if item is None:
                    # Sentinel is only inserted after accepting is disabled. Drain
                    # everything already queued before exiting.
                    while True:
                        try:
                            pending.append(self.q.get_nowait())
                        except queue.Empty:
                            break
                        if len(pending) >= self.batch_size:
                            self._flush(c, pending)
                            pending = []
                    if pending:
                        self._flush(c, pending)
                    break

                pending.append(item)
                if len(pending) >= self.batch_size:
                    self._flush(c, pending)
                    pending = []
                    last_flush = time.monotonic()
        except Exception:
            with self._state_lock:
                self.write_errors += 1
                self._accepting = False
            log.exception("SQLite writer thread stopped unexpectedly")
        finally:
            if pending:
                try:
                    self._flush(c, pending)
                except Exception:
                    with self._state_lock:
                        self.write_errors += 1
                        self._accepting = False
                    log.exception("SQLite writer final flush failed")
            c.close()

    def _flush(self, c: sqlite3.Connection, items: list[Item]) -> bool:
        traffic_rows = []
        alert_rows = []
        for item in items:
            p = item.payload
            if item.kind == "traffic":
                traffic_rows.append(
                    (
                        p["timestamp"], p["source"], p["destination"], p["source_port"],
                        p["destination_port"], p["protocol"], p["packet_size"], p["flags"],
                        p["interface"], p["direction"],
                        json.dumps(p.get("metadata") or {}, separators=(",", ":")),
                    )
                )
            else:
                alert_rows.append(
                    (
                        p["timestamp"], p["threat"], p["category"], p["source"], p["severity"],
                        p["risk_score"], p["confidence"], p["reason"], p["ports_scanned"],
                        p["packets"], p["destinations"], p["ports"], p["window_seconds"],
                        p.get("technique", ""), p.get("incident_id", ""),
                        json.dumps(p.get("evidence") or {}, separators=(",", ":")),
                    )
                )

        delay = 0.02
        last_error: Exception | None = None
        for attempt in range(4):
            try:
                with c:
                    if traffic_rows:
                        c.executemany(
                            "INSERT INTO traffic(timestamp,source,destination,source_port,destination_port,protocol,packet_size,flags,interface,direction,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                            traffic_rows,
                        )
                    if alert_rows:
                        c.executemany(
                            "INSERT INTO alerts(timestamp,threat,category,source,severity,risk_score,confidence,reason,ports_scanned,packets,destinations,ports,window_seconds,technique,incident_id,evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            alert_rows,
                        )
                    traffic_pruned = self._prune_traffic(c)
                    alerts_pruned = self._prune_alerts(c)
                    if traffic_pruned or alerts_pruned:
                        self._update_stats_delta(
                            c,
                            traffic_rows,
                            alert_rows,
                            traffic_pruned=traffic_pruned,
                            alerts_pruned=alerts_pruned,
                        )
                        affected_hosts = set()
                        if alerts_pruned:
                            affected_hosts.update(alerts_pruned["repair_hosts"])
                        self._update_host_stats_delta(c, traffic_rows, alert_rows)
                        self._apply_pruned_host_delta(c, traffic_pruned, alerts_pruned)
                        if affected_hosts:
                            self._repair_host_stats(c, affected_hosts)
                    else:
                        self._update_stats_delta(c, traffic_rows, alert_rows)
                        self._update_host_stats_delta(c, traffic_rows, alert_rows)
                    c.execute("UPDATE telemetry_stats SET revision=revision+1 WHERE id=1")
                with self._state_lock:
                    self.batches_written += 1
                return True
            except sqlite3.OperationalError as exc:
                last_error = exc
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    break
                if attempt == 3:
                    break
                time.sleep(delay)
                delay *= 2
            except Exception as exc:
                last_error = exc
                break

        with self._state_lock:
            self.write_errors += 1
            self.dropped_events += len(items)
            self.dropped_traffic += len(traffic_rows)
            self.dropped_alerts += len(alert_rows)
        if last_error is not None:
            log.error("SQLite batch failed; %d events affected: %s", len(items), last_error)
        else:
            log.error("SQLite batch failed; %d events affected", len(items))
        return False

    def _update_stats_delta(
        self, c: sqlite3.Connection, traffic_rows, alert_rows,
        *, traffic_pruned=None, alerts_pruned=None,
    ):
        tcp = sum(row[5] == "TCP" for row in traffic_rows)
        udp = sum(row[5] == "UDP" for row in traffic_rows)
        icmp = sum(row[5] == "ICMP" for row in traffic_rows)
        dns = sum(row[5] == "DNS" for row in traffic_rows)
        packets = len(traffic_rows)
        threats = len(alert_rows)
        critical = sum(row[4] == "CRITICAL" for row in alert_rows)

        if traffic_pruned:
            packets -= traffic_pruned["packets"]
            tcp -= traffic_pruned["tcp"]
            udp -= traffic_pruned["udp"]
            icmp -= traffic_pruned["icmp"]
            dns -= traffic_pruned["dns"]
        if alerts_pruned:
            threats -= alerts_pruned["threats"]
            critical -= alerts_pruned["critical"]

        c.execute(
            """UPDATE telemetry_stats
               SET packets=packets+?, tcp=tcp+?, udp=udp+?, icmp=icmp+?, dns=dns+?,
                   threats=threats+?, critical=critical+?
               WHERE id=1""",
            (packets, tcp, udp, icmp, dns, threats, critical),
        )

    @staticmethod
    def _values_clause(rows: list[tuple], width: int) -> tuple[str, tuple]:
        if not rows:
            return "", ()
        return ",".join("(" + ",".join("?" for _ in range(width)) + ")" for _ in rows), tuple(v for row in rows for v in row)

    def _update_host_stats_delta(self, c: sqlite3.Connection, traffic_rows, alert_rows):
        packet_counts = {}
        for row in traffic_rows:
            for host in (row[1], row[2]):
                packet_counts[host] = packet_counts.get(host, 0) + 1
        if packet_counts:
            rows = list(packet_counts.items())
            values, params = self._values_clause(rows, 2)
            c.execute(
                f"""INSERT INTO host_stats(host,packets) VALUES {values}
                    ON CONFLICT(host) DO UPDATE SET packets=packets+excluded.packets""",
                params,
            )

        alert_counts = {}
        for row in alert_rows:
            host, severity, risk, timestamp = row[3], row[4], int(row[5] or 0), row[0]
            item = alert_counts.setdefault(host, [0, 0, 0, timestamp])
            item[0] += 1
            item[1] += int(severity == "CRITICAL")
            item[2] = max(item[2], risk)
            if timestamp > item[3]:
                item[3] = timestamp
        if alert_counts:
            rows = [
                (host, count, critical, risk, timestamp)
                for host, (count, critical, risk, timestamp) in alert_counts.items()
            ]
            values, params = self._values_clause(rows, 5)
            c.execute(
                f"""INSERT INTO host_stats(host,alert_count,critical_count,max_risk,last_alert) VALUES {values}
                    ON CONFLICT(host) DO UPDATE SET
                      alert_count=alert_count+excluded.alert_count,
                      critical_count=critical_count+excluded.critical_count,
                      max_risk=MAX(max_risk,excluded.max_risk),
                      last_alert=CASE WHEN last_alert IS NULL OR excluded.last_alert > last_alert THEN excluded.last_alert ELSE last_alert END""",
                params,
            )

    def _apply_pruned_host_delta(self, c: sqlite3.Connection, traffic_pruned, alerts_pruned) -> None:
        if traffic_pruned and traffic_pruned["host_counts"]:
            rows = [(host, count) for host, count in traffic_pruned["host_counts"].items()]
            values, params = self._values_clause(rows, 2)
            c.execute(
                f"""WITH deleted(host,packets) AS (VALUES {values})
                    UPDATE host_stats
                    SET packets=MAX(0, packets-(SELECT packets FROM deleted WHERE deleted.host=host_stats.host))
                    WHERE host IN (SELECT host FROM deleted)""",
                params,
            )
        if alerts_pruned and alerts_pruned["host_counts"]:
            rows = [(host, count, critical) for host, (count, critical, _risk, _timestamp) in alerts_pruned["host_counts"].items()]
            values, params = self._values_clause(rows, 3)
            c.execute(
                f"""WITH deleted(host,alert_count,critical_count) AS (VALUES {values})
                    UPDATE host_stats
                    SET alert_count=MAX(0, alert_count-(SELECT alert_count FROM deleted WHERE deleted.host=host_stats.host)),
                        critical_count=MAX(0, critical_count-(SELECT critical_count FROM deleted WHERE deleted.host=host_stats.host))
                    WHERE host IN (SELECT host FROM deleted)""",
                params,
            )
    def _rebuild_host_stats(self, c: sqlite3.Connection):
        c.execute("DELETE FROM host_stats")
        c.execute("""INSERT INTO host_stats(host, packets)
                     SELECT host, SUM(packets) FROM (
                       SELECT source AS host, COUNT(*) packets FROM traffic GROUP BY source
                       UNION ALL SELECT destination AS host, COUNT(*) packets FROM traffic GROUP BY destination
                     ) GROUP BY host""")
        c.execute("""INSERT INTO host_stats(host,alert_count,critical_count,max_risk,last_alert)
                     SELECT source, COUNT(*), SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END),
                            COALESCE(MAX(risk_score),0), MAX(timestamp)
                     FROM alerts GROUP BY source
                     ON CONFLICT(host) DO UPDATE SET
                       alert_count=excluded.alert_count, critical_count=excluded.critical_count,
                       max_risk=excluded.max_risk, last_alert=excluded.last_alert""")

    def _recount_stats(self, c: sqlite3.Connection):
        row = c.execute(
            """SELECT COUNT(*) packets,
                      COALESCE(SUM(protocol='TCP'),0) tcp,
                      COALESCE(SUM(protocol='UDP'),0) udp,
                      COALESCE(SUM(protocol='ICMP'),0) icmp,
                      COALESCE(SUM(protocol='DNS'),0) dns
               FROM traffic"""
        ).fetchone()
        alerts = c.execute(
            "SELECT COUNT(*) threats, COALESCE(SUM(severity='CRITICAL'),0) critical FROM alerts"
        ).fetchone()
        c.execute(
            """UPDATE telemetry_stats
               SET packets=?, tcp=?, udp=?, icmp=?, dns=?, threats=?, critical=?
               WHERE id=1""",
            (row[0], row[1], row[2], row[3], row[4], alerts[0], alerts[1]),
        )

    def _prune_traffic(self, c: sqlite3.Connection):
        if self.max_traffic <= 0:
            return None
        cutoff = c.execute(
            "SELECT id FROM traffic ORDER BY id DESC LIMIT 1 OFFSET ?",
            (self.max_traffic,),
        ).fetchone()
        if cutoff is None:
            return None
        cutoff_id = int(cutoff[0])
        row = c.execute(
            """SELECT COUNT(*) packets,
                      COALESCE(SUM(protocol='TCP'),0) tcp,
                      COALESCE(SUM(protocol='UDP'),0) udp,
                      COALESCE(SUM(protocol='ICMP'),0) icmp,
                      COALESCE(SUM(protocol='DNS'),0) dns
               FROM traffic WHERE id <= ?""",
            (cutoff_id,),
        ).fetchone()
        host_counts = {
            r[0]: int(r[1] or 0)
            for r in c.execute(
                """SELECT host, SUM(packets) FROM (
                       SELECT source host, COUNT(*) packets FROM traffic
                       WHERE id <= ? GROUP BY source
                       UNION ALL
                       SELECT destination host, COUNT(*) packets FROM traffic
                       WHERE id <= ? GROUP BY destination
                   ) GROUP BY host""",
                (cutoff_id, cutoff_id),
            )
        }
        c.execute("DELETE FROM traffic WHERE id <= ?", (cutoff_id,))
        return {
            "packets": int(row[0] or 0),
            "tcp": int(row[1] or 0),
            "udp": int(row[2] or 0),
            "icmp": int(row[3] or 0),
            "dns": int(row[4] or 0),
            "host_counts": host_counts,
        }

    def _prune_alerts(self, c: sqlite3.Connection):
        if self.max_alerts <= 0:
            return None
        cutoff = c.execute(
            "SELECT id FROM alerts ORDER BY id DESC LIMIT 1 OFFSET ?",
            (self.max_alerts,),
        ).fetchone()
        if cutoff is None:
            return None
        cutoff_id = int(cutoff[0])
        row = c.execute(
            """SELECT COUNT(*) threats,
                      COALESCE(SUM(severity='CRITICAL'),0) critical
               FROM alerts WHERE id <= ?""",
            (cutoff_id,),
        ).fetchone()
        host_counts = {}
        repair_hosts = set()
        deleted_rows = c.execute(
            """SELECT source, COUNT(*) count,
                      SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) critical,
                      COALESCE(MAX(risk_score),0) max_risk, MAX(timestamp) last_alert
               FROM alerts WHERE id <= ? GROUP BY source""",
            (cutoff_id,),
        ).fetchall()
        deleted_hosts = tuple(row[0] for row in deleted_rows)
        current_stats = {}
        if deleted_hosts:
            placeholders = ",".join("?" for _ in deleted_hosts)
            current_stats = {
                row[0]: (int(row[1] or 0), row[2])
                for row in c.execute(
                    f"SELECT host,max_risk,last_alert FROM host_stats WHERE host IN ({placeholders})",
                    deleted_hosts,
                )
            }
        for deleted in deleted_rows:
            host = deleted[0]
            deleted_count = int(deleted[1] or 0)
            deleted_critical = int(deleted[2] or 0)
            deleted_max_risk = int(deleted[3] or 0)
            deleted_last_alert = deleted[4]
            host_counts[host] = (deleted_count, deleted_critical, deleted_max_risk, deleted_last_alert)
            current = current_stats.get(host)
            if current is not None and (
                current[0] <= deleted_max_risk
                or current[1] is None
                or (deleted_last_alert is not None and current[1] <= deleted_last_alert)
            ):
                repair_hosts.add(host)
        c.execute("DELETE FROM alerts WHERE id <= ?", (cutoff_id,))
        return {
            "threats": int(row[0] or 0),
            "critical": int(row[1] or 0),
            "host_counts": host_counts,
            "repair_hosts": repair_hosts,
        }

    def _repair_host_stats(self, c: sqlite3.Connection, hosts: set[str]) -> None:
        """Recompute max-risk/latest-alert fields only for affected hosts."""
        if not hosts:
            return
        rows = [(host,) for host in hosts]
        values, params = self._values_clause(rows, 1)
        c.execute(
            f"""WITH affected(host) AS (VALUES {values}),
                recomputed AS (
                    SELECT a.host, COALESCE(MAX(a.risk_score),0) max_risk, MAX(a.timestamp) last_alert
                    FROM (SELECT source host,risk_score,timestamp FROM alerts) a
                    JOIN affected h ON h.host=a.host
                    GROUP BY a.host
                )
                UPDATE host_stats
                SET max_risk=COALESCE((SELECT max_risk FROM recomputed WHERE recomputed.host=host_stats.host),0),
                    last_alert=(SELECT last_alert FROM recomputed WHERE recomputed.host=host_stats.host)
                WHERE host IN (SELECT host FROM affected)""",
            params,
        )

