from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 timestamp TEXT NOT NULL, source TEXT NOT NULL, destination TEXT NOT NULL,
 source_port INTEGER, destination_port INTEGER, protocol TEXT NOT NULL,
 packet_size INTEGER NOT NULL DEFAULT 0, flags TEXT NOT NULL DEFAULT '',
 interface TEXT NOT NULL DEFAULT '', direction TEXT NOT NULL DEFAULT 'unknown',
 metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 timestamp TEXT NOT NULL, threat TEXT NOT NULL, category TEXT NOT NULL,
 source TEXT NOT NULL, severity TEXT NOT NULL, risk_score INTEGER NOT NULL DEFAULT 0,
 confidence INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL,
 ports_scanned INTEGER NOT NULL DEFAULT 0, packets INTEGER NOT NULL DEFAULT 0,
 destinations INTEGER NOT NULL DEFAULT 0, ports INTEGER NOT NULL DEFAULT 0,
 window_seconds INTEGER NOT NULL DEFAULT 0, technique TEXT NOT NULL DEFAULT '',
 evidence TEXT NOT NULL DEFAULT '{}', incident_id TEXT NOT NULL DEFAULT '', acknowledged INTEGER NOT NULL DEFAULT 0
);
-- Aggregated unidirectional flows. The (source, destination, source_port,
-- destination_port, protocol) tuple is stored exactly as observed and is never
-- normalised: A->B and B->A are separate rows by design. See nemos/flows.py.
CREATE TABLE IF NOT EXISTS flows (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 first_timestamp TEXT NOT NULL, last_timestamp TEXT NOT NULL,
 source TEXT NOT NULL, destination TEXT NOT NULL,
 source_port INTEGER, destination_port INTEGER, protocol TEXT NOT NULL,
 packets INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
 duration REAL NOT NULL DEFAULT 0,
 packets_per_second REAL NOT NULL DEFAULT 0, bytes_per_second REAL NOT NULL DEFAULT 0,
 mean_packet_size REAL NOT NULL DEFAULT 0, stddev_packet_size REAL NOT NULL DEFAULT 0,
 syn INTEGER NOT NULL DEFAULT 0, ack INTEGER NOT NULL DEFAULT 0,
 fin INTEGER NOT NULL DEFAULT 0, rst INTEGER NOT NULL DEFAULT 0,
 interface TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS telemetry_stats (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 packets INTEGER NOT NULL DEFAULT 0,
 tcp INTEGER NOT NULL DEFAULT 0,
 udp INTEGER NOT NULL DEFAULT 0,
 icmp INTEGER NOT NULL DEFAULT 0,
 dns INTEGER NOT NULL DEFAULT 0,
 threats INTEGER NOT NULL DEFAULT 0,
 critical INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS host_stats (
 host TEXT PRIMARY KEY,
 packets INTEGER NOT NULL DEFAULT 0,
 alert_count INTEGER NOT NULL DEFAULT 0,
 critical_count INTEGER NOT NULL DEFAULT 0,
 max_risk INTEGER NOT NULL DEFAULT 0,
 last_alert TEXT
);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_source ON traffic(source);
CREATE INDEX IF NOT EXISTS idx_traffic_destination ON traffic(destination);
CREATE INDEX IF NOT EXISTS idx_traffic_source_destination ON traffic(source, destination);
CREATE INDEX IF NOT EXISTS idx_traffic_protocol ON traffic(protocol);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
CREATE INDEX IF NOT EXISTS idx_alerts_source_severity ON alerts(source, severity);
CREATE INDEX IF NOT EXISTS idx_flows_last_timestamp ON flows(last_timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_source ON flows(source);
CREATE INDEX IF NOT EXISTS idx_flows_destination ON flows(destination);
CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol);


"""


def connect(path: Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    c = sqlite3.connect(path, timeout=10)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def _seed_stats(c: sqlite3.Connection):
    # Reconcile the cached counters at startup. Normal runtime updates remain
    # O(1); this one-time check also repairs counters after a legacy upgrade or
    # an interrupted/manual database change.
    traffic = c.execute(
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
        """INSERT INTO telemetry_stats(id,packets,tcp,udp,icmp,dns,threats,critical,revision)
           VALUES(1,?,?,?,?,?,?,?,0)
           ON CONFLICT(id) DO UPDATE SET
             packets=excluded.packets,
             tcp=excluded.tcp,
             udp=excluded.udp,
             icmp=excluded.icmp,
             dns=excluded.dns,
             threats=excluded.threats,
             critical=excluded.critical""",
        (traffic["packets"], traffic["tcp"], traffic["udp"], traffic["icmp"], traffic["dns"], alerts["threats"], alerts["critical"]),
    )
    _rebuild_host_stats(c)



def _add_column(c: sqlite3.Connection, table: str, column: str, definition: str) -> bool:
    """Add a missing column to a legacy database without destructive migration."""
    columns = {row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()}
    if column in columns:
        return False
    c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    return True


def _migrate(c: sqlite3.Connection):
    # NEMOS has intentionally used additive migrations so upgrades never
    # require deleting telemetry. Keep this list in sync with SCHEMA.
    # Optional/current columns are added with safe defaults. Core identity
    # columns are created by SCHEMA and are intentionally not altered here.
    for column, definition in (
        ("source_port", "INTEGER"),
        ("destination_port", "INTEGER"),
        ("packet_size", "INTEGER NOT NULL DEFAULT 0"),
        ("flags", "TEXT NOT NULL DEFAULT ''"),
        ("interface", "TEXT NOT NULL DEFAULT ''"),
        ("direction", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("metadata", "TEXT NOT NULL DEFAULT '{}'"),
    ):
        _add_column(c, "traffic", column, definition)

    for column, definition in (
        ("risk_score", "INTEGER NOT NULL DEFAULT 0"),
        ("confidence", "INTEGER NOT NULL DEFAULT 0"),
        ("ports_scanned", "INTEGER NOT NULL DEFAULT 0"),
        ("packets", "INTEGER NOT NULL DEFAULT 0"),
        ("destinations", "INTEGER NOT NULL DEFAULT 0"),
        ("ports", "INTEGER NOT NULL DEFAULT 0"),
        ("window_seconds", "INTEGER NOT NULL DEFAULT 0"),
        ("technique", "TEXT NOT NULL DEFAULT ''"),
        ("incident_id", "TEXT NOT NULL DEFAULT ''"),
        ("evidence", "TEXT NOT NULL DEFAULT '{}'"),
        ("acknowledged", "INTEGER NOT NULL DEFAULT 0"),
    ):
        _add_column(c, "alerts", column, definition)

    for column in ("packets", "tcp", "udp", "icmp", "dns", "threats", "critical", "revision"):
        _add_column(c, "telemetry_stats", column, "INTEGER NOT NULL DEFAULT 0")

    c.execute("CREATE TABLE IF NOT EXISTS host_stats (host TEXT PRIMARY KEY, packets INTEGER NOT NULL DEFAULT 0, alert_count INTEGER NOT NULL DEFAULT 0, critical_count INTEGER NOT NULL DEFAULT 0, max_risk INTEGER NOT NULL DEFAULT 0, last_alert TEXT)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_host_stats_risk ON host_stats(max_risk, critical_count, packets)")
    # Create indexes that depend on migrated columns only after additive
    # migrations have completed. This keeps upgrades from legacy databases
    # valid when incident_id/acknowledged did not exist in the old schema.
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident_id_id ON alerts(incident_id, id DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident_source ON alerts(incident_id, source)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged)")


def _rebuild_host_stats(c: sqlite3.Connection):
    c.execute("DELETE FROM host_stats")
    c.execute("""INSERT INTO host_stats(host, packets)
                 SELECT host, SUM(packets) FROM (
                   SELECT source AS host, COUNT(*) AS packets FROM traffic GROUP BY source
                   UNION ALL
                   SELECT destination AS host, COUNT(*) AS packets FROM traffic GROUP BY destination
                 ) GROUP BY host""")
    c.execute("""
        INSERT INTO host_stats(host, alert_count, critical_count, max_risk, last_alert)
        SELECT source, COUNT(*), SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END),
               COALESCE(MAX(risk_score),0), MAX(timestamp)
        FROM alerts GROUP BY source
        ON CONFLICT(host) DO UPDATE SET
          alert_count=excluded.alert_count, critical_count=excluded.critical_count,
          max_risk=excluded.max_risk, last_alert=excluded.last_alert
    """)


def initialize(path: Path):
    c = connect(path)
    try:
        c.executescript(SCHEMA)
        _migrate(c)
        _seed_stats(c)
        c.commit()
    finally:
        c.close()
