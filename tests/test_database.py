import sqlite3
import tempfile
import unittest
from pathlib import Path

from nemos.database import connect, initialize


class DatabaseMigrationTests(unittest.TestCase):
    def test_legacy_optional_columns_are_added_and_stats_reconciled(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "legacy.db"
            c = sqlite3.connect(db)
            c.executescript(
                """
                CREATE TABLE traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT NOT NULL
                );
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    threat TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL
                );
                CREATE TABLE telemetry_stats (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    packets INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO traffic(timestamp,source,destination,protocol)
                VALUES('now','10.0.0.1','10.0.0.2','TCP');
                INSERT INTO alerts(timestamp,threat,category,source,severity,reason)
                VALUES('now','TEST','TEST','10.0.0.1','CRITICAL','legacy');
                INSERT INTO telemetry_stats(id,packets) VALUES(1,999);
                """
            )
            c.commit()
            c.close()

            initialize(db)

            c = connect(db)
            try:
                traffic_cols = {r[1] for r in c.execute("PRAGMA table_info(traffic)")}
                alert_cols = {r[1] for r in c.execute("PRAGMA table_info(alerts)")}
                stats_cols = {r[1] for r in c.execute("PRAGMA table_info(telemetry_stats)")}
                self.assertIn("metadata", traffic_cols)
                self.assertIn("acknowledged", alert_cols)
                self.assertIn("incident_id", alert_cols)
                self.assertIn("critical", stats_cols)
                self.assertTrue(c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='host_stats'").fetchone())
                stats = c.execute(
                    "SELECT packets,tcp,threats,critical FROM telemetry_stats WHERE id=1"
                ).fetchone()
                self.assertEqual(tuple(stats), (1, 1, 1, 1))
            finally:
                c.close()


if __name__ == "__main__":
    unittest.main()
