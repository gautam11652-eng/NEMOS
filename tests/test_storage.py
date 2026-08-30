import tempfile
import time
import unittest
from pathlib import Path
from nemos.database import initialize, connect
from nemos.models import TrafficEvent, Alert
from nemos.storage import BatchWriter, Item

class StorageTests(unittest.TestCase):
    def test_batch_writer(self):
        with tempfile.TemporaryDirectory() as td:
            db=Path(td)/"test.db"; initialize(db)
            w=BatchWriter(db,batch_size=3,flush_seconds=.05);w.start()
            for i in range(7):
                w.submit_traffic(TrafficEvent("now","10.0.0.1",f"10.0.0.{i+2}","TCP",1000,80,64))
            w.submit_alert(Alert("now","TEST","TEST","10.0.0.1","LOW",10,60,"test"))
            # shutdown() drains the queue and joins the writer, so it is the
            # synchronization point; no sleep is needed before asserting.
            w.shutdown()
            c=connect(db)
            self.assertEqual(c.execute("select count(*) from traffic").fetchone()[0],7)
            self.assertEqual(c.execute("select count(*) from alerts").fetchone()[0],1)
            c.close()

    def test_shutdown_does_not_duplicate_the_final_partial_batch(self):
        """A partial batch left pending at shutdown must be written exactly once.

        The sentinel-drain path flushes `pending` and then falls through to the
        `finally` clause, which flushes whatever is still pending. If the drain
        path does not clear the list, the last batch is written twice --
        duplicating traffic rows, duplicating alerts, and double-counting the
        cached telemetry stats. A large batch_size guarantees the final batch is
        still partial, and no sleep is used so the timeout-flush path cannot
        mask the bug by emptying `pending` first.
        """
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "dupe.db"
            initialize(db)
            w = BatchWriter(db, batch_size=100, flush_seconds=30)
            w.start()
            for i in range(5):
                w.submit_traffic(TrafficEvent("now", "10.0.0.1", f"10.0.0.{i + 2}", "TCP", 1000, 80, 64))
            w.submit_alert(Alert("now", "TEST", "TEST", "10.0.0.1", "LOW", 10, 60, "test"))
            w.shutdown()

            c = connect(db)
            try:
                self.assertEqual(c.execute("select count(*) from traffic").fetchone()[0], 5)
                self.assertEqual(c.execute("select count(*) from alerts").fetchone()[0], 1)
                # Cached counters must match the rows actually stored.
                stats = c.execute("select packets, threats from telemetry_stats where id=1").fetchone()
                self.assertEqual(stats["packets"], 5)
                self.assertEqual(stats["threats"], 1)
                # And no destination may appear twice.
                dupes = c.execute(
                    "select destination, count(*) n from traffic group by destination having n > 1"
                ).fetchall()
                self.assertEqual(dupes, [])
            finally:
                c.close()


class StorageLifecycleTests(unittest.TestCase):
    def test_submit_after_shutdown_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "lifecycle.db"
            w = BatchWriter(db, batch_size=2, flush_seconds=.02)
            w.start()
            w.shutdown()
            self.assertFalse(w.submit_traffic(TrafficEvent("now", "10.0.0.1", "10.0.0.2", "TCP")))
            self.assertEqual(w.dropped_events, 1)

    def test_queue_full_is_non_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "full.db"
            w = BatchWriter(db, batch_size=100, flush_seconds=10, max_queue=2, alert_reserve=1)
            w.start()
            # Fill the traffic region; the reserved slot must remain available to alerts.
            w.q.put_nowait(Item("traffic", TrafficEvent("now", "10.0.0.1", "10.0.0.2", "TCP").as_dict()))
            w.q.put_nowait(Item("traffic", TrafficEvent("now", "10.0.0.1", "10.0.0.3", "TCP").as_dict()))
            result = w.submit_traffic(TrafficEvent("now", "10.0.0.1", "10.0.0.4", "TCP"))
            self.assertFalse(result)
            w.shutdown()

    def test_alert_reserve_and_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "priority.db"
            w = BatchWriter(db, batch_size=100, flush_seconds=10, max_queue=4, alert_reserve=1)
            w.start()
            for i in range(3):
                w.q.put_nowait(Item("traffic", TrafficEvent("now", "10.0.0.1", f"10.0.0.{i+2}", "TCP").as_dict()))
            alert = Alert("now", "TEST", "TEST", "10.0.0.1", "HIGH", 80, 90, "test")
            self.assertTrue(w.submit_alert(alert))
            metrics = w.metrics()
            self.assertGreaterEqual(metrics["queue_high_watermark"], 4)
            w.shutdown()

class StorageStatsTests(unittest.TestCase):
    def test_incremental_stats_and_retention(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "stats.db"
            initialize(db)
            w = BatchWriter(db, batch_size=2, flush_seconds=.02, max_traffic=3, max_alerts=2)
            w.start()
            for i in range(6):
                w.submit_traffic(TrafficEvent("x", "10.0.0.1", f"10.0.0.{i+2}", "TCP", None, 443, 60))
            w.shutdown()
            c = connect(db)
            try:
                row = c.execute("SELECT packets,tcp FROM telemetry_stats WHERE id=1").fetchone()
                self.assertEqual(row[0], 3)
                self.assertEqual(row[1], 3)
                self.assertEqual(c.execute("SELECT COUNT(*) FROM traffic").fetchone()[0], 3)
                hosts = {r[0]: r[1] for r in c.execute("SELECT host,packets FROM host_stats").fetchall()}
                self.assertEqual(hosts["10.0.0.1"], 3)
                self.assertEqual(hosts["10.0.0.5"], 1)
            finally:
                c.close()

    def test_host_stats_tracks_alerts_incrementally(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "host-alerts.db"
            initialize(db)
            w = BatchWriter(db, batch_size=2, flush_seconds=.02)
            w.start()
            w.submit_traffic(TrafficEvent("x", "10.0.0.10", "10.0.0.20", "TCP"))
            w.submit_alert(Alert("x", "PORT_SCAN", "RECON", "10.0.0.10", "CRITICAL", 95, 99, "test"))
            w.shutdown()
            c = connect(db)
            try:
                row = c.execute("SELECT packets,alert_count,critical_count,max_risk FROM host_stats WHERE host=?", ("10.0.0.10",)).fetchone()
                self.assertEqual(tuple(row), (1,1,1,95))
            finally:
                c.close()

class StorageFailureRecoveryTests(unittest.TestCase):
    def test_unexpected_worker_exit_can_be_shutdown_and_restarted(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "worker-failure.db"
            w = BatchWriter(db, batch_size=1, flush_seconds=.01)
            w.start()
            original_flush = w._flush

            def broken_flush(*_args, **_kwargs):
                raise RuntimeError("simulated writer failure")

            w._flush = broken_flush
            w.submit_traffic(TrafficEvent("now", "10.0.0.1", "10.0.0.2", "TCP"))
            for _ in range(50):
                if w.thread is not None and not w.thread.is_alive():
                    break
                time.sleep(.01)
            self.assertFalse(w.thread and w.thread.is_alive())
            self.assertFalse(w.metrics()["accepting"])

            # Shutdown must not hang waiting for a dead worker to consume a sentinel.
            w.shutdown(timeout=1)

            w._flush = original_flush
            w.start()
            self.assertTrue(w.submit_traffic(TrafficEvent("now", "10.0.0.1", "10.0.0.3", "TCP")))
            w.shutdown()


if __name__ == "__main__":
    unittest.main()

class StorageRetentionRepairTests(unittest.TestCase):
    def test_retention_repairs_host_max_risk_and_latest_alert(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "retention-alerts.db"
            initialize(db)
            w = BatchWriter(db, batch_size=1, flush_seconds=.01, max_alerts=2)
            w.start()
            for timestamp, risk in (
                ("2026-01-01T00:00:00Z", 99),
                ("2026-01-01T00:00:01Z", 20),
                ("2026-01-01T00:00:02Z", 10),
            ):
                self.assertTrue(
                    w.submit_alert(
                        Alert(timestamp, "TEST", "TEST", "10.0.0.1", "HIGH", risk, 90, "test")
                    )
                )
            w.shutdown()
            c = connect(db)
            try:
                row = c.execute(
                    "SELECT alert_count,max_risk,last_alert FROM host_stats WHERE host=?",
                    ("10.0.0.1",),
                ).fetchone()
                self.assertEqual(tuple(row), (2, 20, "2026-01-01T00:00:02Z"))
            finally:
                c.close()
