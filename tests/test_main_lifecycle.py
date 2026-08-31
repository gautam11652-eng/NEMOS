import importlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class MainLifecycleTests(unittest.TestCase):
    def _load_main_with_stubs(self):
        calls = []
        fake_settings = types.SimpleNamespace(
            log_level="INFO", db_path=Path("/tmp/nemos-test.db"), batch_size=1,
            flush_seconds=0.01, max_traffic=100, max_alerts=100,
            capture_enabled=False, interface=None, host="127.0.0.1", port=0,
            analysis_enabled=True, analysis_window=10.0, max_flows=100,
            persist_flows=True, model_dir=Path("/tmp/nemos-test-model"),
            heartbeat_seconds=0.0, watchdog_poll_seconds=15.0,
        )

        class Writer:
            def __init__(self, *args, **kwargs): calls.append(("writer_init", args, kwargs))
            def start(self): calls.append(("writer_start",))
            def shutdown(self, timeout=10): calls.append(("writer_shutdown", timeout))
            def submit_traffic(self, event): return True
            def submit_alert(self, alert): return True
            def submit_flow(self, flow): return True

        class DetectorConfig:
            @classmethod
            def from_env(cls): return cls()

        class Detector:
            def __init__(self, cfg): pass
            def process(self, event, packet_type): return []
            def observe_arp(self, *args): return None

        class Server:
            def __init__(self, run_action): self.run_action = run_action; self.closed = 0
            def run(self):
                try:
                    self.run_action()
                except Exception as exc:
                    if exc.__class__.__name__ == "ShutdownRequested":
                        calls.append(("waitress_caught_shutdown_requested",))
                    else:
                        raise
            def close(self): self.closed += 1; calls.append(("server_close",))

        server_holder = {}

        def create_server(app, **kwargs):
            def trigger_signal():
                import signal
                handler = signal_handlers[signal.SIGINT]
                handler(None, None)
            server = Server(trigger_signal)
            server_holder["server"] = server
            calls.append(("server_create", kwargs))
            return server

        signal_handlers = {}

        fake_api = types.ModuleType("nemos.api")
        fake_api.create_app = lambda *a, **k: object()
        fake_capture = types.ModuleType("nemos.capture")
        fake_capture.PacketCapture = object
        fake_config = types.ModuleType("nemos.config")
        fake_config.load_settings = lambda base=None: fake_settings
        fake_database = types.ModuleType("nemos.database")
        fake_database.initialize = lambda path: calls.append(("initialize", path))
        fake_detector = types.ModuleType("nemos.detector")
        fake_detector.DetectionConfig = DetectorConfig
        fake_detector.ThreatDetector = Detector
        fake_models = types.ModuleType("nemos.models")
        fake_models.TrafficEvent = object
        fake_models.Alert = object

        class Analysis:
            """Stub analysis engine: records lifecycle calls only."""

            def __init__(self, **kwargs): calls.append(("analysis_init", kwargs))
            def start(self): calls.append(("analysis_start",))
            def observe(self, event): pass
            def record_rule_alerts(self, source, alerts): pass
            def run_cycle(self, now=None, force=False):
                calls.append(("analysis_final_cycle", force))
            def stop(self, timeout=5): calls.append(("analysis_stop", timeout))
            def status(self): return {}

        fake_analysis = types.ModuleType("nemos.analysis")
        fake_analysis.AnalysisEngine = Analysis

        class AnalystStub:
            available = False
            def __init__(self, config=None): pass
            def status(self): return {"available": False}

        fake_analyst = types.ModuleType("nemos.analyst")
        fake_analyst.Analyst = AnalystStub
        fake_analyst.AnalystConfig = types.SimpleNamespace(from_env=lambda: None)
        fake_storage = types.ModuleType("nemos.storage")
        fake_storage.BatchWriter = Writer
        fake_waitress = types.ModuleType("waitress")
        fake_waitress.create_server = create_server

        modules = {
            "nemos.api": fake_api, "nemos.capture": fake_capture,
            "nemos.config": fake_config, "nemos.database": fake_database,
            "nemos.detector": fake_detector, "nemos.models": fake_models,
            "nemos.storage": fake_storage, "waitress": fake_waitress,
            "nemos.analysis": fake_analysis, "nemos.analyst": fake_analyst,
        }
        with patch.dict(sys.modules, modules):
            main_mod = importlib.reload(importlib.import_module("main"))
            def fake_signal(signum, handler):
                signal_handlers[signum] = handler
                return None
            with patch.object(main_mod.signal, "signal", side_effect=fake_signal):
                result = main_mod.main()
        return result, calls, server_holder

    def test_sigint_closes_server_and_cleans_up_without_hanging(self):
        result, calls, server_holder = self._load_main_with_stubs()
        self.assertEqual(result, 0)
        self.assertIn(("server_close",), calls)
        self.assertIn(("waitress_caught_shutdown_requested",), calls)
        self.assertIn(("writer_shutdown", 10), calls)
        self.assertEqual(server_holder["server"].closed, 1)

    def test_analysis_engine_is_started_and_drained_on_shutdown(self):
        """A final forced cycle must run so in-flight flows are not lost."""
        _, calls, _ = self._load_main_with_stubs()
        self.assertIn(("analysis_start",), calls)
        self.assertIn(("analysis_final_cycle", True), calls)
        self.assertIn(("analysis_stop", 5), calls)

    def test_shutdown_order_stops_producers_before_consumers(self):
        """Analysis must drain before the writer closes, or its final alerts
        and flows would be submitted to a writer that is no longer accepting."""
        _, calls, _ = self._load_main_with_stubs()
        names = [c[0] for c in calls]
        self.assertLess(names.index("analysis_stop"), names.index("writer_shutdown"))


if __name__ == "__main__":
    unittest.main()
