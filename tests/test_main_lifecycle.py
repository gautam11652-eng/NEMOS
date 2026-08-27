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
        )

        class Writer:
            def __init__(self, *args, **kwargs): calls.append(("writer_init", args, kwargs))
            def start(self): calls.append(("writer_start",))
            def shutdown(self, timeout=10): calls.append(("writer_shutdown", timeout))
            def submit_traffic(self, event): return True
            def submit_alert(self, alert): return True

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
        fake_storage = types.ModuleType("nemos.storage")
        fake_storage.BatchWriter = Writer
        fake_waitress = types.ModuleType("waitress")
        fake_waitress.create_server = create_server

        modules = {
            "nemos.api": fake_api, "nemos.capture": fake_capture,
            "nemos.config": fake_config, "nemos.database": fake_database,
            "nemos.detector": fake_detector, "nemos.models": fake_models,
            "nemos.storage": fake_storage, "waitress": fake_waitress,
        }
        with patch.dict(sys.modules, modules):
            main_mod = importlib.reload(importlib.import_module("main"))
            original_signal = main_mod.signal.signal
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


if __name__ == "__main__":
    unittest.main()
