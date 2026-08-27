import os
import tempfile
import unittest
from pathlib import Path
from nemos.config import load_settings


class SecurityTests(unittest.TestCase):
    def test_remote_bind_requires_token(self):
        old = os.environ.copy()
        try:
            os.environ["NEMOS_HOST"] = "0.0.0.0"
            os.environ.pop("NEMOS_API_TOKEN", None)
            with tempfile.TemporaryDirectory() as td:
                with self.assertRaises(ValueError):
                    load_settings(Path(td))
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_invalid_flush_value_falls_back(self):
        old = os.environ.copy()
        try:
            os.environ["NEMOS_DB_FLUSH_SECONDS"] = "not-a-number"
            with tempfile.TemporaryDirectory() as td:
                self.assertGreater(load_settings(Path(td)).flush_seconds, 0)
        finally:
            os.environ.clear()
            os.environ.update(old)

if __name__ == "__main__":
    unittest.main()
