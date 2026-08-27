import json
import subprocess
import sys
from pathlib import Path
import unittest


class DemoScriptTests(unittest.TestCase):
    def test_validate_detection_runs_directly_from_project_root(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, str(root / "tools" / "validate_detection.py")],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "PASS")
        self.assertGreater(payload["alert_count"], 0)


if __name__ == "__main__":
    unittest.main()
