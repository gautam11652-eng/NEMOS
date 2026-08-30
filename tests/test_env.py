from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from nemos.env import MAX_ENV_BYTES, load_dotenv, parse_env


class ParseEnvTests(unittest.TestCase):
    def test_basic_pairs(self):
        self.assertEqual(parse_env("A=1\nB=two"), {"A": "1", "B": "two"})

    def test_comments_and_blank_lines_ignored(self):
        text = "# comment\n\n  \nA=1\n#B=2\n"
        self.assertEqual(parse_env(text), {"A": "1"})

    def test_export_prefix_supported(self):
        self.assertEqual(parse_env("export TOKEN=abc"), {"TOKEN": "abc"})

    def test_quotes_are_stripped(self):
        self.assertEqual(parse_env("A='x'\nB=\"y\""), {"A": "x", "B": "y"})

    def test_inner_equals_preserved(self):
        self.assertEqual(parse_env("URL=https://x/y?a=b"), {"URL": "https://x/y?a=b"})

    def test_empty_value_allowed(self):
        self.assertEqual(parse_env("EMPTY="), {"EMPTY": ""})

    def test_no_interpolation(self):
        # A config file must not expand into other values or shell output.
        parsed = parse_env("A=1\nB=$A\nC=${A}\nD=`id`\nE=$(id)")
        self.assertEqual(parsed["B"], "$A")
        self.assertEqual(parsed["C"], "${A}")
        self.assertEqual(parsed["D"], "`id`")
        self.assertEqual(parsed["E"], "$(id)")

    def test_malformed_keys_are_skipped(self):
        parsed = parse_env("no-equals-here\nBAD KEY=1\n1LEADING=2\nbad-dash=3\nGOOD=4")
        self.assertEqual(parsed, {"GOOD": "4"})

    def test_oversized_value_skipped(self):
        self.assertEqual(parse_env("A=" + "x" * 5000), {})

    def test_null_byte_value_skipped(self):
        self.assertEqual(parse_env("A=ok\x00bad"), {})


class LoadDotenvTests(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.copy()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / ".env"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved)

    def test_values_reach_the_environment(self):
        self.path.write_text("NEMOS_TEST_ENV_A=hello\n", encoding="utf-8")
        applied = load_dotenv(self.path)
        self.assertEqual(applied, {"NEMOS_TEST_ENV_A": "hello"})
        self.assertEqual(os.environ["NEMOS_TEST_ENV_A"], "hello")

    def test_existing_environment_wins(self):
        # A systemd unit or explicit export must not be silently overridden.
        os.environ["NEMOS_TEST_ENV_B"] = "from-environment"
        self.path.write_text("NEMOS_TEST_ENV_B=from-file\n", encoding="utf-8")
        load_dotenv(self.path)
        self.assertEqual(os.environ["NEMOS_TEST_ENV_B"], "from-environment")

    def test_override_is_opt_in(self):
        os.environ["NEMOS_TEST_ENV_C"] = "from-environment"
        self.path.write_text("NEMOS_TEST_ENV_C=from-file\n", encoding="utf-8")
        load_dotenv(self.path, override=True)
        self.assertEqual(os.environ["NEMOS_TEST_ENV_C"], "from-file")

    def test_missing_file_is_not_an_error(self):
        self.assertEqual(load_dotenv(Path(self.tmp.name) / "absent"), {})

    def test_directory_is_not_an_error(self):
        self.assertEqual(load_dotenv(Path(self.tmp.name)), {})

    def test_oversized_file_is_ignored(self):
        self.path.write_text("A=" + "x" * (MAX_ENV_BYTES + 10), encoding="utf-8")
        self.assertEqual(load_dotenv(self.path), {})

    def test_secrets_are_not_logged(self):
        self.path.write_text("TELEGRAM_BOT_TOKEN=123:VERY-SECRET\n", encoding="utf-8")
        with self.assertLogs("nemos.env", level="DEBUG") as captured:
            load_dotenv(self.path)
        joined = "\n".join(captured.output)
        self.assertIn("TELEGRAM_BOT_TOKEN", joined)
        self.assertNotIn("VERY-SECRET", joined)


if __name__ == "__main__":
    unittest.main()
