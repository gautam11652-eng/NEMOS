"""Setup tool that binds a Telegram chat without a hand-copied chat id.

The security-relevant part is the one-time code. Without it the tool would
bind whichever chat messaged the bot first, which on a bot with more than one
user means someone else receives the operator's security alerts.
"""

import importlib.util
import stat
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _tool():
    path = ROOT / "tools" / "connect_telegram.py"
    spec = importlib.util.spec_from_file_location("connect_telegram", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _update(text, chat_id=42, update_id=1, **chat):
    base = {"id": chat_id, "type": "private"}
    base.update(chat)
    return {"update_id": update_id, "message": {"text": text, "chat": base}}


class CodeMatchingTests(unittest.TestCase):
    def setUp(self):
        self.tool = _tool()

    def test_correct_code_binds_the_chat(self):
        self.assertEqual(self.tool.match_start(_update("/start abc123"), "abc123"), "42")

    def test_wrong_code_is_rejected(self):
        self.assertIsNone(self.tool.match_start(_update("/start wrong"), "abc123"))

    def test_bare_start_is_rejected(self):
        """Someone who merely finds the bot must not be bound."""
        self.assertIsNone(self.tool.match_start(_update("/start"), "abc123"))
        self.assertIsNone(self.tool.match_start(_update("/start   "), "abc123"))

    def test_other_messages_are_ignored(self):
        for text in ("hello", "/help abc123", "abc123", ""):
            self.assertIsNone(self.tool.match_start(_update(text), "abc123"), text)

    def test_a_prefix_of_the_code_is_rejected(self):
        self.assertIsNone(self.tool.match_start(_update("/start abc"), "abc123"))

    def test_negative_group_ids_are_preserved(self):
        self.assertEqual(
            self.tool.match_start(_update("/start c", chat_id=-1001234567890), "c"),
            "-1001234567890")

    def test_channel_posts_are_accepted(self):
        update = {"update_id": 1,
                  "channel_post": {"text": "/start c", "chat": {"id": -100, "type": "channel"}}}
        self.assertEqual(self.tool.match_start(update, "c"), "-100")

    def test_malformed_updates_do_not_raise(self):
        for update in ({}, {"message": {}}, {"message": {"text": "/start c"}},
                       {"message": {"text": None, "chat": {"id": 1}}}):
            self.assertIsNone(self.tool.match_start(update, "c"))


class LinkTests(unittest.TestCase):
    def test_deep_link_carries_the_code(self):
        tool = _tool()
        self.assertEqual(tool.build_link("nemos_bot", "xyz"),
                         "https://t.me/nemos_bot?start=xyz")

    def test_generated_codes_are_url_safe_and_within_telegram_limits(self):
        import secrets
        tool = _tool()
        code = secrets.token_urlsafe(tool.CODE_BYTES)
        self.assertRegex(code, r"^[A-Za-z0-9_-]+$")
        self.assertLessEqual(len(code), 64)
        self.assertGreaterEqual(len(code), 16, "too short to resist guessing")


class ChatDescriptionTests(unittest.TestCase):
    def test_names_the_chat_so_the_operator_can_confirm_it(self):
        tool = _tool()
        label = tool.describe_chat(_update("/start c", first_name="Gautam", username="g"))
        self.assertIn("Gautam", label)
        self.assertIn("@g", label)

    def test_falls_back_to_the_chat_type(self):
        tool = _tool()
        self.assertIn("private", tool.describe_chat(_update("/start c")))


class EnvWritingTests(unittest.TestCase):
    def setUp(self):
        self.tool = _tool()
        self.path = Path(tempfile.mkdtemp()) / ".env"

    def test_creates_the_file_when_absent(self):
        self.tool.write_env_value(self.path, "TELEGRAM_CHAT_ID", "42")
        self.assertIn("TELEGRAM_CHAT_ID=42", self.path.read_text())

    def test_preserves_every_other_setting(self):
        self.path.write_text("NEMOS_HOST=127.0.0.1\nTELEGRAM_BOT_TOKEN=keep-me\n")
        self.tool.write_env_value(self.path, "TELEGRAM_CHAT_ID", "42")
        text = self.path.read_text()
        self.assertIn("NEMOS_HOST=127.0.0.1", text)
        self.assertIn("TELEGRAM_BOT_TOKEN=keep-me", text)
        self.assertIn("TELEGRAM_CHAT_ID=42", text)

    def test_replaces_rather_than_duplicates(self):
        self.path.write_text("TELEGRAM_CHAT_ID=old\n")
        self.tool.write_env_value(self.path, "TELEGRAM_CHAT_ID", "new")
        text = self.path.read_text()
        self.assertEqual(text.count("TELEGRAM_CHAT_ID"), 1)
        self.assertIn("TELEGRAM_CHAT_ID=new", text)

    def test_a_commented_line_is_not_treated_as_the_setting(self):
        self.path.write_text("# TELEGRAM_CHAT_ID=example\n")
        self.tool.write_env_value(self.path, "TELEGRAM_CHAT_ID", "42")
        text = self.path.read_text()
        self.assertIn("# TELEGRAM_CHAT_ID=example", text)
        self.assertIn("\nTELEGRAM_CHAT_ID=42", text)

    def test_written_readable_only_by_the_owner(self):
        """The file sits beside a bot token."""
        self.tool.write_env_value(self.path, "TELEGRAM_CHAT_ID", "42")
        mode = stat.S_IMODE(self.path.stat().st_mode)
        self.assertEqual(mode & (stat.S_IRWXG | stat.S_IRWXO), 0,
                         f"group/other can read the file (mode {mode:o})")

    def test_the_token_is_never_written_by_this_tool(self):
        source = (ROOT / "tools" / "connect_telegram.py").read_text()
        self.assertNotIn('write_env_value(env_path, "TELEGRAM_BOT_TOKEN"', source)


class NoCredentialOnTheCommandLineTests(unittest.TestCase):
    def test_the_tool_takes_no_token_argument(self):
        """A command line is readable by other users via the process table."""
        source = (ROOT / "tools" / "connect_telegram.py").read_text()
        self.assertNotIn("--token", source)
        self.assertNotIn("--chat", source)
        self.assertIn("NotifierConfig.from_env()", source)


if __name__ == "__main__":
    unittest.main()
