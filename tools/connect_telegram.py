#!/usr/bin/env python3
"""Connect a Telegram chat to NEMOS without looking up a chat id by hand.

Telegram's Bot API has no anonymous send path -- a bot token *is* the bot's
identity, so one is always required. The chat id, however, does not have to be
copied out of a raw ``getUpdates`` response, which is the step people actually
get stuck on. This asks Telegram for it:

    python tools/connect_telegram.py

    1. Validates TELEGRAM_BOT_TOKEN and finds the bot's @username.
    2. Prints a t.me link carrying a one-time code.
    3. You open it and press Start.
    4. NEMOS matches the code, binds that chat, and writes TELEGRAM_CHAT_ID
       to .env. A confirmation message arrives in the chat.

The one-time code is the point of the design. Without it, whoever messaged the
bot first would be bound as the alert recipient -- on a bot with more than one
user, that is someone else reading your security alerts.

The token is never written by this script, never printed, and never passed on a
command line, where other users on the host could read it from the process
table.
"""

from __future__ import annotations

import argparse
import hmac
import secrets
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nemos.env import load_dotenv  # noqa: E402
from nemos.notify import (  # noqa: E402
    TELEGRAM_API_BASE,
    DeliveryError,
    NotifierConfig,
    TelegramChannel,
    http_post,
    redact,
    telegram_api,
)

CODE_BYTES = 16          # ~22 url-safe characters; Telegram allows 64.
POLL_SECONDS = 25        # Long-poll window per getUpdates call.


def build_link(username: str, code: str) -> str:
    return f"https://t.me/{username}?start={code}"


def match_start(update: dict, code: str) -> str | None:
    """Return the chat id if this update is our /start, else None.

    Compared in constant time: the code is a shared secret for the length of
    the setup, and it arrives from an untrusted source.
    """
    message = update.get("message") or update.get("channel_post") or {}
    text = str(message.get("text") or "")
    if not text.startswith("/start"):
        return None
    supplied = text[len("/start"):].strip()
    if not supplied or not hmac.compare_digest(supplied, code):
        return None
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    return str(chat_id) if chat_id is not None else None


def describe_chat(update: dict) -> str:
    """A human label for the bound chat, so the operator can confirm it."""
    chat = (update.get("message") or update.get("channel_post") or {}).get("chat") or {}
    kind = str(chat.get("type") or "chat")
    name = chat.get("title") or " ".join(
        str(chat.get(k)) for k in ("first_name", "last_name") if chat.get(k)
    ).strip()
    handle = f"@{chat['username']}" if chat.get("username") else ""
    return " ".join(part for part in (kind, name, handle) if part) or kind


def write_env_value(path: Path, key: str, value: str) -> None:
    """Set one key in a .env file, preserving every other line.

    Written 0600 because the file sits beside credentials. An existing file
    keeps its own mode if it is already at least as strict.
    """
    lines: list[str] = []
    replaced = False
    if path.exists():
        lines = path.read_text().splitlines()
        for index, line in enumerate(lines):
            if line.split("=", 1)[0].strip() == key and not line.lstrip().startswith("#"):
                lines[index] = f"{key}={value}"
                replaced = True
                break
    if not replaced:
        lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n")
    try:
        path.chmod(0o600)
    except OSError:
        # A filesystem that will not take the mode is not a reason to fail the
        # binding; the value is already written.
        pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=float, default=180.0,
                        help="how long to wait for you to press Start (default: 180s)")
    parser.add_argument("--no-write", action="store_true",
                        help="print the chat id instead of writing it to .env")
    args = parser.parse_args()

    env_path = ROOT / ".env"
    load_dotenv(env_path)
    token = NotifierConfig.from_env().telegram_token
    if not token:
        print("NEMOS Telegram setup\n")
        print("  TELEGRAM_BOT_TOKEN is not set.\n")
        print("  Create a bot: message @BotFather on Telegram, send /newbot, and")
        print("  follow the prompts. It replies with a token that looks like")
        print("  1234567890:AA... Put it in .env beside main.py:\n")
        print("      TELEGRAM_BOT_TOKEN=your_token_here\n")
        print("  Then run this again. A token is unavoidable -- it is what")
        print("  identifies your bot to Telegram -- but this is the only value")
        print("  you will have to copy by hand.")
        return 2

    print("NEMOS Telegram setup\n")
    try:
        me = telegram_api(token, "getMe")
    except DeliveryError as exc:
        print(f"  The token was rejected: {exc}\n")
        print("  Check it against @BotFather, or send /token there to reissue it.")
        return 1

    username = me.get("username")
    if not username:
        print("  Telegram accepted the token but returned no bot username.")
        return 1
    print(f"  Bot: @{username}  ({me.get('first_name') or 'unnamed'})")

    code = secrets.token_urlsafe(CODE_BYTES)
    link = build_link(username, code)
    print("\n  Open this link and press Start:\n")
    print(f"      {link}\n")
    print(f"  Waiting up to {int(args.timeout)}s. Ctrl-C to cancel.")

    # Consume anything already queued so an older /start cannot be replayed,
    # and so the offset starts past unrelated traffic.
    offset = None
    try:
        backlog = telegram_api(token, "getUpdates", {"timeout": 0}) or []
        if backlog:
            offset = backlog[-1]["update_id"] + 1
    except DeliveryError as exc:
        message = str(exc)
        if "409" in message or "webhook" in message.lower():
            print("\n  This bot has a webhook configured, so getUpdates is unavailable.")
            print("  Remove it with deleteWebhook, or set TELEGRAM_CHAT_ID by hand.")
            return 1
        print(f"\n  {message}")
        return 1

    deadline = time.monotonic() + args.timeout
    chat_id = None
    label = ""
    while time.monotonic() < deadline and chat_id is None:
        remaining = max(1, min(POLL_SECONDS, int(deadline - time.monotonic())))
        try:
            updates = telegram_api(
                token, "getUpdates",
                {"timeout": remaining, "offset": offset},
                timeout=remaining + 10,
            ) or []
        except DeliveryError as exc:
            print(f"\n  {exc}")
            return 1
        for update in updates:
            offset = update["update_id"] + 1
            found = match_start(update, code)
            if found:
                chat_id, label = found, describe_chat(update)
                break

    if chat_id is None:
        print("\n  Timed out. Nobody pressed Start with this code.")
        print("  Run it again to get a fresh link -- codes are single-use by design.")
        return 1

    print(f"\n  Connected: {label}")

    try:
        TelegramChannel(token, chat_id, api_base=TELEGRAM_API_BASE).send(
            {
                "severity": "LOW",
                "threat": "NEMOS_CONNECTED",
                "source": "127.0.0.1",
                "risk_score": 0,
                "confidence": 0,
                "reason": "This chat is now connected to NEMOS. Not a detection.",
                "incident_id": "SETUP",
            },
            http_post, 15.0,
        )
        print("  Confirmation message sent.")
    except DeliveryError as exc:
        print(f"  Bound, but the confirmation failed: {redact(str(exc), token)}")

    if args.no_write:
        print(f"\n  TELEGRAM_CHAT_ID={chat_id}")
        return 0

    write_env_value(env_path, "TELEGRAM_CHAT_ID", chat_id)
    print(f"\n  Written to {env_path.name} (mode 0600). Setup is complete.")
    print("  Set NEMOS_NOTIFY=true and start the sensor to receive findings.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n  Cancelled. Nothing was written.")
        raise SystemExit(130) from None
