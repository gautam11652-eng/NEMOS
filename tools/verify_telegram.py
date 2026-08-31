#!/usr/bin/env python3
"""Send one real alert to Telegram and report exactly what happened.

NEMOS's own test suite covers the delivery path against a mock Bot API, but it
cannot prove the last hop: that *your* token and chat id work, and that a
message actually arrives on *your* device. Only you can run that, because only
you have the credentials. This does it in one command:

    python tools/verify_telegram.py

Credentials are read from the environment or a local .env, never from arguments
(a command line is visible to other users in the process table). Nothing is
printed that would disclose them.

    TELEGRAM_BOT_TOKEN=...   from @BotFather
    TELEGRAM_CHAT_ID=...     your user, group or channel id

Getting the chat id: message your bot, then open
https://api.telegram.org/bot<TOKEN>/getUpdates and read result[].message.chat.id

Exit status is 0 only when Telegram confirms delivery.
"""

from __future__ import annotations

import argparse
import sys
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
    format_alert_text,
    http_post,
    redact,
)

# Telegram's own error text, mapped to the thing that is actually wrong. These
# are the failures people hit, and the API's wording does not always make the
# cause obvious.
DIAGNOSES = (
    ("unauthorized", "The bot token is wrong or has been revoked. Re-issue it with "
                     "/token in @BotFather."),
    ("chat not found", "TELEGRAM_CHAT_ID does not name a chat this bot can reach. "
                       "For a group, add the bot to it first; the id is negative "
                       "and usually starts -100."),
    ("bot was blocked", "The recipient blocked this bot. Unblock it and try again."),
    ("bot can't initiate", "Send your bot a message first -- a bot cannot open a "
                           "conversation with a user."),
    ("not enough rights", "The bot is in the chat but lacks permission to post. "
                          "Grant it send-message rights."),
    ("too many requests", "Rate limited by Telegram. Wait and retry; NEMOS's own "
                          "token bucket normally prevents this."),
    ("deactivated", "The target account is deactivated."),
)


def diagnose(message: str) -> str:
    lowered = message.lower()
    for needle, advice in DIAGNOSES:
        if needle in lowered:
            return advice
    return ("Check the token and chat id, and that this host can reach "
            "api.telegram.org over HTTPS.")


def build_alert(severity: str) -> dict[str, object]:
    """A clearly-labelled test finding, so nobody mistakes it for a real one."""
    from nemos.models import utc_now
    return {
        "severity": severity,
        "threat": "NEMOS_DELIVERY_TEST",
        "source": "127.0.0.1",
        "risk_score": 0,
        "confidence": 0,
        "reason": "Test message from tools/verify_telegram.py. Not a detection.",
        "technique": "",
        "incident_id": "VERIFY",
        "timestamp": utc_now(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--severity", default="LOW",
                        help="severity to stamp on the test message (default: LOW)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would be sent and exit without sending")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    config = NotifierConfig.from_env()

    print("NEMOS Telegram delivery check\n")
    token, chat = config.telegram_token, config.telegram_chat_id
    print(f"  token     {'set (' + str(len(token)) + ' chars)' if token else 'MISSING'}")
    print(f"  chat id   {'set' if chat else 'MISSING'}")

    if not token or not chat:
        print("\n  Cannot test: set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in the")
        print("  environment or in a .env file beside main.py, then run this again.")
        print("  Delivery is optional -- NEMOS records every finding locally either way.")
        return 2

    if ":" not in token:
        print("\n  The token does not look like a Telegram bot token; those are of the")
        print("  form <digits>:<letters>. Copy it again from @BotFather.")
        return 2

    alert = build_alert(args.severity.upper())
    print("\n  message to send:")
    for line in format_alert_text(alert).splitlines():
        print(f"    {line}")

    if args.dry_run:
        print("\n  --dry-run: nothing was sent.")
        return 0

    channel = TelegramChannel(token, chat, api_base=TELEGRAM_API_BASE)
    print(f"\n  sending to {TELEGRAM_API_BASE}/bot<redacted>/sendMessage ...")
    try:
        channel.send(alert, http_post, args.timeout)
    except DeliveryError as exc:
        message = redact(str(exc), token)
        print(f"\n  FAILED: {message}\n")
        print(f"  Likely cause: {diagnose(message)}")
        return 1
    except OSError as exc:
        # Network-level: DNS, TLS, proxy, no route.
        print(f"\n  FAILED before Telegram answered: {redact(str(exc), token)}\n")
        print("  Likely cause: this host cannot reach api.telegram.org. Check DNS,")
        print("  egress firewall rules and any HTTPS proxy.")
        return 1

    print("\n  DELIVERED. Telegram confirmed the message; check your chat.\n")
    print("  This proves the last hop only. To see NEMOS itself deliver a finding,")
    print("  set NEMOS_NOTIFY=true and NEMOS_NOTIFY_MIN_SEVERITY to a level your")
    print("  traffic actually reaches, then run the sensor.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
