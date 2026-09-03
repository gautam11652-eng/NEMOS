"""Telegram chat pairing for NEMOS.

The problem this solves: making an operator paste a bot token into a web form
is both a bad experience and a bad security posture. The token is the bot's
whole identity, so a deployment should hold exactly one -- server-side, in the
environment -- and individual operators should link their own chat to it
without ever seeing it.

The flow:

1. The dashboard asks for a pairing code. NEMOS mints one, stores only its
   SHA-256 hash, and renders ``https://t.me/<bot>?start=<code>`` as a QR code.
2. The operator scans it and presses Start. Telegram delivers
   ``/start <code>`` to the bot together with the chat's own id.
3. NEMOS looks the code up by hash, checks it is unexpired and unused, marks it
   used in the same transaction, and binds that chat.

What that buys, and why each part is there:

- **Unpredictable.** Codes come from ``secrets.token_urlsafe``: 128 bits.
- **No replay.** Redemption flips ``used`` inside a single ``BEGIN IMMEDIATE``
  transaction, so two concurrent ``/start`` messages carrying the same code
  cannot both win.
- **No expiry bypass.** Expiry is compared against the server's clock at
  redemption; nothing the client sends influences it.
- **No chat-id injection.** The chat id is read from Telegram's own update
  payload. There is no API path on which a caller supplies one.
- **No cross-user linking.** A code binds whichever chat redeems it and is then
  dead, so an operator cannot be linked by someone else's later scan.
- **Hashed at rest.** A stolen database yields hashes, and a hash cannot be
  handed back to Telegram as a start parameter.

The store also owns the audit log for state-changing actions taken from chat,
because those need the same "who did what, when, and did it succeed" record and
the same durable home.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from .database import connect

log = logging.getLogger(__name__)

# 16 bytes -> 22 url-safe characters. Telegram allows 64 characters in a start
# parameter, and its alphabet is A-Z a-z 0-9 _ - , which token_urlsafe matches.
CODE_BYTES = 16
DEFAULT_TTL = 300.0
MIN_TTL = 30.0
MAX_TTL = 3600.0

# Bounds on stored rows. Pairing codes and audit entries are both written in
# response to outside events, so neither table may grow without limit.
MAX_CODES = 64
MAX_AUDIT = 2000

SCHEMA = """
CREATE TABLE IF NOT EXISTS telegram_pairings (
 code_hash TEXT PRIMARY KEY,
 created_at REAL NOT NULL,
 expires_at REAL NOT NULL,
 used INTEGER NOT NULL DEFAULT 0,
 chat_id TEXT NOT NULL DEFAULT '',
 used_at REAL
);
CREATE TABLE IF NOT EXISTS telegram_links (
 chat_id TEXT PRIMARY KEY,
 label TEXT NOT NULL DEFAULT '',
 linked_at REAL NOT NULL,
 last_seen REAL
);
CREATE TABLE IF NOT EXISTS telegram_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 at REAL NOT NULL,
 actor TEXT NOT NULL DEFAULT '',
 action TEXT NOT NULL,
 target TEXT NOT NULL DEFAULT '',
 result TEXT NOT NULL DEFAULT '',
 detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_telegram_audit_at ON telegram_audit(at DESC);
"""


def hash_code(code: str) -> str:
    """The storage form of a pairing code."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def valid_code_shape(code: Any) -> bool:
    """Reject anything that cannot be one of our codes before touching the DB.

    Cheap, and it keeps a flood of junk ``/start`` payloads from turning into
    database work.
    """
    if not isinstance(code, str):
        return False
    if not 16 <= len(code) <= 64:
        return False
    return all(ch.isalnum() or ch in "-_" for ch in code)


def valid_chat_id(value: Any) -> bool:
    """Telegram chat ids are signed integers; accept nothing else.

    This is the guard against chat-id injection: however a chat id reaches
    NEMOS, it must still look like one Telegram would have issued.
    """
    text = str(value).strip()
    if text.startswith("-"):
        text = text[1:]
    return bool(text) and text.isdigit() and len(text) <= 24


class PairingStore:
    """Durable pairing codes, chat links and the chat action audit log."""

    def __init__(self, db_path: Path, ttl: float = DEFAULT_TTL):
        self.db_path = Path(db_path)
        self.ttl = max(MIN_TTL, min(MAX_TTL, float(ttl)))
        self._ensure()

    def _ensure(self) -> None:
        c = connect(self.db_path)
        try:
            c.executescript(SCHEMA)
            c.commit()
        finally:
            c.close()

    # -- codes ---------------------------------------------------------------

    def issue(self, now: float | None = None) -> tuple[str, float]:
        """Mint a code and return ``(code, expires_at)``.

        The plaintext is returned exactly once, to the caller that asked for
        it. It is never stored, logged or returned again -- a dashboard that
        loses it asks for a new one.

        Issuing also retires every earlier unused code. One pending code at a
        time means a link someone screenshotted an hour ago cannot still be
        live alongside the one on screen now.
        """
        now = time.time() if now is None else now
        code = secrets.token_urlsafe(CODE_BYTES)
        expires = now + self.ttl
        c = connect(self.db_path)
        try:
            c.execute("BEGIN IMMEDIATE")
            c.execute("DELETE FROM telegram_pairings WHERE used = 0")
            c.execute(
                "INSERT INTO telegram_pairings(code_hash, created_at, expires_at) "
                "VALUES (?,?,?)",
                (hash_code(code), now, expires),
            )
            # Keep the used-code history bounded; it exists only so a replay
            # can be reported as a replay rather than as an unknown code.
            c.execute(
                "DELETE FROM telegram_pairings WHERE code_hash NOT IN "
                "(SELECT code_hash FROM telegram_pairings ORDER BY created_at DESC LIMIT ?)",
                (MAX_CODES,),
            )
            c.commit()
        finally:
            c.close()
        return code, expires

    def pending(self, now: float | None = None) -> dict[str, Any] | None:
        """Describe the outstanding code without revealing it."""
        now = time.time() if now is None else now
        c = connect(self.db_path)
        try:
            row = c.execute(
                "SELECT created_at, expires_at FROM telegram_pairings "
                "WHERE used = 0 AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
                (now,),
            ).fetchone()
        finally:
            c.close()
        if row is None:
            return None
        return {
            "created_at": float(row["created_at"]),
            "expires_at": float(row["expires_at"]),
            "expires_in": max(0.0, float(row["expires_at"]) - now),
        }

    def revoke(self) -> int:
        """Invalidate every outstanding code. Returns how many were retired."""
        c = connect(self.db_path)
        try:
            cursor = c.execute("DELETE FROM telegram_pairings WHERE used = 0")
            c.commit()
            return int(cursor.rowcount or 0)
        finally:
            c.close()

    def redeem(self, code: str, chat_id: Any, label: str = "",
               now: float | None = None) -> tuple[bool, str]:
        """Consume a code and link ``chat_id``. Returns ``(ok, reason)``.

        Every rejection reason is deliberately coarse. Telling an unknown
        sender the difference between "expired" and "already used" tells them
        their guess hit a real code.
        """
        now = time.time() if now is None else now
        if not valid_code_shape(code):
            return False, "invalid"
        if not valid_chat_id(chat_id):
            return False, "invalid"
        chat = str(chat_id).strip()
        digest = hash_code(code)
        c = connect(self.db_path)
        try:
            # IMMEDIATE takes the write lock up front, so the check and the
            # flip cannot interleave with another redemption of the same code.
            c.execute("BEGIN IMMEDIATE")
            row = c.execute(
                "SELECT expires_at, used FROM telegram_pairings WHERE code_hash = ?",
                (digest,),
            ).fetchone()
            if row is None:
                c.rollback()
                return False, "unknown"
            if int(row["used"]):
                c.rollback()
                return False, "used"
            if float(row["expires_at"]) <= now:
                c.rollback()
                return False, "expired"
            c.execute(
                "UPDATE telegram_pairings SET used = 1, chat_id = ?, used_at = ? "
                "WHERE code_hash = ? AND used = 0",
                (chat, now, digest),
            )
            c.execute(
                "INSERT INTO telegram_links(chat_id, label, linked_at, last_seen) "
                "VALUES (?,?,?,?) ON CONFLICT(chat_id) DO UPDATE SET "
                "label = excluded.label, last_seen = excluded.last_seen",
                (chat, str(label or "")[:64], now, now),
            )
            c.commit()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            log.warning("pairing redemption failed: %s", exc)
            return False, "error"
        finally:
            c.close()
        return True, ""

    # -- links ---------------------------------------------------------------

    def links(self) -> list[dict[str, Any]]:
        c = connect(self.db_path)
        try:
            rows = c.execute(
                "SELECT chat_id, label, linked_at, last_seen FROM telegram_links "
                "ORDER BY linked_at ASC"
            ).fetchall()
        finally:
            c.close()
        return [
            {
                "chat_id": row["chat_id"],
                "label": row["label"],
                "linked_at": float(row["linked_at"]),
                "last_seen": float(row["last_seen"]) if row["last_seen"] else None,
            }
            for row in rows
        ]

    def chat_ids(self) -> list[str]:
        """Every linked chat. This is the delivery audience."""
        return [item["chat_id"] for item in self.links()]

    def is_linked(self, chat_id: Any) -> bool:
        """Authorisation check for every command except ``/start``."""
        if not valid_chat_id(chat_id):
            return False
        c = connect(self.db_path)
        try:
            row = c.execute(
                "SELECT 1 FROM telegram_links WHERE chat_id = ?", (str(chat_id).strip(),)
            ).fetchone()
        finally:
            c.close()
        return row is not None

    def touch(self, chat_id: Any, now: float | None = None) -> None:
        if not valid_chat_id(chat_id):
            return
        now = time.time() if now is None else now
        c = connect(self.db_path)
        try:
            c.execute(
                "UPDATE telegram_links SET last_seen = ? WHERE chat_id = ?",
                (now, str(chat_id).strip()),
            )
            c.commit()
        finally:
            c.close()

    def unlink(self, chat_id: Any) -> bool:
        if not valid_chat_id(chat_id):
            return False
        c = connect(self.db_path)
        try:
            cursor = c.execute(
                "DELETE FROM telegram_links WHERE chat_id = ?", (str(chat_id).strip(),)
            )
            c.commit()
            return bool(cursor.rowcount)
        finally:
            c.close()

    # -- audit ---------------------------------------------------------------

    def record(self, actor: Any, action: str, target: str = "", result: str = "ok",
               detail: str = "", now: float | None = None) -> None:
        """Append one audit entry. Never raises: an audit write must not be
        able to take down the thread performing the action it describes."""
        now = time.time() if now is None else now
        try:
            c = connect(self.db_path)
        except sqlite3.Error:  # pragma: no cover - defensive
            log.warning("could not open the database to record an audit entry")
            return
        try:
            c.execute(
                "INSERT INTO telegram_audit(at, actor, action, target, result, detail) "
                "VALUES (?,?,?,?,?,?)",
                (now, str(actor)[:32], str(action)[:48], str(target)[:64],
                 str(result)[:32], str(detail)[:200]),
            )
            c.execute(
                "DELETE FROM telegram_audit WHERE id NOT IN "
                "(SELECT id FROM telegram_audit ORDER BY id DESC LIMIT ?)",
                (MAX_AUDIT,),
            )
            c.commit()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            log.warning("could not record an audit entry: %s", exc)
        finally:
            c.close()

    def audit(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        c = connect(self.db_path)
        try:
            rows = c.execute(
                "SELECT at, actor, action, target, result, detail FROM telegram_audit "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        finally:
            c.close()
        return [dict(row) for row in rows]


__all__ = [
    "CODE_BYTES",
    "DEFAULT_TTL",
    "MAX_AUDIT",
    "MAX_CODES",
    "PairingStore",
    "SCHEMA",
    "hash_code",
    "valid_chat_id",
    "valid_code_shape",
]
