from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

# A .env holds secrets (bot tokens, API tokens). Refuse to read an oversized
# file rather than pulling an arbitrary blob into the process environment.
MAX_ENV_BYTES = 64 * 1024
MAX_VALUE_LENGTH = 4096


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_env(text: str) -> dict[str, str]:
    """Parse dotenv-style ``KEY=VALUE`` text.

    Deliberately minimal: no variable interpolation, no command substitution
    and no multi-line values. A configuration file must not be able to expand
    into arbitrary content, so this parser only ever produces literal strings.
    """
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, separator, value = line.partition("=")
        if not separator:
            continue
        key = key.strip()
        # Environment names are restricted so a malformed file cannot inject
        # surprising keys into the process environment.
        if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
            continue
        value = _strip_quotes(value.strip())
        if "\x00" in value or len(value) > MAX_VALUE_LENGTH:
            continue
        values[key] = value
    return values


def load_dotenv(path: Path, *, override: bool = False) -> dict[str, str]:
    """Load ``path`` into ``os.environ`` and return the values applied.

    Existing environment variables win by default: an explicit ``export`` or a
    systemd unit must not be silently overridden by a stale file on disk.
    Missing or unreadable files are not an error; NEMOS runs on environment
    variables alone and the file is only a convenience.
    """
    path = Path(path)
    try:
        if not path.is_file():
            return {}
        if path.stat().st_size > MAX_ENV_BYTES:
            log.warning("ignoring %s: larger than %d bytes", path, MAX_ENV_BYTES)
            return {}
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("could not read %s: %s", path, exc)
        return {}

    applied: dict[str, str] = {}
    for key, value in parse_env(text).items():
        if not override and key in os.environ:
            continue
        os.environ[key] = value
        applied[key] = value
    if applied:
        # Names only -- values in this file are secrets by design. This is DEBUG
        # because callers typically load a .env before configuring logging and
        # report the result themselves once handlers exist.
        log.debug("loaded %d setting(s) from %s: %s", len(applied), path.name, ", ".join(sorted(applied)))
    return applied


__all__ = ["load_dotenv", "parse_env", "MAX_ENV_BYTES", "MAX_VALUE_LENGTH"]
