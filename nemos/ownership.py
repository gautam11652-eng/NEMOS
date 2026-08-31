"""Keep files created under ``sudo`` usable by the person who ran it.

Packet capture needs CAP_NET_RAW, so the sensor is commonly started with
``sudo python main.py``. Everything it then creates -- the SQLite database, the
data directory, the trained model -- is owned by root. The next command the
operator runs *without* sudo, such as training a model, fails on a file it
appears to own but cannot read.

That was reported from a real Kali deployment: ``data/nemos.db`` came out
root-owned and training could not open it until ownership was corrected by
hand. Nothing in NEMOS caused that to be discoverable; the failure surfaced as
a bare permission error on a path the user had never chosen to make root's.

The fix is narrow on purpose. When -- and only when -- the process is running
as root *via sudo*, files NEMOS creates are given back to the invoking user.
A deliberate ``su`` to root, a root login, or a systemd unit running as root
sets no SUDO_UID, so nothing is changed there: those are cases where root
ownership is intended.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


def sudo_owner() -> tuple[int, int] | None:
    """Return (uid, gid) of the user behind sudo, or None if not applicable.

    None covers every case where re-owning would be wrong or impossible: not
    root, not under sudo, or a SUDO_UID that is not a usable integer.
    """
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    raw_uid = os.environ.get("SUDO_UID")
    if not raw_uid:
        return None
    try:
        uid = int(raw_uid)
        gid = int(os.environ.get("SUDO_GID", uid))
    except (TypeError, ValueError):
        return None
    if uid == 0:
        return None
    return uid, gid


def give_back(*paths: Path | str) -> None:
    """Hand ownership of each existing path to the user behind sudo.

    Best effort by design: a filesystem that will not take a chown, or a path
    that has since vanished, is not a reason to fail the operation the caller
    was actually performing. Failures are logged at debug level because they
    are not actionable for the operator -- the data is still written and still
    readable by root.
    """
    owner = sudo_owner()
    if owner is None:
        return
    uid, gid = owner
    for path in paths:
        target = Path(path)
        try:
            if target.exists():
                os.chown(target, uid, gid)
        except OSError as exc:  # pragma: no cover - platform dependent
            log.debug("could not re-own %s for uid %s: %s", target, uid, exc)


__all__ = ["give_back", "sudo_owner"]
