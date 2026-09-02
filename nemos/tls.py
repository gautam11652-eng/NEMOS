"""TLS handshake fingerprinting: JA3 and JA3S.

Encrypted traffic is the blind spot every metadata-only sensor has. NEMOS can
see that a host opened a TLS session and how much data crossed it, but not what
was said -- and increasingly, everything worth seeing is inside that session.

The handshake is the one part that is not encrypted. Before a session key
exists, client and server must negotiate in cleartext: which TLS versions they
speak, which ciphers, which extensions, which curves. That negotiation is a
property of the *software*, not of the user, and it is remarkably distinctive.
Chrome, curl, python-requests, Go's crypto/tls and a Cobalt Strike beacon all
present recognisably different handshakes. JA3 is the standard way to hash that
into one comparable string.

**This module never reads application data.** It parses the ClientHello and
ServerHello and stops. Everything after the handshake is ciphertext and is not
touched, so NEMOS's claim that it does not inspect encrypted payloads remains
exactly true. What it now also reads is the unencrypted negotiation in front of
that, and the server name in it.

Two things are easy to get wrong and both are handled here.

**GREASE must be stripped.** RFC 8701 has clients inject reserved values into
cipher, extension and curve lists specifically so that middleboxes cannot
assume the lists are fixed. Chrome sends different GREASE values on every
single connection. Hash the lists as they arrive and Chrome gets a new
fingerprint per connection, which makes JA3 worse than useless: every browser
session looks like a brand-new piece of software. The values follow the pattern
0x?A?A with both bytes equal, and are removed before hashing.

**The input is attacker-controlled.** Every length in a handshake is a number
chosen by whoever sent the packet, on the capture thread's critical path. Each
one is bounded and range-checked against the bytes actually present; a
malformed or hostile record yields None rather than an exception or a long
loop.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

# TLS record content type 22 -- a handshake record. Application data is 23 and
# is deliberately never parsed here.
RECORD_HANDSHAKE = 0x16

HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_SERVER_HELLO = 0x02

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B

#: Legal record versions. Used to tell a TLS record from arbitrary bytes that
#: happen to begin with 0x16, so fingerprinting can key on the record header
#: rather than on a port number -- which is what lets NEMOS fingerprint TLS
#: running somewhere it has no business running.
_LEGAL_VERSIONS = frozenset({0x0300, 0x0301, 0x0302, 0x0303, 0x0304})

#: Nothing beyond this prefix of a flow is examined. A ClientHello is normally
#: well under 1 KB; the cap means a hostile peer cannot make the capture thread
#: walk an arbitrarily long buffer.
MAX_HANDSHAKE_BYTES = 4096

#: Bounds on list lengths. Real handshakes are far below these; they exist so a
#: crafted length field cannot produce a very long loop.
MAX_CIPHERS = 512
MAX_EXTENSIONS = 128
MAX_GROUPS = 256

#: An SNI host is a DNS name. Anything longer is malformed, and the value is
#: recorded, so it is truncated rather than trusted.
MAX_SNI_LENGTH = 253


def is_grease(value: int) -> bool:
    """Whether a value is a GREASE placeholder (RFC 8701).

    The reserved values are 0x0A0A, 0x1A1A, 0x2A2A ... 0xFAFA: both bytes
    equal, low nibble of each is 0xA. Leaving these in makes every Chrome
    connection a distinct fingerprint.
    """
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


@dataclass(frozen=True, slots=True)
class TLSHello:
    """What one handshake message disclosed. All of it is pre-encryption."""

    kind: str                      # "client" or "server"
    version: int = 0               # negotiated/offered version from the body
    ciphers: tuple[int, ...] = ()
    extensions: tuple[int, ...] = ()
    groups: tuple[int, ...] = ()
    point_formats: tuple[int, ...] = ()
    server_name: str = ""

    @property
    def version_name(self) -> str:
        return {
            0x0300: "SSLv3", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
            0x0303: "TLS1.2", 0x0304: "TLS1.3",
        }.get(self.version, f"0x{self.version:04x}")

    def ja3_string(self) -> str:
        """The comma/dash joined form JA3 hashes.

        Client: Version,Ciphers,Extensions,Groups,PointFormats
        Server: Version,Cipher,Extensions
        """
        join = lambda values: "-".join(str(v) for v in values)  # noqa: E731
        if self.kind == "server":
            cipher = self.ciphers[0] if self.ciphers else ""
            return f"{self.version},{cipher},{join(self.extensions)}"
        return ",".join((
            str(self.version), join(self.ciphers), join(self.extensions),
            join(self.groups), join(self.point_formats),
        ))

    def fingerprint(self) -> str:
        """The JA3 (or JA3S) hash: MD5 of the string above.

        MD5 because the JA3 specification says MD5 and the value's whole
        purpose is to be comparable with fingerprints from other tools and
        public corpora. It is an identifier, never a security control.
        """
        return hashlib.md5(  # noqa: S324 - interoperability, not security
            self.ja3_string().encode("utf-8")
        ).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            f"ja3{'s' if self.kind == 'server' else ''}": self.fingerprint(),
            "tls_version": self.version_name,
        }
        if self.server_name:
            data["sni"] = self.server_name
        return data


class _Reader:
    """Bounds-checked cursor. Any read past the end aborts the whole parse."""

    __slots__ = ("_data", "_at")

    def __init__(self, data: bytes):
        self._data = data
        self._at = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._at

    def take(self, count: int) -> bytes:
        if count < 0 or count > self.remaining:
            raise _Malformed
        chunk = self._data[self._at:self._at + count]
        self._at += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        raw = self.take(2)
        return (raw[0] << 8) | raw[1]

    def u24(self) -> int:
        raw = self.take(3)
        return (raw[0] << 16) | (raw[1] << 8) | raw[2]


class _Malformed(Exception):
    """Internal: the bytes do not form a handshake we can read."""


def looks_like_handshake(payload: bytes) -> bool:
    """Cheap pre-filter, run before any real parsing.

    Keyed on the record header rather than on a destination port, so TLS
    speaking on a port it has no business speaking on is still fingerprinted --
    which is itself worth knowing.
    """
    if len(payload) < 6 or payload[0] != RECORD_HANDSHAKE:
        return False
    version = (payload[1] << 8) | payload[2]
    if version not in _LEGAL_VERSIONS:
        return False
    return payload[5] in (HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO)


def _read_extensions(reader: _Reader, hello_kind: str) -> tuple[
        tuple[int, ...], tuple[int, ...], tuple[int, ...], str]:
    extensions: list[int] = []
    groups: list[int] = []
    point_formats: list[int] = []
    server_name = ""

    if reader.remaining < 2:
        return (), (), (), ""
    block = _Reader(reader.take(reader.u16()))

    while block.remaining >= 4 and len(extensions) < MAX_EXTENSIONS:
        ext_type = block.u16()
        body = _Reader(block.take(block.u16()))
        if not is_grease(ext_type):
            extensions.append(ext_type)

        if ext_type == EXT_SUPPORTED_GROUPS and body.remaining >= 2:
            entries = _Reader(body.take(body.u16()))
            while entries.remaining >= 2 and len(groups) < MAX_GROUPS:
                group = entries.u16()
                if not is_grease(group):
                    groups.append(group)
        elif ext_type == EXT_EC_POINT_FORMATS and body.remaining >= 1:
            entries = _Reader(body.take(body.u8()))
            while entries.remaining >= 1 and len(point_formats) < MAX_GROUPS:
                point_formats.append(entries.u8())
        elif ext_type == EXT_SERVER_NAME and hello_kind == "client" and body.remaining >= 5:
            names = _Reader(body.take(body.u16()))
            if names.remaining >= 3 and names.u8() == 0:  # host_name
                raw = names.take(names.u16())[:MAX_SNI_LENGTH]
                # A hostile SNI is an attacker-chosen string that reaches
                # storage, the API and the console, so it is decoded strictly
                # and kept to characters a DNS name can contain.
                try:
                    candidate = raw.decode("ascii")
                except UnicodeDecodeError:
                    candidate = ""
                if candidate and all(
                    c.isalnum() or c in "-._" for c in candidate
                ):
                    server_name = candidate.lower()

    return tuple(extensions), tuple(groups), tuple(point_formats), server_name


def parse_hello(payload: bytes) -> TLSHello | None:
    """Parse the first ClientHello or ServerHello in ``payload``.

    Returns None for anything that is not a readable handshake -- a truncated
    record, an unexpected message type, a length that overruns the bytes
    present. Never raises: this runs on the capture thread, where an exception
    per malformed packet is a denial of service.
    """
    if not looks_like_handshake(payload):
        return None

    try:
        reader = _Reader(payload[:MAX_HANDSHAKE_BYTES])
        reader.take(1)                       # content type, already checked
        reader.take(2)                       # record version
        record_length = reader.u16()
        # Trust the smaller of the declared length and what actually arrived:
        # a ClientHello can span TCP segments and we only ever see the first.
        body = _Reader(reader.take(min(record_length, reader.remaining)))

        message_type = body.u8()
        if message_type not in (HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO):
            return None
        kind = "client" if message_type == HANDSHAKE_CLIENT_HELLO else "server"
        body.u24()                           # handshake length
        version = body.u16()
        body.take(32)                        # random
        body.take(body.u8())                 # session id

        ciphers: list[int] = []
        if kind == "client":
            suites = _Reader(body.take(body.u16()))
            while suites.remaining >= 2 and len(ciphers) < MAX_CIPHERS:
                suite = suites.u16()
                if not is_grease(suite):
                    ciphers.append(suite)
            body.take(body.u8())             # compression methods
        else:
            ciphers.append(body.u16())       # server picks exactly one
            body.take(1)                     # compression method

        extensions, groups, formats, sni = _read_extensions(body, kind)
        return TLSHello(
            kind=kind, version=version, ciphers=tuple(ciphers),
            extensions=extensions, groups=groups, point_formats=formats,
            server_name=sni,
        )
    except (_Malformed, IndexError, ValueError):
        return None


__all__ = [
    "MAX_HANDSHAKE_BYTES",
    "TLSHello",
    "is_grease",
    "looks_like_handshake",
    "parse_hello",
]
