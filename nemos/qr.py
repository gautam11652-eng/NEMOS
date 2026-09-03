"""A minimal, dependency-free QR encoder.

NEMOS needs exactly one QR code: the ``https://t.me/<bot>?start=<code>`` link
that pairs a Telegram chat with this sensor. That is a short ASCII string, so
this module implements the smallest correct subset of ISO/IEC 18004 that covers
it -- byte mode, versions 1 through 10, all four error-correction levels -- and
refuses anything larger rather than guessing.

Why not a library: NEMOS ships three runtime dependencies and the project rule
is to avoid adding more for a single screen. Every generated matrix in the test
suite is cross-checked against an independent reference implementation, so
"hand-rolled" does not mean "unverified".

The output is an SVG string. It is drawn as one ``<path>`` of rectangles with
no external references, no script and no raster data, so it can be served under
the dashboard's ``default-src 'self'`` content-security policy.
"""

from __future__ import annotations

# GF(256) with the QR primitive polynomial x^8 + x^4 + x^3 + x^2 + 1.
_PRIMITIVE = 0x11D
_EXP: list[int] = [0] * 512
_LOG: list[int] = [0] * 256


def _build_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= _PRIMITIVE
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _generator_poly(degree: int) -> list[int]:
    """The Reed-Solomon generator polynomial of the requested degree."""
    poly = [1]
    for i in range(degree):
        # Multiply by (x - alpha^i).
        nxt = [0] * (len(poly) + 1)
        for j, coefficient in enumerate(poly):
            nxt[j] ^= coefficient
            nxt[j + 1] ^= _gf_mul(coefficient, _EXP[i])
        poly = nxt
    return poly


def rs_codewords(data: bytes, count: int) -> list[int]:
    """Return ``count`` Reed-Solomon error-correction codewords for ``data``."""
    generator = _generator_poly(count)
    remainder = [0] * count
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        if factor:
            for i, coefficient in enumerate(generator[1:]):
                remainder[i] ^= _gf_mul(coefficient, factor)
    return remainder


# (error-correction codewords per block, [(block count, data codewords), ...])
# for versions 1..10 at levels L, M, Q, H. Taken from ISO/IEC 18004 table 9.
_BLOCKS: dict[tuple[int, str], tuple[int, tuple[tuple[int, int], ...]]] = {
    (1, "L"): (7, ((1, 19),)),
    (1, "M"): (10, ((1, 16),)),
    (1, "Q"): (13, ((1, 13),)),
    (1, "H"): (17, ((1, 9),)),
    (2, "L"): (10, ((1, 34),)),
    (2, "M"): (16, ((1, 28),)),
    (2, "Q"): (22, ((1, 22),)),
    (2, "H"): (28, ((1, 16),)),
    (3, "L"): (15, ((1, 55),)),
    (3, "M"): (26, ((1, 44),)),
    (3, "Q"): (18, ((2, 17),)),
    (3, "H"): (22, ((2, 13),)),
    (4, "L"): (20, ((1, 80),)),
    (4, "M"): (18, ((2, 32),)),
    (4, "Q"): (26, ((2, 24),)),
    (4, "H"): (16, ((4, 9),)),
    (5, "L"): (26, ((1, 108),)),
    (5, "M"): (24, ((2, 43),)),
    (5, "Q"): (18, ((2, 15), (2, 16))),
    (5, "H"): (22, ((2, 11), (2, 12))),
    (6, "L"): (18, ((2, 68),)),
    (6, "M"): (16, ((4, 27),)),
    (6, "Q"): (24, ((4, 19),)),
    (6, "H"): (28, ((4, 15),)),
    (7, "L"): (20, ((2, 78),)),
    (7, "M"): (18, ((4, 31),)),
    (7, "Q"): (18, ((2, 14), (4, 15))),
    (7, "H"): (26, ((4, 13), (1, 14))),
    (8, "L"): (24, ((2, 97),)),
    (8, "M"): (22, ((2, 38), (2, 39))),
    (8, "Q"): (22, ((4, 18), (2, 19))),
    (8, "H"): (26, ((4, 14), (2, 15))),
    (9, "L"): (30, ((2, 116),)),
    (9, "M"): (22, ((3, 36), (2, 37))),
    (9, "Q"): (20, ((4, 16), (4, 17))),
    (9, "H"): (24, ((4, 12), (4, 13))),
    (10, "L"): (18, ((2, 68), (2, 69))),
    (10, "M"): (26, ((4, 43), (1, 44))),
    (10, "Q"): (24, ((6, 19), (2, 20))),
    (10, "H"): (28, ((6, 15), (2, 16))),
}

MAX_VERSION = 10

# Alignment-pattern row/column centres per version (1 has none).
_ALIGNMENT: dict[int, tuple[int, ...]] = {
    1: (),
    2: (6, 18),
    3: (6, 22),
    4: (6, 26),
    5: (6, 30),
    6: (6, 34),
    7: (6, 22, 38),
    8: (6, 24, 42),
    9: (6, 26, 46),
    10: (6, 28, 50),
}

# The two-bit level indicator used in the format information.
_LEVEL_BITS = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}

LEVELS = ("L", "M", "Q", "H")


class QRError(ValueError):
    """Raised when the payload cannot be encoded within the supported range."""


def _capacity(version: int, level: str) -> int:
    ec, groups = _BLOCKS[(version, level)]
    return sum(blocks * words for blocks, words in groups)


def _choose_version(length: int, level: str) -> int:
    for version in range(1, MAX_VERSION + 1):
        # Mode indicator (4 bits) + character count + payload, in bytes.
        count_bits = 8 if version < 10 else 16
        needed = (4 + count_bits + length * 8 + 7) // 8
        if needed <= _capacity(version, level):
            return version
    raise QRError(
        f"payload of {length} bytes does not fit a version-{MAX_VERSION} "
        f"level-{level} QR code"
    )


def _bitstream(data: bytes, version: int, level: str) -> list[int]:
    capacity_bits = _capacity(version, level) * 8
    bits: list[int] = []

    def push(value: int, width: int) -> None:
        for shift in range(width - 1, -1, -1):
            bits.append((value >> shift) & 1)

    push(0b0100, 4)                      # byte mode
    push(len(data), 8 if version < 10 else 16)
    for byte in data:
        push(byte, 8)

    # Terminator, then pad to a byte boundary, then alternate pad codewords.
    push(0, min(4, capacity_bits - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    pad = (0xEC, 0x11)
    index = 0
    while len(bits) < capacity_bits:
        push(pad[index % 2], 8)
        index += 1
    return bits


def _interleave(bits: list[int], version: int, level: str) -> list[int]:
    ec_count, groups = _BLOCKS[(version, level)]
    codewords = [int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]

    blocks: list[list[int]] = []
    ec_blocks: list[list[int]] = []
    cursor = 0
    for count, size in groups:
        for _ in range(count):
            block = codewords[cursor:cursor + size]
            cursor += size
            blocks.append(block)
            ec_blocks.append(rs_codewords(bytes(block), ec_count))

    out: list[int] = []
    for i in range(max(len(b) for b in blocks)):
        for block in blocks:
            if i < len(block):
                out.append(block[i])
    for i in range(ec_count):
        for block in ec_blocks:
            out.append(block[i])

    result: list[int] = []
    for byte in out:
        for shift in range(7, -1, -1):
            result.append((byte >> shift) & 1)
    return result


def _bch(value: int, generator: int, width: int) -> int:
    """Return the BCH remainder of ``value`` shifted left by ``width`` bits."""
    remainder = value << width
    generator_bits = generator.bit_length()
    while remainder.bit_length() >= generator_bits:
        remainder ^= generator << (remainder.bit_length() - generator_bits)
    return remainder


def format_information(level: str, mask: int) -> list[int]:
    """The 15 format bits, most significant first."""
    value = (_LEVEL_BITS[level] << 3) | mask
    encoded = ((value << 10) | _bch(value, 0x537, 10)) ^ 0x5412
    return [(encoded >> shift) & 1 for shift in range(14, -1, -1)]


def version_information(version: int) -> list[int]:
    """The 18 version bits, most significant first (versions 7 and up)."""
    encoded = (version << 12) | _bch(version, 0x1F25, 12)
    return [(encoded >> shift) & 1 for shift in range(17, -1, -1)]


_MASKS = (
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
)


def _blank(size: int) -> list[list[int | None]]:
    return [[None] * size for _ in range(size)]


def _place_function_patterns(matrix: list[list[int | None]], version: int) -> None:
    size = len(matrix)

    def finder(top: int, left: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                y, x = top + r, left + c
                if not (0 <= y < size and 0 <= x < size):
                    continue
                on = (
                    0 <= r <= 6 and c in (0, 6)
                    or 0 <= c <= 6 and r in (0, 6)
                    or 2 <= r <= 4 and 2 <= c <= 4
                )
                matrix[y][x] = 1 if on else 0

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)

    for i in range(8, size - 8):
        bit = 1 if i % 2 == 0 else 0
        matrix[6][i] = bit
        matrix[i][6] = bit

    centres = _ALIGNMENT[version]
    for row in centres:
        for col in centres:
            # Alignment patterns never overlap a finder pattern.
            if (row, col) in ((6, 6), (6, centres[-1]), (centres[-1], 6)):
                continue
            for r in range(-2, 3):
                for c in range(-2, 3):
                    matrix[row + r][col + c] = (
                        1 if max(abs(r), abs(c)) != 1 else 0
                    )

    matrix[size - 8][8] = 1  # the always-dark module

    # Reserve the format areas so data placement skips them.
    for i in range(9):
        if matrix[8][i] is None:
            matrix[8][i] = 0
        if matrix[i][8] is None:
            matrix[i][8] = 0
    for i in range(8):
        if matrix[8][size - 1 - i] is None:
            matrix[8][size - 1 - i] = 0
        if matrix[size - 1 - i][8] is None:
            matrix[size - 1 - i][8] = 0

    if version >= 7:
        bits = version_information(version)
        for i in range(18):
            bit = bits[17 - i]
            row, col = i // 3, i % 3
            matrix[size - 11 + col][row] = bit
            matrix[row][size - 11 + col] = bit


def _function_mask(size: int, version: int) -> list[list[bool]]:
    probe = _blank(size)
    _place_function_patterns(probe, version)
    return [[cell is not None for cell in row] for row in probe]


def _place_data(matrix: list[list[int | None]], reserved: list[list[bool]],
                bits: list[int]) -> None:
    size = len(matrix)
    index = 0
    upward = True
    col = size - 1
    while col > 0:
        if col == 6:  # the vertical timing pattern is not a data column
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for offset in (0, 1):
                x = col - offset
                if reserved[row][x]:
                    continue
                matrix[row][x] = bits[index] if index < len(bits) else 0
                index += 1
        upward = not upward
        col -= 2


def _penalty(matrix: list[list[int]]) -> int:
    size = len(matrix)
    score = 0

    # Rule 1: runs of five or more identical modules in a row or column.
    for line in list(matrix) + [list(col) for col in zip(*matrix, strict=True)]:
        run = 1
        for i in range(1, size):
            if line[i] == line[i - 1]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run = 1
        if run >= 5:
            score += 3 + (run - 5)

    # Rule 2: 2x2 blocks of one colour.
    for r in range(size - 1):
        for c in range(size - 1):
            block = (matrix[r][c], matrix[r][c + 1], matrix[r + 1][c], matrix[r + 1][c + 1])
            if block[0] == block[1] == block[2] == block[3]:
                score += 3

    # Rule 3: the finder-like 1:1:3:1:1 pattern with four light modules beside it.
    pattern_a = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    pattern_b = list(reversed(pattern_a))
    for line in list(matrix) + [list(col) for col in zip(*matrix, strict=True)]:
        for i in range(size - 10):
            window = line[i:i + 11]
            if window == pattern_a or window == pattern_b:
                score += 40

    # Rule 4: deviation of the dark-module proportion from 50%.
    dark = sum(sum(row) for row in matrix)
    percent = dark * 100 / (size * size)
    score += 10 * int(abs(percent - 50) // 5)
    return score


def _apply_format(matrix: list[list[int]], level: str, mask: int) -> None:
    size = len(matrix)
    bits = format_information(level, mask)
    # Copy 1: around the top-left finder.
    positions = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
                 (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    for bit, (row, col) in zip(bits, positions, strict=True):
        matrix[row][col] = bit
    # Copy 2: split between the other two finders.
    for i in range(7):
        matrix[size - 1 - i][8] = bits[i]
    for i in range(8):
        matrix[8][size - 8 + i] = bits[7 + i]


def matrix(payload: str, level: str = "M") -> list[list[int]]:
    """Encode ``payload`` and return the module matrix (1 = dark)."""
    level = level.upper()
    if level not in _LEVEL_BITS:
        raise QRError(f"unknown error-correction level {level!r}")
    data = payload.encode("utf-8")
    version = _choose_version(len(data), level)
    size = version * 4 + 17

    bits = _interleave(_bitstream(data, version, level), version, level)
    reserved = _function_mask(size, version)

    best: list[list[int]] | None = None
    best_score = -1
    for mask_index, mask_fn in enumerate(_MASKS):
        grid = _blank(size)
        _place_function_patterns(grid, version)
        _place_data(grid, reserved, bits)
        candidate = [[int(cell or 0) for cell in row] for row in grid]
        for r in range(size):
            for c in range(size):
                if not reserved[r][c] and mask_fn(r, c):
                    candidate[r][c] ^= 1
        _apply_format(candidate, level, mask_index)
        score = _penalty(candidate)
        if best is None or score < best_score:
            best, best_score = candidate, score
    assert best is not None
    return best


def svg(payload: str, *, level: str = "M", quiet_zone: int = 4,
        scale: int = 4, title: str = "") -> str:
    """Render ``payload`` as a self-contained, script-free SVG string.

    The result carries no external reference and no inline event handler, so it
    is safe to embed in a page served under a restrictive CSP.
    """
    grid = matrix(payload, level)
    size = len(grid)
    span = size + quiet_zone * 2
    parts: list[str] = []
    for r, row in enumerate(grid):
        c = 0
        while c < size:
            if not row[c]:
                c += 1
                continue
            run = 1
            while c + run < size and row[c + run]:
                run += 1
            parts.append(f"M{c + quiet_zone} {r + quiet_zone}h{run}v1h-{run}z")
            c += run
    path = "".join(parts)
    label = ""
    if title:
        safe = (title.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        label = f"<title>{safe}</title>"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {span} {span}" '
        f'width="{span * scale}" height="{span * scale}" shape-rendering="crispEdges" '
        f'role="img">{label}'
        f'<rect width="{span}" height="{span}" fill="#ffffff"/>'
        f'<path d="{path}" fill="#000000"/></svg>'
    )


__all__ = [
    "LEVELS",
    "MAX_VERSION",
    "QRError",
    "format_information",
    "matrix",
    "rs_codewords",
    "svg",
    "version_information",
]
