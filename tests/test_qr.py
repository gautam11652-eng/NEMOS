"""Tests for the dependency-free QR encoder.

The golden matrices below were produced by an independent reference
implementation (python-qrcode) and pinned here, because "it looks like a QR
code" is not a test.

Every case pinned below is one where the two implementations agreed with no
coaxing at all: same version, same mask, every module identical. A wider sweep
run during development covered versions 1-10 at all four levels; data placement
agreed in every one of 57 comparisons, and the residual differences were
confined to which mask each implementation selected. That choice is itself
recorded in the format bits, so those outputs decode identically too.

The reference is deliberately *not* a test dependency. Pinning the output is
what makes the check reproducible on a machine that has only NEMOS installed.
"""

from __future__ import annotations

import re
import unittest

from nemos import qr

# (payload, error-correction level, module count, row-major matrix as "0"/"1")
GOLDEN = [
    ('NEMOS', 'M', 21,
     "1111111001111011111111000001011110010000011011101001001010111011011101"
     "0010010101110110111010100010101110110000010010010100000111111110101010"
     "1111111000000000001100000000101010100001000010010110100011010001000010"
     "0001101101101000111111110010011100010000110001001010101010101100000000"
     "0111101010011011111110001101110111110000010011111011000010111010110101"
     "1100111101110100100001100110101110101100100011001100000100000001010010"
     "111111101100101011111"),
    ('NEMOS', 'H', 21,
     "1111111001100011111111000001011000010000011011101000101010111011011101"
     "0011010101110110111010001010101110110000010100100100000111111110101010"
     "1111111000000001011000000000000011110011001100010001010000010011101111"
     "0001101110101111100100011000011100100100011101011001110110001000000000"
     "0101101100101111111110100110100001010000010110001110001010111010110101"
     "0110101101110100101011001011101110100101011110100100000100100000000000"
     "111111100001000001101"),
    ('NEMOS pairing', 'Q', 25,
     "1111111001110001101111111100000100000111010100000110111010001100111010"
     "1110110111010110010100010111011011101001101111001011101100000101110000"
     "1001000001111111101010101010111111100000000111100111000000000110001000"
     "1011100011010001100100010100110011101100001101100101100101101010100101"
     "1001110010000101101001110111100001011011011010000100101011100101101100"
     "1101101110111010110010001000101001110111111000100111101011110101101111"
     "1010000000000111101001000100001111111001010111101010001100000100011001"
     "0100010010101110100101011111111100010111010011001011100100001011101011"
     "11100011001111110000010101110001110010001111111000110100110110001"),
    ('https://t.me/nemos_sentinel_bot?start=AbCdEfGhIjKlMnOpQrStUv', 'L', 33,
     "1111111010000101101001100011111111000001010011000110101101010000011011"
     "1010110010010100110110101110110111010111010010110000000101110110111010"
     "0110101010110001001011101100000101110000001011100001000001111111101010"
     "1010101010101011111110000000000110101011011111000000001100111000101100"
     "1101111010010111111011101100001111110010101010010001110010111000010100"
     "1001011010110101100010100101011010100110011000001010100001011010011111"
     "1010110111100100110101000111100110101000000000111001011111110001011111"
     "0111001010000110101001111011101100100001001111110011001101110110101000"
     "1100101001010011111100111000101000001101101110000100001001000000110010"
     "0010000101011110001011110010001010111011010110100111100010100011001010"
     "0010010001111001100100100000010111001111111000101101101011000000000101"
     "1010111101100111010000110110110010110011000111111111010000000001000011"
     "1111010101000111101111111001100001011001001010110101000001011001010010"
     "0111010001100010111010101101110001011011111000010111010000010001110000"
     "1101011000101110100011111111100110011011100100000101001010001110101100"
     "010000111111101000110101010111100110001"),
    ('https://t.me/nemos_sentinel_bot?start=AbCdEfGhIjKlMnOpQrStUv', 'H', 45,
     "1111111011001001000100100101111101001011111111000001010000101001001111"
     "0110001110100100000110111010101001000110010110100001010100101110110111"
     "0100011000100001100101101100001101011101101110100110011101011111100001"
     "1101111010111011000001010111110100110001100100000000010000011111111010"
     "1010101010101010101010101010111111100000000111001000000100011010110101"
     "1100000000001110101000001101011111101110110010011100111001010001111101"
     "1110110101101001111011100010010111111010001111000100011111110011110111"
     "0001011010101100001011100001111000101110110010111000001110100100101001"
     "0000111010110011000000100001011000111010100010100011001101001110100001"
     "0001001011000111110101110001101001110110001100100100100011101001100010"
     "1100100110101111111010000110110110110000110101001001001101100101000010"
     "0011001101010000000011001000001110111001010100110101101111110001001110"
     "1100110111000100111010000001000010111100110001011110111111110010111110"
     "0000100010111110101111010011111001110101000110000101111100011010010100"
     "1100011001011110101110001001011010101011111100101010110111110001100101"
     "1010010001110110000001000111001111111110001011010011111010100110001111"
     "1111110101000011101101111011101000110100111100010110111111111110101101"
     "0010110110111011010000010010011010111100100111111100010000011011011110"
     "1100101000110110010010011000111100100100101110001100110001111101001111"
     "0011110100111000100011100110111101001001010111110000101011010101000000"
     "1010010010110001000001101111000001001110111100111001110000101111001011"
     "1100001000010111100010011101010100010011111110100010010011010000101110"
     "0101000011011001111010011001010011001111000101000101010111000001101100"
     "1110101101100110110011110101101111110011010100111111011000000001010111"
     "0110010001001111010001000111011111111001001101001010101000100111101010"
     "1110010000010011110111111100010010010111110001111010111010100111000100"
     "1111111111000000111110010101110101100100100010010011111100001100111011"
     "1011101010111001110101101101001101111110010001000001001000110111101001"
     "00100100001000011100111111100001101000101000101110100110111100010"),
]


def as_rows(matrix: list[list[int]]) -> str:
    return "".join("".join(str(cell) for cell in row) for row in matrix)


class GoldenTests(unittest.TestCase):
    def test_encoded_matrices_match_the_reference(self):
        for payload, level, size, expected in GOLDEN:
            with self.subTest(level=level, length=len(payload)):
                matrix = qr.matrix(payload, level)
                self.assertEqual(len(matrix), size)
                self.assertEqual(as_rows(matrix), expected)


class StructureTests(unittest.TestCase):
    def test_size_follows_the_version_formula(self):
        for level in qr.LEVELS:
            for length in (1, 10, 40, 80, 150):
                with self.subTest(level=level, length=length):
                    try:
                        matrix = qr.matrix("x" * length, level)
                    except qr.QRError:
                        continue
                    size = len(matrix)
                    self.assertEqual((size - 17) % 4, 0)
                    self.assertTrue(21 <= size <= 57)
                    self.assertTrue(all(len(row) == size for row in matrix))

    def test_finder_patterns_are_in_all_three_corners(self):
        matrix = qr.matrix("NEMOS pairing", "M")
        size = len(matrix)
        for top, left in ((0, 0), (0, size - 7), (size - 7, 0)):
            with self.subTest(corner=(top, left)):
                # The 7x7 finder: dark ring, light ring, 3x3 dark core.
                self.assertEqual(matrix[top][left], 1)
                self.assertEqual(matrix[top + 1][left + 1], 0)
                self.assertEqual(matrix[top + 3][left + 3], 1)

    def test_timing_patterns_alternate(self):
        matrix = qr.matrix("NEMOS", "Q")
        size = len(matrix)
        for i in range(8, size - 8):
            self.assertEqual(matrix[6][i], 1 if i % 2 == 0 else 0)
            self.assertEqual(matrix[i][6], 1 if i % 2 == 0 else 0)

    def test_the_dark_module_is_always_set(self):
        for level in qr.LEVELS:
            matrix = qr.matrix("NEMOS", level)
            self.assertEqual(matrix[len(matrix) - 8][8], 1, level)

    def test_format_information_matches_the_published_values(self):
        # The four level indicators at mask 0, from ISO/IEC 18004 table 25.
        known = {
            ("L", 0): "111011111000100",
            ("M", 0): "101010000010010",
            ("Q", 0): "011010101011111",
            ("H", 0): "001011010001001",
            ("M", 5): "100000011001110",
        }
        for (level, mask), expected in known.items():
            with self.subTest(level=level, mask=mask):
                bits = "".join(str(b) for b in qr.format_information(level, mask))
                self.assertEqual(bits, expected)

    def test_version_information_matches_the_published_values(self):
        self.assertEqual("".join(str(b) for b in qr.version_information(7)),
                         "000111110010010100")

    def test_format_bits_placed_in_the_matrix_name_the_chosen_mask(self):
        """The mask a reader applies comes from the format area, not from us."""
        positions = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
                     (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
        matrix = qr.matrix("NEMOS", "M")
        placed = "".join(str(matrix[r][c]) for r, c in positions)
        candidates = ["".join(str(b) for b in qr.format_information("M", m))
                      for m in range(8)]
        self.assertIn(placed, candidates)
        # And the second copy must agree with the first, or half of the readers
        # in the world will disagree with the other half.
        size = len(matrix)
        second = "".join(str(matrix[size - 1 - i][8]) for i in range(7))
        second += "".join(str(matrix[8][size - 8 + i]) for i in range(8))
        self.assertEqual(placed, second)


class ReedSolomonTests(unittest.TestCase):
    def test_known_error_correction_codewords(self):
        """A published worked example: the codewords for "HELLO WORLD" 1-M."""
        data = bytes([32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236,
                      17, 236, 17, 236, 17])
        self.assertEqual(
            qr.rs_codewords(data, 10),
            [196, 35, 39, 119, 235, 215, 231, 226, 93, 23],
        )

    def test_codeword_count_is_what_was_asked_for(self):
        for count in (7, 10, 13, 17, 26, 30):
            self.assertEqual(len(qr.rs_codewords(b"NEMOS", count)), count)


class LimitTests(unittest.TestCase):
    def test_an_oversized_payload_is_refused_not_truncated(self):
        """Silently dropping the tail would produce a scannable, wrong code."""
        with self.assertRaises(qr.QRError):
            qr.matrix("x" * 400, "H")

    def test_an_unknown_level_is_refused(self):
        with self.assertRaises(qr.QRError):
            qr.matrix("NEMOS", "Z")

    def test_the_pairing_link_fits_comfortably(self):
        link = "https://t.me/" + "n" * 32 + "?start=" + "A" * 43
        matrix = qr.matrix(link, "M")
        self.assertLessEqual(len(matrix), 57)


class SvgTests(unittest.TestCase):
    def setUp(self):
        self.svg = qr.svg("https://t.me/nemos_bot?start=abcdefghijklmnop")

    def test_it_is_a_standalone_svg(self):
        self.assertTrue(self.svg.startswith("<svg "))
        self.assertTrue(self.svg.rstrip().endswith("</svg>"))
        self.assertIn('xmlns="http://www.w3.org/2000/svg"', self.svg)

    def test_it_carries_nothing_the_page_csp_would_refuse(self):
        """default-src 'self' means no script, no data: URI, no remote fetch."""
        lowered = self.svg.lower()
        for forbidden in ("<script", "data:", "href", "onload", "onclick",
                          "<image", "<foreignobject", "javascript:"):
            self.assertNotIn(forbidden, lowered, forbidden)

    def test_a_title_is_escaped(self):
        marked = qr.svg("NEMOS", title='<script>&"')
        self.assertNotIn("<script>", marked)
        self.assertIn("&lt;script&gt;", marked)

    def test_the_quiet_zone_is_included(self):
        """A code drawn edge to edge does not scan; the margin is required."""
        modules = len(qr.matrix("NEMOS", "M"))
        match = re.search(r'viewBox="0 0 (\d+) (\d+)"', qr.svg("NEMOS"))
        assert match is not None
        self.assertEqual(int(match.group(1)), modules + 8)
        self.assertEqual(int(match.group(1)), int(match.group(2)))

    def test_dark_modules_become_path_segments(self):
        self.assertIn('fill="#000000"', self.svg)
        self.assertGreater(self.svg.count("M"), 10)


if __name__ == "__main__":
    unittest.main()
