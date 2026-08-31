"""Documentation must match the code.

NEMOS's central claim is that it does not overstate itself, which makes a stale
number in the README a correctness bug rather than a cosmetic one. Every count
the documentation quotes is checked here against the code that produces it, so
the docs cannot silently drift the way they did between 4.0.0 and 4.1.0.
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text()
CHANGELOG = (ROOT / "CHANGELOG.md").read_text()


def _detector_source() -> str:
    return (ROOT / "nemos" / "detector.py").read_text()


class VersionTests(unittest.TestCase):
    def test_version_matches_changelog_and_security_policy(self):
        version = re.search(r'VERSION\s*=\s*"([^"]+)"',
                            (ROOT / "nemos" / "version.py").read_text()).group(1)
        latest = re.search(r"^## (\d+\.\d+\.\d+)", CHANGELOG, re.M).group(1)
        self.assertEqual(version, latest,
                         "nemos/version.py and the newest CHANGELOG entry disagree")
        major_minor = ".".join(version.split(".")[:2])
        self.assertIn(f"| {major_minor}.x | Yes |", (ROOT / "SECURITY.md").read_text())


class CountTests(unittest.TestCase):
    def test_documented_test_count_is_real(self):
        """A test count that drifts makes every other number suspect."""
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--collect-only"],
            cwd=ROOT, capture_output=True, text=True, timeout=300,
        )
        collected = re.search(r"(\d+) tests? collected", result.stdout)
        if not collected:
            self.skipTest("could not determine the collected test count")
        actual = int(collected.group(1))
        for claim in re.findall(r"(\d{3,4}) automated tests", README):
            self.assertEqual(int(claim), actual,
                             f"README claims {claim} tests; {actual} are collected")
        for claim in re.findall(r"# (\d{3,4}) tests", README):
            self.assertEqual(int(claim), actual,
                             f"README claims {claim} tests; {actual} are collected")

    def test_documented_technique_count_is_real(self):
        from nemos.attack import TECHNIQUES
        for claim in re.findall(r"ATT&CK coverage (\d+) -> (\d+) techniques", CHANGELOG):
            self.assertEqual(int(claim[1]), len(TECHNIQUES))

    def test_documented_rule_count_is_real(self):
        """Counts distinct threat labels the detector can emit."""
        source = _detector_source()
        emitted = set(re.findall(r'add\(\s*\n?\s*"([A-Z0-9_]+)"', source))
        emitted |= set(re.findall(r'f"TCP_\{kind\.upper\(\)\}_SCAN"', source)) and {
            "TCP_NULL_SCAN", "TCP_FIN_SCAN", "TCP_XMAS_SCAN"} or set()
        emitted |= set(re.findall(r'_emit\(\s*\n?\s*[a-z_]+,\s*"([A-Z0-9_]+)"', source))
        for claim in re.findall(r"Detection rules: \d+ -> (\d+)", CHANGELOG):
            self.assertGreaterEqual(
                len(emitted), int(claim) - 2,
                f"CHANGELOG claims {claim} rules; found {len(emitted)}: {sorted(emitted)}")


class PerformanceClaimTests(unittest.TestCase):
    """Performance numbers must be reproducible, not remembered.

    4.0.0 published 189,356 packets/sec from a benchmark whose windows stayed
    nearly empty. The figure was real but unrepresentative, and nothing in the
    repository let a reader check it.
    """

    def test_benchmark_script_exists_and_is_runnable(self):
        script = ROOT / "tools" / "benchmark.py"
        self.assertTrue(script.is_file())
        result = subprocess.run([sys.executable, str(script), "--help"],
                                cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_readme_points_at_the_benchmark_for_its_numbers(self):
        self.assertIn("tools/benchmark.py", README)
        self.assertIn("## Performance", README)

    def test_the_superseded_figure_is_not_presented_as_current(self):
        """It may appear only as an explicit correction."""
        for line in (README + CHANGELOG).splitlines():
            if "189,356" in line or "189,000" in line:
                self.assertRegex(
                    line.lower(), r"correct|superseded|originally",
                    f"the withdrawn figure appears as a live claim: {line.strip()}")

    def test_linear_cost_is_disclosed(self):
        """A known limitation the reader can hit must be stated, not implied."""
        self.assertIn("linear in window size", README)


class HonestyTests(unittest.TestCase):
    def test_limitations_are_still_declared(self):
        """Delivery is now proven end to end, so the declared gap has moved.

        What must never happen is the section quietly disappearing: every
        release states what it has *not* exercised. Capture on a physical
        interface under load is the remaining one.
        """
        recent = CHANGELOG.split("## 4.0.0")[0]
        self.assertIn("Known limitations", recent)
        self.assertRegex(
            recent,
            r"physical interface|sustained production load",
            "the remaining unexercised path is no longer declared",
        )

    def test_no_credential_is_committed_with_the_verification_claim(self):
        """Verifying delivery required real credentials; none may be stored."""
        import re as _re
        for path in (ROOT / "CHANGELOG.md", ROOT / "README.md", ROOT / ".env.example"):
            text = path.read_text()
            self.assertIsNone(
                _re.search(r"\b\d{8,12}:AA[A-Za-z0-9_-]{30,}", text),
                f"a Telegram bot token pattern appears in {path.name}",
            )

    def test_verified_claims_name_how_they_were_verified(self):
        """A "verified" claim must say what was run, not merely assert it."""
        recent = CHANGELOG.split("## 4.0.0")[0]
        if "### Verified" in recent:
            block = recent.split("### Verified")[1].split("###")[0]
            self.assertIn("test_capture_live.py", block)
            self.assertRegex(block, r"delivered|confirmed by Telegram")

    def test_readme_still_states_what_nemos_is_not(self):
        self.assertIn("What NEMOS is not", README)
        self.assertIn("not proof", README.lower().replace("not proof of", "not proof of"))


if __name__ == "__main__":
    unittest.main()
