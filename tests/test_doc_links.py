"""Every link in the documentation must resolve.

The docs were reorganised once, and a reorganisation is exactly when links rot:
a section that moves to another file leaves `(#that-section)` pointing at
nothing, and nothing about a broken anchor is visible in a diff. Since NEMOS
asks readers to follow these links for the detail the README no longer carries,
a dead one is a documentation bug rather than a cosmetic one.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Inline links, but not image embeds and not bare autolinks.
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*$", re.M)
FENCE = re.compile(r"```.*?```", re.S)


def pages() -> list[Path]:
    found = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md",
             ROOT / "CHANGELOG.md", ROOT / "CODE_OF_CONDUCT.md"]
    found += sorted((ROOT / "docs").rglob("*.md"))
    return [p for p in found if p.exists()]


def slug(heading: str) -> str:
    """GitHub's anchor rule: lowercase, drop punctuation, spaces to hyphens."""
    text = re.sub(r"`|\*|_", "", heading)
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"\s+", "-", text.strip())


def anchors(path: Path) -> set[str]:
    body = FENCE.sub("", path.read_text())
    return {slug(h) for h in HEADING.findall(body)}


class LinkTests(unittest.TestCase):
    def test_every_relative_link_resolves(self):
        broken = []
        for page in pages():
            body = FENCE.sub("", page.read_text())
            for target in LINK.findall(body):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                dest = (page.parent / target.split("#", 1)[0]).resolve()
                if not dest.exists():
                    broken.append(f"{page.relative_to(ROOT)} -> {target}")
        self.assertEqual(broken, [], "links to files that do not exist")

    def test_every_anchor_resolves(self):
        """A moved section leaves an anchor pointing at nothing."""
        broken = []
        for page in pages():
            body = FENCE.sub("", page.read_text())
            for target in LINK.findall(body):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                if "#" not in target:
                    continue
                file_part, _, anchor = target.partition("#")
                if not anchor:
                    continue
                dest = page if not file_part else (page.parent / file_part)
                if not dest.exists():
                    continue           # reported by the test above
                if anchor not in anchors(dest):
                    broken.append(
                        f"{page.relative_to(ROOT)} -> {target}")
        self.assertEqual(broken, [], "anchors that point at no heading")


class ShapeTests(unittest.TestCase):
    def test_the_readme_stays_short_enough_to_read(self):
        """It reached 1,502 lines, which is not a document anyone reads. The
        depth lives in docs/ and the README links to it."""
        length = len((ROOT / "README.md").read_text().splitlines())
        self.assertLess(length, 600,
                        f"README is {length} lines; move detail into docs/")

    def test_every_doc_is_reachable_from_the_readme(self):
        """A page nothing links to is a page nobody finds."""
        readme = (ROOT / "README.md").read_text()
        contributing = (ROOT / "CONTRIBUTING.md").read_text()
        linked = set(LINK.findall(readme)) | set(LINK.findall(contributing))
        linked = {t.split("#", 1)[0] for t in linked}
        orphans = []
        for doc in sorted((ROOT / "docs").glob("*.md")):
            rel = f"docs/{doc.name}"
            if rel in linked:
                continue
            # or linked from another doc that is itself reachable
            if any(doc.name in LINK.findall(other.read_text())
                   for other in (ROOT / "docs").glob("*.md") if other != doc):
                continue
            orphans.append(rel)
        self.assertEqual(orphans, [], "docs nothing links to")


if __name__ == "__main__":
    unittest.main()
