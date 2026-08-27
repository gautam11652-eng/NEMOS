import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "nemos" / "templates" / "index.html"
JS = ROOT / "nemos" / "static" / "app.js"


def test_dashboard_static_dom_contract():
    html = HTML.read_text()
    js = JS.read_text()
    ids = set(re.findall(r'id="([^"]+)"', html))
    refs = set(re.findall(r'\$\("([^"]+)"\)', js))
    # These controls are created dynamically inside the incident modal.
    dynamic = {"copy-fingerprint", "export-evidence"}
    assert not (refs - ids - dynamic)
    assert 'style=' not in js
    assert 'style=' not in html


def test_dashboard_js_syntax_when_node_is_available():
    node = shutil.which("node")
    if not node:
        return
    result = subprocess.run(
        [node, "--check", str(JS)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_dashboard_branding_and_navigation_contract():
    html = HTML.read_text()
    assert "THREATCORE" not in html.upper()
    for section in ("overview", "incidents", "hosts", "network", "techniques"):
        assert f'href="#{section}"' in html
        assert f'id="{section}"' in html
    for element_id in ("packets", "tcp", "dns", "threats", "critical", "timeline", "risk-chart", "incidents-body", "hosts-body", "technique-list", "network-graph", "traffic-body", "incident-modal"):
        assert f'id="{element_id}"' in html
    assert "THREATCORE" not in JS.read_text().upper()


def test_dashboard_navigation_sections_are_direct_and_observed():
    html = HTML.read_text()
    js = JS.read_text()
    # Each primary navigation target must be a direct section/header so
    # hash navigation lands on the intended view rather than a shared grid.
    assert re.search(r'<section class="panel" id="hosts">', html)
    assert re.search(r'<section class="panel" id="techniques">', html)
    assert 'document.getElementById(id)' in js
    assert "querySelectorAll('.main > [id], .main > header[id]')" not in js
