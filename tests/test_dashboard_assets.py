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
    for element_id in ("packets", "tcp", "udp", "dns", "threats", "critical", "timeline", "posture-score", "incidents-body", "hosts-body", "technique-list", "attack-summary", "network-graph", "traffic-body", "telegram-card", "health-grid", "incident-modal"):
        assert f'id="{element_id}"' in html
    assert "THREATCORE" not in JS.read_text().upper()
    assert "Network Exposure Monitoring" in html
    assert "Created by" in html
    assert "gautam11652-eng/NEMOS" in html
    assert "gautam11652@gmail.com" in html
    assert "risk-chart" not in html
    assert "risk-chart" not in JS.read_text()
    assert "TELEGRAM" in html.upper()
