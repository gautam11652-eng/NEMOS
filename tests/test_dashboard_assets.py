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
    # ML detection section: every element the AI renderer writes into must exist.
    for element_id in ("ai", "ai-badge", "ai-status", "ai-model-state", "ai-model-version",
                       "ai-model-trained", "ai-model-samples", "ai-scored", "ai-window",
                       "ai-note", "ai-assessments"):
        assert f'id="{element_id}"' in html, element_id
    assert 'href="#ai"' in html
    assert "THREATCORE" not in JS.read_text().upper()
    assert "Network Exposure Monitoring" in html
    assert "Created by" in html
    assert "gautam11652-eng/NEMOS" in html
    assert "gautam11652@gmail.com" in html
    assert "risk-chart" not in html
    assert "risk-chart" not in JS.read_text()
    assert "TELEGRAM" in html.upper()


def test_ai_section_does_not_overstate_the_model():
    """The dashboard must not present the anomaly score as a probability."""
    js = JS.read_text()
    lowered = js.lower()
    assert "not a probability" in lowered
    for phrase in ("ai detected attack", "confirmed attack", "malware detected",
                   "guaranteed", "100% accurate"):
        assert phrase not in lowered, phrase


def test_dashboard_renders_only_backend_supplied_ai_fields():
    """Each AI tile must be filled from a real API field, not a computed placeholder."""
    js = JS.read_text()
    for source in ("model.available", "meta.model_version", "meta.trained_at",
                   "meta.samples", "model.scored_windows", "status.window_seconds",
                   "a.anomaly_score", "a.baseline_state", "explanation"):
        assert source in js, source
