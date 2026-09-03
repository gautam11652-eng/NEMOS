"""Static contract tests for the dashboard.

These assert the things that break silently in a browser: an id the script
writes into that the markup does not define, a syntax error, a view that has no
route, or inline styles that would be refused by the Content-Security-Policy the
API sets. They deliberately do not assert visual design.
"""

import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "nemos" / "templates" / "index.html"
JS = ROOT / "nemos" / "static" / "app.js"
CSS = ROOT / "nemos" / "static" / "app.css"

VIEWS = ("overview", "incidents", "detections", "hosts", "network",
         "attack", "analytics", "sensor", "settings")


def test_every_scripted_id_exists_in_the_markup():
    """$("x") with no matching id is a silent null dereference at runtime.

    An element the script renders itself counts: the pairing countdown only
    exists while a code is on screen, and its lookup is null-guarded. What must
    never happen is a lookup for an id that appears in neither place, which is
    always a typo.
    """
    js = JS.read_text()
    ids = set(re.findall(r'id="([^"]+)"', HTML.read_text()))
    ids |= set(re.findall(r'id="([^"${]+)"', js))
    refs = set(re.findall(r'\$\("([^"]+)"\)', js))
    missing = refs - ids
    assert not missing, f"script references ids absent from the template: {sorted(missing)}"


def test_no_inline_styles():
    """The API sets default-src 'self'; inline style attributes are refused.

    Dynamic sizing is done with custom properties via style.setProperty, which
    is not an inline style attribute.
    """
    assert "style=" not in HTML.read_text()
    assert "style=" not in JS.read_text()


def test_javascript_parses_when_node_is_available():
    node = shutil.which("node")
    if not node:
        return
    result = subprocess.run(
        [node, "--check", str(JS)], cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_every_view_has_a_route_a_section_and_a_title():
    html = HTML.read_text()
    js = JS.read_text()
    for view in VIEWS:
        assert f'href="#{view}"' in html, f"no nav link for {view}"
        assert f'data-view="{view}"' in html, f"no data-view for {view}"
        assert f'id="view-{view}"' in html, f"no section for {view}"
        assert f"{view}:" in js or f'"{view}"' in js, f"{view} missing from the router"


def test_hidden_attribute_is_honoured():
    """Every toggled element sets its own display, so [hidden] must outrank them.

    Without this rule all nine views, the drawer and the palette paint at once --
    which is exactly what happened before it was added.
    """
    assert re.search(r"\[hidden\]\s*\{[^}]*display:\s*none\s*!important", CSS.read_text())


def test_favicon_is_a_served_file_not_a_data_uri():
    """A data: URI favicon is blocked by the page's own CSP."""
    html = HTML.read_text()
    assert 'rel="icon"' in html
    assert "data:image" not in html
    assert (ROOT / "nemos" / "static" / "favicon.svg").is_file()


def test_untrusted_values_are_escaped_before_insertion():
    """Alert fields carry attacker-influenced values such as source addresses."""
    js = JS.read_text()
    assert "const esc =" in js
    # Spot-check that the row renderers escape rather than interpolate raw.
    assert "${esc(a.source)}" in js
    assert "${esc(a.threat)}" in js


def test_branding_and_attribution_are_present():
    html = HTML.read_text()
    assert "THREATCORE" not in html.upper()
    assert "THREATCORE" not in JS.read_text().upper()
    assert "Network Exposure Monitoring" in html
    assert "Created by" in html
    assert "gautam11652-eng/NEMOS" in html
    assert "gautam11652@gmail.com" in html


def test_dashboard_states_its_own_limits():
    """The interface must not imply more certainty than the sensor has."""
    html = HTML.read_text()
    js = JS.read_text()
    assert "not proof of compromise" in html
    assert "not a probability" in js


def test_only_real_api_endpoints_are_called():
    """Guards against calling an endpoint that does not exist.

    An earlier revision fetched /api/attack, which is not a route; the view
    silently rendered empty.
    """
    js = JS.read_text()
    # Both helpers: api() reads, apiSend() writes. A POST to a route that does
    # not exist fails just as silently as a GET did.
    called = set(re.findall(r'\bapi(?:Send)?\("(/api/[^"?]+)', js))
    routes = set(re.findall(
        r'@app\.(?:get|post|put|patch|delete|route)\("(/api/[^"<]*)',
        (ROOT / "nemos" / "api.py").read_text(),
    ))
    unknown = {c for c in called if c not in routes}
    assert not unknown, f"dashboard calls endpoints that do not exist: {sorted(unknown)}"
