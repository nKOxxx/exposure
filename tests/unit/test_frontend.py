"""Static checks on the embedded single-page UI.

The UI ships as one self-contained HTML file with an inline script, so it has no
JS build step and no JS test runner. These checks catch the failure classes that
would otherwise only surface as a silently dead button in the browser:

* **implicit-global DOM access** — element IDs use hyphens (``f-city``), which
  are not valid JS identifiers. Writing ``f_city.value`` raises a ReferenceError
  and kills the whole handler. This is a real bug that shipped once.
* **dangling element references** — ``el('typo')`` for an id that isn't in the
  document.
* **CSP compliance** — no external scripts, styles, fonts, or images.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from importlib import resources
from pathlib import Path

import pytest


def _index_html() -> str:
    path = resources.files("exposure.app") / "static" / "index.html"
    return path.read_text(encoding="utf-8")


def _script_body(html: str) -> str:
    match = re.search(r"<script>(.*?)</script>", html, re.DOTALL)
    assert match, "index.html must contain an inline <script> block"
    return match.group(1)


def _element_ids(html: str) -> set[str]:
    return set(re.findall(r'\bid="([^"]+)"', html))


# Identifiers the script may legitimately reference without declaring them.
_KNOWN_GLOBALS = {
    "document", "window", "console", "navigator", "fetch", "JSON", "Math",
    "Promise", "Object", "Array", "String", "Number", "Boolean", "Date",
    "setTimeout", "clearTimeout", "confirm", "alert", "location", "e", "res",
}


def test_no_implicit_global_dom_access() -> None:
    """No ``someIdentifier.value`` where the identifier was never declared.

    Regression test: the first release referenced ``f_city.value`` for an
    element with ``id="f-city"``. Hyphens are not valid in JS identifiers, so
    the bare name did not exist and every handler using it threw immediately.
    """
    script = _script_body(_index_html())

    declared: set[str] = set()
    declared |= set(re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)", script))
    declared |= set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)", script))
    # function parameters and arrow params (coarse but sufficient here)
    for params in re.findall(r"\(([^)]*)\)\s*=>", script):
        declared |= {p.strip() for p in params.split(",") if p.strip().isidentifier()}
    for params in re.findall(r"function\s*[\w$]*\s*\(([^)]*)\)", script):
        declared |= {p.strip() for p in params.split(",") if p.strip().isidentifier()}
    declared |= {m.strip() for m in re.findall(r"([A-Za-z_$][\w$]*)\s*=>", script)}

    # DOM-ish property access on a bare identifier.
    dom_props = r"(?:value|checked|textContent|innerHTML|classList|dataset|files|style)"
    offenders: set[str] = set()
    for ident in re.findall(rf"(?<![.\w$]) ?\b([A-Za-z_$][\w$]*)\.{dom_props}\b", script):
        if ident in declared or ident in _KNOWN_GLOBALS:
            continue
        offenders.add(ident)

    assert not offenders, (
        "implicit-global DOM access (these identifiers are never declared; "
        f"element ids use hyphens so the bare name does not exist): {sorted(offenders)}"
    )


def test_all_referenced_element_ids_exist() -> None:
    """Every el('x') / getElementById('x') target must exist in the document."""
    html = _index_html()
    script = _script_body(html)
    ids = _element_ids(html)

    referenced = set(re.findall(r"\bel\(\s*'([^']+)'\s*\)", script))
    referenced |= set(re.findall(r"getElementById\(\s*'([^']+)'\s*\)", script))
    # Ids built at runtime (e.g. 'key-'+id) are excluded from the static check.
    referenced = {r for r in referenced if "+" not in r}

    missing = sorted(r for r in referenced if r not in ids)
    assert not missing, f"script references element ids that do not exist: {missing}"


def test_form_field_ids_are_all_wired() -> None:
    """Every subject form field is actually read by the create handler."""
    script = _script_body(_index_html())
    for field in ("f-name", "f-alt", "f-city", "f-country", "f-emp", "f-user",
                  "f-dom", "f-email"):
        assert f"'{field}'" in script, f"form field {field} is never read by the UI"


def test_ui_never_asks_for_a_phone_number() -> None:
    """Exposure does not collect the user's phone number (product decision).

    Detecting a phone number exposed *about* the user is still supported; this
    only asserts the UI never asks them to type one in.
    """
    html = _index_html()
    assert 'id="f-phone"' not in html
    assert "f-phone" not in _script_body(html)


def test_scan_options_are_wired() -> None:
    script = _script_body(_index_html())
    for field in ("opt-search", "opt-sensitive", "opt-manual"):
        assert f"'{field}'" in script, f"scan option {field} is never read by the UI"


def test_handlers_surface_errors() -> None:
    """A throwing handler must tell the user, never fail silently (spec §35)."""
    script = _script_body(_index_html())
    assert "unhandledrejection" in script, "missing global promise-rejection handler"
    assert "function guard(" in script, "handlers must be wrapped so errors surface"
    for button in ("btn-create", "btn-scan", "btn-preview", "btn-export", "btn-delete-all"):
        pattern = rf"el\('{button}'\)\.onclick\s*=\s*guard\("
        assert re.search(pattern, script), f"{button} handler is not wrapped in guard()"


def test_no_external_resources() -> None:
    """CSP hard gate #6: no external scripts, styles, fonts, or images."""
    html = _index_html()
    assert not re.search(r"<script[^>]+\bsrc=", html), "external script tag found"
    assert not re.search(r'<link[^>]+href="https?://', html), "external stylesheet/font found"
    assert not re.search(r'<img[^>]+src="https?://', html), "external image found"
    assert "@import" not in html, "CSS @import found"


def test_session_token_placeholder_present() -> None:
    """The server injects the session token at request time."""
    assert "%%SESSION_TOKEN%%" in _index_html()


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_inline_script_parses(tmp_path: Path) -> None:
    """The inline script must at least be syntactically valid JavaScript."""
    script = _script_body(_index_html())
    js = tmp_path / "ui.js"
    js.write_text(script, encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [shutil.which("node") or "node", "--check", str(js)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"inline script has a syntax error:\n{result.stderr}"
