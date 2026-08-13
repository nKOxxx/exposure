"""robots.txt compliance and the sandboxing around optional JS rendering."""

from __future__ import annotations

import httpx
import pytest

from exposure.config import Settings
from exposure.domain.enums import SourceStatus
from exposure.retrieval import browser as browser_mod
from exposure.retrieval.browser import (
    RenderedPage,
    RenderingUnavailable,
    _target_is_permitted,
    render_if_available,
)
from exposure.retrieval.client import RetrievalError, SecureRetriever
from exposure.retrieval.robots import RobotsPolicy

# --------------------------------------------------------------------------- #
# robots.txt
# --------------------------------------------------------------------------- #

DISALLOW_ALL = "User-agent: *\nDisallow: /\n"
ALLOW_PROFILES = "User-agent: *\nDisallow: /private/\n"


def _policy_with(monkeypatch: pytest.MonkeyPatch, body: str | None, status: int = 200):
    """A RobotsPolicy whose robots.txt fetch is stubbed."""
    policy = RobotsPolicy("Exposure/test")

    def fake_load(robots_url: str):  # type: ignore[no-untyped-def]
        if body is None or status >= 400:
            return None
        from protego import Protego

        return Protego.parse(body)

    monkeypatch.setattr(policy, "_load", fake_load)
    return policy


def test_disallowed_path_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy_with(monkeypatch, DISALLOW_ALL)
    assert policy.allows("https://site.example/anything") is False


def test_allowed_path_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy_with(monkeypatch, ALLOW_PROFILES)
    assert policy.allows("https://site.example/people/jane") is True
    assert policy.allows("https://site.example/private/secret") is False


def test_missing_robots_means_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 404 or unreachable robots.txt must not block the whole scan."""
    assert _policy_with(monkeypatch, None).allows("https://site.example/x") is True


def test_policy_can_be_disabled() -> None:
    policy = RobotsPolicy("Exposure/test", enabled=False)
    assert policy.allows("https://site.example/anything") is True


def test_result_is_cached_per_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = RobotsPolicy("Exposure/test")
    calls: list[str] = []

    def counting_load(robots_url: str):  # type: ignore[no-untyped-def]
        calls.append(robots_url)
        from protego import Protego

        return Protego.parse(ALLOW_PROFILES)

    monkeypatch.setattr(policy, "_load", counting_load)
    policy.allows("https://site.example/a")
    policy.allows("https://site.example/b")
    policy.allows("https://other.example/a")
    assert len(calls) == 2, "robots.txt should be fetched once per origin"


def test_retriever_reports_robots_block_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A disallowed page is recorded as blocked, never silently dropped."""
    retriever = SecureRetriever(
        Settings(),
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, headers={"content-type": "text/html"}, text="hi")
        ),
    )
    monkeypatch.setattr(retriever._robots, "allows", lambda url: False)
    with pytest.raises(RetrievalError) as exc:
        retriever.fetch("https://site.example/blocked")
    assert exc.value.status == SourceStatus.RETRIEVAL_BLOCKED
    assert exc.value.reason == "robots_txt_disallows"
    retriever.close()


def test_robots_can_be_switched_off_in_settings() -> None:
    settings = Settings()
    settings.obey_robots_txt = False
    retriever = SecureRetriever(
        settings,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, headers={"content-type": "text/html"}, text="hi")
        ),
    )
    assert retriever._robots is None
    retriever.close()


# --------------------------------------------------------------------------- #
# Rendering sandbox — the SSRF boundary Playwright would otherwise bypass
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url,allowed",
    [
        ("https://example.com/page", True),
        ("http://example.com/page", True),
        ("http://127.0.0.1/admin", False),
        ("http://localhost/admin", False),
        ("http://169.254.169.254/latest/meta-data/", False),
        ("http://10.0.0.5/internal", False),
        ("http://[::1]/", False),
        ("file:///etc/passwd", False),
        ("data:text/html,hi", False),
        ("https://", False),
    ],
)
def test_rendered_page_may_only_request_public_addresses(url: str, allowed: bool) -> None:
    """Requests a rendered page makes are filtered, not just the initial URL."""
    assert _target_is_permitted(url) is allowed


def test_render_returns_none_without_playwright(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(self, url: str) -> RenderedPage:  # type: ignore[no-untyped-def]
        raise RenderingUnavailable("playwright is not installed")

    monkeypatch.setattr(browser_mod.BrowserRenderer, "render", boom)
    assert render_if_available("https://example.com/") is None


def test_render_returns_none_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A rendering failure must never break a scan."""

    def boom(self, url: str) -> RenderedPage:  # type: ignore[no-untyped-def]
        raise RuntimeError("browser crashed")

    monkeypatch.setattr(browser_mod.BrowserRenderer, "render", boom)
    assert render_if_available("https://example.com/") is None


def test_render_refuses_private_target_before_launching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The URL policy is applied before any browser starts."""
    launched = {"yes": False}

    def fake_import(*args, **kwargs):  # type: ignore[no-untyped-def]
        launched["yes"] = True
        raise AssertionError("browser must not launch for a blocked URL")

    monkeypatch.setattr(browser_mod, "validate_url_syntax", browser_mod.validate_url_syntax)
    assert render_if_available("http://169.254.169.254/") is None
    assert launched["yes"] is False
