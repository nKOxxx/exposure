"""Optional JavaScript rendering for pages that return nothing statically.

Many pages that matter for a personal-exposure scan (company directories,
profile aggregators) ship an empty shell and build the content in JavaScript. A
static fetch sees nothing. Measured on real pages: crunchbase 113 -> 724
characters of text, zoominfo 0 -> 106, cypherhunter 0 -> 726.

This is **plain rendering of a public page**, not bot-detection evasion. Exposure
deliberately does not implement stealth browsers, CAPTCHA solving, proxy
rotation, or authenticated scraping (spec sections 3 and 8). A page that refuses
an ordinary browser is recorded as blocked, not worked around.

Security note: Playwright drives a real browser and therefore does **not** go
through :class:`GuardedBackend`. The SSRF boundary is re-established here by
validating the target before navigation and by aborting, at the network layer,
any request the page makes to a private or loopback address. Without that, a
public page could redirect or fetch its way to an internal service.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from exposure.security.validation import (
    UrlPolicyError,
    is_blocked_address,
    is_blocked_hostname,
    validate_url_syntax,
)

_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


class RenderingUnavailable(RuntimeError):
    """Playwright (or its browser) is not installed."""


@dataclass(slots=True)
class RenderedPage:
    url: str
    html: str
    status: int


def _target_is_permitted(url: str) -> bool:
    """Whether the browser may issue a request to this URL."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").strip("[]")
    if not host or is_blocked_hostname(host):
        return False
    # Literal IPs can be judged immediately; names are resolved by the browser,
    # so the pre-navigation check below covers the initial target and this
    # handler covers everything the page subsequently requests.
    try:
        import ipaddress

        return not is_blocked_address(ipaddress.ip_address(host))
    except ValueError:
        return True


class BrowserRenderer:
    """Renders a page in a throwaway headless browser, then closes it.

    Applies the spec's sandbox requirements: temporary profile, no persisted
    cookies, no extensions, no downloads, no camera/microphone/geolocation, and
    a hard timeout.
    """

    def __init__(self, timeout_ms: int = 20000, settle_ms: int = 1200) -> None:
        self._timeout_ms = timeout_ms
        self._settle_ms = settle_ms

    def render(self, url: str) -> RenderedPage:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - optional extra
            raise RenderingUnavailable("playwright is not installed") from exc

        # Re-apply the retrieval policy: the browser bypasses GuardedBackend.
        url = validate_url_syntax(url)

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--disable-extensions", "--disable-plugins", "--mute-audio"],
            )
            try:
                context = browser.new_context(
                    user_agent=_USER_AGENT,
                    accept_downloads=False,
                    permissions=[],  # no geolocation, camera, microphone, clipboard
                    java_script_enabled=True,
                    service_workers="block",
                )
                context.set_default_timeout(self._timeout_ms)
                page = context.new_page()

                # Block the page from reaching private/loopback addresses.
                def _guard(route, request):  # type: ignore[no-untyped-def]
                    if _target_is_permitted(request.url):
                        route.continue_()
                    else:
                        route.abort()

                page.route("**/*", _guard)

                response = page.goto(
                    url, wait_until="domcontentloaded", timeout=self._timeout_ms
                )
                page.wait_for_timeout(self._settle_ms)
                html = page.content()
                status = response.status if response is not None else 0
                final_url = page.url
                with contextlib.suppress(Exception):
                    context.close()
                return RenderedPage(url=final_url, html=html, status=status)
            finally:
                with contextlib.suppress(Exception):
                    browser.close()


def render_if_available(url: str, timeout_ms: int = 20000) -> RenderedPage | None:
    """Render ``url``, returning ``None`` if rendering is unavailable or fails."""
    try:
        return BrowserRenderer(timeout_ms=timeout_ms).render(url)
    except (RenderingUnavailable, UrlPolicyError):
        return None
    except Exception:
        # A rendering failure must never break a scan; the static result stands.
        return None
