"""HTML parsing with the standard library only.

Downloaded HTML is untrusted *data*, never executable instructions (spec section
9). We use ``html.parser`` (no lxml/bs4 dependency) to pull out visible text,
the title, meta tags, JSON-LD blocks, and links. Scripts and styles are dropped.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from typing import Any

try:  # optional: a real HTML5 tree parser, ~2x faster than the stdlib one
    from selectolax.parser import HTMLParser as HTMLParserFast
except ImportError:  # pragma: no cover - fallback path is exercised by tests
    HTMLParserFast = None  # type: ignore[assignment,misc]

_SKIP_CONTENT_TAGS = {"script", "style", "noscript", "template", "svg"}
_BLOCK_TAGS = {
    "p", "div", "br", "li", "ul", "ol", "tr", "table", "section", "article",
    "header", "footer", "h1", "h2", "h3", "h4", "h5", "h6",
}


@dataclass(slots=True)
class ParsedHTML:
    title: str | None = None
    text: str = ""
    meta: dict[str, str] = field(default_factory=dict)
    jsonld: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self._in_title = False
        self._skip_depth = 0
        self._script_type: str | None = None
        self._buf: list[str] = []
        self.meta: dict[str, str] = {}
        self.jsonld: list[dict[str, Any]] = []
        self.links: list[str] = []
        self._jsonld_buf: list[str] = []
        self._in_jsonld = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("type", "").lower() == "application/ld+json":
            self._in_jsonld = True
            self._jsonld_buf = []
            return
        if tag in _SKIP_CONTENT_TAGS:
            self._skip_depth += 1
            return
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = a.get("property") or a.get("name")
            content = a.get("content")
            if key and content:
                self.meta[key.lower()] = content
        elif tag == "a":
            href = a.get("href")
            if href:
                self.links.append(href)
        if tag in _BLOCK_TAGS:
            self._buf.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_jsonld:
            self._in_jsonld = False
            raw = "".join(self._jsonld_buf).strip()
            if raw:
                self._parse_jsonld(raw)
            return
        if tag in _SKIP_CONTENT_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if tag == "title":
            self._in_title = False
        if tag in _BLOCK_TAGS:
            self._buf.append("\n")

    def handle_data(self, data: str) -> None:
        if self._in_jsonld:
            self._jsonld_buf.append(data)
            return
        if self._skip_depth > 0:
            return
        if self._in_title and self.title is None:
            self.title = data.strip() or None
        self._buf.append(data)

    def _parse_jsonld(self, raw: str) -> None:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return
        items = data if isinstance(data, list) else [data]
        for item in items:
            if isinstance(item, dict):
                if "@graph" in item and isinstance(item["@graph"], list):
                    self.jsonld.extend(g for g in item["@graph"] if isinstance(g, dict))
                else:
                    self.jsonld.append(item)

    @property
    def text(self) -> str:
        joined = "".join(self._buf)
        lines = [ln.strip() for ln in joined.splitlines()]
        return "\n".join(ln for ln in lines if ln)


def _decode(body: bytes) -> str:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("latin-1", errors="replace")


def _parse_with_selectolax(text: str) -> ParsedHTML | None:
    """Parse with selectolax (lexbor): ~2x faster and a real HTML5 tree.

    Returns ``None`` if selectolax is unavailable or the document defeats it,
    so the standard-library parser below stays as a guaranteed fallback.
    """
    if HTMLParserFast is None:
        return None
    try:
        tree = HTMLParserFast(text)
    except Exception:
        return None

    meta: dict[str, str] = {}
    for node in tree.css("meta"):
        key = node.attributes.get("property") or node.attributes.get("name")
        content = node.attributes.get("content")
        if key and content:
            meta[key.lower()] = content

    jsonld: list[dict[str, Any]] = []
    for node in tree.css('script[type="application/ld+json"]'):
        raw = (node.text() or "").strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        for item in data if isinstance(data, list) else [data]:
            if not isinstance(item, dict):
                continue
            graph = item.get("@graph")
            if isinstance(graph, list):
                jsonld.extend(g for g in graph if isinstance(g, dict))
            else:
                jsonld.append(item)

    links = [
        href for node in tree.css("a") if (href := node.attributes.get("href"))
    ]

    title_node = tree.css_first("title")
    title = (title_node.text() or "").strip() if title_node else None

    # Drop non-visible content before taking text (spec section 9).
    for node in tree.css("script, style, noscript, template, svg"):
        node.decompose()
    body_node = tree.body or tree.root
    raw_text = body_node.text(separator="\n") if body_node else ""
    lines = [ln.strip() for ln in raw_text.splitlines()]

    return ParsedHTML(
        title=title or None,
        text="\n".join(ln for ln in lines if ln),
        meta=meta,
        jsonld=jsonld,
        links=links,
    )


def parse_html(body: bytes) -> ParsedHTML:
    """Parse HTML bytes into structured, sanitized fields."""
    text = _decode(body)

    parsed = _parse_with_selectolax(text)
    if parsed is not None:
        return parsed

    collector = _Collector()
    # A malformed document must never crash the pipeline (spec section 28).
    with contextlib.suppress(Exception):
        collector.feed(text)
    return ParsedHTML(
        title=unescape(collector.title) if collector.title else None,
        text=collector.text,
        meta=collector.meta,
        jsonld=collector.jsonld,
        links=collector.links,
    )
