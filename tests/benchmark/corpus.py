"""Synthetic, consented identity-resolution benchmark corpus (spec section 28).

Each case pairs a subject with a page and a ground-truth label: is the page about
the subject (``is_match``)? The benchmark measures PRECISION of the
HIGH_CONFIDENCE state — of the pages we auto-confirm, how many are truly the
subject. Target: >= 98%.

The corpus deliberately includes hard cases: common names, same-name people,
changed employers, shared cities, aliases, and conflicting biographies.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Case:
    label: str
    subject: dict
    html: str
    url: str
    is_match: bool


def _page(title: str, body: str) -> str:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>"


CASES: list[Case] = [
    # --- true matches with strong direct identifiers ---
    Case(
        "distinctive-email",
        {"name": "Nadia Okonkwo", "city": "Lagos", "emails": ["nadia.okonkwo@mail.com"]},
        _page("Nadia Okonkwo", "<p>Contact nadia.okonkwo@mail.com for details.</p>"),
        "https://a.example/1",
        True,
    ),
    Case(
        "owned-domain",
        {"name": "Tomas Berg", "personal_domains": ["tomasberg.se"]},
        _page("Home", "<p>Welcome to my site.</p>"),
        "https://tomasberg.se/about",
        True,
    ),
    Case(
        "phone-match",
        {"name": "Wei Chen", "phones": ["+65 6123 4567"]},
        _page("Wei Chen", "<p>Call +65 6123 4567.</p>"),
        "https://b.example/2",
        True,
    ),
    Case(
        "username-plus-name",
        {"name": "Priya Nair", "usernames": ["prnair88"]},
        _page("Priya Nair", "<p>Follow prnair88 on the forum. Priya Nair posts here.</p>"),
        "https://c.example/3",
        True,
    ),
    Case(
        "name-employer-location",
        {"name": "Jane Example", "city": "London", "employers": ["Acme Corp"]},
        _page("Jane Example", "<p>Jane Example, London, works at Acme Corp.</p>"),
        "https://d.example/4",
        True,
    ),
    # --- true matches that SHOULD remain non-high-confidence (recall cost ok) ---
    Case(
        "true-but-thin-name-only",
        {"name": "John Smith", "city": "Leeds"},
        _page("John Smith", "<p>John Smith wrote this article.</p>"),
        "https://e.example/5",
        True,
    ),
    # --- NON-matches: namesakes and conflicts (must NOT be high confidence) ---
    Case(
        "namesake-different-city",
        {"name": "Jane Example", "city": "London", "employers": ["Acme Corp"]},
        _page("Jane Example", "<p>Jane Example, a chef in Sydney, opened a restaurant.</p>"),
        "https://f.example/6",
        False,
    ),
    Case(
        "common-name-namesake",
        {"name": "John Smith", "city": "Leeds", "employers": ["Globex"]},
        _page("John Smith", "<p>John Smith, plumber in Denver, reviews tools.</p>"),
        "https://g.example/7",
        False,
    ),
    Case(
        "same-name-different-employer-and-city",
        {"name": "Maria Garcia", "city": "Madrid", "employers": ["BankCo"]},
        _page("Maria Garcia", "<p>Maria Garcia teaches yoga in Buenos Aires.</p>"),
        "https://h.example/8",
        False,
    ),
    Case(
        "name-only-unrelated-topic",
        {"name": "David Lee", "city": "Toronto", "employers": ["Initech"]},
        _page("David Lee", "<p>David Lee is a 19th-century historical figure.</p>"),
        "https://i.example/9",
        False,
    ),
    Case(
        "wrong-person-shared-city-only",
        {"name": "Sara Ahmed", "city": "Dubai", "employers": ["Falcon LLC"]},
        _page("Directory", "<p>Many people live in Dubai. Sara Ahmed is not listed.</p>"),
        "https://j.example/10",
        False,
    ),
    Case(
        "email-belongs-to-someone-else",
        {"name": "Sam Rivera", "emails": ["sam.rivera@mail.com"]},
        _page("Other", "<p>Contact a different person at hello@other.com.</p>"),
        "https://k.example/11",
        False,
    ),
]
