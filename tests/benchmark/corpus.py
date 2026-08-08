"""Synthetic identity-resolution benchmark corpus (spec section 28).

Every case pairs a subject with a page and a ground-truth label: does the page
refer to that subject? The corpus is fully synthetic — no real person's data is
used — and deterministic, so the precision figure is reproducible.

The corpus deliberately over-weights the hard cases that break commercial
PII-removal products: common names, same-name individuals in other cities,
changed employers, shared cities with no other evidence, aliases, conflicting
biographies, outdated pages, and pages that merely mention a name in passing.

Metrics are defined in ``test_identity_precision.py``:

* **precision** — of the pages auto-confirmed (HIGH_CONFIDENCE/CONFIRMED), how
  many truly refer to the subject. This is the gated metric (>= 98%).
* **recall** — of the pages that truly refer to the subject, how many were
  auto-confirmed. Reported, not gated: abstention is preferred (spec P5).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Case:
    label: str
    subject: dict
    html: str
    url: str
    is_match: bool
    tags: tuple[str, ...] = field(default_factory=tuple)


def _page(title: str, body: str) -> str:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>"


def _jsonld_person(**fields: object) -> str:
    import json

    payload = {"@type": "Person", **{k: v for k, v in fields.items() if v is not None}}
    return f'<script type="application/ld+json">{json.dumps(payload)}</script>'


# --------------------------------------------------------------------------- #
# Personas. Deliberately varied: distinctive vs very common names, different
# regions, some with strong identifiers and some with almost none.
# --------------------------------------------------------------------------- #

PERSONAS: list[dict] = [
    {
        "key": "nadia",
        "name": "Nadia Okonkwo",
        "city": "Lagos", "country": "Nigeria",
        "employer": "Kano Analytics", "title": "Data Lead",
        "email": "nadia.okonkwo@mailbox.example",
        "phone": "+234 802 555 0142",
        "username": "nokonkwo",
        "domain": "nadiaokonkwo.example",
        "common_name": False,
    },
    {
        "key": "john",
        "name": "John Smith",
        "city": "Leeds", "country": "UK",
        "employer": "Northgate Logistics", "title": "Operations Manager",
        "email": "j.smith.leeds@mailbox.example",
        "phone": "+44 113 555 0198",
        "username": "jsmithleeds",
        "domain": None,
        "common_name": True,
    },
    {
        "key": "maria",
        "name": "Maria Garcia",
        "city": "Madrid", "country": "Spain",
        "employer": "Banco Estrella", "title": "Risk Analyst",
        "email": "m.garcia@mailbox.example",
        "phone": "+34 91 555 0177",
        "username": "mgarcia88",
        "domain": None,
        "common_name": True,
    },
    {
        "key": "wei",
        "name": "Wei Chen",
        "city": "Singapore", "country": "Singapore",
        "employer": "Harbour Fintech", "title": "Engineer",
        "email": "wei.chen@mailbox.example",
        "phone": "+65 6555 0123",
        "username": "weichen_sg",
        "domain": None,
        "common_name": True,
    },
    {
        "key": "tomas",
        "name": "Tomas Bergqvist",
        "city": "Uppsala", "country": "Sweden",
        "employer": "Nordvind AB", "title": "Architect",
        "email": "tomas@bergqvist.example",
        "phone": "+46 18 555 0166",
        "username": "tbergqvist",
        "domain": "bergqvist.example",
        "common_name": False,
    },
    {
        "key": "priya",
        "name": "Priya Nair",
        "city": "Bengaluru", "country": "India",
        "employer": "Meridian Labs", "title": "Product Manager",
        "email": "priya.nair@mailbox.example",
        "phone": "+91 80 5555 0110",
        "username": "prnair88",
        "domain": None,
        "common_name": False,
    },
    {
        "key": "sara",
        "name": "Sara Ahmed",
        "city": "Dubai", "country": "UAE",
        "employer": "Falcon Trading", "title": "Compliance Officer",
        "email": "s.ahmed@mailbox.example",
        "phone": "+971 4 555 0134",
        "username": "sahmed_ae",
        "domain": None,
        "common_name": True,
    },
    {
        "key": "lucas",
        "name": "Lucas Almeida",
        "city": "Porto", "country": "Portugal",
        "employer": "Douro Systems", "title": "Consultant",
        "email": "lucas.almeida@mailbox.example",
        "phone": "+351 22 555 0155",
        "username": "lalmeida",
        "domain": None,
        "common_name": False,
    },
]

# Cities/employers used to construct convincing "different person" pages.
_OTHER_CITIES = ["Sydney", "Denver", "Buenos Aires", "Toronto", "Osaka", "Cape Town",
                 "Warsaw", "Lyon"]
_OTHER_EMPLOYERS = ["Blue Harbor Co", "Vantage Foods", "Pinewood Clinic", "Orbit Media",
                    "Rockwell Freight", "Summit Dental", "Larkspur Press", "Ironwood Legal"]
_OTHER_TITLES = ["chef", "plumber", "yoga teacher", "veterinarian", "photographer",
                 "bus driver", "florist", "dentist"]


def _subject_of(p: dict, *, with_email=True, with_phone=True, with_username=True,
                with_domain=True) -> dict:
    spec: dict = {"name": p["name"], "city": p["city"], "country": p["country"]}
    if p["employer"]:
        spec["employers"] = [p["employer"]]
    if with_email and p["email"]:
        spec["emails"] = [p["email"]]
    if with_phone and p["phone"]:
        spec["phones"] = [p["phone"]]
    if with_username and p["username"]:
        spec["usernames"] = [p["username"]]
    if with_domain and p["domain"]:
        spec["personal_domains"] = [p["domain"]]
    return spec


def _build() -> list[Case]:
    cases: list[Case] = []
    add = cases.append

    for i, p in enumerate(PERSONAS):
        k = p["key"]
        subj = _subject_of(p)
        other_city = _OTHER_CITIES[i % len(_OTHER_CITIES)]
        other_emp = _OTHER_EMPLOYERS[i % len(_OTHER_EMPLOYERS)]
        other_title = _OTHER_TITLES[i % len(_OTHER_TITLES)]

        # ---------------- TRUE MATCHES: strong direct identifiers ------------
        add(Case(
            f"{k}-email-on-page",
            subj,
            _page(p["name"], f"<p>Contact {p['name']} at {p['email']}.</p>"),
            f"https://directory.example/{k}/1",
            True, ("direct", "email"),
        ))
        add(Case(
            f"{k}-phone-international",
            subj,
            _page(p["name"], f"<p>Reach {p['name']} on {p['phone']}.</p>"),
            f"https://directory.example/{k}/2",
            True, ("direct", "phone"),
        ))
        add(Case(
            f"{k}-jsonld-full-profile",
            subj,
            _page(
                p["name"],
                _jsonld_person(
                    name=p["name"], jobTitle=p["title"], email=p["email"],
                    worksFor={"@type": "Organization", "name": p["employer"]},
                    address={"@type": "PostalAddress", "addressLocality": p["city"]},
                )
                + f"<p>{p['name']} profile.</p>",
            ),
            f"https://profiles.example/{k}/3",
            True, ("direct", "structured"),
        ))
        add(Case(
            f"{k}-name-employer-city",
            subj,
            _page(
                p["name"],
                f"<p>{p['name']} works at {p['employer']} in {p['city']}. "
                f"Role: {p['title']}.</p>",
            ),
            f"https://news.example/{k}/4",
            True, ("corroborated",),
        ))
        add(Case(
            f"{k}-username-plus-name",
            subj,
            _page(
                p["name"],
                f'<p>{p["name"]} posts as {p["username"]}.</p>'
                f'<a href="https://github.com/{p["username"]}">code</a>',
            ),
            f"https://forum.example/{k}/5",
            True, ("username",),
        ))

        if p["domain"]:
            add(Case(
                f"{k}-own-domain",
                subj,
                _page("Home", f"<p>Welcome. I am {p['name']}.</p>"),
                f"https://{p['domain']}/about",
                True, ("direct", "owned-domain"),
            ))

        # TRUE matches that SHOULD stay below auto-confirm (recall cost, by design)
        add(Case(
            f"{k}-true-but-name-only",
            subj,
            _page(p["name"], f"<p>An article written by {p['name']}.</p>"),
            f"https://blog.example/{k}/6",
            True, ("thin", "abstain-expected"),
        ))
        add(Case(
            f"{k}-true-but-city-only",
            subj,
            _page(p["name"], f"<p>{p['name']} spoke at a meetup in {p['city']}.</p>"),
            f"https://events.example/{k}/7",
            True, ("thin", "abstain-expected"),
        ))

        # Outdated but still the subject: old employer, current name + city.
        add(Case(
            f"{k}-outdated-employer",
            subj,
            _page(
                p["name"],
                f"<p>{p['name']}, formerly of {other_emp}, now based in {p['city']} "
                f"at {p['employer']}.</p>",
            ),
            f"https://archive.example/{k}/8",
            True, ("outdated",),
        ))

        # ---------------- NON-MATCHES: namesakes and confusions --------------
        add(Case(
            f"{k}-namesake-other-city",
            subj,
            _page(
                p["name"],
                f"<p>{p['name']} is a {other_title} based in {other_city}.</p>",
            ),
            f"https://local.example/{k}/9",
            False, ("namesake", "location-conflict"),
        ))
        add(Case(
            f"{k}-namesake-other-employer-city",
            subj,
            _page(
                p["name"],
                f"<p>{p['name']} joined {other_emp} in {other_city} last year.</p>",
            ),
            f"https://press.example/{k}/10",
            False, ("namesake", "location-conflict"),
        ))
        add(Case(
            f"{k}-namesake-historical",
            subj,
            _page(
                p["name"],
                f"<p>{p['name']} (1841–1902) was a botanist in {other_city}.</p>",
            ),
            f"https://history.example/{k}/11",
            False, ("namesake", "historical"),
        ))
        add(Case(
            f"{k}-different-person-same-city",
            subj,
            _page(
                "Staff directory",
                f"<p>Our {p['city']} office is staffed by other people entirely.</p>",
            ),
            f"https://company.example/{k}/12",
            False, ("no-anchor",),
        ))
        add(Case(
            f"{k}-someone-elses-contact",
            subj,
            _page(
                "Contact us",
                "<p>Email hello@unrelated.example or call +1 202 555 0000.</p>",
            ),
            f"https://unrelated.example/{k}/13",
            False, ("no-anchor",),
        ))
        add(Case(
            f"{k}-namesake-with-own-email",
            subj,
            _page(
                p["name"],
                f"<p>{p['name']} in {other_city}. Write to other.{k}@elsewhere.example.</p>",
            ),
            f"https://elsewhere.example/{k}/14",
            False, ("namesake", "decoy-email"),
        ))
        # A page that mentions the employer but a different person.
        add(Case(
            f"{k}-employer-page-other-staff",
            subj,
            _page(
                f"{p['employer']} team",
                f"<p>{p['employer']} in {p['city']} welcomes its new director, "
                f"someone with an entirely different name.</p>",
            ),
            f"https://corp.example/{k}/15",
            False, ("no-anchor",),
        ))
        # "Mentioned in passing": the page is ABOUT someone else but names the
        # subject, and shares their city and organisation. Found by live testing
        # against Wikipedia, where this auto-confirmed the wrong person's page.
        add(Case(
            f"{k}-mentioned-on-another-persons-page",
            subj,
            _page(
                f"Gregory Vance - {p['employer']}",
                f"<p>Gregory Vance, based in {p['city']}, leads {p['employer']}. "
                f"He has collaborated with {p['name']} on several projects.</p>",
            ),
            f"https://encyclopedia.example/{k}/17",
            False, ("mentioned-in-passing", "topic-conflict"),
        ))
        add(Case(
            f"{k}-listed-among-many-people",
            subj,
            _page(
                f"Dana Whitfield - {p['employer']}",
                f"<p>Dana Whitfield of {p['employer']} in {p['city']}. "
                f"Also attending: {p['name']}, and eleven others.</p>",
            ),
            f"https://encyclopedia.example/{k}/18",
            False, ("mentioned-in-passing", "topic-conflict"),
        ))
        # The subject's OWN page must still match even though a title is present.
        add(Case(
            f"{k}-own-titled-profile-page",
            subj,
            _page(
                f"{p['name']} - {p['employer']}",
                f"<p>{p['name']} is {p['title']} at {p['employer']}, {p['city']}.</p>",
            ),
            f"https://encyclopedia.example/{k}/19",
            True, ("titled-profile",),
        ))

        # Similar-but-different name (should not match on fuzzy grounds).
        first, _, last = p["name"].partition(" ")
        add(Case(
            f"{k}-similar-different-name",
            subj,
            _page(
                f"{first}a {last}sson",
                f"<p>{first}a {last}sson works at {p['employer']} in {p['city']}.</p>",
            ),
            f"https://similar.example/{k}/16",
            False, ("similar-name",),
        ))

    # ------------------------------------------------------------------ #
    # Cross-persona confusion: two different people who share a common name.
    # ------------------------------------------------------------------ #
    common = [p for p in PERSONAS if p["common_name"]]
    for a in common:
        for b in common:
            if a["key"] == b["key"]:
                continue
            # Page about B, evaluated against subject A. Names differ, so these
            # are simply "not me" pages with realistic professional detail.
            cases.append(Case(
                f"cross-{a['key']}-vs-{b['key']}",
                _subject_of(a),
                _page(
                    b["name"],
                    f"<p>{b['name']}, {b['title']} at {b['employer']}, {b['city']}. "
                    f"Contact {b['email']}.</p>",
                ),
                f"https://cross.example/{a['key']}/{b['key']}",
                False,
                ("cross-person",),
            ))

    # ------------------------------------------------------------------ #
    # Alias handling: subject declares an alternate name.
    # ------------------------------------------------------------------ #
    alias_subject = _subject_of(PERSONAS[0]) | {"alt_names": ["N. Okonkwo"]}
    cases.append(Case(
        "alias-alternate-name-with-employer",
        alias_subject,
        _page(
            "N. Okonkwo",
            f"<p>N. Okonkwo leads data work at {PERSONAS[0]['employer']} "
            f"in {PERSONAS[0]['city']}.</p>",
        ),
        "https://alias.example/1",
        True,
        ("alias",),
    ))
    cases.append(Case(
        "alias-initial-only-other-city",
        alias_subject,
        _page("N. Okonkwo", "<p>N. Okonkwo, a surveyor in Toronto.</p>"),
        "https://alias.example/2",
        False,
        ("alias", "namesake"),
    ))

    return cases


CASES: list[Case] = _build()

# Sanity: the corpus must contain a meaningful number of both classes.
assert len(CASES) >= 100, f"corpus too small: {len(CASES)}"
assert sum(1 for c in CASES if c.is_match) >= 30
assert sum(1 for c in CASES if not c.is_match) >= 30
