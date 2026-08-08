"""Query planner: turn a Subject into a bounded set of reasonable queries.

The planner never generates hundreds of permutations (spec section 7). Sensitive
queries (email, phone) are flagged so the caller can require explicit opt-in
before any identifier leaves the machine.
"""

from __future__ import annotations

from exposure.config import Settings
from exposure.discovery.provider import DiscoveryPlan, PlannedQuery
from exposure.domain.models import Subject


def plan_queries(subject: Subject, settings: Settings) -> DiscoveryPlan:
    name = subject.primary_name
    queries: list[PlannedQuery] = []

    def add(pq: PlannedQuery) -> None:
        if len(queries) < settings.max_queries and pq.text.strip():
            queries.append(pq)

    if name:
        quoted = f'"{name}"'
        add(PlannedQuery(text=quoted, rationale="name"))
        for loc in subject.locations:
            for part in (loc.city, loc.country):
                if part:
                    add(PlannedQuery(text=f"{quoted} {part}", rationale="name+location"))
        for emp in subject.employers:
            add(PlannedQuery(text=f"{quoted} {emp.name}", rationale="name+employer"))
        add(PlannedQuery(text=quoted, rationale="name+pdf", filetype="pdf"))

    for username in subject.usernames:
        add(PlannedQuery(text=f'"{username}"', rationale="username"))

    for domain in subject.personal_domains:
        add(PlannedQuery(text=f"site:{domain}", rationale="owned-domain", site=domain))

    # Sensitive identifiers last; flagged so they require opt-in.
    for email in subject.emails:
        add(PlannedQuery(text=f'"{email.value}"', sensitive=True, rationale="email"))
    for phone in subject.phones:
        add(PlannedQuery(text=f'"{phone.value}"', sensitive=True, rationale="phone"))

    return DiscoveryPlan(queries=queries)
