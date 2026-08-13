"""Application service layer.

Centralizes all operations so the HTTP API is a thin adapter and the same logic
is exercised directly by tests. Holds the database, settings, and the loaded
remediation registry.
"""

from __future__ import annotations

import contextlib
import threading
from dataclasses import asdict
from typing import Any

from exposure.app.schemas import (
    CaseCreate,
    CaseEvent,
    FindingDecision,
    ProviderUpdate,
    ScanCreate,
    SubjectCreate,
)
from exposure.assessment import explain_priority, identity_reason, why_it_matters
from exposure.assessment.rules import Assessment
from exposure.config import Settings
from exposure.domain.enums import (
    CaseState,
    RemediationRoute,
    Severity,
    VerificationStatus,
)
from exposure.domain.models import (
    LocationHint,
    Name,
    OrganisationHint,
    RemediationCase,
    SecretField,
    Subject,
)
from exposure.export import build_report, write_report
from exposure.remediation import (
    Registry,
    assert_transition,
    generate_draft,
    load_registry,
    routes_for_finding,
    verify_source,
)
from exposure.resolution import apply_user_decision
from exposure.scanner import Scanner, ScanOptions
from exposure.security.redaction import mask_email, mask_phone
from exposure.storage.database import Database


class ServiceError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class Service:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        registry: Registry | None = None,
        retriever_factory: Any | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.registry = registry or load_registry()
        self._scan_lock = threading.Lock()
        # Injectable so tests can drive the full pipeline offline.
        self._retriever_factory = retriever_factory

    # -- subjects ----------------------------------------------------------- #

    def create_subject(self, payload: SubjectCreate) -> Subject:
        names = [Name(value=payload.name.strip(), is_primary=True)]
        names += [Name(value=n.strip()) for n in payload.alt_names if n.strip()]
        # Merge the multi-location list with the legacy single city/country,
        # de-duplicating so the same place is not searched twice.
        locations: list[LocationHint] = []
        seen_places: set[tuple[str, str]] = set()
        raw_places = [(loc.city, loc.country) for loc in payload.locations]
        raw_places.append((payload.city, payload.country))
        for city, country in raw_places:
            city = (city or "").strip() or None
            country = (country or "").strip() or None
            if not city and not country:
                continue
            key = ((city or "").lower(), (country or "").lower())
            if key in seen_places:
                continue
            seen_places.add(key)
            locations.append(LocationHint(city=city, country=country))
        subject = Subject(
            names=names,
            locations=locations,
            employers=[OrganisationHint(name=e.strip()) for e in payload.employers if e.strip()],
            usernames=[u.strip() for u in payload.usernames if u.strip()],
            personal_domains=[d.strip().lower() for d in payload.personal_domains if d.strip()],
            emails=[
                SecretField(value=e.strip(), display=mask_email(e.strip()))
                for e in payload.emails
                if e.strip()
            ],
            phones=[
                SecretField(value=p.strip(), display=mask_phone(p.strip()))
                for p in payload.phones
                if p.strip()
            ],
        )
        return self.db.create_subject(subject)

    def get_subject(self, subject_id: str) -> Subject:
        subject = self.db.get_subject(subject_id)
        if subject is None:
            raise ServiceError("subject not found", 404)
        return subject

    def list_subjects(self) -> list[dict[str, Any]]:
        return [self._subject_public(s) for s in self.db.list_subjects()]

    def delete_subject(self, subject_id: str) -> None:
        self.get_subject(subject_id)
        self.db.delete_subject(subject_id)

    @staticmethod
    def _subject_public(subject: Subject) -> dict[str, Any]:
        # Sensitive fields returned masked only.
        return {
            "id": subject.id,
            "primary_name": subject.primary_name,
            "names": [n.value for n in subject.names],
            "locations": [loc.as_text() for loc in subject.locations],
            "employers": [e.name for e in subject.employers],
            "usernames": subject.usernames,
            "personal_domains": subject.personal_domains,
            "emails": [e.display for e in subject.emails],
            "phones": [p.display for p in subject.phones],
            "created_at": subject.created_at.isoformat(),
        }

    def subject_public(self, subject_id: str) -> dict[str, Any]:
        return self._subject_public(self.get_subject(subject_id))

    # -- scans -------------------------------------------------------------- #

    def _options(self, payload: ScanCreate) -> ScanOptions:
        return ScanOptions(
            use_search=payload.use_search,
            include_sensitive=payload.include_sensitive,
            manual_urls=payload.manual_urls,
        )

    def start_scan(self, subject_id: str, payload: ScanCreate) -> tuple[str, Any]:
        """Synchronous scan (used by tests and the CLI). One scan at a time."""
        subject = self.get_subject(subject_id)
        scanner = Scanner(self.db, self.settings, self._retriever_factory)
        with self._scan_lock:
            return scanner.run(subject, self._options(payload))

    def start_scan_background(self, subject_id: str, payload: ScanCreate) -> str:
        """Create the scan record, run the pipeline in a thread, return the id.

        The worker thread opens its own SQLite connection (WAL allows a writer
        alongside the main connection's readers) so we never share one connection
        across threads.
        """
        subject = self.get_subject(subject_id)
        options = self._options(payload)
        # Pre-create the record on the main connection so the id is queryable now.
        scan_id = Scanner(self.db, self.settings, self._retriever_factory).begin(subject)

        def _work() -> None:
            thread_db = Database(self.settings, self.db.secrets)
            thread_db.connect()
            try:
                # run_existing records ERROR on the scan row itself, so a failure
                # here is already persisted; we just avoid crashing the thread.
                with contextlib.suppress(Exception), self._scan_lock:
                    Scanner(thread_db, self.settings, self._retriever_factory).run_existing(
                        scan_id, subject, options
                    )
            finally:
                thread_db.close()

        threading.Thread(target=_work, daemon=True, name=f"scan-{scan_id[:8]}").start()
        return scan_id

    def scan_plan(self, subject_id: str) -> list[dict[str, Any]]:
        """Preview the queries a scan would send (spec section 24)."""
        from exposure.discovery import plan_queries

        subject = self.get_subject(subject_id)
        plan = plan_queries(subject, self.settings)
        return [
            {"text": q.as_query().text, "sensitive": q.sensitive, "rationale": q.rationale}
            for q in plan.queries
        ]

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        scan = self.db.get_scan(scan_id)
        if scan is None:
            raise ServiceError("scan not found", 404)
        return scan

    # -- findings ----------------------------------------------------------- #

    def list_findings(self, subject_id: str | None = None) -> list[dict[str, Any]]:
        return [self._finding_summary(f.id) for f in self.db.list_findings(subject_id)]

    def _finding_summary(self, finding_id: str) -> dict[str, Any]:
        f = self.db.get_finding(finding_id)
        if f is None:
            raise ServiceError("finding not found", 404)
        source = self.db.get_source(f.source_id)
        return {
            "id": f.id,
            "category": f.category.value,
            "priority": f.overall_priority.value,
            "sensitivity": f.sensitivity.value,
            "discoverability": f.discoverability.value,
            "misuse_potential": f.misuse_potential.value,
            "persistence": f.persistence.value,
            "identity_state": f.match_state.value,
            "identity_confidence": f.identity_confidence,
            "needs_review": not f.match_state.actionable,
            "summary": f.summary,
            "source_domain": source.registrable_domain if source else None,
            "source_url": source.url if source else None,
        }

    def finding_detail(self, finding_id: str) -> dict[str, Any]:
        f = self.db.get_finding(finding_id)
        if f is None:
            raise ServiceError("finding not found", 404)
        source = self.db.get_source(f.source_id)
        match = self.db.get_match_for_source(f.source_id) if source else None
        observations = [
            {
                "type": o.type.value,
                "display_value": o.display_value,
                "evidence_snippet": o.evidence_snippet,
                "is_sensitive": o.is_sensitive,
                "extractor": f"{o.extractor}/{o.extractor_version}",
            }
            for o in (self.db.observations_for_source(f.source_id) if source else [])
            if o.id in set(f.observation_ids)
        ]
        supporting = [s.detail for s in match.supporting_signals] if match else []
        contradicting = [s.detail for s in match.contradicting_signals] if match else []
        assessment = Assessment(
            sensitivity=f.sensitivity,
            discoverability=f.discoverability,
            misuse_potential=f.misuse_potential,
            persistence=f.persistence,
            overall_priority=f.overall_priority,
            reason_codes=f.explanation_codes,
        )
        # The five questions a finding must answer (spec section 34).
        return {
            "id": f.id,
            "source_id": f.source_id,
            "what": f.summary,
            "why_it_is_you": identity_reason(f.match_state, supporting),
            "why_it_matters": why_it_matters(f.category),
            "priority_reason": explain_priority(assessment),
            "how_we_check": (
                "We will re-fetch this source and re-run the query, and report only "
                "what we observe — never assume removal."
            ),
            "category": f.category.value,
            "priority": f.overall_priority.value,
            "dimensions": {
                "sensitivity": f.sensitivity.value,
                "discoverability": f.discoverability.value,
                "misuse_potential": f.misuse_potential.value,
                "persistence": f.persistence.value,
            },
            "identity": {
                "state": f.match_state.value,
                "confidence": f.identity_confidence,
                "supporting": supporting,
                "contradicting": contradicting,
            },
            "explanation_codes": f.explanation_codes,
            "observations": observations,
            "source": {
                "url": source.url if source else None,
                "domain": source.registrable_domain if source else None,
                "title": source.title if source else None,
            },
        }

    def decide_finding(self, finding_id: str, payload: FindingDecision) -> dict[str, Any]:
        f = self.db.get_finding(finding_id)
        if f is None:
            raise ServiceError("finding not found", 404)
        match = self.db.get_match_for_source(f.source_id)
        if match is None:
            raise ServiceError("match not found", 404)
        apply_user_decision(match, payload.decision)
        self.db.upsert_match(match)
        self.db.update_finding_match_state(finding_id, match.state)
        return self._finding_summary(finding_id)

    def routes_for(self, finding_id: str) -> list[dict[str, Any]]:
        f = self.db.get_finding(finding_id)
        if f is None:
            raise ServiceError("finding not found", 404)
        source = self.db.get_source(f.source_id)
        subject = self.db.get_subject(f.subject_id)
        if source is None or subject is None:
            raise ServiceError("source/subject missing", 404)
        options = routes_for_finding(f, source, subject, self.registry)
        return [
            {
                "route": o.route.value,
                "registry_id": o.registry_id,
                "provider": o.provider,
                "recommended": o.recommended,
                "reason": o.reason,
                "jurisdiction_relevant": o.jurisdiction_relevant,
                "official_url": o.entry.official_url if o.entry else "",
                "portal_url": o.entry.portal_url if o.entry else None,
                "side_effects": o.entry.side_effects if o.entry else "",
                "informational": o.entry.informational if o.entry else True,
            }
            for o in options
        ]

    # -- cases -------------------------------------------------------------- #

    def create_case(self, payload: CaseCreate) -> dict[str, Any]:
        f = self.db.get_finding(payload.finding_id)
        if f is None:
            raise ServiceError("finding not found", 404)
        route = RemediationRoute.NO_ACTION_AVAILABLE
        entry = None
        if payload.registry_route_id:
            entry = self.registry.get(payload.registry_route_id)
            if entry is None:
                raise ServiceError("unknown registry route", 400)
            route = entry.route_type
        elif payload.route:
            route = RemediationRoute(payload.route)
        case = RemediationCase(
            finding_id=payload.finding_id,
            route=route,
            registry_route_id=payload.registry_route_id,
            state=CaseState.ACTION_SELECTED,
        )
        self.db.add_case(case)
        self.db.add_case_event(case.id, "created", {"route": route.value})

        source = self.db.get_source(f.source_id)
        subject = self.db.get_subject(f.subject_id)
        draft = generate_draft(f, source, subject, entry)  # type: ignore[arg-type]
        draft_dict = asdict(draft)
        draft_dict["route"] = draft.route.value
        return {"case": self._case_public(case), "draft": draft_dict}

    def get_case(self, case_id: str) -> dict[str, Any]:
        case = self.db.get_case(case_id)
        if case is None:
            raise ServiceError("case not found", 404)
        return self._case_public(case) | {"events": self.db.list_case_events(case_id)}

    def list_cases(self) -> list[dict[str, Any]]:
        return [self._case_public(c) for c in self.db.list_cases()]

    #: Where each case state sits in the user's workflow, and what they do next.
    _CASE_STAGE: dict[CaseState, tuple[str, str, str | None]] = {
        CaseState.DISCOVERED: ("to_do", "Choose how to act", "ACTION_SELECTED"),
        CaseState.ACTION_SELECTED: ("to_do", "Open the draft and send it", "REQUEST_PREPARED"),
        CaseState.REQUEST_PREPARED: (
            "to_do", "Send it, then mark it submitted", "USER_MARKED_SUBMITTED",
        ),
        CaseState.USER_MARKED_SUBMITTED: ("waiting", "Sent — waiting on them", "AWAITING_RESPONSE"),
        CaseState.AWAITING_RESPONSE: ("waiting", "Waiting on them — check again", None),
        CaseState.SOURCE_CHANGED: ("verify", "The page changed — verify it", None),
        CaseState.VERIFICATION_PENDING: ("verify", "Ready to verify", None),
        CaseState.VERIFIED: ("done", "Verified removed", None),
        CaseState.REQUEST_DENIED: ("to_do", "They refused — try another route", "ACTION_SELECTED"),
        CaseState.REAPPEARED: ("to_do", "It came back — act again", "ACTION_SELECTED"),
        CaseState.SOURCE_UNREACHABLE: ("waiting", "Page unreachable — try later", None),
        CaseState.NOT_APPLICABLE: ("done", "No action available", None),
        CaseState.REJECTED: ("done", "Not you", None),
        CaseState.USER_ABANDONED: ("done", "You stopped this one", None),
        CaseState.REVIEWED: ("to_do", "Choose how to act", "ACTION_SELECTED"),
    }

    #: Case states worth re-checking: something was asked for and the outcome
    #: is not yet settled, or was settled and could regress.
    _RECHECKABLE = (
        CaseState.USER_MARKED_SUBMITTED,
        CaseState.AWAITING_RESPONSE,
        CaseState.VERIFICATION_PENDING,
        CaseState.SOURCE_CHANGED,
        CaseState.VERIFIED,
        CaseState.REAPPEARED,
    )

    def recheck_all(self) -> dict[str, Any]:
        """Re-verify every open case and report what actually changed.

        This is the loop that makes Exposure a remediation tool rather than a
        scanner: a request was sent, and the only honest way to know whether it
        worked is to look again. Reports observed states only — a page that is
        merely unreachable is never counted as removed.
        """
        changes: list[dict[str, Any]] = []
        checked = 0
        for case in self.db.list_cases():
            if case.state not in self._RECHECKABLE:
                continue
            before = case.state
            try:
                result = self.verify_case(case.id)
            except ServiceError:
                continue
            checked += 1
            after = CaseState(result["state"])
            verification = result.get("verification") or {}
            status = verification.get("source_status", "UNKNOWN")
            if after != before:
                finding = self.db.get_finding(case.finding_id)
                source = self.db.get_source(finding.source_id) if finding else None
                changes.append(
                    {
                        "case_id": case.id,
                        "domain": source.registrable_domain if source else "",
                        "from": before.value,
                        "to": after.value,
                        "status": status,
                        "good": after == CaseState.VERIFIED,
                        "bad": after == CaseState.REAPPEARED,
                    }
                )
        return {
            "checked": checked,
            "changed": len(changes),
            "changes": changes,
            "resolved": sum(1 for c in changes if c["good"]),
            "reappeared": sum(1 for c in changes if c["bad"]),
        }

    def cleanup_board(self) -> dict[str, Any]:
        """The Cleanup view: what to do now, what you're waiting on, what's done.

        A flat list of case rows does not tell someone what to actually do next.
        This groups every case into a stage, names the next action in plain
        words, and carries the page it belongs to so the board is readable
        without opening anything.
        """
        lanes: dict[str, list[dict[str, Any]]] = {
            "to_do": [], "waiting": [], "verify": [], "done": [],
        }
        for case in self.db.list_cases():
            finding = self.db.get_finding(case.finding_id)
            if finding is None:
                continue
            source = self.db.get_source(finding.source_id)
            lane, next_label, next_state = self._CASE_STAGE.get(
                case.state, ("to_do", "Review this", None)
            )
            entry = self._case_public(case) | {
                "category": finding.category.value,
                "priority": finding.overall_priority.value,
                "domain": source.registrable_domain if source else "",
                "url": source.url if source else "",
                "title": (source.title if source else None) or (
                    source.registrable_domain if source else ""
                ),
                "next_label": next_label,
                "next_state": next_state,
                "verification": case.verification.model_dump(mode="json")
                if case.verification
                else None,
            }
            lanes[lane].append(entry)

        return {
            "lanes": lanes,
            "counts": {k: len(v) for k, v in lanes.items()},
            "total": sum(len(v) for v in lanes.values()),
        }

    def add_case_event(self, case_id: str, payload: CaseEvent) -> dict[str, Any]:
        case = self.db.get_case(case_id)
        if case is None:
            raise ServiceError("case not found", 404)
        try:
            target = CaseState(payload.target_state)
        except ValueError as exc:
            raise ServiceError(f"unknown state: {payload.target_state}", 400) from exc
        from exposure.remediation import InvalidTransition

        try:
            assert_transition(case.state, target)
        except InvalidTransition as exc:
            raise ServiceError(str(exc), 400) from exc
        case.state = target
        if target == CaseState.USER_MARKED_SUBMITTED:
            from exposure.domain.models import utcnow

            case.submitted_at = utcnow()
        self.db.update_case(case)
        self.db.add_case_event(case_id, "transition", {"to": target.value, "note": payload.note})
        return self._case_public(case)

    def verify_case(self, case_id: str) -> dict[str, Any]:
        case = self.db.get_case(case_id)
        if case is None:
            raise ServiceError("case not found", 404)
        finding = self.db.get_finding(case.finding_id)
        if finding is None:
            raise ServiceError("finding not found", 404)
        source = self.db.get_source(finding.source_id)
        subject = self.db.get_subject(finding.subject_id)
        if source is None or subject is None:
            raise ServiceError("source/subject missing", 404)

        target_values = [
            o.value_normalized
            for o in self.db.observations_for_source(finding.source_id)
            if o.id in set(finding.observation_ids)
        ]
        from exposure.domain.models import utcnow
        from exposure.retrieval.client import SecureRetriever

        make = self._retriever_factory or (lambda s: SecureRetriever(s))
        retriever = make(self.settings)
        try:
            verification = verify_source(retriever, source, target_values, subject)
        finally:
            retriever.close()
        case.verification = verification
        case.last_checked_at = utcnow()

        # Something previously confirmed gone has come back. This is the failure
        # mode removal services are criticised for, so it is detected explicitly
        # rather than left as a stale "verified".
        gone_states = (
            VerificationStatus.URL_GONE,
            VerificationStatus.PERSONAL_DATA_REMOVED,
            VerificationStatus.CONTENT_REMOVED,
        )
        if case.state == CaseState.VERIFIED and verification.source_status not in gone_states:
            case.state = CaseState.REAPPEARED
            self.db.update_case(case)
            self.db.add_case_event(
                case_id, "reappeared", {"status": verification.source_status.value}
            )
            return self._case_public(case) | {
                "verification": verification.model_dump(mode="json"),
                "reappeared": True,
            }
        # Move toward a verified/reappeared state based on what we observed.
        if case.state in (CaseState.USER_MARKED_SUBMITTED, CaseState.AWAITING_RESPONSE):
            case.state = CaseState.VERIFICATION_PENDING
        if case.state == CaseState.VERIFICATION_PENDING and verification.source_status in (
            VerificationStatus.URL_GONE,
            VerificationStatus.PERSONAL_DATA_REMOVED,
            VerificationStatus.CONTENT_REMOVED,
        ):
            case.state = CaseState.VERIFIED
        self.db.update_case(case)
        self.db.add_case_event(
            case_id, "verification", {"status": verification.source_status.value}
        )
        return self._case_public(case) | {
            "verification": verification.model_dump(mode="json")
        }

    @staticmethod
    def _case_public(case: RemediationCase) -> dict[str, Any]:
        return {
            "id": case.id,
            "finding_id": case.finding_id,
            "route": case.route.value,
            "registry_route_id": case.registry_route_id,
            "state": case.state.value,
            "opened_at": case.opened_at.isoformat(),
            "submitted_at": case.submitted_at.isoformat() if case.submitted_at else None,
            "last_checked_at": case.last_checked_at.isoformat() if case.last_checked_at else None,
        }

    # -- providers ---------------------------------------------------------- #

    def list_providers(self) -> list[dict[str, Any]]:
        known = {p["id"]: p for p in self.db.list_providers()}
        # DuckDuckGo is the keyless, always-available default; it has no stored
        # settings row and needs no configuration.
        out: list[dict[str, Any]] = [
            {
                "id": "duckduckgo",
                "kind": "search",
                "enabled": True,
                "config": {},
                "has_key": False,
                "needs_key": False,
                "always_available": True,
            }
        ]
        for pid, kind in (("searxng", "search"), ("brave", "search"), ("ai", "ai")):
            row = known.get(pid, {"id": pid, "kind": kind, "enabled": False, "config": {}})
            row["has_key"] = self.db.secrets.get_api_key(pid) is not None
            row["needs_key"] = pid != "searxng"
            row["always_available"] = False
            out.append(row)
        return out

    def active_search_provider(self) -> str:
        """Which provider a scan would use right now (honest UI pre-flight)."""
        searxng = self.db.get_provider("searxng")
        if searxng and searxng.get("enabled") and searxng.get("config", {}).get("base_url"):
            return "searxng"
        if self.db.secrets.get_api_key("brave"):
            return "brave"
        return "duckduckgo"

    def set_provider(self, provider_id: str, payload: ProviderUpdate) -> dict[str, Any]:
        kind = "search" if provider_id in ("brave", "searxng") else "ai"
        if provider_id == "searxng" and payload.enabled:
            from exposure.discovery.providers.searxng import validate_instance_url

            base_url = str(payload.config.get("base_url", ""))
            try:
                payload.config["base_url"] = validate_instance_url(base_url)
            except Exception as exc:
                raise ServiceError(f"invalid SearXNG URL: {exc}", 400) from exc
        # The API key goes to the secret vault, never the database.
        if payload.api_key:
            self.db.secrets.set_api_key(provider_id, payload.api_key)
        self.db.set_provider(provider_id, kind, payload.enabled, payload.config)
        provider = self.db.get_provider(provider_id) or {
            "id": provider_id,
            "kind": kind,
            "enabled": payload.enabled,
            "config": payload.config,
        }
        provider["has_key"] = self.db.secrets.get_api_key(provider_id) is not None
        return provider

    # -- exports ------------------------------------------------------------ #

    def export_report(self, subject_id: str) -> dict[str, str]:
        self.get_subject(subject_id)
        return write_report(self.db, subject_id, self.settings.export_dir)

    def report_json(self, subject_id: str) -> dict[str, Any]:
        self.get_subject(subject_id)
        return build_report(self.db, subject_id)

    # -- dashboard ---------------------------------------------------------- #

    def grouped_findings(self, subject_id: str) -> list[dict[str, Any]]:
        """Findings grouped by the page they were found on.

        One page normally yields several findings (a username, a linked profile,
        an email). Listing those as separate rows repeats the same page over and
        over and never shows *what* was actually found. Grouping by source, and
        carrying the concrete values through, is what makes the list readable
        and actionable. Sensitive values are the masked display forms.
        """
        self.get_subject(subject_id)
        by_source: dict[str, dict[str, Any]] = {}

        for finding in self.db.list_findings(subject_id):
            source = self.db.get_source(finding.source_id)
            if source is None:
                continue
            group = by_source.setdefault(
                finding.source_id,
                {
                    "source_id": finding.source_id,
                    "url": source.url,
                    "domain": source.registrable_domain,
                    "title": source.title,
                    "identity_state": finding.match_state.value,
                    "identity_confidence": finding.identity_confidence,
                    "needs_review": not finding.match_state.actionable,
                    "priority": finding.overall_priority.value,
                    "finding_ids": [],
                    "items": [],
                },
            )
            group["finding_ids"].append(finding.id)
            if Severity(finding.overall_priority) > Severity(group["priority"]):
                group["priority"] = finding.overall_priority.value

            wanted = set(finding.observation_ids)
            for obs in self.db.observations_for_source(finding.source_id):
                if obs.id not in wanted:
                    continue
                entry = {
                    "category": finding.category.value,
                    "label": finding.category.value.replace("_", " ").title(),
                    "value": obs.display_value,
                    "sensitive": obs.is_sensitive,
                }
                if entry not in group["items"]:
                    group["items"].append(entry)

        groups = list(by_source.values())
        # Unreviewed first, then by priority: that is the order of work.
        rank = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "NONE": 4}
        groups.sort(key=lambda g: (not g["needs_review"], rank.get(g["priority"], 5)))
        return groups

    def scan_quality(self, subject_id: str) -> dict[str, Any]:
        """Explain the coverage and confidence the user is actually looking at.

        Two things routinely make a scan look broken when it is working:

        * many result pages are login walls or JavaScript shells (LinkedIn,
          Crunchbase, Bloomberg, ZoomInfo…), so a static fetch yields nothing —
          measured here rather than left as a silent gap;
        * a page that only carries a name, or a name and a city, is genuinely
          not enough to prove identity, so it stays in review. That is the
          product working, but only if we say so and make reviewing easy.

        Deliberately makes no promise that adding a particular profile field
        will confirm anything: whether it helps depends on the page text, and
        empirically it often does not.
        """
        self.get_subject(subject_id)
        findings = self.db.list_findings(subject_id)
        source_ids = {f.source_id for f in findings}

        unreadable = 0
        for row in self.db.conn.execute(
            "SELECT s.id, COUNT(o.id) AS obs FROM sources s "
            "LEFT JOIN observations o ON o.source_id = s.id "
            "WHERE s.status = 'RETRIEVED' GROUP BY s.id"
        ):
            if row["obs"] <= 1:
                unreadable += 1
        blocked = self.db.conn.execute(
            "SELECT COUNT(*) FROM sources WHERE status != 'RETRIEVED'"
        ).fetchone()[0]

        needs_review = sum(1 for f in findings if not f.match_state.actionable)
        return {
            "total_findings": len(findings),
            "needs_review": needs_review,
            "sources_with_findings": len(source_ids),
            "unreadable_pages": unreadable,
            "unfetchable_pages": blocked,
            "message": (
                f"{needs_review} of {len(findings)} findings need your confirmation. "
                "Exposure will not guess that a page is you from a name alone — "
                "mark each one “This is me” or “Not me” and it moves into Cleanup."
                if needs_review
                else ""
            ),
            "coverage_note": (
                f"{unreadable} page(s) returned a login wall or script-only content "
                "(LinkedIn, Crunchbase and similar), so nothing could be read from them."
                if unreadable
                else ""
            ),
        }

    def dashboard(self, subject_id: str) -> dict[str, Any]:
        findings = self.db.list_findings(subject_id)
        counts = {"HIGH": 0, "MODERATE": 0, "LOW": 0, "needs_review": 0}
        for f in findings:
            if not f.match_state.actionable:
                counts["needs_review"] += 1
            elif f.overall_priority in (Severity.HIGH, Severity.CRITICAL):
                counts["HIGH"] += 1
            elif f.overall_priority == Severity.MODERATE:
                counts["MODERATE"] += 1
            else:
                counts["LOW"] += 1
        return {
            "counts": counts,
            "total": len(findings),
            "quality": self.scan_quality(subject_id),
        }

    # -- danger zone -------------------------------------------------------- #

    def delete_all(self) -> None:
        self.db.delete_all()
