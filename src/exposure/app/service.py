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
from exposure.domain.enums import CaseState, RemediationRoute, Severity
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
        locations = []
        if payload.city or payload.country:
            locations.append(LocationHint(city=payload.city, country=payload.country))
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
        # Move toward a verified/reappeared state based on what we observed.
        from exposure.domain.enums import VerificationStatus

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
        out = []
        for pid, kind in (("searxng", "search"), ("brave", "search"), ("ai", "ai")):
            row = known.get(pid, {"id": pid, "kind": kind, "enabled": False, "config": {}})
            row["has_key"] = self.db.secrets.get_api_key(pid) is not None
            row["needs_key"] = pid != "searxng"
            out.append(row)
        return out

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
        return {"counts": counts, "total": len(findings)}

    # -- danger zone -------------------------------------------------------- #

    def delete_all(self) -> None:
        self.db.delete_all()
