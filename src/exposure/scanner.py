"""Scan orchestration: DISCOVER -> OBSERVE -> RESOLVE -> ASSESS.

Runs synchronously (call it inside a worker thread). Enforces the scan budgets,
records every source (including blocked ones) so failures are never silently
converted into absence, and only emits findings for candidates with a real
identity anchor — precision over recall.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from exposure.assessment import (
    AssessmentContext,
    assess,
    group_into_findings,
    identity_reason,
    summarize,
)
from exposure.config import Settings
from exposure.discovery import (
    DiscoveryProvider,
    ProviderError,
    SearchCandidate,
    plan_queries,
)
from exposure.discovery.providers import (
    BraveSearchProvider,
    DuckDuckGoProvider,
    ManualURLProvider,
    SearXNGProvider,
)
from exposure.domain.enums import MatchState, SignalKind, SourceStatus
from exposure.domain.models import Finding, Observation, Source, Subject, new_id, utcnow
from exposure.extraction import extract_document
from exposure.resolution import resolve
from exposure.retrieval import canonical_url, registrable_domain
from exposure.retrieval.client import RetrievalError, SecureRetriever
from exposure.storage.database import Database


@dataclass(slots=True)
class ScanOptions:
    use_search: bool = False
    include_sensitive: bool = False
    manual_urls: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanStats:
    queries_planned: int = 0
    queries_run: int = 0
    sensitive_skipped: int = 0
    candidates: int = 0
    retrieved: int = 0
    blocked: int = 0
    failed: int = 0
    bytes_downloaded: int = 0
    findings: int = 0
    provider_errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "queries_planned": self.queries_planned,
            "queries_run": self.queries_run,
            "sensitive_skipped": self.sensitive_skipped,
            "candidates": self.candidates,
            "retrieved": self.retrieved,
            "blocked": self.blocked,
            "failed": self.failed,
            "bytes_downloaded": self.bytes_downloaded,
            "findings": self.findings,
            "provider_errors": self.provider_errors,
        }


def _has_identity_anchor(match) -> bool:  # type: ignore[no-untyped-def]
    return any(
        s.kind in (SignalKind.IDENTITY, SignalKind.DIRECT) for s in match.supporting_signals
    )


class Scanner:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        retriever_factory: Callable[[Settings], SecureRetriever] | None = None,
    ) -> None:
        self._db = db
        self._settings = settings
        self._make_retriever = retriever_factory or (lambda s: SecureRetriever(s))

    def begin(self, subject: Subject) -> str:
        """Create the scan record and return its id (before work starts)."""
        scan_id = new_id()
        self._db.create_scan(scan_id, subject.id, utcnow())
        return scan_id

    def run_existing(self, scan_id: str, subject: Subject, options: ScanOptions) -> ScanStats:
        """Run the pipeline for an already-created scan record."""
        stats = ScanStats()
        try:
            self._run_inner(scan_id, subject, options, stats)
            status = "INCOMPLETE" if stats.provider_errors else "COMPLETE"
            self._db.finish_scan(scan_id, status, utcnow(), stats.as_dict())
        except Exception as exc:  # never leave a scan dangling
            self._db.finish_scan(
                scan_id, "ERROR", utcnow(), stats.as_dict(), error=type(exc).__name__
            )
            raise
        return stats

    def run(self, subject: Subject, options: ScanOptions) -> tuple[str, ScanStats]:
        scan_id = self.begin(subject)
        return scan_id, self.run_existing(scan_id, subject, options)

    def _select_provider(self) -> DiscoveryProvider:
        """Pick the search provider, preferring reliability where configured.

        Order:
        1. SearXNG if the user configured a self-hosted instance (keyless, and
           keeps queries off third-party infrastructure);
        2. Brave if an API key is set (most reliable results);
        3. DuckDuckGo — the keyless, zero-setup default so "search for me" works
           out of the box with nothing configured.

        Because a usable default always exists, this never raises for "nothing
        configured". It still returns a provider whose own errors (e.g. a
        DuckDuckGo rate-limit) are surfaced as an *incomplete* scan.
        """
        searxng = self._db.get_provider("searxng")
        if searxng and searxng.get("enabled"):
            base_url = str(searxng.get("config", {}).get("base_url", ""))
            if not base_url:
                raise ProviderError("searxng_url_missing")
            return SearXNGProvider(base_url)

        key = self._db.secrets.get_api_key("brave")
        if key:
            return BraveSearchProvider(key)

        return DuckDuckGoProvider()

    def _gather_candidates(
        self, subject: Subject, options: ScanOptions, stats: ScanStats
    ) -> list[tuple[SearchCandidate, bool]]:
        """Return ``(candidate, from_search)`` pairs, deduped and capped."""
        plan = plan_queries(subject, self._settings)
        stats.queries_planned = len(plan.queries)
        pairs: list[tuple[SearchCandidate, bool]] = []

        search_provider = None
        if options.use_search:
            try:
                search_provider = self._select_provider()
            except ProviderError as exc:
                stats.provider_errors.append(str(exc))

        if search_provider is not None:
            for pq in plan.queries:
                if pq.sensitive and not options.include_sensitive:
                    stats.sensitive_skipped += 1
                    continue
                try:
                    results = search_provider.search(
                        pq.as_query(), self._settings.max_results_per_query
                    )
                    stats.queries_run += 1
                    pairs.extend((c, True) for c in results)
                except ProviderError as exc:
                    stats.provider_errors.append(str(exc))

        manual = ManualURLProvider(options.manual_urls)
        pairs.extend((c, False) for c in manual.all_candidates())

        # Dedupe by canonical URL, keep the first occurrence (prefer from_search).
        seen: set[str] = set()
        deduped: list[tuple[SearchCandidate, bool]] = []
        for cand, from_search in pairs:
            try:
                canon = canonical_url(cand.url)
            except Exception:  # noqa: S112 - a malformed candidate URL is simply skipped
                continue
            if canon in seen:
                continue
            seen.add(canon)
            deduped.append((cand, from_search))
            if len(deduped) >= self._settings.max_candidate_urls:
                break
        stats.candidates = len(deduped)
        return deduped

    def _run_inner(
        self, scan_id: str, subject: Subject, options: ScanOptions, stats: ScanStats
    ) -> None:
        candidates = self._gather_candidates(subject, options, stats)
        retriever = self._make_retriever(self._settings)
        try:
            for cand, from_search in candidates:
                if stats.retrieved >= self._settings.max_documents_per_scan:
                    break
                if stats.bytes_downloaded >= self._settings.max_scan_bytes:
                    break
                self._process_candidate(retriever, scan_id, subject, cand, from_search, stats)
        finally:
            retriever.close()

    def _process_candidate(
        self,
        retriever: SecureRetriever,
        scan_id: str,
        subject: Subject,
        cand: SearchCandidate,
        from_search: bool,
        stats: ScanStats,
    ) -> None:
        try:
            doc = retriever.fetch(cand.url)
        except RetrievalError as exc:
            # Record the source with its explicit failure status.
            source = Source(
                url=cand.url,
                canonical_url=canonical_url(cand.url),
                registrable_domain=registrable_domain(cand.url),
                status=exc.status,
                title=cand.title or None,
            )
            self._db.upsert_source(source, scan_id)
            if exc.status == SourceStatus.RETRIEVAL_BLOCKED:
                stats.blocked += 1
            else:
                stats.failed += 1
            return

        stats.retrieved += 1
        stats.bytes_downloaded += len(doc.body)

        reg_domain = registrable_domain(doc.final_url)
        extraction = extract_document(doc.content_type, doc.body, subject)
        source = Source(
            url=cand.url,
            canonical_url=canonical_url(doc.final_url),
            registrable_domain=reg_domain,
            title=extraction.title or cand.title or None,
            retrieved_at=datetime.now(UTC),
            http_status=doc.status_code,
            content_type=doc.content_type,
            content_hash=doc.content_hash,
            status=SourceStatus.RETRIEVED,
        )
        self._db.upsert_source(source, scan_id)

        observations = [
            Observation(
                source_id=source.id,
                type=item.type,
                value_normalized=item.value_normalized,
                display_value=item.display_value,
                evidence_snippet=item.evidence_snippet,
                extractor=item.extractor,
                extractor_version=item.extractor_version,
                is_sensitive=item.is_sensitive,
            )
            for item in extraction.items
        ]
        self._db.add_observations(observations)

        match = resolve(source, observations, subject)
        self._db.upsert_match(match)

        if match.state == MatchState.REJECTED or not _has_identity_anchor(match):
            return  # source recorded, but no findings (precision over recall)

        groups = group_into_findings(observations)
        categories_present = frozenset(groups.keys())
        supporting_names = [s.name for s in match.supporting_signals]

        for category, obs_list in groups.items():
            ctx = AssessmentContext(
                from_search=from_search,
                registrable_domain=reg_domain,
                categories_on_source=categories_present,
                match_state=match.state,
            )
            a = assess(category, ctx)
            finding = Finding(
                subject_id=subject.id,
                source_id=source.id,
                category=category,
                sensitivity=a.sensitivity,
                discoverability=a.discoverability,
                misuse_potential=a.misuse_potential,
                persistence=a.persistence,
                overall_priority=a.overall_priority,
                assessment_confidence=1.0,
                identity_confidence=match.confidence,
                match_state=match.state,
                explanation_codes=a.reason_codes,
                summary=summarize(category),
                observation_ids=[o.id for o in obs_list],
                assessment_policy_version=a.policy_version,
            )
            self._db.add_finding(finding)
            stats.findings += 1
        # identity_reason is available for the finding-detail view via the match.
        _ = identity_reason(match.state, supporting_names)
