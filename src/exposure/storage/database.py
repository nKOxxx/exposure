"""SQLite persistence with a thin, typed repository layer.

We use raw ``sqlite3`` rather than an ORM: the schema is small and stable, the
persisted values must be fully auditable, and it keeps the dependency surface
minimal (spec section 29). Migrations are plain forward-only ``.sql`` files.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import uuid
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any

from exposure.config import Settings
from exposure.domain.enums import (
    CaseState,
    FindingCategory,
    MatchState,
    ObservationType,
    RemediationRoute,
    Severity,
    SourceStatus,
)
from exposure.domain.models import (
    Finding,
    LocationHint,
    Match,
    Name,
    Observation,
    OrganisationHint,
    RemediationCase,
    SecretField,
    Signal,
    Source,
    Subject,
    Verification,
)
from exposure.security.redaction import mask_email, mask_phone
from exposure.storage.secrets import SecretStore

_MIGRATIONS_PACKAGE = "exposure.storage.migrations"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _dt(value: Any) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _dt_req(value: Any) -> datetime:
    """Convert a NOT-NULL timestamp column value to a datetime."""
    return datetime.fromisoformat(value)


class Database:
    """Owns the SQLite connection and all persistence operations."""

    def __init__(self, settings: Settings, secrets: SecretStore | None = None) -> None:
        self.settings = settings
        self.secrets = secrets or SecretStore(settings.workspace)
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle ---------------------------------------------------------- #

    def connect(self) -> None:
        self.settings.ensure_dirs()
        conn = sqlite3.connect(
            self.settings.db_path,
            detect_types=0,
            isolation_level=None,  # autocommit; we manage transactions explicitly
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        self._conn = conn
        self.migrate()
        # NOTE: orphan cleanup is deliberately NOT done here. Scan workers open
        # their own connection while a scan is in flight, so doing it on every
        # connect() would mark the live scan as interrupted. The application
        # calls mark_orphaned_scans() once at startup instead.

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -- migrations --------------------------------------------------------- #

    def migrate(self) -> None:
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        applied = {
            row["version"] for row in self.conn.execute("SELECT version FROM schema_migrations")
        }
        for version, sql in self._migration_files():
            if version in applied:
                continue
            # executescript() manages its own transaction (it commits any pending
            # one first), so we must not wrap it in an explicit BEGIN/COMMIT.
            self.conn.executescript(sql)
            self.conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, datetime.now().astimezone().isoformat()),
            )

    def _migration_files(self) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        pkg = resources.files(_MIGRATIONS_PACKAGE)
        for entry in pkg.iterdir():
            name = entry.name
            if name.endswith(".sql") and name[:4].isdigit():
                out.append((int(name[:4]), entry.read_text(encoding="utf-8")))
        out.sort(key=lambda t: t[0])
        return out

    # -- subjects ----------------------------------------------------------- #

    def create_subject(self, subject: Subject) -> Subject:
        profile = {
            "names": [n.model_dump() for n in subject.names],
            "locations": [loc.model_dump() for loc in subject.locations],
            "employers": [e.model_dump() for e in subject.employers],
            "usernames": subject.usernames,
            "personal_domains": subject.personal_domains,
        }
        with self._tx():
            self.conn.execute(
                "INSERT INTO subjects(id, created_at, profile) VALUES (?, ?, ?)",
                (subject.id, subject.created_at.isoformat(), json.dumps(profile)),
            )
            for field, kind, mask in (
                (subject.emails, "EMAIL", mask_email),
                (subject.phones, "PHONE", mask_phone),
            ):
                for item in field:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO subject_identifiers"
                        "(id, subject_id, kind, display, value_enc) VALUES (?, ?, ?, ?, ?)",
                        (
                            uuid.uuid4().hex,
                            subject.id,
                            kind,
                            item.display or mask(item.value),
                            self.secrets.encrypt_field(item.value),
                        ),
                    )
        return subject

    def get_subject(self, subject_id: str) -> Subject | None:
        row = self.conn.execute(
            "SELECT id, created_at, profile FROM subjects WHERE id = ?", (subject_id,)
        ).fetchone()
        if row is None:
            return None
        profile = json.loads(row["profile"])
        emails: list[SecretField] = []
        phones: list[SecretField] = []
        for ident in self.conn.execute(
            "SELECT kind, display, value_enc FROM subject_identifiers WHERE subject_id = ?",
            (subject_id,),
        ):
            field = SecretField(
                value=self.secrets.decrypt_field(ident["value_enc"]),
                display=ident["display"],
            )
            (emails if ident["kind"] == "EMAIL" else phones).append(field)
        return Subject(
            id=row["id"],
            created_at=_dt_req(row["created_at"]),
            names=[Name(**n) for n in profile.get("names", [])],
            locations=[LocationHint(**loc) for loc in profile.get("locations", [])],
            employers=[OrganisationHint(**e) for e in profile.get("employers", [])],
            usernames=profile.get("usernames", []),
            personal_domains=profile.get("personal_domains", []),
            emails=emails,
            phones=phones,
        )

    def list_subjects(self) -> list[Subject]:
        ids = [r["id"] for r in self.conn.execute("SELECT id FROM subjects ORDER BY created_at")]
        return [s for sid in ids if (s := self.get_subject(sid)) is not None]

    def delete_subject(self, subject_id: str) -> None:
        with self._tx():
            self.conn.execute("DELETE FROM subjects WHERE id = ?", (subject_id,))

    # -- scans -------------------------------------------------------------- #

    def create_scan(self, scan_id: str, subject_id: str, started_at: datetime) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT INTO scans(id, subject_id, started_at, status) VALUES (?, ?, ?, 'RUNNING')",
                (scan_id, subject_id, started_at.isoformat()),
            )

    def update_scan_stats(self, scan_id: str, stats: dict[str, Any]) -> None:
        """Persist in-progress counters so the UI can show live progress.

        Without this, stats only appear when a scan finishes and a running scan
        reports zeros the whole time — which reads as a frozen app.
        """
        with self._tx():
            self.conn.execute(
                "UPDATE scans SET stats = ? WHERE id = ?", (json.dumps(stats), scan_id)
            )

    def mark_orphaned_scans(self) -> int:
        """Fail scans left RUNNING by a process that exited (e.g. a restart).

        Their worker thread is gone, so they would otherwise poll forever.
        """
        with self._tx():
            cur = self.conn.execute(
                "UPDATE scans SET status='INTERRUPTED', finished_at=?,"
                " error='server restarted during scan' WHERE status='RUNNING'",
                (datetime.now().astimezone().isoformat(),),
            )
        return int(cur.rowcount or 0)

    def finish_scan(
        self,
        scan_id: str,
        status: str,
        finished_at: datetime,
        stats: dict[str, Any],
        error: str | None = None,
    ) -> None:
        with self._tx():
            self.conn.execute(
                "UPDATE scans SET status=?, finished_at=?, stats=?, error=? WHERE id=?",
                (status, finished_at.isoformat(), json.dumps(stats), error, scan_id),
            )

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["stats"] = json.loads(d.get("stats") or "{}")
        return d

    # -- sources ------------------------------------------------------------ #

    def upsert_source(self, source: Source, scan_id: str | None) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT INTO sources(id, scan_id, url, canonical_url, registrable_domain,"
                " title, retrieved_at, http_status, content_type, content_hash, status)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET title=excluded.title,"
                " retrieved_at=excluded.retrieved_at, http_status=excluded.http_status,"
                " content_type=excluded.content_type, content_hash=excluded.content_hash,"
                " status=excluded.status",
                (
                    source.id,
                    scan_id,
                    source.url,
                    source.canonical_url,
                    source.registrable_domain,
                    source.title,
                    _iso(source.retrieved_at),
                    source.http_status,
                    source.content_type,
                    source.content_hash,
                    source.status.value,
                ),
            )

    def get_source(self, source_id: str) -> Source | None:
        row = self.conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        return self._row_to_source(row) if row else None

    def find_source_by_canonical(self, scan_id: str, canonical_url: str) -> Source | None:
        row = self.conn.execute(
            "SELECT * FROM sources WHERE scan_id = ? AND canonical_url = ?",
            (scan_id, canonical_url),
        ).fetchone()
        return self._row_to_source(row) if row else None

    def _row_to_source(self, row: sqlite3.Row) -> Source:
        return Source(
            id=row["id"],
            url=row["url"],
            canonical_url=row["canonical_url"],
            registrable_domain=row["registrable_domain"],
            title=row["title"],
            retrieved_at=_dt(row["retrieved_at"]),
            http_status=row["http_status"],
            content_type=row["content_type"],
            content_hash=row["content_hash"],
            status=SourceStatus(row["status"]),
        )

    # -- observations ------------------------------------------------------- #

    def add_observations(self, observations: list[Observation]) -> None:
        if not observations:
            return
        with self._tx():
            self.conn.executemany(
                "INSERT INTO observations(id, source_id, type, value_normalized, display_value,"
                " evidence_snippet, extractor, extractor_version, is_sensitive, observed_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        o.id,
                        o.source_id,
                        o.type.value,
                        o.value_normalized,
                        o.display_value,
                        o.evidence_snippet,
                        o.extractor,
                        o.extractor_version,
                        1 if o.is_sensitive else 0,
                        o.observed_at.isoformat(),
                    )
                    for o in observations
                ],
            )

    def observations_for_source(self, source_id: str) -> list[Observation]:
        rows = self.conn.execute(
            "SELECT * FROM observations WHERE source_id = ?", (source_id,)
        ).fetchall()
        return [
            Observation(
                id=r["id"],
                source_id=r["source_id"],
                type=ObservationType(r["type"]),
                value_normalized=r["value_normalized"],
                display_value=r["display_value"],
                evidence_snippet=r["evidence_snippet"],
                extractor=r["extractor"],
                extractor_version=r["extractor_version"],
                is_sensitive=bool(r["is_sensitive"]),
                observed_at=_dt_req(r["observed_at"]),
            )
            for r in rows
        ]

    # -- matches ------------------------------------------------------------ #

    def upsert_match(self, match: Match) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT INTO matches(id, source_id, subject_id, state, confidence, supporting,"
                " contradicting, resolution_version, user_overridden, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(source_id, subject_id) DO UPDATE SET state=excluded.state,"
                " confidence=excluded.confidence, supporting=excluded.supporting,"
                " contradicting=excluded.contradicting, resolution_version=excluded.resolution_version,"
                " user_overridden=excluded.user_overridden",
                (
                    match.id,
                    match.source_id,
                    match.subject_id,
                    match.state.value,
                    match.confidence,
                    json.dumps([s.model_dump() for s in match.supporting_signals]),
                    json.dumps([s.model_dump() for s in match.contradicting_signals]),
                    match.resolution_version,
                    1 if match.user_overridden else 0,
                    match.created_at.isoformat(),
                ),
            )

    def get_match_for_source(self, source_id: str) -> Match | None:
        row = self.conn.execute(
            "SELECT * FROM matches WHERE source_id = ?", (source_id,)
        ).fetchone()
        return self._row_to_match(row) if row else None

    def _row_to_match(self, row: sqlite3.Row) -> Match:
        return Match(
            id=row["id"],
            source_id=row["source_id"],
            subject_id=row["subject_id"],
            state=MatchState(row["state"]),
            confidence=row["confidence"],
            supporting_signals=[Signal(**s) for s in json.loads(row["supporting"])],
            contradicting_signals=[Signal(**s) for s in json.loads(row["contradicting"])],
            resolution_version=row["resolution_version"],
            user_overridden=bool(row["user_overridden"]),
            created_at=_dt_req(row["created_at"]),
        )

    # -- findings ----------------------------------------------------------- #

    def supersede_findings_for_url(self, subject_id: str, canonical_url: str) -> int:
        """Drop earlier findings for the same page before re-recording it.

        Each scan creates a fresh source row, so without this a re-scan stacks a
        second copy of every finding and the totals climb with each run.
        """
        with self._tx():
            cur = self.conn.execute(
                "DELETE FROM findings WHERE subject_id = ? AND source_id IN "
                "(SELECT id FROM sources WHERE canonical_url = ?)",
                (subject_id, canonical_url),
            )
        return int(cur.rowcount or 0)

    def add_finding(self, finding: Finding) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT INTO findings(id, subject_id, source_id, category, sensitivity,"
                " discoverability, misuse_potential, persistence, overall_priority,"
                " assessment_confidence, identity_confidence, match_state, explanation_codes,"
                " summary, observation_ids, assessment_policy_version, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    finding.id,
                    finding.subject_id,
                    finding.source_id,
                    finding.category.value,
                    finding.sensitivity.value,
                    finding.discoverability.value,
                    finding.misuse_potential.value,
                    finding.persistence.value,
                    finding.overall_priority.value,
                    finding.assessment_confidence,
                    finding.identity_confidence,
                    finding.match_state.value,
                    json.dumps(finding.explanation_codes),
                    finding.summary,
                    json.dumps(finding.observation_ids),
                    finding.assessment_policy_version,
                    finding.created_at.isoformat(),
                ),
            )

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return self._row_to_finding(row) if row else None

    def list_findings(self, subject_id: str | None = None) -> list[Finding]:
        if subject_id:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE subject_id = ? ORDER BY created_at DESC",
                (subject_id,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def update_finding_match_state(self, finding_id: str, state: MatchState) -> None:
        with self._tx():
            self.conn.execute(
                "UPDATE findings SET match_state = ? WHERE id = ?", (state.value, finding_id)
            )

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            subject_id=row["subject_id"],
            source_id=row["source_id"],
            category=FindingCategory(row["category"]),
            sensitivity=Severity(row["sensitivity"]),
            discoverability=Severity(row["discoverability"]),
            misuse_potential=Severity(row["misuse_potential"]),
            persistence=Severity(row["persistence"]),
            overall_priority=Severity(row["overall_priority"]),
            assessment_confidence=row["assessment_confidence"],
            identity_confidence=row["identity_confidence"],
            match_state=MatchState(row["match_state"]),
            explanation_codes=json.loads(row["explanation_codes"]),
            summary=row["summary"],
            observation_ids=json.loads(row["observation_ids"]),
            assessment_policy_version=row["assessment_policy_version"],
            created_at=_dt_req(row["created_at"]),
        )

    # -- remediation cases -------------------------------------------------- #

    def add_case(self, case: RemediationCase) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT INTO remediation_cases(id, finding_id, route, registry_route_id, state,"
                " opened_at, submitted_at, last_checked_at, verification, note)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    case.id,
                    case.finding_id,
                    case.route.value,
                    case.registry_route_id,
                    case.state.value,
                    case.opened_at.isoformat(),
                    _iso(case.submitted_at),
                    _iso(case.last_checked_at),
                    case.verification.model_dump_json() if case.verification else None,
                    case.note,
                ),
            )

    def update_case(self, case: RemediationCase) -> None:
        with self._tx():
            self.conn.execute(
                "UPDATE remediation_cases SET route=?, registry_route_id=?, state=?,"
                " submitted_at=?, last_checked_at=?, verification=?, note=? WHERE id=?",
                (
                    case.route.value,
                    case.registry_route_id,
                    case.state.value,
                    _iso(case.submitted_at),
                    _iso(case.last_checked_at),
                    case.verification.model_dump_json() if case.verification else None,
                    case.note,
                    case.id,
                ),
            )

    def get_case(self, case_id: str) -> RemediationCase | None:
        row = self.conn.execute(
            "SELECT * FROM remediation_cases WHERE id = ?", (case_id,)
        ).fetchone()
        return self._row_to_case(row) if row else None

    def list_cases(self) -> list[RemediationCase]:
        rows = self.conn.execute(
            "SELECT * FROM remediation_cases ORDER BY opened_at DESC"
        ).fetchall()
        return [self._row_to_case(r) for r in rows]

    def _row_to_case(self, row: sqlite3.Row) -> RemediationCase:
        return RemediationCase(
            id=row["id"],
            finding_id=row["finding_id"],
            route=RemediationRoute(row["route"]),
            registry_route_id=row["registry_route_id"],
            state=CaseState(row["state"]),
            opened_at=_dt_req(row["opened_at"]),
            submitted_at=_dt(row["submitted_at"]),
            last_checked_at=_dt(row["last_checked_at"]),
            verification=(
                Verification.model_validate_json(row["verification"])
                if row["verification"]
                else None
            ),
            note=row["note"],
        )

    def add_case_event(self, case_id: str, kind: str, detail: dict[str, Any]) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT INTO case_events(id, case_id, at, kind, detail) VALUES (?,?,?,?,?)",
                (
                    uuid.uuid4().hex,
                    case_id,
                    datetime.now().astimezone().isoformat(),
                    kind,
                    json.dumps(detail),
                ),
            )

    def list_case_events(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT at, kind, detail FROM case_events WHERE case_id = ? ORDER BY at", (case_id,)
        ).fetchall()
        return [{"at": r["at"], "kind": r["kind"], "detail": json.loads(r["detail"])} for r in rows]

    # -- provider settings -------------------------------------------------- #

    def set_provider(self, pid: str, kind: str, enabled: bool, config: dict[str, Any]) -> None:
        # Guard: never persist anything key-shaped in provider config.
        for k in config:
            if "key" in k.lower() or "secret" in k.lower() or "token" in k.lower():
                raise ValueError(f"refusing to persist secret-like field in provider config: {k}")
        with self._tx():
            self.conn.execute(
                "INSERT INTO provider_settings(id, kind, enabled, config) VALUES (?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, enabled=excluded.enabled,"
                " config=excluded.config",
                (pid, kind, 1 if enabled else 0, json.dumps(config)),
            )

    def get_provider(self, pid: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM provider_settings WHERE id = ?", (pid,)
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "kind": row["kind"],
            "enabled": bool(row["enabled"]),
            "config": json.loads(row["config"]),
        }

    def list_providers(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT id FROM provider_settings ORDER BY id").fetchall()
        return [p for r in rows if (p := self.get_provider(r["id"])) is not None]

    # -- deletion ----------------------------------------------------------- #

    def delete_scan(self, scan_id: str) -> None:
        with self._tx():
            self.conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    def delete_all(self) -> None:
        """Delete the database file and all local artifacts. No fake deletion."""
        self.close()
        db = self.settings.db_path
        for path in (db, Path(str(db) + "-wal"), Path(str(db) + "-shm")):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        self.secrets.purge()

    # -- transaction helper ------------------------------------------------- #

    class _Tx:
        def __init__(self, conn: sqlite3.Connection) -> None:
            self._conn = conn

        def __enter__(self) -> sqlite3.Connection:
            self._conn.execute("BEGIN")
            return self._conn

        def __exit__(self, exc_type: object, *_: object) -> None:
            if exc_type is None:
                self._conn.execute("COMMIT")
            else:
                self._conn.execute("ROLLBACK")

    def _tx(self) -> Database._Tx:
        return Database._Tx(self.conn)
