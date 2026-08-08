"""Local report export: JSON and self-contained HTML (spec section 3, 41).

Reports contain only masked identifiers (we never store raw sensitive values in
findings/observations display fields) and a provenance block so any finding can
be traced to the exact logic versions that produced it (spec section 39). The
HTML has no external scripts or fonts.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from exposure import (
    APP_VERSION,
    ASSESSMENT_POLICY_VERSION,
    REGISTRY_VERSION,
    RESOLVER_VERSION,
    SCHEMA_VERSION,
)
from exposure.storage.database import Database


def build_report(db: Database, subject_id: str) -> dict[str, Any]:
    subject = db.get_subject(subject_id)
    if subject is None:
        raise ValueError("unknown subject")

    findings = db.list_findings(subject_id)
    finding_blocks = []
    for f in findings:
        source = db.get_source(f.source_id)
        finding_blocks.append(
            {
                "id": f.id,
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
                },
                "explanation_codes": f.explanation_codes,
                "summary": f.summary,
                "source": {
                    "url": source.url if source else None,
                    "domain": source.registrable_domain if source else None,
                    "title": source.title if source else None,
                    "retrieved_at": source.retrieved_at.isoformat()
                    if source and source.retrieved_at
                    else None,
                },
            }
        )

    cases = []
    for c in db.list_cases():
        finding = db.get_finding(c.finding_id)
        if finding is None or finding.subject_id != subject_id:
            continue
        cases.append(
            {
                "id": c.id,
                "finding_id": c.finding_id,
                "route": c.route.value,
                "state": c.state.value,
                "submitted_at": c.submitted_at.isoformat() if c.submitted_at else None,
                "verification": c.verification.model_dump(mode="json")
                if c.verification
                else None,
            }
        )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "subject": {
            "id": subject.id,
            "primary_name": subject.primary_name,
            "created_at": subject.created_at.isoformat(),
        },
        "provenance": {
            "app": APP_VERSION,
            "resolver": RESOLVER_VERSION,
            "assessment_policy": ASSESSMENT_POLICY_VERSION,
            "registry": REGISTRY_VERSION,
            "schema": SCHEMA_VERSION,
        },
        "summary": _summary_counts(finding_blocks),
        "findings": finding_blocks,
        "cases": cases,
    }


def _summary_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"HIGH": 0, "MODERATE": 0, "LOW": 0, "needs_review": 0, "CRITICAL": 0, "NONE": 0}
    for f in findings:
        if f["identity"]["state"] not in ("CONFIRMED", "HIGH_CONFIDENCE"):
            counts["needs_review"] += 1
        else:
            counts[f["priority"]] = counts.get(f["priority"], 0) + 1
    return counts


def render_html(report: dict[str, Any]) -> str:
    def esc(v: object) -> str:
        return html.escape(str(v if v is not None else ""))

    s = report["summary"]
    rows = []
    for f in report["findings"]:
        src = f["source"]
        rows.append(
            "<tr>"
            f"<td><span class='pri pri-{esc(f['priority'])}'>{esc(f['priority'])}</span></td>"
            f"<td>{esc(f['category'])}</td>"
            f"<td>{esc(f['identity']['state'])} "
            f"({esc(round(float(f['identity']['confidence']) * 100))}%)</td>"
            f"<td>{esc(f['summary'])}</td>"
            f"<td><a href='{esc(src['url'])}' rel='noreferrer noopener'>{esc(src['domain'])}</a></td>"
            "</tr>"
        )
    prov = report["provenance"]
    prov_line = " · ".join(f"{k} {esc(v)}" for k, v in prov.items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exposure report</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem;
        line-height: 1.5; }}
h1 {{ font-size: 1.5rem; }}
.counts span {{ display:inline-block; margin-right:1rem; font-weight:600; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ text-align: left; padding: .5rem; border-bottom: 1px solid #8884; vertical-align: top; }}
.pri {{ padding: .1rem .4rem; border-radius: .3rem; font-size: .8rem; font-weight:700; }}
.pri-HIGH, .pri-CRITICAL {{ background:#c0392b; color:#fff; }}
.pri-MODERATE {{ background:#e67e22; color:#fff; }}
.pri-LOW, .pri-NONE {{ background:#7f8c8d; color:#fff; }}
footer {{ margin-top: 2rem; font-size: .8rem; opacity: .7; }}
</style></head>
<body>
<h1>Your exposure report</h1>
<p>Generated {esc(report['generated_at'])} for {esc(report['subject']['primary_name'])}.</p>
<div class="counts">
  <span>High: {esc(s.get('HIGH', 0))}</span>
  <span>Moderate: {esc(s.get('MODERATE', 0))}</span>
  <span>Low: {esc(s.get('LOW', 0))}</span>
  <span>Needs review: {esc(s.get('needs_review', 0))}</span>
</div>
<table>
<thead><tr><th>Priority</th><th>Type</th><th>Identity</th><th>What we found</th><th>Source</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=5>No findings.</td></tr>'}</tbody>
</table>
<footer>
<p>Exposure reports observable states only. It never claims information was erased
from the internet. Delisting is not deletion.</p>
<p>Provenance: {prov_line}</p>
</footer>
</body></html>"""


def write_report(db: Database, subject_id: str, export_dir: Path) -> dict[str, str]:
    report = build_report(db, subject_id)
    export_dir.mkdir(parents=True, exist_ok=True)
    stamp = report["generated_at"].replace(":", "").replace("-", "")[:15]
    json_path = export_dir / f"exposure-report-{stamp}.json"
    html_path = export_dir / f"exposure-report-{stamp}.html"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    return {"json": str(json_path), "html": str(html_path)}
