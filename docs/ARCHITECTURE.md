# Architecture

One trusted local application; several explicitly untrusted boundaries. No
microservices, no cloud, no message broker, no vector/graph DB (spec §4).

```
DISCOVER → OBSERVE → RESOLVE → ASSESS → REVIEW → REMEDIATE → VERIFY
```

## Modules (`src/exposure/`)

| Module | Responsibility |
|--------|----------------|
| `domain/` | The six primitives — Subject, Source, Observation, Match, Finding, RemediationCase — and all enums. |
| `config.py` | Settings + workspace paths (single deletable location). |
| `storage/` | SQLite repositories, forward-only SQL migrations, secret store (keyring/encrypted-file), field encryption. |
| `security/` | Redaction, URL/IP validation, loopback session guard. |
| `retrieval/` | Canonicalization, SSRF network policy (pinned-IP backend), size/decompression limits, the secure client. |
| `discovery/` | Query planner + replaceable providers (Brave, manual URL). |
| `extraction/` | Deterministic HTML/metadata/PII/subject-token extraction; optional semantic layer. |
| `resolution/` | Evidence-family signals, contradiction handling, resolver with abstention. |
| `assessment/` | Deterministic four-dimension policy, reason codes, plain-language explanation. |
| `remediation/` | Registry, route matching, local request drafts, case state machine, verification. |
| `ai/` | Optional, tool-free provider abstraction, sanitization, strict schemas. |
| `scanner.py` | Orchestrates the DISCOVER→ASSESS pipeline with budgets. |
| `export.py` | Local JSON + self-contained HTML report with provenance. |
| `app/` | FastAPI app, security middleware, service layer, embedded single-page UI. |

## Key invariants

- **Confidence ≠ severity.** Identity confidence and exposure severity are
  computed and displayed separately (spec P4).
- **Deterministic decisions.** Risk category, remediation route, workflow state,
  and verification are reproducible without any model (spec P6). The LLM only
  explains.
- **Evidence before inference.** Every finding traces to observations →
  source → provenance.
- **Minimize collection.** Raw pages are discarded after extraction; only
  minimal structured evidence is retained.
- **Component versioning.** App, resolver, assessment policy, registry, and
  extractor versions are recorded so any finding is auditable (spec §39).

## Data flow for one candidate

```
URL → validate scheme/host → SecureRetriever (pinned-IP connect, size caps)
    → extract_document (HTML/PII/metadata/subject-tokens)
    → resolve (signals → Match state + confidence)   [skip if no identity anchor]
    → assess each category (dimensions + priority + reason codes)
    → persist Source + Observations + Match + Findings
```
