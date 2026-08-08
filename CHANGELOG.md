# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-08

Initial reference implementation of the Exposure v0.2 specification.

### Added
- Local-first FastAPI application bound to loopback, served with an embedded
  self-contained frontend (no external scripts or fonts).
- Six-primitive domain model: Subject, Source, Observation, Match, Finding,
  RemediationCase.
- SQLite storage with forward-only SQL migrations and complete-deletion support.
- SSRF-hardened retrieval boundary: scheme allow-list, IP-range blocking,
  DNS-rebinding defense via a pinned-IP network backend, redirect revalidation,
  and response-size / decompression-bomb limits.
- Discovery subsystem with a replaceable provider protocol, a query planner with
  a bounded budget, a Brave Search provider, and a manual-URL provider.
- Deterministic extraction (HTML text, metadata/JSON-LD/OpenGraph, PII) with
  minimal-evidence storage.
- Evidence-based identity resolution using signal families, correlation damping,
  contradiction handling, and explicit abstention states.
- Deterministic, versioned exposure-assessment policy with reason codes.
- Remediation registry (Google, California DROP, generic GDPR/publisher, user
  controlled) with route matching, local request-draft templates, and a case
  state machine.
- Verification of both source and search state without trusting user memory.
- Optional AI layer (off by default) with tool-free containment, input
  sanitization, strict output schemas, and prompt-injection tests.
- Security, functional, identity-benchmark, and registry test suites; CI.

### Security
- All twelve v0.2 hard release gates (spec section 42) are covered by automated
  tests. See docs/RELEASE_GATES.md.

### Fixed
Found by browser testing:
- Subject form and scan controls were dead. Hyphenated element ids
  (`f-city`, `opt-search`) were referenced as bare JS identifiers, so every
  handler threw a `ReferenceError` before doing anything. Handlers now resolve
  elements explicitly, are wrapped so failures surface to the user, and a
  static test rejects implicit-global DOM access.

Found by the first live scan against real public pages:
- **Phone false positives.** ISO dates (`2026-08-05`), year ranges
  (`1815-1852`), and ISBNs were extracted as telephone numbers — 159 of them
  across two articles, one of which became a HIGH-priority `CONTACT_PHONE`
  finding. A phone now requires an international prefix or a nearby word-bounded
  cue, and identifier-prefixed digit runs are rejected. ("Intelligence" was
  matching the cue "tel".)
- **Wrong-person auto-confirmation.** A page *about* someone else that merely
  mentions the subject, on a shared city and organisation, reached
  HIGH_CONFIDENCE. The resolver now derives the page's topic and treats a
  mismatch as a contradiction, so mention-only pages go to review.
- **Over-collection.** 246 of 278 stored observations were bare dates that map
  to no finding and no signal. Only birth-announced dates are retained now.
- `registrable_domain` collapsed any host under an unrecognised TLD to its last
  label, so `a.example` and `b.example` both became `example`. Unknown suffixes
  now fall back to the full hostname.
- `parse_social` mis-parsed handles: `lstrip("www.")` stripped characters rather
  than the prefix, and a global routing-segment list meant `t.me/channel` lost
  its handle while `youtube.com/watch` gained a bogus one. Routing segments are
  now per platform.
- Ordering a `Severity` against a bare string silently fell back to
  lexicographic comparison inside risk prioritisation; it now raises.
- Phone matching failed between national and international spellings of the
  same number; it now compares a nine-digit significant suffix.
- `load_registry()` pointed at a missing directory returned an empty registry,
  presenting "no removal routes" as fact. It now raises.
