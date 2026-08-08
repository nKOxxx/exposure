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
