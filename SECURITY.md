# Security Policy

Exposure processes hostile content from the public internet on the user's own
machine. Security is a primary design goal, not an afterthought.

- Full threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- Release-blocking security gates: [docs/RELEASE_GATES.md](docs/RELEASE_GATES.md)
- Engineering baseline: NIST SSDF (SP 800-218) and OWASP ASVS 5.0 where relevant.

## Reporting a vulnerability

Please open a private security advisory on the repository rather than a public
issue. Include reproduction steps and affected versions. Do not include real
personal data in a report.

## Highlights

- Loopback-only binding; Host/Origin/session-token checks on the local API.
- SSRF-hardened retriever with DNS-rebinding defense (pinned-IP connections).
- Secrets in the OS keyring or an encrypted vault — never in SQLite, logs, or
  exports.
- AI is off by default and, when on, has no tools and produces schema-validated
  output only.
- Removal-registry entries require provenance and CODEOWNERS review.
