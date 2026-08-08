# Exposure

**A local evidence and remediation engine for personal digital exposure.**

Exposure helps one person answer four questions about themselves:

1. What information about me can reasonably be found on the public internet?
2. Which findings actually refer to me?
3. Which findings materially increase my privacy, security, or reputational exposure?
4. What legitimate action can I take to correct, remove, delist, suppress, or monitor each finding?

Exposure is **not** an OSINT investigation platform, a people-search engine, an
autonomous deletion bot, a legal decision engine, or a cloud repository of
personal information. Everything runs locally. No account. No telemetry. No
required cloud backend.

> Status: v0.2 reference implementation. See `docs/` for the specification,
> the security model, and the release-gate checklist.

## Install (from source)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,pdf]"
```

## Run

```bash
exposure
```

This starts a local server bound to `127.0.0.1` on a random port and opens the
UI in your browser. The port and a session token are printed to the terminal.

## The loop

```
DISCOVER → OBSERVE → RESOLVE → ASSESS → REVIEW → REMEDIATE → VERIFY
```

## Privacy contract

```
OBSERVE   — never fabricate what exists.
RESOLVE   — never confidently assign information to someone without evidence.
ASSESS    — never hide uncertainty behind an AI score.
ACT       — never create external effects without explicit authorization.
VERIFY    — never call something removed merely because we requested it.
MINIMIZE  — never retain more personal information than the product needs.
```

## Safety notes

- The retriever refuses non-`http(s)` schemes and any address that resolves to a
  private, loopback, link-local, or cloud-metadata range (SSRF defense).
- AI is **off by default**. The product is fully functional with no AI.
- Exposure never sends email, submits legal requests, uploads ID documents, or
  performs any consequential external action on your behalf. It prepares drafts
  and opens official destinations; you submit them.
- Exposure never claims something was "erased from the internet." It reports
  observable states only.

## License

Apache-2.0. See [LICENSE](LICENSE).
