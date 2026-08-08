# Threat Model

Exposure is a local, single-user application that fetches and processes hostile
content from the public internet. The threat model follows spec section 30.

## Trust boundaries

- **Trusted:** the local Exposure process and its SQLite workspace.
- **Untrusted:** every URL, every HTTP response, every search result, every
  page rendered in the user's browser, and any AI provider output.

Instructions come only from the user via the local UI. Content fetched from the
web is data, never commands.

## Adversaries and mitigations

### 1. Malicious website
Attempts SSRF, huge/compressed responses, redirect loops, malformed content,
parser abuse, prompt injection, tracking.

- Scheme allow-list (`http(s)` only) and IP-range blocking (`security/validation.py`).
- DNS-rebinding defense: resolve + validate + connect to a pinned IP atomically
  (`retrieval/network_policy.py`).
- Redirects followed manually; every hop re-validated.
- Response size caps and decompression-bomb defense (`retrieval/limits.py`).
- Timeouts and a global per-scan byte/document budget.
- JavaScript execution off by default; `trust_env=False` (no proxy hijack).
- HTML parsed as data with the standard library; scripts/styles dropped.

### 2. Malicious search result
Tries to misidentify the subject, poison AI analysis, or point at internal
resources.

- Identity resolution is evidence-based with contradiction handling and
  abstention; namesakes never reach HIGH_CONFIDENCE (benchmark ≥ 98% precision).
- Candidate URLs are validated before retrieval; internal addresses are blocked.

### 3. Malicious local web page (CSRF / DNS rebinding against the loopback API)
A page in the user's browser tries to call the local API.

- Strict Host validation on every request.
- Strict Origin validation + a random session token on every mutating request.
- CSP with no external origins; no wildcard CORS.
(`security/session.py`, `app/main.py`, `tests/security/test_app_security.py`.)

### 4. Compromised AI output
Tries to trigger actions, fabricate legal claims, invent findings, or exfiltrate
secrets.

- The AI has no tools, no filesystem, no DB, and no network beyond one chat
  endpoint. It only explains.
- Input is a minimal sanitized packet (masked identifiers, neutralized snippets).
- Output must match a strict schema; anything else is rejected.
(`ai/`, `tests/security/test_ai_containment.py`.)

### 5. Malicious registry contribution
Tries to replace an official removal destination with a phishing site.

- Every entry requires an authoritative source (provenance) and a
  `last_verified` date; URLs are safety-validated on load.
- `CODEOWNERS` requires review of `registry/**`.
- Expired entries are not recommended until revalidated.
(`remediation/registry.py`, `tests/security/test_registry.py`, `CODEOWNERS`.)

## Explicitly out of scope (security boundary, not backlog)

Dark-web/breach search, face/reverse-image identification, bulk/relationship
discovery, anti-bot/CAPTCHA bypass, authenticated scraping, automatic sending of
email or legal requests, and any autonomous irreversible external action. See
spec section 3 and 23.
