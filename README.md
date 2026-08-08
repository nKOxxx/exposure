<div align="center">

# 🛡️ Exposure

**Find out what the internet knows about you — and do something about it.
Entirely on your own machine.**

[![CI](https://github.com/nKOxxx/exposure/actions/workflows/ci.yml/badge.svg)](https://github.com/nKOxxx/exposure/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Local-first](https://img.shields.io/badge/local--first-no%20account%2C%20no%20telemetry-brightgreen.svg)](#privacy-contract)

</div>

---

Exposure is a **local-first personal privacy tool**. It answers four questions
about *you*:

1. What information about me can reasonably be found on the public internet?
2. Which of it actually refers to me — and not to someone with my name?
3. Which of it materially increases my privacy, security or reputational risk?
4. What can I legitimately do about each item?

It runs as a small web app on `127.0.0.1`. There is **no account, no telemetry,
no cloud backend, and no data leaves your machine** unless you explicitly ask it
to run a search.

> **Exposure is not** an OSINT platform, a people-search engine, an autonomous
> deletion bot, or a legal advice engine. It is a tool for looking yourself up
> and cleaning up. See [Scope and limits](#scope-and-limits).

## Why this exists

Paid "delete my data" services have a measurable accuracy problem. A 2025 peer
reviewed study of four commercial PII-removal services found that, on average,
**only 41.1% of the records they surfaced were confirmed by participants as
actually describing them** ([He et al., PoPETs 2025](https://petsymposium.org/popets/2025/popets-2025-0125.pdf)).
Meanwhile Mozilla discontinued its paid Monitor Plus removal product in December
2025. The category is not solved.

Exposure takes the opposite trade: **it would rather tell you "I'm not sure"
than confidently show you a stranger's home address and call it yours.**

## How it works

```
DISCOVER → OBSERVE → RESOLVE → ASSESS → REVIEW → REMEDIATE → VERIFY
```

| Stage | What happens |
|---|---|
| **Discover** | Generates a small, bounded set of search queries — and shows you every one before it leaves your machine. Or skip search entirely and paste URLs yourself. |
| **Observe** | Fetches pages through an SSRF-hardened retriever and extracts structured observations. Raw pages are discarded; only minimal evidence is kept. |
| **Resolve** | Decides whether a page is really about you, using evidence families, contradiction handling and explicit abstention. |
| **Assess** | Scores four independent dimensions — sensitivity, discoverability, misuse potential, persistence — deterministically, with reason codes. No AI in the loop. |
| **Remediate** | Matches each finding to real removal routes (Google delisting, California DROP, GDPR erasure/rectification, publisher contact, or "you control this"), and drafts the request locally. |
| **Verify** | Re-checks the source later and reports what it *observes*. It never claims something was deleted. |

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/nKOxxx/exposure.git
cd exposure
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[pdf]"
```

<details>
<summary>Windows (PowerShell)</summary>

```powershell
git clone https://github.com/nKOxxx/exposure.git
cd exposure
py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[pdf]"
```
</details>

Optional extras: `pdf` (read PDFs), `keyring` (store secrets in your OS keychain
rather than an encrypted file), `dev` (tests and linters).

## Run

```bash
exposure
```

That starts a server bound to `127.0.0.1` on a random free port and opens the UI.
Data lives in `~/.exposure`.

```
exposure --help
  --host        loopback only; anything else is refused
  --port        0 picks a free port (default)
  --workspace   override where data is stored
  --no-browser  don't open a browser
```

## First scan, without any API key

You do **not** need a search API key. The most private way to use Exposure:

1. Open the **Me** tab and enter your name (everything else is optional).
2. Click **Preview queries that will leave my machine**.
3. Run those searches yourself in your own browser.
4. Paste the interesting URLs into **Manual URLs** and click **Run scan**.

Nothing about you is ever sent to a third party this way.

<details>
<summary>Using the Brave Search API instead (optional)</summary>

Exposure can run the queries for you via Brave. Get a key at
[brave.com/search/api](https://brave.com/search/api) — note it is a paid API with
a small monthly credit, not an unlimited free tier — then add it under
**Settings → brave**. The key is stored in your OS keyring or an encrypted local
file; it is never written to the database, logs or exports.

Exposure deliberately does not depend on any single provider: Microsoft retired
the Bing Search APIs in 2025 and Google's Custom Search JSON API is closed to new
customers, so the provider interface is replaceable and the manual path always
works.
</details>

## What it asks you for

Name, and optionally alternate names, city, country, employers, usernames and
personal domains, plus your email address if you want it used.

**Exposure never asks for your phone number, date of birth, home address, ID
document or any payment detail.** It still reports those when it finds them
exposed about you — it simply doesn't need you to hand them over first. Your
email is encrypted at rest and always displayed masked (`j•••@example.com`).

## Privacy contract

```
OBSERVE   Never fabricate what exists.
RESOLVE   Never confidently assign information to someone without evidence.
ASSESS    Never hide uncertainty behind an AI score.
ACT       Never create external effects without your explicit authorization.
VERIFY    Never call something removed merely because removal was requested.
MINIMIZE  Never retain more personal information than the product needs.
```

Concretely:

- **Nothing is sent automatically.** Exposure drafts removal requests and opens
  the official destination. *You* submit them.
- **Delisting is not deletion.** Removing a Google result does not remove the
  page. Exposure says so, every time.
- **AI is off by default** and the product is fully functional without it. When
  enabled, the model gets a sanitized packet, has no tools, and its output is
  schema-validated or discarded.
- **"Delete all my data" really deletes** — database, cache, exports and local
  encryption keys.

## Security

The retriever treats every URL and response as hostile:

- scheme allow-list, and rejection of private, loopback, link-local and
  cloud-metadata addresses;
- **DNS-rebinding defense** — resolution, validation and connection are atomic,
  and the socket connects to a pinned validated IP;
- redirects re-validated at every hop; response-size and decompression-bomb caps;
- the local API enforces `Host`, `Origin` and a per-run session token, under a
  CSP with no external origins.

Full model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Reporting:
[SECURITY.md](SECURITY.md).

## Accuracy

Identity resolution is measured, not asserted. The gate is **precision** — of the
pages Exposure auto-confirms as you, how many really are:

```
corpus=168 synthetic cases   precision=1.0000   recall=0.7867   false positives=0
```

Recall is deliberately lower than precision: thin evidence (a name and nothing
else) stays in **Needs review** rather than being presented as fact.

The first live run against real pages found — and fixed — three false-positive
classes that synthetic tests missed, including a page *about someone else* being
auto-confirmed because it mentioned the subject. That write-up is in
[docs/LIVE_SCAN_RESULTS.md](docs/LIVE_SCAN_RESULTS.md), including what is still
unproven.

## Scope and limits

Deliberately **not** built, as a security boundary rather than a roadmap:

```
dark-web / breach-credential search      face or reverse-image identification
bulk or batch person scanning            relatives and social-graph discovery
discovering unknown emails or phones     location history
CAPTCHA / anti-bot / WAF bypass          authenticated-site scraping
automatic legal submissions              automatic email sending
```

Exposure is for looking *yourself* up. It omits the capabilities whose main
additional value would be investigating other people. That does not make misuse
impossible — it keeps the tool aligned with personal privacy remediation.

## Development

```bash
pip install -e ".[dev,pdf]"
ruff check src tests     # lint
mypy                     # strict type check
pytest -q                # 353 tests
pytest tests/benchmark -q -s   # identity precision gate
```

Docs: [architecture](docs/ARCHITECTURE.md) ·
[threat model](docs/THREAT_MODEL.md) ·
[release gates](docs/RELEASE_GATES.md) ·
[specification](docs/SPEC.md)

Contributions to the [removal registry](registry/) are especially welcome — every
entry needs an authoritative source and a verification date, because a wrong
removal link is a phishing risk.

## License

[Apache-2.0](LICENSE)

---

<div align="center">
<sub>Exposure is a tool, not legal advice. Removal outcomes depend on
publishers, jurisdictions and law that this software cannot control.</sub>
</div>
