# Live-web scan results

Date: 2026-08-08 · Subject: Ada Lovelace (historical figure, d. 1852 — no living
person's data was used)

The deterministic pipeline was validated offline against mocked retrievers and a
synthetic corpus. This is the first run against the **real internet**: real DNS,
real TLS, real gzip, real redirects, and real adversarially-messy HTML.

## What was fetched

| URL | Purpose | Outcome |
|---|---|---|
| `https://example.com/` | minimal page | RETRIEVED 200 |
| `http://www.iana.org/domains/reserved` | http→https redirect | RETRIEVED 200 |
| `https://www.python.org/` | large, complex, gzip | RETRIEVED 200 |
| `https://en.wikipedia.org/wiki/Ada_Lovelace` | the subject's own page | RETRIEVED 200 |
| `https://en.wikipedia.org/wiki/Charles_Babbage` | a *different* person who worked with her | RETRIEVED 200 |
| `https://httpbin.org/status/404` | missing page | RETRIEVED 404 |
| `http://169.254.169.254/latest/meta-data/` | **SSRF probe** | **RETRIEVAL_BLOCKED** |
| `https://…-does-not-exist….invalid/` | DNS failure | RETRIEVAL_BLOCKED |

6 retrieved, 2 blocked, 0 failed, 1.75 MB, 1.4 s.

**The SSRF defense held against the live network** — the cloud-metadata address
was refused at connect time, not merely by URL inspection.

## What broke (and is now fixed)

The synthetic benchmark reported 100% precision. Real pages immediately produced
false positives that the synthetic corpus could not have caught.

| Defect | Evidence | Fix |
|---|---|---|
| ISO dates, year ranges and ISBNs extracted as phone numbers | 159 bogus `PHONE` observations across two articles; one became a HIGH-priority `CONTACT_PHONE` finding | Phone requires `+` prefix or a word-bounded cue; identifier prefixes (ISBN/DOI/IBAN…) rejected |
| The cue regex matched inside words | "In**tel**ligence" satisfied the cue `tel`, admitting an ISBN | word boundaries on all cues |
| A page **about another person** auto-confirmed as the subject | Charles Babbage's article reached `HIGH_CONFIDENCE` for Ada Lovelace (she is mentioned; they share city and organisation) — and produced a **CRITICAL** `HOME_ADDRESS` finding from *his* residence | Resolver derives the page topic; a topic mismatch is a contradiction, so mention-only pages go to review |
| Over-collection | 246 of 278 stored observations were bare dates, which map to no finding and no signal | Only birth-announced dates retained |

## Before and after, same pages

| | Before | After |
|---|---|---|
| Observations stored | 446 | 31 |
| Phone false positives | 159 | 0 |
| Babbage page identity | `HIGH_CONFIDENCE` (wrong) | `AMBIGUOUS` + `page_topic_conflict` |
| Ada Lovelace page identity | `HIGH_CONFIDENCE` | `HIGH_CONFIDENCE` (unchanged, correct) |
| False CRITICAL findings | 1 | 0 |

The subject's own page still resolves correctly, so the fixes cost no true
positives here.

## Benchmark impact

The real-world failure mode was added to the synthetic corpus as
`mentioned-in-passing` cases. Without the topic-conflict fix, **16 of 16** are
auto-confirmed false positives; with it, **0**. Corpus is now 168 cases:

```
corpus=168  auto-confirmed=59  precision=1.0000  recall=0.7867  fp=0
```

## What this still does not prove

- One subject, eight URLs. Precision on real pages is **demonstrated, not
  measured** — a real precision figure needs a labelled corpus of live pages.
- No search-provider API key was available, so the Brave connector has still
  never been exercised against the live API. Only the manual-URL path ran.
- Only English-language pages, and only HTML (no live PDF).
- Wikipedia is unusually well-structured. Data-broker and directory pages — the
  actual target class — were not tested.

Re-run with:

```bash
python /path/to/live_scan.py
```
