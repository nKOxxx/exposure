# Exposure vs. reverselookup.com

A blunt comparison, because "how are we better and what are we missing" deserves
a straight answer. Facts about reverselookup.com below were gathered from its own
site and third-party reviews on 2026-08-08; anything unconfirmed is marked.

## They are opposite products

reverselookup.com is a **finder**: you type in *someone else's* phone, email,
name or photo and it returns their address, relatives, employment and social
profiles. It is operated by ClarityCheck Inc. (a Delaware registered-agent
address), sits in the people-search / data-broker category, and sells that
lookup as a subscription.

Exposure is a **fixer**: you look up *yourself*, and it helps you get the
resulting exposure corrected, delisted or deleted.

One sentence: **reverselookup.com is one of the sites Exposure is designed to
help you get removed from.** They are not really competitors; they are on
opposite sides of the same problem.

## Where Exposure is better

| | reverselookup.com | Exposure |
|---|---|---|
| **Purpose** | Look up other people | Look up and clean up yourself |
| **Price** | $0.99 7-day trial → **$29.99 every 28 days** auto-renew, plus paid add-ons | Free, open source (Apache-2.0) |
| **Account** | Required | None |
| **Where your data goes** | Into a commercial people-search service | Stays on your machine; no account, no telemetry, no cloud |
| **Is it itself a data broker?** | Functions as one (aggregates + licenses personal data) | No — it collects nothing centrally and cannot sell anything |
| **Remediation** | None — it exposes, it doesn't remove | Google delisting, California DROP, GDPR erasure/rectification, publisher contact, self-service |
| **Accuracy stance** | Self-hedged: results "may not be 100% accurate… a starting point" | Precision-first; abstains rather than guess (benchmark gate ≥98%, 0 false positives on 168 cases) |
| **Auditability** | Closed; opaque ownership (shared mail-drop address) | Fully open source and inspectable |
| **Billing complaints** | Recurring theme: surprise charges after the trial, refund difficulty | Nothing to bill |
| **Data minimisation** | Maximises data it holds about people | Discards raw pages, keeps minimal evidence, "delete everything" really deletes |

The billing pattern is worth calling out specifically: the dominant complaint
about this category (and reverselookup.com's 1-star reviews) is the $0.99-trial
converting to a ~$30 recurring charge billed every 28 days — 13 times a year, not
12. Exposure has no such surface because it costs nothing and runs locally.

## What Exposure is missing (the honest part)

Being the ethical option doesn't make the gaps disappear. Here is what they have
that we don't:

1. **Data breadth — the real gap.** reverselookup.com licenses aggregated
   data-broker feeds and paid public-records datasets. It can surface an unlisted
   phone number or a home address that a free open-web search will never return.
   Exposure only sees the public web. **This is the single most significant
   difference in raw capability**, and it is partly by design: those paid broker
   datasets are exactly what Exposure helps you file DROP / GDPR deletions
   against, so ingesting them ourselves would be hypocritical. But it does mean
   Exposure will miss broker-held data that a paid lookup would show. A future,
   honest way to close this: let the user paste a broker's own "here's what we
   have on you" page in as a source.

2. **Zero-setup search.** They have search built in; you type a name and get
   results. Exposure now offers **one-click assisted search** (it builds the
   queries and opens them in your own browser — private, free, no key) and
   optional Brave/SearXNG providers, but there is still no "type name → instant
   results" with nothing configured, because no free web-search API exists that
   would allow it without breaking. This is a genuine friction gap.

3. **Reverse lookups** (phone→identity, email→identity, reverse image). We
   deliberately omit these — their main value is investigating *other* people,
   which is Exposure's explicit non-goal — but it is a capability they have and
   we don't.

4. **Product polish of a funded company:** cross-device accounts, a mobile app,
   a support team, richer report styling. Exposure is a local single-user tool.

5. **Niche add-ons** (VIN/vehicle history, sex-offender-registry checks). Out of
   scope for us.

## What neither has yet — Exposure's opportunity

reverselookup.com is a **static, on-demand** lookup: no monitoring, no alerts, no
watchlist (confirmed from its own FAQ). Exposure also only does explicit rescans
today. Continuous "tell me when something new about me appears" monitoring is
unbuilt in both — and for a *self*-protection tool it is a far more natural
feature than it is for a people-finder. That is the most valuable thing Exposure
could add next, and the competitor has left it open.

## Bottom line

Exposure wins on ethics, price, privacy, transparency, and — crucially — on
actually *doing something* about what it finds. It loses on raw data breadth and
out-of-the-box search convenience, because it refuses to become the kind of data
broker that would close those gaps. That trade is the product.
