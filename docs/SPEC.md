# EXPOSURE v0.2

Local-First Personal Digital Exposure and Remediation System
Status: Engineering specification
Target: v0.2 reference implementation
Architecture objective: Lean, auditable, safe, extensible
Primary distribution: GitHub
Operating model: Local-first, single-user, no required account, no required cloud backend

> Saved verbatim from chat session 2026-08-08. Independent review: EXPOSURE_v0.2_REVIEW.md

---

# 0. Executive specification

Exposure answers four questions:

1. What information about me can reasonably be found on the public internet?
2. Which findings actually refer to me?
3. Which findings materially increase my privacy, security, or reputational exposure?
4. What legitimate action can I take to correct, remove, delist, suppress, or monitor each finding?

The complete product loop is:

```text
DISCOVER
   ↓
OBSERVE
   ↓
RESOLVE IDENTITY
   ↓
ASSESS
   ↓
REVIEW
   ↓
REMEDIATE
   ↓
VERIFY
```

Exposure is not an OSINT investigation platform.
Exposure is not a people-search engine.
Exposure is not an autonomous deletion bot.
Exposure is not a legal decision engine.
Exposure is not a cloud repository of personal information.

Exposure is a local personal exposure-management utility.

The design requirement for v0.2 is:

```text
One person
One local workspace
One understandable scan
One evidence model
One remediation queue
Minimal retained data
No autonomous irreversible actions
```

---

# 1. Audit of v0.1

v0.1 had the right conceptual pipeline but several engineering weaknesses.

| v0.1 assumption                | Problem                                                                 | v0.2 correction                                                             |
| ------------------------------ | ----------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Next.js + FastAPI              | Two application stacks increase packaging, dependencies and maintenance | One Python application serves one compiled static frontend                  |
| Docker as primary install      | Fine for developers, bad for normal users                               | Native one-command/local binary distribution first; Docker remains optional |
| Generic crawler                | Creates SSRF, parser, resource and hostile-content risks                | Hardened retrieval boundary with explicit network policy                    |
| LLM analysis of pages          | Web pages can contain prompt injection and malicious instructions       | LLM receives sanitized structured observations only, with zero tools        |
| "Identity score"               | Naive weighted scoring creates false confidence                         | Evidence-based entity resolution with contradiction handling and abstention |
| Full-page evidence             | Unnecessary retention of sensitive and copyrighted content              | Store extracted observations and minimal snippets by default                |
| Single "Remove" button         | Removal is legally and technically heterogeneous                        | Explicit remediation route taxonomy                                         |
| Automatic removal              | Creates authorization, legal and reliability problems                   | Human-confirmed submission in v0.2                                          |
| Broker-by-broker automation    | Brittle and increasingly unnecessary in some jurisdictions              | Prefer official mechanisms such as California DROP where applicable         |
| LLM determines risk            | Non-deterministic and difficult to audit                                | Deterministic exposure policy; LLM only explains                            |
| "Self-verification" safeguards | Cannot actually be enforced in open-source software                     | Minimize abuse capability by product design                                 |
| Generic future harness         | Risk of premature abstraction                                           | Extract only six stable domain-independent primitives                       |
| Continuous monitoring          | Expands background execution, storage and network complexity            | Explicit rescans only in v0.2                                               |
| Dark web/breach searching      | High sensitivity and authorization complexity                           | Out of scope for v0.2                                                       |

This audit changes the architecture significantly.

---

# 2. Product principles

Every architectural decision must satisfy these principles.

## P1. Local means local

Personal profiles, findings, remediation state and user decisions remain on the user's machine.

No Exposure-operated server is necessary for normal operation.
No account is necessary.
No analytics are enabled by default.
No telemetry endpoint exists in the initial reference implementation.

## P2. Minimize collection

The application collects enough information to answer the user's question, not everything technically retrievable about them.

EDPB guidance emphasizes data minimisation, purpose limitation, storage limitation and data protection by design and default. Exposure should embody those principles even where a particular local processing operation might not legally require them.

## P3. Evidence before inference

A conclusion must point to observations.
An observation must point to a source.
A source must have provenance.

No unsupported AI assertion becomes a finding.

## P4. Confidence and severity are separate

These are independent:

```text
How sure are we this is you?
versus
How undesirable is this if it is you?
```

Never collapse them.

## P5. Abstention is a successful outcome

When identity is ambiguous:

```text
UNKNOWN
```

is preferable to:

```text
84% probably you
```

without defensible evidence.

## P6. Deterministic decisions, probabilistic assistance

Identity resolution may use probabilistic techniques.
Natural-language explanations may use AI.

But:

```text
risk category
remediation route
workflow state
deletion verification
```

must be independently reproducible.

## P7. Human authorization before external effect

v0.2 never:

* sends email automatically
* submits legal requests automatically
* signs declarations
* uploads identity documents
* fills CAPTCHAs
* bypasses authentication
* impersonates the user
* contacts third parties without an explicit user action

## P8. Never promise deletion

Exposure reports:

```text
REQUEST AVAILABLE
REQUEST SUBMITTED
SOURCE NO LONGER PRESENT
SEARCH RESULT DELISTED
VERIFIED ON [DATE]
```

It never claims:

```text
ERASED FROM THE INTERNET
```

because that cannot normally be established.

---

# 3. Scope

## Required for v0.2

### Subject definition

The user can define:

```text
full name
alternate names
country
city
current employer
past employers
personal domains
known usernames
emails
phone numbers
```

Every field except name is optional.
Sensitive identifiers are visually distinguished.

### Discovery

Generate and execute reasonable public-web queries.

### Retrieval

Retrieve candidate public pages safely.

### Extraction

Extract relevant observations from retrieved documents.

### Entity resolution

Determine whether each candidate likely refers to the subject.

### Findings

Convert validated observations into exposure findings.

### Assessment

Classify sensitivity and remediation priority.

### Remediation

Explain legitimate remediation routes.

### Case tracking

Track user remediation actions.

### Verification

Rescan an affected source and independently establish its current status.

### Export

Generate a local JSON report and human-readable HTML report.

## Explicitly out of scope

```text
dark-web search
credential dumps
password databases
facial recognition
face search
reverse-image person identification
family graph discovery
bulk person search
contact-list enrichment
phone-owner lookup
email-owner lookup
location tracking
vehicle/property aggregation
social graph reconstruction
automated browser impersonation
CAPTCHA bypass
anti-bot bypass
authenticated-site scraping
automatic legal submissions
automatic email sending
continuous cloud monitoring
mobile application
team accounts
enterprise dashboard
central Exposure API
```

This list should be considered a security boundary, not a postponed feature roadmap.

---

# 4. Architecture

The v0.2 architecture consists of one trusted application and several explicitly untrusted boundaries.

```text
┌───────────────────────────────────────────────┐
│                 LOCAL MACHINE                 │
│                                               │
│   ┌───────────────────────────────────────┐   │
│   │             Exposure Core             │   │
│   │                                       │   │
│   │  Subject                              │   │
│   │  Discovery                            │   │
│   │  Retrieval                            │   │
│   │  Extraction                           │   │
│   │  Resolution                           │   │
│   │  Assessment                           │   │
│   │  Remediation                          │   │
│   │  Verification                         │   │
│   └───────────────┬───────────────────────┘   │
│                   │                           │
│            ┌──────▼───────┐                   │
│            │ SQLite Store │                   │
│            └──────────────┘                   │
│                                               │
│   Browser UI ◄── localhost API                │
│                                               │
└───────────────────┬───────────────────────────┘
                    │
                    │ controlled egress
                    ▼
        ┌─────────────────────────┐
        │ UNTRUSTED INTERNET      │
        │                         │
        │ Search APIs             │
        │ Public webpages         │
        │ Removal endpoints       │
        │ Optional LLM APIs       │
        └─────────────────────────┘
```

No microservices.
No message broker.
No Redis.
No Kubernetes.
No vector database.
No graph database.
No Elasticsearch.
No persistent worker cluster.
No cloud storage.

Those technologies solve problems v0.2 does not have.

---

# 5. Technology decision

## Backend

Python 3.12+

Recommended components:

```text
FastAPI
Pydantic
SQLAlchemy or SQLModel
SQLite
httpx
selectolax or BeautifulSoup
tldextract
RapidFuzz
cryptography
```

Optional:

```text
Playwright
```

but disabled by default.

## Frontend

React + TypeScript + Vite.

Not Next.js.

There is no server-side rendering requirement.
The frontend is compiled during release and embedded into the Python package.

At runtime:

```text
exposure
```

starts the local process and opens:

```text
http://127.0.0.1:<random-port>
```

The user should not need Node.js.

## Release targets

Phase 1:

```text
pipx install exposure
uvx exposure
```

Phase 2:

```text
Exposure.app
Exposure.exe
Linux binary/package
```

Docker remains available for contributors and reproducibility, not as the primary consumer UX.

---

# 6. Core domain model

The v0.1 model was too generic.

v0.2 uses six stable primitives:

```text
Subject
Source
Observation
Match
Finding
RemediationCase
```

These are the only primitives that should initially enter the reusable harness.

## Subject

The person being protected.

```python
class Subject:
    id: UUID
    names: list[Name]
    locations: list[LocationHint]
    employers: list[OrganisationHint]
    usernames: list[str]
    emails: list[SecretField]
    phones: list[SecretField]
    created_at: datetime
```

## Source

Where information was observed.

```python
class Source:
    id: UUID
    url: str
    canonical_url: str
    registrable_domain: str
    retrieved_at: datetime
    http_status: int | None
    content_type: str | None
    content_hash: str | None
```

## Observation

A factual item extracted from a source.

Examples:

```text
name = "Jane Example"
employment =
    organisation: Acme Corp
    role: Partner, New Ventures
email =
    j***@example.com
location =
    London
```

Observation structure:

```python
class Observation:
    id: UUID
    source_id: UUID
    type: ObservationType
    value_normalized: str
    display_value: str
    evidence_snippet: str
    extractor: str
    extractor_version: str
    observed_at: datetime
```

The extractor must be recorded.

## Match

A resolution relationship between source observations and the Subject.

```python
class Match:
    source_id: UUID
    subject_id: UUID
    state:
        CONFIRMED
        HIGH_CONFIDENCE
        POSSIBLE
        AMBIGUOUS
        REJECTED
    confidence: float
    supporting_signals: list[Signal]
    contradicting_signals: list[Signal]
    resolution_version: str
```

## Finding

A relevant exposure on a matched source.

```python
class Finding:
    id: UUID
    subject_id: UUID
    source_id: UUID
    category: FindingCategory
    sensitivity: Severity
    discoverability: Severity
    misuse_potential: Severity
    persistence: Severity
    overall_priority: Severity
    assessment_confidence: float
    explanation_codes: list[str]
```

## RemediationCase

Tracks attempts to address a finding.

```python
class RemediationCase:
    id: UUID
    finding_id: UUID
    route: RemediationRoute
    state: CaseState
    opened_at: datetime
    submitted_at: datetime | None
    last_checked_at: datetime | None
    verification: Verification | None
```

---

# 7. Discovery subsystem

Discovery produces candidates.
It does not determine truth.

```text
Subject
   ↓
Query Planner
   ↓
Discovery Provider
   ↓
Candidate URLs
```

## Provider abstraction

```python
class DiscoveryProvider(Protocol):
    id: str
    async def search(
        self,
        query: SearchQuery
    ) -> list[SearchCandidate]:
        ...
```

Providers must be replaceable.

This is necessary because the search API landscape is unstable.

Microsoft retired the Bing Search APIs in August 2025. Google's Custom Search JSON API is unavailable to new customers and existing customers must transition by January 1, 2027. Brave currently offers a general Search API, but Exposure must not depend structurally on one commercial provider.

## v0.2 discovery providers

Required:

```text
BraveSearchProvider
ManualURLProvider
```

Optional/community:

```text
SearXNGProvider
```

ManualURLProvider is important.

Exposure remains useful without sending personal identifiers to a search API.
The system can generate queries for the user and allow discovered URLs to be imported manually.

## Query budget

Do not generate hundreds of permutations.

Initial default:

```text
Maximum generated queries: 15
Maximum results/query: 10
Maximum candidate URLs: 100
```

Examples:

```text
"Jane Example"
"Jane Example" London
"Jane Example" Acme
"jane@example.com"
"known_username"
"Jane Example" filetype:pdf
```

Sensitive-field queries must require an explicit checkbox before transmission to an external search provider:

```text
Search using my email address
Search using my phone number
```

Default:

```text
OFF
```

The UI must make clear that enabling this transmits the identifier to the configured search provider.

---

# 8. Retrieval security boundary

The retriever is one of the highest-risk components in Exposure.

Treat every URL and every response as hostile.

OWASP identifies server-side URL retrieval as an SSRF attack surface.

## URL policy

Allow:

```text
https
http
```

Reject:

```text
file:
ftp:
gopher:
data:
javascript:
blob:
ws:
wss:
custom schemes
```

## Network address policy

Before connection:

1. Resolve hostname.
2. Inspect every resulting address.
3. Reject private, loopback, link-local, multicast, reserved and unspecified ranges.
4. Connect only to validated addresses.
5. Revalidate on redirects.
6. Revalidate DNS after redirects.

Block examples:

```text
127.0.0.0/8
::1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
fc00::/7
fe80::/10
```

Cloud metadata addresses must also be rejected.

## Retrieval limits

Defaults:

```text
connection timeout        5 seconds
total request timeout     10 seconds
maximum redirects         5
maximum HTML response     5 MB
maximum PDF response      15 MB
global concurrency        8
per-domain concurrency    2
```

A global scan budget must also exist.

Example:

```text
Maximum retrieved documents: 100
Maximum downloaded bytes: 100 MB
```

This prevents accidental or malicious resource exhaustion.

## JavaScript

JavaScript execution is off by default.

Static HTTP retrieval is the normal path.

If Playwright support is enabled:

```text
separate process
temporary profile
no browser credentials
no extensions
no persisted cookies
downloads disabled
microphone disabled
camera disabled
location disabled
clipboard disabled
private-network requests blocked
hard execution timeout
```

No authenticated browser profiles are imported.

## Robots and site restrictions

Exposure does not implement anti-bot bypass.

No CAPTCHA solving.
No proxy rotation designed to evade restrictions.
No login bypass.
No WAF circumvention.

If a source cannot reasonably be retrieved, Exposure records:

```text
RETRIEVAL_BLOCKED
```

and allows the user to inspect it manually.

---

# 9. Content processing boundary

Downloaded content is untrusted data.

It is never executable instructions.

Pipeline:

```text
HTTP BODY
    ↓
type validation
    ↓
size validation
    ↓
parser
    ↓
visible-text extraction
    ↓
normalization
    ↓
PII/entity extraction
    ↓
observation generation
```

Raw HTML should normally be discarded after extraction.

Default persistent evidence should consist of:

```text
URL
page title
retrieval timestamp
content hash
minimal relevant snippet
structured observations
extractor version
```

Not:

```text
entire webpage
every image
every linked file
complete browser archive
```

This materially reduces both privacy exposure and storage requirements.

---

# 10. Identity resolution

This is the highest-value technical subsystem.

Commercial PII-removal products have demonstrated serious false-match problems. The aforementioned 2025 study found that only 41.1% of surfaced records were judged by study participants to actually describe them.

Exposure therefore optimizes for precision before recall.

## Resolution strategy

Never use one arbitrary weighted sum.

Signals belong to evidence families.

Example families:

```text
IDENTITY
full name
alternate name
username

LOCATION
city
country

PROFESSIONAL
employer
job title
company domain

DIRECT
email
phone
owned domain
known username

CONTRADICTIONS
different city
different employer chronology
different middle name
clearly incompatible biography
```

Correlated signals cannot be independently counted at full weight.

Example:

```text
"Jane Example"
"Jane A. Example"
"Jane Example, London"
```

are largely one name/location evidence family, not three independent confirmations.

## Strong identifiers

Strong exact matches include:

```text
known personal email
known phone
known domain
known username where sufficiently distinctive
```

These significantly raise confidence.

They are never displayed unnecessarily in logs or exports.

## Contradictions

Contradictions must reduce confidence.

Example:

```text
Name matches.
Employer matches.
Page states person lives in Sydney.
Subject has always been London-based.

Result:
AMBIGUOUS
```

The model must not simply accumulate positive evidence.

## Resolution states

```text
CONFIRMED
User explicitly confirmed.

HIGH_CONFIDENCE
System threshold met with independent evidence.

POSSIBLE
Evidence suggests match but is insufficient.

AMBIGUOUS
Material supporting and contradicting evidence.

REJECTED
User or system determined that it is another person.
```

Only:

```text
CONFIRMED
HIGH_CONFIDENCE
```

can automatically enter the remediation priority queue.

Everything else enters:

```text
Needs review
```

## User feedback

A user may choose:

```text
This is me
Not me
Unsure
```

This decision applies locally.
It is not used as cloud training data.

---

# 11. Extraction architecture

Extraction happens in two layers.

## Layer A: deterministic

Preferred wherever possible.

Extract:

```text
emails
phone numbers
URLs
social links
dates
JSON-LD Person fields
JSON-LD Organization fields
OpenGraph metadata
titles
headings
postal-like structures
known subject tokens
```

## Layer B: semantic

Used only when deterministic extraction is insufficient.

Examples:

```text
"Jane joined Acme as CFO in 2021."
"A resident of London..."
"Contact Jane via..."
```

Semantic extraction can use:

```text
local LLM
remote LLM
small NLP model
```

but its output remains an observation candidate until validated.

---

# 12. LLM containment

The LLM is not an agent.

It receives no network tool.
It receives no filesystem tool.
It receives no shell tool.
It receives no database credentials.
It receives no remediation submission capability.

The correct architecture is:

```text
HOSTILE WEBPAGE
     ↓
deterministic sanitization
     ↓
structured finding packet
     ↓
LLM
     ↓
schema validated output
```

Never:

```text
HOSTILE WEBPAGE
     ↓
AUTONOMOUS AGENT
     ↓
TOOLS / NETWORK / FILESYSTEM
```

## LLM input

Send only what is required:

```json
{
  "page_title": "...",
  "relevant_snippets": ["..."],
  "observations": [],
  "finding_category": "HOME_ADDRESS"
}
```

Do not automatically send:

```text
all subject emails
phone numbers unrelated to the finding
complete user profile
other findings
API keys
local paths
remediation history
```

## LLM responsibilities

Allowed:

```text
plain-English explanation
summary
candidate categorization
suggested review questions
```

Not allowed:

```text
final identity determination
risk score
legal entitlement determination
external action
removal verification
```

All LLM output uses strict structured schemas.
Invalid output is rejected.

---

# 13. Finding taxonomy

Keep v0.2 small.

Initial categories:

```text
CONTACT_EMAIL
CONTACT_PHONE
HOME_ADDRESS
PERSONAL_LOCATION
DATE_OF_BIRTH
PROFESSIONAL_PROFILE
SOCIAL_PROFILE
USERNAME
PERSONAL_DOCUMENT
PUBLIC_RECORD
COMPANY_RECORD
IMAGE_REFERENCE
OUTDATED_INFORMATION
INCORRECT_INFORMATION
OTHER_PERSONAL_INFORMATION
```

No speculative categories.

No psychological profiling.
No political inference.
No ethnicity inference.
No religion inference.
No medical inference.
No sexual-orientation inference.
No financial-worth inference.

Exposure reports what a source reveals.
It does not manufacture additional sensitive attributes.

---

# 14. Exposure assessment

Replace the v0.1 single multiplication formula.

Use four independently visible dimensions.

```text
Sensitivity
Discoverability
Misuse potential
Persistence
```

Each:

```text
NONE
LOW
MODERATE
HIGH
CRITICAL
```

Example:

```text
Home address

Sensitivity          HIGH
Discoverability      HIGH
Misuse potential     HIGH
Persistence          MODERATE
Identity confidence  98%

Priority             HIGH
```

## Policy-driven priority

A versioned ruleset determines priority.

Example:

```yaml
HOME_ADDRESS:
  base: HIGH
PHONE:
  base: MODERATE
PROFESSIONAL_PROFILE:
  base: LOW
```

Modifiers:

```text
indexed prominently
combined with phone
combined with family information
clearly outdated
controlled by the user
government/public-interest source
identity uncertain
```

The rule engine must expose reason codes.

Example:

```text
PRIORITY_HIGH because:
BASE_HOME_ADDRESS
+ SEARCH_INDEXED
+ DIRECT_PHONE_PRESENT
```

Do not let the LLM produce this classification.

---

# 15. Remediation model

There is no generic `REMOVE`.

There are six routes:

```text
SOURCE_DELETE
SOURCE_CORRECT
SOURCE_OPT_OUT
SEARCH_DELIST
USER_CONTROLLED_REMOVE
NO_ACTION_AVAILABLE
```

Optional:

```text
CONTACT_PUBLISHER
```

is a mechanism, not an outcome.

## SOURCE_DELETE

Attempts to remove information from the original publisher/controller.

## SOURCE_CORRECT

Used for inaccurate or outdated information where correction is more appropriate than deletion.

## SOURCE_OPT_OUT

Used for broker/listing systems that provide an opt-out mechanism.

The FTC notes that people-search sites commonly provide opt-out processes, that data can reappear later, and that public records themselves are unaffected by broker opt-outs.

## SEARCH_DELIST

Removes or suppresses search indexing associated with the person.

This does not remove the source.

Google explicitly states that removal from Google Search does not delete the information from the hosting site.

European guidance similarly distinguishes search-engine delisting from deletion of the original content.

## USER_CONTROLLED_REMOVE

Example:

```text
public LinkedIn field
old GitHub profile text
personal website
public Facebook post
```

Exposure should tell the user to change the source they themselves control.

## NO_ACTION_AVAILABLE

This is an acceptable answer.

Examples can include:

```text
lawful public records
material retained under legal obligation
certain journalism/public-interest material
historical archives
information necessary for legal claims
```

The GDPR right to erasure is not absolute and contains explicit exceptions including freedom of expression and information, legal obligations, public-interest functions, research/archive circumstances and legal claims.

Exposure must not tell a user:

```text
You have a legal right to remove this.
```

unless the workflow is merely quoting an authoritative rule and clearly marking the result as informational rather than legal advice.

---

# 16. Remediation registry

The registry becomes a first-class subsystem.

```text
registry/
    google.yaml
    bing.yaml
    california-drop.yaml
    generic-gdpr.yaml
    generic-publisher.yaml
```

Each route contains:

```yaml
id: google_personal_info
provider: Google
route_type: SEARCH_DELIST
jurisdictions:
  - GLOBAL
applies_to:
  - CONTACT_EMAIL
  - CONTACT_PHONE
  - HOME_ADDRESS
official_url: "..."
verification:
  type: manual_or_provider_status
last_verified: 2026-08-01
expires_after_days: 180
sources:
  - "official-documentation-url"
```

Every registry entry must contain an authoritative supporting source where possible.

## Registry governance

Every workflow PR requires:

```text
official source
reviewer
last verified date
jurisdiction
expected user inputs
side effects
verification procedure
```

Expired workflows remain visible internally but are not recommended to users until revalidated.

## California DROP

California's Delete Request and Opt-Out Platform should be treated as a jurisdiction-level route rather than recreating hundreds of broker-specific processes.

As of August 1, 2026, California data brokers are required to access DROP at least every 45 days and process applicable deletion requests.

Where applicable, Exposure should recommend:

```text
California DROP
```

before:

```text
manually submit 137 broker forms
```

That is simpler, safer and more maintainable.

---

# 17. Request generation

Requests are generated locally.

Example workflow:

```text
Finding
    ↓
Applicable routes
    ↓
User chooses route
    ↓
Required fields displayed
    ↓
Draft generated
    ↓
User reviews
    ↓
User opens official destination
    ↓
User submits externally
    ↓
User marks submitted
```

No automatic email sending in v0.2.
No automatically attached ID document.
No invented legal claims.

If legal language is generated, the system records the template version.

---

# 18. Case state machine

Use explicit state transitions.

```text
DISCOVERED
    ↓
REVIEWED
    ↓
ACTION_SELECTED
    ↓
REQUEST_PREPARED
    ↓
USER_MARKED_SUBMITTED
    ↓
AWAITING_RESPONSE
    ↓
SOURCE_CHANGED
    ↓
VERIFICATION_PENDING
    ↓
VERIFIED
```

Alternative outcomes:

```text
REJECTED
NOT_APPLICABLE
REQUEST_DENIED
USER_ABANDONED
SOURCE_UNREACHABLE
REAPPEARED
```

Never use:

```text
DONE
```

because it hides what actually occurred.

---

# 19. Verification

Verification is observation, not assumption.

## Source verification

Exposure retrieves the original URL again.

Possible outcomes:

```text
URL_GONE
CONTENT_REMOVED
PERSONAL_DATA_REMOVED
CONTENT_CHANGED
UNCHANGED
ACCESS_BLOCKED
UNKNOWN
```

## Search verification

Separate from source verification.

Possible:

```text
SEARCH_RESULT_PRESENT
SEARCH_RESULT_NOT_OBSERVED
```

Use wording carefully.

Not finding something in one query does not prove universal delisting.

Therefore:

```text
Not observed in the tested search
```

is preferable to:

```text
Removed from Google
```

unless provider status explicitly confirms removal.

## Evidence

Store:

```text
verification timestamp
query used
provider
status
new source hash
matching observations
```

---

# 20. Local application security

"localhost" is not sufficient protection.

The service must bind only to:

```text
127.0.0.1
::1
```

Never:

```text
0.0.0.0
```

by default.

## Runtime session

Generate a cryptographically random session secret at startup.

The browser UI must establish a same-session relationship with the backend.

Reject unauthorized API calls.

## HTTP protections

Required:

```text
strict Host validation
strict Origin validation
no wildcard CORS
CSRF protection for mutations
Content-Security-Policy
X-Content-Type-Options
Referrer-Policy
frame restrictions
no external JavaScript
no externally hosted fonts
```

## Secrets

API keys must never be placed in:

```text
SQLite plaintext
frontend localStorage
query strings
logs
exports
```

Preferred storage:

```text
macOS Keychain
Windows Credential Manager
Linux Secret Service
```

Fallback:
encrypted local secrets file protected by a user password.

---

# 21. Storage model

Database:

```text
SQLite
```

Recommended tables:

```text
subjects
subject_identifiers
sources
observations
matches
findings
remediation_cases
case_events
provider_settings
schema_migrations
```

Do not store secrets in provider_settings.

## Sensitive fields

Sensitive identifiers should be encrypted at rest when supported.

The UI should mask them by default.

Example:

```text
n•••••@domain.com
+971 •• ••• ••12
```

## Retention

Default behavior:

```text
raw response body: discard after processing
temporary extraction artifacts:
delete after scan
structured findings:
retain until user deletes workspace
logs:
7-day local rolling retention
network debug logs:
off
```

The user gets:

```text
Delete scan
Delete subject
Delete all Exposure data
```

The last function must delete:

```text
database
cache
temporary files
generated exports
local encryption material where appropriate
```

No fake deletion.

---

# 22. Logging

Logs must never contain raw:

```text
email
phone
address
API key
generated legal request
complete source body
```

Use identifiers:

```text
subject_id=...
source_id=...
finding_id=...
```

Error example:

```text
retrieval_failed
source_id=51a...
reason=timeout
```

Not:

```text
Failed to download page containing Jane Smith's address...
```

---

# 23. Open-source safety boundary

This requires precision.

An open-source application cannot guarantee that users only search themselves.
A malicious actor can modify any local check.

Therefore v0.2 does not rely on a fake authorization gate.

Instead, the reference implementation deliberately excludes capabilities whose dominant additional value would be investigating other people.

No:

```text
bulk subject import
batch name scanning
relationship graph expansion
find relatives
discover unknown emails
discover unknown phones
face matching
reverse identity lookup
breach credential collection
location history
people ranking
target dossiers
```

This does not make misuse impossible.

It keeps the official product aligned with personal privacy remediation.

---

# 24. Search privacy

Searching for yourself can itself disclose sensitive information.

Exposure must distinguish:

```text
information stored locally
from
information transmitted to providers
```

Before first external search, show:

```text
Exposure will send the following query to Brave Search:

"Jane Example" London

[Search]
```

For email or phone:

```text
This search transmits your email address
to the configured search provider.

[Cancel] [Search anyway]
```

The user can enable:

```text
Always approve non-sensitive queries
```

Sensitive identifiers always require separate opt-in unless the user explicitly changes the setting.

---

# 25. AI privacy

Default operation must not require a remote LLM.

Three operating modes:

```text
NO AI
LOCAL AI
REMOTE AI
```

NO AI must remain fully functional.

LOCAL AI can use an OpenAI-compatible local endpoint such as Ollama.

REMOTE AI requires explicit configuration.

Before activation:

```text
Some extracted source content may be sent
to your selected AI provider for analysis.
```

The application sends minimal finding packets rather than entire subject profiles.

---

# 26. API

Internal local API only.

Version from the beginning:

```text
/api/v1/
```

Core endpoints:

```text
POST   /subjects
GET    /subjects/{id}
DELETE /subjects/{id}

POST   /subjects/{id}/scans
GET    /scans/{id}
POST   /scans/{id}/cancel

GET    /findings
GET    /findings/{id}
POST   /findings/{id}/confirm
POST   /findings/{id}/reject
GET    /findings/{id}/remediation-routes

POST   /cases
GET    /cases/{id}
POST   /cases/{id}/events
POST   /cases/{id}/verify

GET    /settings/providers
PUT    /settings/providers/{id}

POST   /exports
```

Do not expose arbitrary crawler endpoints such as:

```text
POST /fetch?url=...
```

The retrieval engine should only operate on URLs associated with a scan or explicit manual source import.

---

# 27. Internal package structure

```text
exposure/
├── src/exposure/
│
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   └── static/
│
│   ├── domain/
│   │   ├── subject.py
│   │   ├── source.py
│   │   ├── observation.py
│   │   ├── match.py
│   │   ├── finding.py
│   │   └── remediation.py
│
│   ├── discovery/
│   │   ├── planner.py
│   │   ├── provider.py
│   │   └── providers/
│
│   ├── retrieval/
│   │   ├── client.py
│   │   ├── network_policy.py
│   │   ├── limits.py
│   │   └── canonicalize.py
│
│   ├── extraction/
│   │   ├── html.py
│   │   ├── metadata.py
│   │   ├── pii.py
│   │   └── semantic.py
│
│   ├── resolution/
│   │   ├── signals.py
│   │   ├── resolver.py
│   │   └── policy.py
│
│   ├── assessment/
│   │   ├── taxonomy.py
│   │   ├── rules.py
│   │   └── explain.py
│
│   ├── remediation/
│   │   ├── registry.py
│   │   ├── routes.py
│   │   ├── templates.py
│   │   └── verification.py
│
│   ├── ai/
│   │   ├── provider.py
│   │   ├── sanitize.py
│   │   └── schemas.py
│
│   ├── storage/
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── secrets.py
│   │   └── migrations/
│
│   └── security/
│       ├── session.py
│       ├── redaction.py
│       └── validation.py
│
├── frontend/
│
├── registry/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── fixtures/
│   └── benchmark/
│
├── docs/
│
├── pyproject.toml
├── uv.lock
└── LICENSE
```

This is enough structure.

Do not create a plugin framework yet.
Interfaces are sufficient.

---

# 28. Testing strategy

A privacy product that cannot measure false positives is not ready.

Tests must cover four dimensions.

## Functional

```text
query generation
URL canonicalization
parsing
extraction
deduplication
finding generation
workflow transitions
verification
exports
```

## Identity benchmark

Create a synthetic and consented benchmark corpus containing:

```text
distinctive names
common names
same-name individuals
changed employers
shared cities
aliases
conflicting profiles
old pages
incorrect pages
```

Primary metric:

```text
precision
```

not number of findings.

v0.2 target:

```text
HIGH_CONFIDENCE identity precision >= 98%
```

on the internal benchmark.

If this requires more results to remain POSSIBLE:

Good.

## Security

Mandatory tests:

```text
localhost bind enforcement
DNS rebinding defense
private-IP rejection
redirect-to-private-IP rejection
oversized response rejection
redirect-limit enforcement
unsupported scheme rejection
malformed HTML handling
decompression bomb protection
host-header rejection
CSRF rejection
invalid-origin rejection
secret redaction
LLM schema rejection
LLM prompt-injection fixture
```

## Remediation registry

Every registry entry gets automated checks for:

```text
schema validity
official URL availability
required fields
expiry
duplicate IDs
jurisdiction validity
supported finding types
```

---

# 29. Security development lifecycle

Use NIST SSDF as the engineering baseline and OWASP ASVS 5.0 as the application-control checklist where relevant. NIST's current stable SSDF is 1.1, while revision 1.2 remains draft as of the current NIST publication index; OWASP lists ASVS 5.0.0 as its current stable release.

CI must include:

```text
unit tests
integration tests
security regression tests
linting
type checking
dependency vulnerability scanning
secret scanning
static analysis
frontend dependency audit
build verification
```

Release artifacts should include:

```text
version
commit hash
SHA-256 checksums
SBOM
changelog
```

Dependencies are pinned.
Lockfiles are committed.

No dependency is added merely to avoid writing a trivial function.

---

# 30. Threat model

The system must explicitly defend against:

### Malicious websites

Attempting:

```text
SSRF
huge responses
redirect loops
malformed content
parser exploitation
prompt injection
tracking
browser exploitation
```

### Malicious search results

Designed to:

```text
misidentify a subject
poison AI analysis
redirect to internal resources
generate false exposure
```

### Malicious local webpages

Trying to communicate with the localhost service through the user's browser.

Mitigation:

```text
Origin checks
session authentication
CSRF controls
Host validation
```

### Compromised AI output

Trying to:

```text
trigger actions
fabricate legal claims
invent findings
exfiltrate secrets
```

Mitigation:

The AI has no capabilities allowing any of those actions.

### Malicious registry contribution

Trying to replace an official removal destination with an attacker-controlled phishing site.

Mitigation:

```text
CODEOWNERS review
official-source requirement
domain comparison
registry validation
signed releases
```

This attack is particularly important because users may submit identification documents through legitimate remediation processes.

A poisoned removal registry could be catastrophic.

---

# 31. Remediation safety

Exposure must never ask the user to upload an ID document into Exposure.

If a legitimate external removal process requires identity verification:

```text
This provider may ask you to verify your identity.
Exposure does not need or store that document.

[Open official provider]
```

Any external destination requiring sensitive information receives a warning and must originate from a verified registry route.

---

# 32. UX architecture

The interface should have only four primary screens.

```text
1. Me
2. Findings
3. Cleanup
4. Settings
```

## Me

Subject configuration and scan.

## Findings

All confirmed/probable findings.

Primary filters:

```text
Priority
Type
Confidence
Status
```

## Cleanup

Remediation cases.

Example:

```text
3 ready to act
2 awaiting response
1 ready to verify
```

## Settings

```text
Search provider
AI provider
Privacy controls
Local storage
Export
Delete all data
```

Do not expose architectural complexity to users.

---

# 33. Main dashboard

Primary UI:

```text
YOUR EXPOSURE

High          3
Moderate      8
Low          14
Needs review  7

────────────────────────────

HOME ADDRESS
example.com/profile

Identity
Very likely you

Exposure
High

Your home address and personal telephone
number appear together on this page.

[Review]

────────────────────────────

OLD BIOGRAPHY
conference.example/speaker

Identity
Confirmed

Exposure
Low

Your title appears to be outdated.

[Review]
```

Do not show a giant:

```text
57 / 100
```

as the primary measure.

A global score creates false precision and encourages gamification.

If a summary score is added later, it must remain secondary.

---

# 34. Finding detail

Each finding should answer exactly five things:

```text
WHAT DID WE FIND?
WHY DO WE THINK IT IS YOU?
WHY MIGHT IT MATTER?
WHAT CAN YOU DO?
HOW WILL WE CHECK THE RESULT?
```

That should be the conceptual backbone of the product.

---

# 35. Failure semantics

Errors must be explicit.

Examples:

```text
Search provider unavailable
Source blocked automated retrieval
Source timed out
Identity ambiguous
Unable to assess safely
Removal instructions expired
Verification inconclusive
```

Never silently convert failure into absence.

Example:

Bad:

```text
No information found
```

when Brave failed.

Correct:

```text
Scan incomplete.
Search provider returned an error.
```

This distinction is essential for user trust.

---

# 36. Metrics

Because Exposure has no central telemetry, product-quality metrics are measured in tests and optionally displayed locally.

Engineering metrics:

```text
identity precision
identity recall
ambiguous-match rate
retrieval success rate
extraction precision
duplicate rate
remediation coverage
verification accuracy
scan duration
bytes downloaded
API queries used
```

The most important metric is not:

```text
findings discovered
```

It is:

```text
correct actionable findings
```

A scanner producing 15 correct findings is better than one producing 150 noisy ones.

---

# 37. Performance budgets

Standard scan target:

```text
queries                 <= 15
candidate URLs          <= 100
retrieved pages         <= 100
download                <= 100 MB
database size           typically < 20 MB
memory                   target < 500 MB
```

No requirement exists for sub-second scans.

Accuracy and safety win over raw speed.

---

# 38. Accessibility and portability

Browser UI must work at minimum in:

```text
Chrome
Edge
Firefox
Safari
```

Frontend should meet reasonable WCAG AA expectations.

No functionality should require a mouse.
No removal workflow should depend on color alone.

---

# 39. Versioning

Version separately:

```text
application
database schema
resolver
assessment policy
remediation registry
AI prompt/schema
```

Example finding provenance:

```text
Exposure 0.2.1
Resolver 1.0
Assessment policy 1.2
Registry 2026.08.08
Extractor html/1.1
```

This makes future auditing possible.

---

# 40. Development milestones

## M0: Foundation

Deliver:

```text
repository
CI
single local server
compiled frontend
SQLite
migrations
settings
secret storage
runtime session security
```

Exit criterion:
A release artifact launches locally without developer tooling.

## M1: Safe discovery

Deliver:

```text
subject setup
query planner
Brave connector
manual URL import
secure retriever
source normalization
```

Exit criterion:
A scan can discover and safely retrieve public sources.
Security tests for SSRF must already pass.

## M2: Evidence

Deliver:

```text
deterministic extraction
observation model
minimal evidence storage
source deduplication
```

Exit criterion:
Every displayed extracted fact traces to a source and snippet.

## M3: Identity resolution

Deliver:

```text
signal families
contradictions
resolution states
user confirmation
benchmark corpus
```

Exit criterion:
High-confidence precision target:

```text
>= 98%
```

on the approved benchmark.

## M4: Exposure assessment

Deliver:

```text
finding taxonomy
deterministic policy
reason codes
finding dashboard
```

Exit criterion:
Findings are consistently prioritized without an LLM.

## M5: Remediation

Deliver:

```text
registry
route matching
request templates
case state machine
official destination handling
```

Exit criterion:
At least these routes work:

```text
Google personal-information removal
generic source-owner contact
generic GDPR request guidance
California DROP guidance
user-controlled source removal
```

## M6: Verification

Deliver:

```text
source recheck
observation comparison
case verification
search-result recheck
```

Exit criterion:
A submitted remediation can be reassessed without relying on user memory.

## M7: Optional AI

Only after the deterministic application is complete.

Deliver:

```text
provider abstraction
local AI support
remote AI support
sanitization
schema validation
prompt-injection tests
```

Exit criterion:
Turning AI completely off does not break the product.

---

# 41. v0.2 acceptance test

A clean machine should be able to do:

```text
Install Exposure
→ Open local application
→ Define myself
→ Review exactly what queries will leave my machine
→ Run scan
→ See retrieved sources
→ Understand which sources probably refer to me
→ Reject false matches
→ See why sensitive findings matter
→ Choose an available remediation route
→ Generate instructions/request locally
→ Open the authoritative destination
→ Mark request submitted
→ Return later
→ Verify the source again
→ Export my local report
→ Delete every piece of Exposure data
```

If that entire loop works reliably, v0.2 is complete.

---

# 42. Hard release gates

The application cannot be tagged v0.2 if any of these remain unresolved:

```text
Retriever can access private network addresses.
High-confidence identity precision is below target.
LLM can trigger external actions.
Sensitive API keys appear in logs.
Raw pages are retained indefinitely.
External scripts execute in the local UI.
Removal links can enter the registry without provenance.
The application claims deletion where only delisting occurred.
Search-provider failure appears as zero findings.
A user cannot delete the local workspace completely.
An ordinary scan requires an Exposure-operated server.
AI is required for basic operation.
```

These are release blockers.

---

# 43. Harness boundary

We should still extract the reusable architecture, but much less aggressively than v0.1 proposed.

The reusable core is:

```text
Source
Observation
Subject
Match
Finding
Action/Case
```

And the generic pipeline:

```text
DISCOVER
    ↓
OBSERVE
    ↓
RESOLVE
    ↓
ASSESS
    ↓
ACT
    ↓
VERIFY
```

Do not yet create:

```text
plugin SDK
generic agent framework
universal workflow language
distributed event bus
generic evidence graph database
cross-product UI framework
```

If Exposure and a second application independently need one of those abstractions, extract it then.

The harness should emerge from repeated reality.

Not anticipated elegance.

---

# 44. Product differentiation

Exposure does not win by discovering the most information.

Tools such as SpiderFoot already provide extensive OSINT collection and correlation, with hundreds of modules.

Exposure wins by doing something narrower:

```text
OSINT tools:
How much can I discover about a target?

Exposure:
What can people discover about me,
which of it matters,
and what can I realistically do about it?
```

Existing consumer products also demonstrate that merely finding broker records is insufficient. Accuracy, false identity associations, inconsistent removal procedures and recurring reappearance are substantive problems.

Mozilla's paid Monitor Plus broker-removal product has also been discontinued, while Mozilla continues breach monitoring, showing that the market is not simply a solved category of permanent automated removal.

Our differentiation should therefore be:

```text
local
open
inspectable
precise
evidence-backed
remediation-oriented
provider-independent
non-autonomous
```

---

# 45. Final engineering rule

Every feature proposed for Exposure must pass five questions:

```text
1. Does it materially help a person understand
   or reduce their own digital exposure?

2. Can we establish the result from evidence?

3. Can we implement it without unnecessarily
   collecting more personal data?

4. Can the user understand what leaves
   their device and why?

5. Does it preserve human control over
   consequential external actions?
```

If the answer to any of those is no:

Do not build it into v0.2.

---

# 46. Definition of the system

Exposure v0.2 is therefore not:

```text
an AI that searches the internet for people
```

It is:

```text
a local evidence and remediation engine
for personal digital exposure.
```

Its fundamental contract is:

```text
OBSERVE
Never fabricate what exists.

RESOLVE
Never confidently assign information
to someone without sufficient evidence.

ASSESS
Never hide uncertainty behind an AI score.

ACT
Never create consequential external effects
without the user's explicit authorization.

VERIFY
Never call something removed merely because
we requested its removal.

MINIMIZE
Never retain more personal information
than the product needs.
```

That contract should survive every future version.
