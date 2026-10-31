# ScamShield AI feature matrix

Status reflects the checked-in implementation and tests, not intended behavior.
“Integration unavailable” means a UI or service boundary may exist, but the
capability is not activated or a live provider check has not been performed.

| Area | Capability | Status | Evidence / limitation |
|---|---|---|---|
| Core services | FastAPI, Streamlit, SQLite, Windows `.\start.ps1` | Implemented and tested | Backend route tests, Streamlit AppTest, and a fresh launcher smoke test with both HTTP services returning 200. |
| Accounts | Registration, login, logout, scrypt password hashes, 12-hour hashed sessions, profile/password change, account deletion | Implemented and tested | Backend tests cover auth, revocation, account ownership and server-side admin role checks. |
| Accounts | Session listing/revocation UI, password reset and email verification | Not implemented | No session-management routes or configured email delivery workflow. |
| Authorization | Account-scoped investigations, saved reports, watchlist and deletion | Implemented and tested | Backend tests verify cross-account isolation and ownership checks. |
| Abuse controls | Sign-in attempt limit | Partially implemented | Limit is per email over 15 minutes; no general API or source-IP rate limiter. |
| Investigations | Website URL checks using TinyFish Search and Fetch | Implemented and tested | Request formats and error handling are covered by mocked API tests; no live provider call was made for this phase. |
| Job verification | Job-specific Search query and exact submitted-offer URL Fetch | Implemented and tested | Exact fetch, final URL, title/text, company/role/job-ID comparisons, company-level evidence labels, and provider-failure handling have deterministic mocked tests. |
| Job verification | Official company-domain / recruiter identity verification | Not implemented | No authoritative company-domain registry or recruiter identity provider is configured. Reports explicitly state that page text and email-domain resemblance do not verify ownership or identity. |
| Job verification | Rule-based fee, placement, sensitive-data, urgency and recruiter-domain signals | Implemented and tested | Each warning is an explainable inference. Missing pages do not add risk; public email-provider and domain-difference signals are low weight. |
| Investigations | Message and payment request analysis | Implemented and tested | Deterministic English-language rules; no LLM, financial account validation, or multilingual model. |
| Investigations | Email, phone, company and domain public-search records | Implemented and tested | Consent is required for email/phone lookups. Results are evidence-only and are not scored or treated as identity verification. |
| Evidence quality | Exact target-domain/company relevance gate, URL canonicalization, duplicate suppression | Implemented and tested | Irrelevant results are retained with `unrelated_not_scored`; only related warning results can add an allegation indicator. |
| Evidence quality | Redirect awareness | Partially implemented | A different final host returned by Fetch is shown and excluded from scoring. The app cannot control or guarantee TinyFish’s remote redirect policy or prevent a redirect before it occurs. |
| Evidence quality | Source credibility, publication-date/freshness scoring, domain similarity, impersonation detection, conflicting-source reconciliation | Not implemented | No trusted reputation dataset or tested scoring policy is configured. |
| Risk analysis | Explainable rule scoring and separation of public allegations from rule inferences | Implemented and tested | Missing information adds no points. A public allegation is labeled and contributes only a low-weight signal; it is not proof of wrongdoing. |
| AI analysis | Gemini/other LLM evidence-grounded analysis | Implemented but integration unavailable | Integration status can report provider configuration; no LLM analysis path is integrated. Current reports identify deterministic analysis. |
| Threat providers | TinyFish Search/Fetch configuration display | Partially implemented | Credential presence is displayed, not a live health check; last-success time and connection failure reason are not recorded. |
| Threat providers | Google Safe Browsing, VirusTotal, URLhaus, PhishTank, AbuseIPDB, WHOIS, DNS and SSL enrichment | Not implemented | No provider adapters or API requests are present. |
| Local tools | QR decoding, screenshot/document OCR, voice scam analysis | Not implemented | Navigation presents unavailable states; corresponding decoder/OCR/transcription modules are absent. |
| Investigation tools | Batch URL analysis and independently controlled redirect-chain inspection | Not implemented | No batch workflow or client-controlled redirect fetcher. |
| Reports | PDF generation/download, CSV history export, saved reports, filters and comparisons | Implemented and tested | PDF is generated from saved report data; history is account-scoped. |
| Reports | Secure share links and user notifications/alert history | Not implemented | No share-token/expiry workflow or notification store. |
| Dashboard | Database-backed counts, recent records, risk distribution and activity chart | Implemented and tested | Empty database uses an empty state; public-source evidence-only records are excluded from scored-risk charts. |
| Dashboard | Watchlist manual management and visual history/timeline/evidence graph | Implemented and tested | These summarize stored account data; no scheduled checks are implied. |
| Monitoring | Scheduled watchlist checks, risk-change alerts and email alerts | Not implemented | No scheduler, persistent job queue or mail provider. |
| Security | Password hashing, hashed sessions, role enforcement, parameterized SQL, API input constraints | Implemented and tested | Covered in current backend tests. |
| Security | Initial-target SSRF validation | Implemented and tested | Rejects non-HTTP(S), credentialed, local and non-global IP destinations after DNS resolution. Remote TinyFish redirect destinations cannot be prevalidated or guaranteed by this app. |
| Security | Upload validation, malware scanning and audit-log history | Not implemented | No file-upload endpoint or structured audit-trail store. |
| UI | White/cobalt/lime responsive design and public/account/workspace views | Implemented and tested | Streamlit AppTest and a narrow browser viewport check; interactive pages retain explicit unavailable states for missing integrations. |

## Phase 1 audit notes

- The project is a small Python application: FastAPI modules under `app/`,
  one Streamlit entry point and local SVGs under `frontend/`, and unittest
  coverage under `tests/`. The `.venv`, local database, `.env`, launcher logs
  and PID files are runtime/local data, not application source.
- SQLite initialization performs additive migration for investigation ownership.
  SQL values are parameterized; query fragments used for optional filters are
  assembled from fixed internal column names.
- API validation errors use generic messages. TinyFish errors are logged by
  status/type and returned without upstream response bodies or credentials.
- The app checks and validates the originally submitted URL. TinyFish performs
  remote fetching, so the app does not claim complete redirect/SSRF protection.
- Integration configuration is not the same as a live connection test. A key
  configured in the local environment must not be surfaced in reports or UI.
- No source file or test requires reading `.env`; keep the local file private.

## Phase 2 changes

- Added canonical URL normalization (host/scheme/default-port normalization,
  fragment and common tracking-parameter removal) and deduplication.
- Search results must match the exact target domain or explicitly mention it
  before a warning can affect a website score. Job-search evidence must name
  the company or reference the exact submitted URL/job ID; sharing the offer
  host alone does not establish relevance.
- Returned Fetch content from a different final domain is labeled as a redirect
  destination, excluded from score inputs, and called out as an information gap.
- Added tests for unrelated results, allegations, redirects, canonicalization,
  domain boundaries, company relevance and URL deduplication.
- Centralized frontend Bearer authorization headers so API calls and PDF
  downloads use the same tested session-token handling.
- Verification: 42 tests passed; Python compilation and changed-file Pylance
  diagnostics passed; Streamlit AppTest covered public/auth views and 27
  workspace routes; a fresh `.\start.ps1` smoke test returned HTTP 200 from
  FastAPI and Streamlit. Services were then stopped cleanly.
- Live TinyFish Search/Fetch calls were not made, so real-provider success is
  not claimed.

## Job verification improvements

- When an offer URL is supplied, the API issues a targeted Search request and
  fetches that exact URL; Search and Fetch run concurrently. Provider failures
  return an explicit API error and do not save a successful-shaped report.
- Search results are distinguished as listing references, company-level
  evidence, or unrelated results. A generic company/careers result is never
  treated as proof that the submitted role exists.
- Fetched page title/text, final URL, company-name presence, role-text overlap
  and available job identifier are shown as separate checks. Page-content risk
  rules are applied only when the exact submitted URL was returned on its
  submitted domain and the fetched details match the offer text.
- Public allegations remain company-level allegations, not proof of the
  individual offer. Missing or blocked pages do not increase the score.
- Famous-company names do not reduce scores. Matching page details receive no
  score reduction because this build cannot independently prove official
  domain ownership. Recruiter email domains remain unverified; public-provider
  and offer-host differences add only explicitly explained low-weight warnings.
- Each job report keeps its own evidence. The Streamlit workspace clears a
  prior report on investigation-mode changes and before submitting a new
  request, including requests that later fail.
- TinyFish diagnostics log provider/operation, request status, response status,
  duration, result count, and per-URL error count without keys or response
  bodies. Live Search/Fetch behavior was mocked for these tests; no live
  provider verification was performed.
- Final validation: all 57 tests passed, including mocked listing, internship,
  impersonation-like domain, registration-fee, generic-search, unavailable URL,
  recruiter-domain, evidence-isolation and TinyFish-failure cases. Streamlit
  AppTest verified the job report fields and stale-report clearing; Pylance
  diagnostics were empty for changed Python files.
