# ScamShield AI feature matrix

Status reflects the current implementation and tests, not intended behavior.
Optional provider availability and live checks are stated separately.

| Area | Capability | Status | Evidence / limitation |
|---|---|---|---|
| Core services | FastAPI, Streamlit, SQLite, Windows `.\start.ps1` | Implemented and tested | Backend route tests and Streamlit AppTest; the final launcher smoke result is recorded below. |
| Accounts | Registration, login, logout, scrypt password hashes, 12-hour hashed sessions, profile/password change, account deletion | Implemented and tested | Backend tests cover auth, revocation, account ownership and server-side admin role checks. Public signup always creates a regular user; an operator must provision administrator roles directly in SQLite. |
| Accounts | Session listing/revocation UI, password reset and email verification | Not implemented | No session-management routes or configured email delivery workflow. |
| Authorization | Account-scoped investigations, saved reports, watchlist and deletion | Implemented and tested | Backend tests verify cross-account isolation and ownership checks. |
| Abuse controls | Sign-in attempt limit | Partially implemented | Limit is per email over 15 minutes; no general API or source-IP rate limiter. |
| Investigations | Website URL checks using TinyFish Search and Fetch | Implemented and tested | Mocked API tests cover request formats and errors. Live smoke checks in the current environment returned Search results and fetched Microsoft, Amazon India, and Google homepages; live availability is not guaranteed. |
| Job verification | Job-specific Search query, exact submitted-offer URL Fetch, structured listing extraction | Implemented and tested | Mocked tests cover exact URL/final URL, title, company, job ID, description/application fields, mismatch states, generic search isolation, and provider errors. A live Amazon Careers URL matched its final URL, title, and job ID; employer authority remains unverified. |
| Job verification | Redirected careers-page handling | Implemented and tested | Known platform hosts and same-domain-family redirects can be checked for listing-detail consistency. A live Google Careers URL redirected to `www.google.com`, but returned a generic search page with no role details; that listing remained insufficiently verified. Redirects never establish employer authority. |
| Job verification | Official company-domain / recruiter identity verification | Not implemented | No authoritative company-domain registry or recruiter identity provider is configured. Reports explicitly state that page text and email-domain resemblance do not verify ownership or identity. |
| Job verification | Rule-based fee, placement, sensitive-data, urgency, unusual hiring promises and recruiter-domain signals | Implemented and tested | Each warning is an explainable inference with supporting evidence. Missing pages add no points; recruiter/offer host mismatch adds none. A low job score is classified as “Insufficient evidence” unless warning signals justify a higher class. |
| Investigations | Message and payment request analysis | Implemented and tested | Deterministic English-language rules; merchant search allegations are only scored when the result mentions the requested merchant, and repeated search results contribute at most one 8-point allegation signal. No LLM, financial account validation, or multilingual model. |
| Investigations | Email, phone, company and domain public-search records | Implemented and tested | Consent is required for email/phone lookups. Results are evidence-only and are not scored or treated as identity verification. |
| Evidence quality | Exact target-domain/company relevance gate, URL canonicalization, duplicate suppression | Implemented and tested | Irrelevant results are retained with `unrelated_not_scored`; only related warning results can add an allegation indicator. |
| Evidence quality | Redirect awareness | Partially implemented | Recognized job platforms and same-domain-family redirects may be checked for job-detail consistency; unrelated cross-domain content is excluded. The app cannot control TinyFish’s remote redirect policy or prevent a redirect before it occurs. |
| Evidence quality | Source credibility, publication-date/freshness scoring, limited subdomain impersonation heuristic, conflicting-source reconciliation | Partially implemented | A company brand appearing only in an unverified subdomain adds an explainable warning; this heuristic is not an authoritative domain check and does not cover all lookalikes. |
| Risk analysis | Explainable rule scoring and separation of public allegations from rule inferences | Implemented and tested | Missing information adds no points. Website allegations must directly accuse the target; first-party warnings and brand-impersonation advisories are not scored. Multiple related allegations contribute at most one low-weight signal per website or job report. |
| Offer documents | Pasted text, PDF and image offer extraction and screening | Implemented and tested | In-memory extraction supports text PDFs and JPG/JPEG/PNG OCR. Extracted claims are not authenticated; report retention is opt-in. No antivirus or document-signature verification is provided. |
| Email analysis | Pasted email and `.eml` analysis | Implemented and tested | Rules identify phishing, payment, credential, OTP and attachment-name indicators. `.eml` attachments are ignored. Link research is opt-in; headers and sender identity are not authenticated. |
| AI analysis | Optional Gemini evidence-grounded interpretation | Implemented; live provider not tested | Requires `GEMINI_API_KEY`; structured response validation and evidence-index checks are enforced. AI text is labeled as interpretation and cannot alter the rule-based score. |
| Threat providers | TinyFish Search/Fetch configuration display | Implemented; live smoke-tested | Presence is displayed without key material. Live Search returned 10 results; live Fetch of the exact Amazon job URL returned the submitted final URL, matching title/job ID, and no provider errors. This is not a continuous health check. |
| Threat providers | Google Safe Browsing, VirusTotal, URLhaus, PhishTank, AbuseIPDB, WHOIS, DNS and SSL enrichment | Not implemented | No provider adapters or API requests are present. |
| Local tools | QR decoding and screenshot OCR | Implemented and tested | OpenCV QR decoding is tested with generated QR images. A local Tesseract smoke test extracted the test phrase and returned confidence. QR destinations are displayed before the user explicitly prepares a website investigation. OCR confidence is not an accuracy guarantee. |
| Local tools | Voice scam analysis | Not implemented | No speech transcription or audio-analysis integration. |
| Investigation tools | Batch URL analysis and CSV import/export | Implemented and tested | Each URL is processed independently, canonical duplicates are skipped, inputs are capped at 10, requests are limited to three per user per minute, and per-URL failures do not abort the batch. |
| Investigation tools | Independently controlled redirect-chain inspection | Not implemented | TinyFish performs remote Fetch and redirect behavior is controlled by the provider; this application cannot guarantee every redirect destination. |
| Reports | PDF generation/download, CSV history export, saved reports, filters and comparisons | Implemented and tested | PDF is generated from saved report data; history is account-scoped. |
| Reports | Secure share links and email notifications | Not implemented | No share-token/expiry workflow or email delivery provider. |
| Dashboard | Database-backed counts, recent records, risk distribution and activity chart | Implemented and tested | Empty database uses an empty state; public-source evidence-only records are excluded from scored-risk charts. |
| Dashboard | Watchlist manual management and visual history/timeline/evidence graph | Implemented and tested | User-owned watchlist entries and investigation history are isolated by account. |
| Monitoring | Opt-in scheduled watchlist checks and in-app alerts | Implemented and tested | APScheduler runs in-process, settings/check history are stored in SQLite, and lifecycle and owner access are tested. Checks pause while the API is stopped; no email alerts are sent. |
| Security | Password hashing, hashed sessions, role enforcement, parameterized SQL, API input constraints | Implemented and tested | Covered in current backend tests. |
| Security | Initial-target SSRF validation | Implemented and tested | Rejects non-HTTP(S), credentialed, local and non-global IP destinations after DNS resolution. Remote TinyFish redirect destinations cannot be prevalidated or guaranteed by this app. |
| Security | Upload validation and in-memory file processing | Implemented and tested | 8 MB size cap, extension/content checks, 20-megapixel cap, PDF page cap, OCR timeout, and attachment-ignore behavior. Malware scanning and audit-log history are not implemented. |
| UI | Deep-navy cybersecurity theme, animated ambient effects, responsive workspace | Implemented and browser/AppTest-checked | Landing, authentication, dashboard, website/message/job investigations, watchlist, settings and analytics were browser-checked. Document-level horizontal overflow was absent at 1440, 1366, 768 and 390 px; reduced motion stopped ambient-scene animations. This is not a full assistive-technology audit. |

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
- At the time of this earlier audit, live TinyFish Search/Fetch calls were not
  made. See the current advanced-feature validation below for this run's live
  smoke-test result.

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
  bodies. Live service smoke tests below are separate from mocked exact-listing
  tests.

## Advanced feature validation

- Offer documents, email analysis, QR/OCR, Gemini response handling, batch
  processing, scheduler lifecycle and ownership checks have automated
  regressions. Sensitive offer/email/OCR/QR reports are retained only with
  explicit user consent.
- The complete automated suite passed **110 tests** in the final local run.
  Python compilation, `pip check`, and `git diff --check` passed. Streamlit
  AppTest loaded the advanced screens and verified multiple batch reports render
  without duplicate chart IDs.
- An isolated FastAPI instance returned HTTP 200 for `/health` and
  `/openapi.json`; registration returned 201, an unauthenticated history
  request returned 401, and authenticated email/batch/monitoring-status routes
  returned expected responses. An isolated Streamlit instance returned an
  HTML page with HTTP 200. Temporary services and their temporary database
  were stopped/removed without changing the existing port-8000 service.
- Real TinyFish Search and Fetch smoke tests succeeded in final validation.
  Fetch of the exact Amazon Careers URL
  `https://www.amazon.jobs/en/jobs/10477396/software-development-engineer-2026`
  returned the same final URL, matching title and job ID `10477396`. The page
  did not establish employer authority or authenticate a separate offer, so
  the result remains partially verified. Gemini has no configured key and was
  not live-tested; mocked unavailable/malformed-response tests passed.
- Local Tesseract extracted text and returned a confidence value. OCR and
  Gemini interpretations are not proof, and no antivirus, sender-authentication
  or official-domain ownership service is integrated.
- The APScheduler service is in-process; run one FastAPI worker to avoid
  duplicate scheduled checks across multiple worker processes. Checks pause
  when the application is stopped and are re-registered on startup.
- Final browser testing used a disposable SQLite database. Website, job,
  offer-document, email, QR, OCR, batch and saved-report workflows were
  exercised. The PDF endpoint returned a valid PDF; browser download-event
  confirmation and complete watchlist controls were not verified in that run.
  A watchlist API response-validation defect found in the run has since been
  fixed and covered by regression tests.
- The actual `.\start.ps1` launcher started FastAPI and Streamlit successfully
  against a disposable database; both services were then stopped. Health
  endpoints returned HTTP 200. No cloud deployment was performed.

## Final verification

- The current environment's full test suite passed **110 tests**. Python
  compilation, `pip check`, and `git diff --check` passed.
- Both already-running local services responded successfully: FastAPI
  `/health` and the Streamlit page returned HTTP 200.
- Live TinyFish Search returned 9 Microsoft-careers results. TinyFish Fetch
  successfully returned the Microsoft homepage. An in-app live website scan
  displayed fetched content and attributed search/fetch evidence.
- An in-app live check of Amazon job `10477396` fetched the submitted
  `amazon.jobs` URL and reported matching company, role, and job ID details.
  The result remained **Partially verified** because the domain and employer
  authority were not independently authenticated.
- Browser/API checks covered registration, sign-in/out, a rule-based message
  report, watchlist persistence, profile update, user analytics, saved-report
  persistence, unauthenticated access denial, and cross-user read/delete
  isolation. Disposable test accounts and their data were removed.
- Gemini was not configured and was not live-tested. No production deployment
  was performed.
