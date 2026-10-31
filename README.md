# ScamShield AI

ScamShield AI is a FastAPI and Streamlit scam-screening app. Website and offer
research use TinyFish Search and Fetch. Text analysis is deterministic,
explainable rule-based screening; no LLM provider is configured.

## Windows setup

Open PowerShell in this project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
```

Set `TINYFISH_API_KEY` in `.env` locally. Do not share or commit that file. If
`.env` already exists, preserve it and edit it without copying over it.
Public registration always creates a regular account. To provision an
administrator, register the account first, stop the services, then update its
role directly in the local database using the operator command in the
authentication section below. Do not put credentials in frontend code.

Start the backend and dashboard together from a PowerShell terminal in the
project root:

```powershell
.\start.ps1
```

The launcher verifies the virtual environment and required packages, starts
FastAPI on port `8000` and Streamlit on port `8501`, checks both HTTP services,
then keeps them running. Open `http://127.0.0.1:8501`. Press `Ctrl+C` in the
launcher terminal or, from another PowerShell terminal, run:

```powershell
.\stop.ps1
```

Service logs and launcher PID files are written to the ignored `.run\` folder.
If startup fails, review `backend-error.log` or `frontend-error.log`. The
launcher will not terminate a process that already owns ports 8000 or 8501.

To run either service separately for development:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
.\.venv\Scripts\python.exe -m streamlit run frontend\streamlit_app.py
```

Run tests:

```powershell
python -m unittest discover -s tests -v
```

The backend listens at `http://127.0.0.1:8000`; the dashboard is normally at
`http://localhost:8501`. Set `SCAMSHIELD_API_URL` if the backend is elsewhere.
Set `SCAMSHIELD_DATABASE_PATH` to choose another SQLite file.

## Features

- Premium white, electric cobalt and acid-lime visual system with a native
  Streamlit light theme, responsive styling, motion-aware effects, and locally
  stored original SVG illustrations.
- Public information views for Features, Solutions, How it works, Threat
  Intelligence, Security Methodology, About, FAQ, Contact, Privacy and Terms.
  The privacy/terms copy is informational and not legally reviewed.
- Account portal includes password registration, sign-in, profile management
  and password changes; the public URL input queues a scan until sign-in.
- Overview dashboard shows actual SQLite investigation counts, risk bands,
  activity and recent reports. Empty databases show an honest empty state.
- Dedicated investigation workspace, source-backed Threat Intelligence view,
  searchable/filterable history, side-by-side report comparison and risk
  methodology page, report timeline, evidence grouping graph, CSV history export
  and user-scoped investigation deletion.
- Plotly risk gauge, indicator contribution chart and database-backed trend
  charts.
- PDF and JSON report downloads from saved investigation data.
- Local account registration, sign-in/sign-out, profile updates and password
  changes. Passwords are stored with Python's scrypt password hash; session
  tokens are random, time-limited, stored server-side as hashes and revoked at
  sign-out or password change.
- Investigation history, saved reports, watchlists and dashboard analytics
  are scoped to the signed-in account. Existing pre-account history is retained
  in SQLite, but remains unassigned and is not exposed to newly registered
  accounts.
- Server-enforced administrator analytics for accounts with an operator-
  provisioned `admin` database role. Public registration cannot grant admin
  access based on a claimed email address.
- Integration status reports configuration without returning key
  material. TinyFish status means credentials are configured, not that a live
  request has been tested. Watchlist entries support manual follow-up only;
  they do not run scheduled monitoring or generate alerts.
- Screenshot OCR, QR decoding, Gemini assistant, VirusTotal, Scam Alerts, and
  community moderation pages are explicitly marked unavailable, not simulated.
- Scam DNA is a transparent mapping of existing report indicators to possible
  social-engineering stages; it does not claim to reconstruct attacker intent.
- Website investigation combines a TinyFish Search query with TinyFish Fetch
  page content.
- Job/internship investigation issues a job-specific Search query and, when an
  offer URL is supplied, fetches that exact URL through TinyFish. The report
  records submitted/final URLs, fetched title/text, structured company, role,
  job-ID, description and application details when returned. It compares
  submitted company, role and any supplied job ID. Generic company results are
  labelled as company-level evidence, not proof of a specific listing.
- Recognized third-party recruitment-platform redirects (including Greenhouse,
  Lever, Ashby, Workday, SmartRecruiters, iCIMS, Jobvite, Indeed, LinkedIn,
  ZipRecruiter and Wellfound) can be checked for listing-detail consistency
  without adding risk points solely for platform hosting. Unrecognized
  cross-domain redirects are recorded and excluded from listing verification
  and page-content scoring. Platform or page consistency does not verify the
  employer's authority or offer authenticity.
- Recruiter email domains are screened for public email providers and
  differences from the offer host; a host mismatch is informational only and
  adds no risk points because legitimate employers may use external recruiting
  platforms. Public email providers may trigger a low-weight warning. Neither
  check verifies identity. Matching page text does not establish that a domain is
  company-operated. Official careers-domain ownership is not independently
  verified by this build, and matching offer details do not reduce risk scores.
- Job-offer inputs are scored with explicit rules for fees, guaranteed
  placement claims, sensitive identity/banking requests (including Aadhaar,
  PAN and OTPs), urgency, unsupported no-interview promises, unusual salary
  claims and suspicious brand-only subdomains. Every indicator includes its
  evidence and point contribution. Missing or inaccessible listing evidence
  adds no risk points. Low job scores are classified as **Insufficient
  evidence** rather than a green low-risk finding when authenticity is
  unverified.
- Email, phone, company and domain investigations collect real TinyFish public
  search results. Email and phone lookups require explicit consent. These
  reports do not assign a risk score or claim identity/reputation verification.
- Message and payment request analysis runs local deterministic rules and does
  not automatically open message links. When a merchant is supplied for
  payment analysis, TinyFish Search results are attributed and marked relevant
  or unrelated; unrelated warning results cannot affect the score, and
  multiple merchant-related public allegations contribute at most one
  low-weight signal.
- Reports explain each matched indicator and score contribution. Missing
  information adds no risk points.
- TinyFish Search/Fetch server logs record provider, operation, request outcome,
  HTTP response status when available, duration, result count and per-URL error
  count. Logs do not include credentials or upstream response bodies. Provider
  failures abort the investigation request rather than creating a completed
  report.
- Website/job search evidence is matched to the investigated domain or company;
  unrelated results remain visible but are excluded from risk scoring.
- Evidence records identify TinyFish Search or TinyFish Fetch as the provider;
  when the same URL is returned by both, the combined source retains both
  attributions.
- Evidence URLs are canonicalized for duplicate detection. A Fetch result whose
  final host differs from the submitted target is labeled and excluded from
  scoring; this does not prevent or control redirects followed by TinyFish.
- SQLite stores investigation reports and supports history/retrieval. Raw
  message/payment submissions and offer descriptions are not persisted;
  user-submitted-text snippets are redacted in stored records.
- Investigation report state is cleared on sign-out, account change, and before
  each new investigation so a failed request or later user cannot see a stale
  report from the previous request or account.

## Security and interpretation limits

The API rejects non-HTTP(S), localhost/local hostnames, literal non-public IPs,
and DNS hostnames that resolve to any non-public IP at validation time. This
check happens in the application before forwarding URLs to TinyFish.

TinyFish Fetch's official [API reference](https://docs.tinyfish.ai/fetch-api/reference.md)
reports `final_url` after redirects and includes an `invalid_redirect_url`
per-URL error code. It does not document a caller-configurable redirect-blocking
policy or DNS/destination pinning. Therefore this app cannot guarantee that
redirects followed by the remote Fetch service stay on public hosts. DNS can
also change after validation, and the remote service resolves the hostname
independently. Treat remote URL fetching as a residual security risk; only
investigate URLs you are authorized to submit.

Accounts are local to this installation. Email verification, OAuth, email-based
password recovery, and multi-factor authentication are not configured. Password
changes require a signed-in user; email recovery is unavailable without an
email delivery provider. Protect the host and SQLite database accordingly.
Public registration always assigns the `user` role. To grant administrator
access, stop the app and promote an account through a local operator action:

```powershell
.\.venv\Scripts\python.exe -c "import sqlite3; db=sqlite3.connect('scamshield.db'); cursor=db.execute('UPDATE users SET role=? WHERE email=?', ('admin', 'your-email@example.com')); db.commit(); print(f'Updated {cursor.rowcount} account(s)'); db.close()"
```

If `SCAMSHIELD_DATABASE_PATH` points to a different file, use that database
path instead. Review existing `admin` roles when upgrading, because prior
administrator assignments remain in the database.

Upstream error bodies and internal exception details are not returned to the
dashboard. Live API failures return a clear service error, and failed requests
do not create a completed investigation report. TinyFish per-URL fetch errors
can be returned in a successful API response; such investigations are marked
partial when usable page/search evidence is missing.

Risk scores represent configured indicators, not a probability that fraud
occurred. Public allegations are labeled as allegations. A low score does not
guarantee safety, and the tool does not make legal findings.

## Troubleshooting

- **PowerShell blocks activation:** run
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then activate again.
- **TinyFish reports not configured:** check that `.env` has a non-empty
  `TINYFISH_API_KEY` assignment and restart FastAPI.
- **Dashboard cannot reach backend:** start Uvicorn and confirm the URL in
  `SCAMSHIELD_API_URL`.
- **TinyFish authentication/rate errors:** verify the key locally and review
  your TinyFish account allowance. Do not paste the key into issue reports.

Dashboard metrics are queried from the local database rather than seeded or
simulated. TinyFish outages are displayed as errors or partial research states;
they are not replaced with sample results. No public/shareable report links
are created.

## Scope and optional capabilities

The current release does not integrate Gemini or VirusTotal, and does not
implement image OCR, QR decoding, voice transcription, scheduled watchlist
checks, alerts, moderation workflows, or public-facing shareable reports.
Adding a provider key alone does not activate those features. The integrations
page marks these capabilities as unavailable/not implemented rather than
returning simulated results. A dedicated email-password-reset workflow is also
unavailable because no email delivery provider is configured.

The linked YouTube reference was opened, but its player displayed “An error
occurred. Please try again later.” No video appearance was inferred or copied.
The current interface follows the project's written white, cobalt-blue and
acid-lime design direction.
