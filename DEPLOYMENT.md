# Deployment

## Supported operating mode

Use one FastAPI process/worker. The APScheduler watchlist service runs in that
process; multiple workers or replicas can schedule duplicate checks. Scheduled
checks pause during restarts and resume from SQLite settings at startup.

SQLite must be stored on durable storage. Do not use an ephemeral container
filesystem for `scamshield.db`. Back up the database securely and restrict
filesystem access because it contains account and investigation records.
For multi-instance or high-availability deployment, replace SQLite and the
in-process scheduler with shared, production-grade services before scaling.

## Environment

Set these variables in the platform's secret/configuration manager, never in
source control:

| Variable | Required | Purpose |
|---|---|---|
| `TINYFISH_API_KEY` | For live web research | TinyFish Search and Fetch authentication |
| `SCAMSHIELD_DATABASE_PATH` | Recommended | Path on a persistent mounted volume |
| `SCAMSHIELD_API_URL` | For a separately hosted UI | FastAPI base URL used by Streamlit |
| `SCAMSHIELD_ALLOWED_HOSTS` | Required outside local development | Comma-separated exact hostnames accepted by FastAPI; default is local development hosts only |
| `GEMINI_API_KEY` | Optional | Enables consent-based Gemini interpretation |
| `GEMINI_MODEL` | Optional | Gemini model name |
| `TESSERACT_CMD` | Optional | Tesseract executable path when not on `PATH` |

Install operating-system dependencies for Python, Tesseract OCR, and OpenCV
runtime libraries as required by the chosen host. Do not expose `.env` or
credentials through logs, build artifacts, or static files.

## Start locally on Windows

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
.\start.ps1
```

The launcher binds locally to FastAPI `127.0.0.1:8000` and Streamlit
`127.0.0.1:8501`. Use `.\stop.ps1` to stop it. Health check:
`GET /health`.

## Container/platform deployment

Deploy the FastAPI and Streamlit commands as separate services on a platform
that supports persistent volumes and private service networking:

```text
python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT --workers 1
python -m streamlit run frontend/streamlit_app.py --server.address 0.0.0.0 --server.port $PORT --server.headless true
```

Mount the persistent volume at the database location and set
`SCAMSHIELD_DATABASE_PATH` to its absolute path. Configure Streamlit's
`SCAMSHIELD_API_URL` to the private FastAPI service URL. Put TLS and public
ingress at a trusted reverse proxy/platform layer; do not expose FastAPI's
administrative docs publicly unless protected. Configure health checks against
`/health`. Keep FastAPI at one replica while monitoring is in-process.
Set `SCAMSHIELD_ALLOWED_HOSTS` to the exact API hostname(s), separated by
commas; do not use `*` in production. Enforce request-rate limits at the public
proxy too, especially when users share an upstream proxy address. Do not trust
forwarded client-address headers unless the proxy is explicitly configured as
trusted.

These are deployment instructions, not evidence that a cloud deployment has
been performed. Validate HTTPS, backups, restore procedures, allowed origins,
resource sizing, and provider limits in the target environment before launch.

## Operations and known limitations

- Run `python -m unittest discover -s tests -v` before deployment.
- Monitor `.run` logs locally; production logs must not contain credentials or
  uploaded document contents.
- SQLite persistence and backups are the operator's responsibility.
- Email verification, password recovery, MFA, antivirus scanning, and email
  delivery are not configured.
- TinyFish performs remote Fetch and may follow redirects outside the app's
  control. The app validates initial and returned final URLs, but cannot
  pre-approve every provider redirect hop or pin the provider's DNS resolution;
  residual SSRF and DNS-rebinding risks remain. See [SECURITY.md](./SECURITY.md).
- A successful job page fetch does not prove employer authority or offer
  authenticity. Gemini is optional and its interpretations do not change the
  rule-based score.
