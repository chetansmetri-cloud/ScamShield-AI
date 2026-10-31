import ipaddress
import logging
import os
import re
import sqlite3
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from dotenv import dotenv_values, load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field, HttpUrl
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from app.analyzers.rules import analyze_text, classify_score
from app.database import InvestigationStore
from app.investigations import investigate_job, investigate_website
from app.reporting import build_pdf_report

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(ENV_FILE)

logger = logging.getLogger(__name__)

SEARCH_API_URL = "https://api.search.tinyfish.ai"
FETCH_API_URL = "https://api.fetch.tinyfish.ai"
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_FETCH_URLS = 10

app = FastAPI(title="ScamShield AI API", version="0.2.0")
store = InvestigationStore(
    os.getenv(
        "SCAMSHIELD_DATABASE_PATH",
        str(Path(__file__).resolve().parent.parent / "scamshield.db"),
    )
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    _: Request,
    error: RequestValidationError,
) -> JSONResponse:
    logger.debug("Request validation failed (%d field errors)", len(error.errors()))
    return JSONResponse(
        status_code=422,
        content={"detail": "Request input is invalid. Check the provided fields."},
    )


class FetchRequest(BaseModel):
    urls: list[HttpUrl] = Field(min_length=1, max_length=MAX_FETCH_URLS)


class WebsiteInvestigationRequest(BaseModel):
    url: HttpUrl


class JobInvestigationRequest(BaseModel):
    company_name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=10000)
    recruiter_contact: str | None = Field(default=None, max_length=500)
    offer_url: HttpUrl | None = None


class TextInvestigationRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10000)
    research_links: bool = False
    merchant_name: str | None = Field(default=None, max_length=200)


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class ProfileRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class WatchlistRequest(BaseModel):
    value: str = Field(min_length=1, max_length=500)
    item_type: str = Field(pattern="^(domain|email|phone|organization)$")


class SaveReportRequest(BaseModel):
    note: str = Field(default="", max_length=500)


class PublicIntelligenceRequest(BaseModel):
    entity_type: str = Field(pattern="^(email|phone|company|domain)$")
    value: str = Field(min_length=2, max_length=300)
    consent_to_public_search: bool = False


def _api_key() -> str:
    key = str(dotenv_values(ENV_FILE).get("TINYFISH_API_KEY") or "").strip()
    if not key:
        raise HTTPException(
            status_code=503,
            detail="TinyFish is not configured. Set TINYFISH_API_KEY on the server.",
        )
    return key


def validate_external_url(url: HttpUrl | str) -> str:
    value = str(url)
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise HTTPException(status_code=422, detail="Only public HTTP(S) URLs are allowed.")

    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise HTTPException(status_code=422, detail="Local network URLs cannot be fetched.")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            default_port = 80 if parsed.scheme.lower() == "http" else 443
            resolved = socket.getaddrinfo(
                host,
                parsed.port or default_port,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror:
            raise HTTPException(
                status_code=422,
                detail="The URL hostname could not be verified as publicly reachable.",
            ) from None
        if not resolved:
            raise HTTPException(
                status_code=422,
                detail="The URL hostname could not be verified as publicly reachable.",
            )
        for result in resolved:
            resolved_address = ipaddress.ip_address(result[4][0].split("%", 1)[0])
            if not resolved_address.is_global:
                raise HTTPException(
                    status_code=422,
                    detail="URLs resolving to non-public IP addresses cannot be fetched.",
                )
    else:
        if not address.is_global:
            raise HTTPException(
                status_code=422,
                detail="Non-public IP addresses cannot be fetched.",
            )

    return value


async def tinyfish_request(
    method: str,
    endpoint: str,
    *,
    params: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started_at = time.perf_counter()
    operation = "search" if endpoint == SEARCH_API_URL else "fetch"
    try:
        api_key = _api_key()
    except HTTPException as exc:
        logger.warning(
            "provider=TinyFish operation=%s request_status=not_sent response_status=none duration_ms=%d result_count=0 error_status=%d",
            operation,
            round((time.perf_counter() - started_at) * 1000),
            exc.status_code,
        )
        raise
    headers = {"X-API-Key": api_key}
    if json_body is not None:
        headers["Content-Type"] = "application/json"

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.request(
                method,
                endpoint,
                headers=headers,
                params=params,
                json=json_body,
            )
    except httpx.TimeoutException as exc:
        logger.warning(
            "provider=TinyFish operation=%s request_status=timeout response_status=none duration_ms=%d result_count=0",
            operation,
            round((time.perf_counter() - started_at) * 1000),
        )
        raise HTTPException(status_code=504, detail="TinyFish request timed out.") from exc
    except httpx.RequestError as exc:
        logger.warning(
            "provider=TinyFish operation=%s request_status=failed response_status=none duration_ms=%d result_count=0 error_type=%s",
            operation,
            round((time.perf_counter() - started_at) * 1000),
            type(exc).__name__,
        )
        raise HTTPException(status_code=502, detail="Unable to reach TinyFish.") from exc

    if not response.is_success:
        logger.warning(
            "provider=TinyFish operation=%s request_status=failed response_status=%d duration_ms=%d result_count=0",
            operation,
            response.status_code,
            round((time.perf_counter() - started_at) * 1000),
        )
        raise HTTPException(
            status_code=502,
            detail=f"TinyFish request failed with HTTP {response.status_code}.",
        )

    try:
        payload = response.json()
    except ValueError as exc:
        logger.warning(
            "provider=TinyFish operation=%s request_status=invalid_response response_status=%d duration_ms=%d result_count=0",
            operation,
            response.status_code,
            round((time.perf_counter() - started_at) * 1000),
        )
        raise HTTPException(status_code=502, detail="TinyFish returned an invalid response.") from exc

    if not isinstance(payload, dict):
        logger.warning(
            "provider=TinyFish operation=%s request_status=invalid_response response_status=%d duration_ms=%d result_count=0",
            operation,
            response.status_code,
            round((time.perf_counter() - started_at) * 1000),
        )
        raise HTTPException(status_code=502, detail="TinyFish returned an invalid response.")
    results = payload.get("results")
    result_count = len(results) if isinstance(results, list) else 0
    errors = payload.get("errors")
    error_count = len(errors) if isinstance(errors, list) else 0
    logger.info(
        "provider=TinyFish operation=%s request_status=completed response_status=%d duration_ms=%d result_count=%d provider_error_count=%d",
        operation,
        response.status_code,
        round((time.perf_counter() - started_at) * 1000),
        result_count,
        error_count,
    )
    return payload


async def search_web(query: str) -> dict[str, Any]:
    return await tinyfish_request("GET", SEARCH_API_URL, params={"query": query})


async def fetch_pages(urls: list[str]) -> dict[str, Any]:
    safe_urls = [validate_external_url(url) for url in urls]
    return await tinyfish_request(
        "POST",
        FETCH_API_URL,
        json_body={"urls": safe_urls},
    )


def _save_investigation(result: dict[str, Any]) -> dict[str, Any]:
    persisted = dict(result)
    owner_id = persisted.pop("_owner_id", None)
    if result["investigation_type"] in {"message", "payment", "job"}:
        persisted["indicators"] = [
            {
                **indicator,
                "evidence": (
                    "[redacted user-submitted text]"
                    if indicator.get("classification") == "inference"
                    else indicator.get("evidence")
                ),
            }
            for indicator in result.get("indicators", [])
        ]
    store.save(persisted, user_id=owner_id)
    result.pop("_owner_id", None)
    return result


def _admin_emails() -> set[str]:
    return {
        email.strip().lower()
        for email in os.getenv("SCAMSHIELD_ADMIN_EMAILS", "").split(",")
        if email.strip()
    }


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Sign in to access this resource.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.removeprefix("Bearer ").strip()
    user = store.session_user(token) if token else None
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Your session is invalid or expired. Sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_admin(user: dict[str, str] = Depends(get_current_user)) -> dict[str, str]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return user


def _valid_email(value: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value.strip()))


@app.post("/api/auth/register", status_code=201)
async def register(request: RegisterRequest) -> dict[str, Any]:
    if not _valid_email(request.email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    try:
        user = store.register_user(
            request.email,
            request.display_name,
            request.password,
            admin_emails=_admin_emails(),
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="An account with that email already exists.") from exc
    return {"user": user, "access_token": store.create_session(user["id"]), "token_type": "bearer"}


@app.post("/api/auth/login")
async def login(request: LoginRequest) -> dict[str, Any]:
    user = store.authenticate_user(request.email, request.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Email or password is incorrect, or sign-in is temporarily limited.")
    return {"user": user, "access_token": store.create_session(user["id"]), "token_type": "bearer"}


@app.get("/api/auth/me")
async def current_account(user: dict[str, str] = Depends(get_current_user)) -> dict[str, str]:
    return user


@app.post("/api/auth/logout")
async def logout(
    authorization: str = Header(),
    _: dict[str, str] = Depends(get_current_user),
) -> dict[str, str]:
    store.revoke_session(authorization.removeprefix("Bearer ").strip())
    return {"status": "signed_out"}


@app.patch("/api/auth/profile")
async def update_profile(
    request: ProfileRequest,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, str]:
    updated = store.update_profile(user["id"], request.display_name)
    if updated is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    return updated


@app.post("/api/auth/password")
async def change_password(
    request: ChangePasswordRequest,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, str]:
    if not store.change_password(user["id"], request.current_password, request.new_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    return {"status": "password_updated", "message": "Sign in again with your new password."}


@app.delete("/api/auth/account", status_code=204)
async def delete_account(user: dict[str, str] = Depends(get_current_user)) -> Response:
    store.delete_user(user["id"])
    return Response(status_code=204)


@app.delete("/api/history/{investigation_id}", status_code=204)
async def delete_history_item(
    investigation_id: str,
    user: dict[str, str] = Depends(get_current_user),
) -> Response:
    if not store.delete_investigation(user["id"], investigation_id):
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return Response(status_code=204)


@app.get("/api/integrations")
async def integrations(_: dict[str, str] = Depends(get_current_user)) -> dict[str, Any]:
    configured = bool(str(dotenv_values(ENV_FILE).get("TINYFISH_API_KEY") or "").strip())
    return {
        "tinyfish_search": {"configured": configured, "status": "credentials_available" if configured else "not_configured"},
        "tinyfish_fetch": {"configured": configured, "status": "credentials_available" if configured else "not_configured"},
        "gemini": {"configured": bool(os.getenv("GEMINI_API_KEY")), "status": "optional_provider_not_integrated"},
        "virustotal": {"configured": bool(os.getenv("VIRUSTOTAL_API_KEY")), "status": "optional_provider_not_integrated"},
        "ocr": {"configured": False, "status": "not_implemented"},
        "qr_scanning": {"configured": False, "status": "not_implemented"},
        "speech_to_text": {"configured": False, "status": "not_implemented"},
    }


@app.get("/api/admin/analytics")
async def admin_analytics(_: dict[str, str] = Depends(require_admin)) -> dict[str, int]:
    return store.admin_analytics()


@app.get("/api/saved")
async def saved_reports(user: dict[str, str] = Depends(get_current_user)) -> list[dict[str, Any]]:
    return store.saved_investigations(user["id"])


@app.put("/api/saved/{investigation_id}")
async def save_report(
    investigation_id: str,
    request: SaveReportRequest,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, str]:
    try:
        store.save_investigation(user["id"], investigation_id, request.note)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Investigation not found.") from exc
    return {"status": "saved"}


@app.delete("/api/saved/{investigation_id}", status_code=204)
async def remove_saved_report(
    investigation_id: str,
    user: dict[str, str] = Depends(get_current_user),
) -> Response:
    store.unsave_investigation(user["id"], investigation_id)
    return Response(status_code=204)


@app.get("/api/watchlist")
async def watchlist(user: dict[str, str] = Depends(get_current_user)) -> list[dict[str, str]]:
    return store.list_watchlist(user["id"])


@app.post("/api/watchlist", status_code=201)
async def add_watchlist(
    request: WatchlistRequest,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, str]:
    value = request.value.strip()
    if request.item_type == "domain":
        if "://" in value or "/" in value or "@" in value:
            raise HTTPException(status_code=422, detail="Enter a domain only, without a scheme, path, or credentials.")
        if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value):
            raise HTTPException(status_code=422, detail="Enter a valid public domain name.")
    elif request.item_type == "email" and not _valid_email(value):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    elif request.item_type == "phone" and not re.fullmatch(r"\+?[0-9 ()-]{7,30}", value):
        raise HTTPException(status_code=422, detail="Enter a valid phone number.")
    try:
        return store.add_watchlist_item(user["id"], value, request.item_type)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="This watchlist entry already exists.") from exc


@app.delete("/api/watchlist/{item_id}", status_code=204)
async def remove_watchlist_item(
    item_id: str,
    user: dict[str, str] = Depends(get_current_user),
) -> Response:
    store.remove_watchlist_item(user["id"], item_id)
    return Response(status_code=204)


@app.get("/health")
async def health() -> dict[str, str]:
    store.analytics()
    return {"status": "ok", "database": "connected"}


@app.get("/api/analytics")
async def analytics(user: dict[str, str] = Depends(get_current_user)) -> dict[str, Any]:
    return store.analytics(user_id=user["id"])


@app.get("/api/search")
async def search(
    query: str = Query(min_length=1, max_length=500),
    _: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    normalized_query = query.strip()
    if not normalized_query:
        raise HTTPException(status_code=422, detail="Query cannot be blank.")
    return await search_web(normalized_query)


@app.post("/api/fetch")
async def fetch(
    request: FetchRequest,
    _: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    return await fetch_pages([str(url) for url in request.urls])


@app.post("/api/investigations/website")
async def website_investigation(
    request: WebsiteInvestigationRequest,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    result = await investigate_website(str(request.url), search_web, fetch_pages)
    result["_owner_id"] = user["id"]
    return _save_investigation(result)


@app.post("/api/investigations/intelligence")
async def public_intelligence_investigation(
    request: PublicIntelligenceRequest,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    value = request.value.strip()
    if not value:
        raise HTTPException(status_code=422, detail="Enter an entity to investigate.")
    if request.entity_type in {"email", "phone"} and not request.consent_to_public_search:
        raise HTTPException(
            status_code=400,
            detail="Confirm authorization before submitting email or phone data to public search.",
        )
    if request.entity_type == "email" and not _valid_email(value):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    if request.entity_type == "phone" and not re.fullmatch(r"\+?[0-9 ()-]{7,30}", value):
        raise HTTPException(status_code=422, detail="Enter a valid phone number.")
    if request.entity_type == "domain":
        if "://" in value:
            value = urlsplit(value).hostname or ""
        if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value):
            raise HTTPException(status_code=422, detail="Enter a domain name without a path.")
    query = {
        "email": f'"{value}" email contact',
        "phone": f'"{value}" phone number',
        "company": f'"{value}" company official website contact',
        "domain": f'"{value}" domain reputation',
    }[request.entity_type]
    search_payload = await search_web(query)
    raw_results = search_payload.get("results", [])
    results = raw_results if isinstance(raw_results, list) else []
    evidence = []
    for item in results:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str) or urlsplit(url).scheme.lower() not in {"http", "https"}:
            continue
        evidence.append(
            {
                "title": str(item.get("title", ""))[:300],
                "url": url,
                "excerpt": str(item.get("snippet", ""))[:1200],
                "source_type": "search_result",
            }
        )
    report = {
        "id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "investigation_type": request.entity_type,
        "target": f"{request.entity_type.title()} intelligence: {value}",
        "risk_score": 0,
        "risk_category": "Evidence gathered; not scored",
        "confidence": "limited",
        "information_completeness": "public search results only",
        "analysis_method": "evidence_only",
        "live_research": "completed" if evidence else "partial",
        "scoring_explanation": (
            "This investigation only gathers public search evidence. No risk score or "
            "identity/reputation verification is performed."
        ),
        "indicators": [],
        "evidence": evidence,
        "sources": [entry["url"] for entry in evidence],
        "recommended_next_steps": [
            "Review original sources and verify important claims independently."
        ],
        "missing_information": ["No identity, ownership, or authoritative reputation verification was performed."],
        "disclaimer": "Public search results may be incomplete or refer to unrelated entities. This is not a finding of fraud.",
        "_owner_id": user["id"],
    }
    return _save_investigation(report)


@app.post("/api/investigations/job")
async def job_investigation(
    request: JobInvestigationRequest,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    offer_url = (
        validate_external_url(str(request.offer_url))
        if request.offer_url
        else None
    )
    result = await investigate_job(
        company_name=request.company_name,
        description=request.description,
        recruiter_contact=request.recruiter_contact,
        offer_url=offer_url,
        search=search_web,
        fetch=fetch_pages,
    )
    result["_owner_id"] = user["id"]
    return _save_investigation(result)


@app.post("/api/analyze/message")
async def message_analysis(
    request: TextInvestigationRequest,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    analysis = analyze_text(request.text, kind="message")
    evidence: list[dict[str, Any]] = []
    sources: list[str] = []
    live_research = "not_requested"
    if request.research_links:
        extracted = re.findall(r"https?://[^\s<>()]+", request.text, flags=re.IGNORECASE)
        urls = list(dict.fromkeys(url.rstrip(".,;:!?") for url in extracted))[:3]
        if urls:
            hosts = list(
                dict.fromkeys(urlsplit(validate_external_url(url)).hostname for url in urls)
            )
            host_query = " OR ".join(host for host in hosts if host)
            search_payload = await search_web(
                f'"{host_query}" scam complaint warning'
            )
            search_results = search_payload.get("results", [])
            if isinstance(search_results, list):
                for item in search_results:
                    if isinstance(item, dict) and isinstance(item.get("url"), str):
                        evidence.append(
                            {
                                "title": str(item.get("title", "")),
                                "url": item["url"],
                                "excerpt": str(item.get("snippet", "")),
                                "source_type": "search_result",
                            }
                        )
            pages_payload = await fetch_pages(urls)
            pages = pages_payload.get("results", [])
            pages = pages if isinstance(pages, list) else []
            if pages:
                page_text = "\n".join(
                    str(page.get("text", ""))
                    for page in pages
                    if isinstance(page, dict)
                )
                page_analysis = analyze_text(page_text, kind="message_link")
                analysis["indicators"].extend(page_analysis["indicators"])
            evidence.extend(
                {
                    "title": page.get("title", ""),
                    "url": page.get("final_url") or page.get("url"),
                    "excerpt": str(page.get("text", ""))[:1200],
                    "source_type": "fetched_page",
                }
                for page in pages
                if isinstance(page, dict)
            )
            sources = list(
                dict.fromkeys(
                    str(item.get("url")) for item in evidence if item.get("url")
                )
            )
            live_research = "completed" if search_results or pages else "partial"
        else:
            live_research = "not_applicable"
    score = min(
        100,
        sum(item["score_contribution"] for item in analysis["indicators"]),
    )
    analysis["risk_score"] = score
    analysis["risk_category"] = classify_score(score)
    total = sum(item["score_contribution"] for item in analysis["indicators"])
    analysis["scoring_explanation"] = (
        f"Score is the sum of matched rule contributions ({total}), capped at 100. "
        "No points are added for missing information."
    )
    result = {
        **analysis,
        "risk_score": score,
        "risk_category": classify_score(score),
        "id": str(uuid.uuid4()),
        "investigation_type": "message",
        "target": "Suspicious message",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evidence": evidence,
        "sources": sources,
        "live_research": live_research,
    }
    result["_owner_id"] = user["id"]
    return _save_investigation(result)


@app.post("/api/analyze/payment")
async def payment_analysis(
    request: TextInvestigationRequest,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    analysis = analyze_text(request.text, kind="payment")
    evidence: list[dict[str, Any]] = []
    sources: list[str] = []
    live_research = "not_requested"
    if request.merchant_name and request.merchant_name.strip():
        search_payload = await search_web(
            f'"{request.merchant_name.strip()}" official company complaints scam'
        )
        results = search_payload.get("results", [])
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict) or not isinstance(item.get("url"), str):
                    continue
                url = item["url"]
                title = str(item.get("title", ""))
                snippet = str(item.get("snippet", ""))
                evidence.append(
                    {
                        "title": title,
                        "url": url,
                        "excerpt": snippet,
                        "source_type": "search_result",
                    }
                )
                sources.append(url)
                if re.search(r"\b(scam|fraud|complaint|warning)\b", f"{title} {snippet}", re.I):
                    analysis["indicators"].append(
                        {
                            "name": "Public payment-related warning or allegation",
                            "explanation": "A search result contains warning-related language; it does not establish fraud.",
                            "evidence": f"{title} {snippet}"[:500],
                            "source": url,
                            "score_contribution": 8,
                            "classification": "public_allegation",
                            "severity": "low",
                        }
                    )
        score = min(
            100,
            sum(item["score_contribution"] for item in analysis["indicators"]),
        )
        analysis["risk_score"] = score
        analysis["risk_category"] = classify_score(score)
        total = sum(
            item["score_contribution"] for item in analysis["indicators"]
        )
        analysis["scoring_explanation"] = (
            f"Score is the sum of matched rule and supported allegation contributions ({total}), "
            "capped at 100. No points are added for missing information."
        )
        live_research = "completed" if evidence else "partial"
    result = {
        **analysis,
        "id": str(uuid.uuid4()),
        "investigation_type": "payment",
        "target": "Payment request",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evidence": evidence,
        "sources": sources,
        "live_research": live_research,
    }
    result["_owner_id"] = user["id"]
    return _save_investigation(result)


@app.get("/api/history")
async def history(
    limit: int = Query(default=50, ge=1, le=200),
    investigation_type: str | None = Query(default=None, max_length=30),
    risk_category: str | None = Query(default=None, max_length=50),
    search_text: str | None = Query(default=None, max_length=200),
    user: dict[str, str] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return store.list_recent(
        limit,
        investigation_type=investigation_type,
        risk_category=risk_category,
        search_text=search_text,
        user_id=user["id"],
    )


@app.get("/api/history/{investigation_id}/pdf")
async def history_pdf(
    investigation_id: str,
    user: dict[str, str] = Depends(get_current_user),
) -> Response:
    report = store.get(investigation_id, user_id=user["id"])
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    content = build_pdf_report(report)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="scamshield-{investigation_id}.pdf"'
        },
    )


@app.get("/api/history/{investigation_id}")
async def history_item(
    investigation_id: str,
    user: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    item = store.get(investigation_id, user_id=user["id"])
    if item is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return item
