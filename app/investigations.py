import asyncio
import re
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qs, unquote, urlsplit

from app.analyzers.rules import analyze_text
from app.evidence import (
    canonicalize_url,
    deduplicate_urls,
    deduplicate_url_items,
    domain_evidence_is_relevant,
    domain_matches_url,
)

Search = Callable[[str], Awaitable[dict[str, Any]]]
Fetch = Callable[[list[str]], Awaitable[dict[str, Any]]]
FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "yandex.com",
    "mail.com",
}
COMPANY_NAME_SUFFIXES = {
    "co",
    "company",
    "corp",
    "corporation",
    "inc",
    "incorporated",
    "llc",
    "ltd",
    "limited",
    "plc",
    "the",
}
ROLE_STOPWORDS = {
    "and",
    "for",
    "from",
    "with",
    "the",
    "at",
    "in",
    "on",
    "of",
}
ROLE_SYNONYMS = {
    "internship": "intern",
    "interns": "intern",
    "engineering": "engineer",
    "development": "developer",
    "science": "scientist",
    "analysis": "analyst",
}
RECRUITMENT_PLATFORMS = {
    "boards.greenhouse.io": "Greenhouse",
    "job-boards.greenhouse.io": "Greenhouse",
    "greenhouse.io": "Greenhouse",
    "jobs.lever.co": "Lever",
    "lever.co": "Lever",
    "jobs.ashbyhq.com": "Ashby",
    "ashbyhq.com": "Ashby",
    "myworkdayjobs.com": "Workday",
    "jobs.smartrecruiters.com": "SmartRecruiters",
    "smartrecruiters.com": "SmartRecruiters",
    "icims.com": "iCIMS",
    "jobvite.com": "Jobvite",
    "indeed.com": "Indeed",
    "linkedin.com": "LinkedIn",
    "ziprecruiter.com": "ZipRecruiter",
    "wellfound.com": "Wellfound",
}


def _first_string(
    mappings: tuple[Mapping[str, Any], ...],
    names: tuple[str, ...],
    *,
    limit: int = 8000,
) -> str | None:
    for mapping in mappings:
        for name in names:
            value = mapping.get(name)
            if isinstance(value, str) and value.strip():
                return value.strip()[:limit]
    return None


def _labeled_listing_identifier(value: str) -> str | None:
    match = re.search(
        r"\b(?:job|requisition|req|position|posting)\s*"
        r"(?:id|number|no\.?|#)?\s*[:#=-]\s*"
        r"([a-z0-9][a-z0-9_-]{2,})",
        value,
        re.IGNORECASE,
    )
    return match.group(1).casefold() if match else None


def _labeled_page_field(
    text: str,
    labels: tuple[str, ...],
    *,
    limit: int,
) -> str | None:
    label_pattern = "|".join(re.escape(label) for label in labels)
    match = re.search(
        rf"(?im)^\s*(?:{label_pattern})\s*[:=-]\s*([^\r\n]{{2,{limit}}})",
        text,
    )
    return match.group(1).strip() if match else None


def _search_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_results = payload.get("results", [])
    if not isinstance(raw_results, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str):
            continue
        normalized.append(
            {
                "title": str(item.get("title", "")),
                "snippet": str(item.get("snippet", "")),
                "url": url,
                "site_name": str(item.get("site_name", "")),
            }
        )
    return [
        {key: value for key, value in item.items() if key != "canonical_url"}
        for item in deduplicate_url_items(normalized)
    ]


def _fetch_results(
    payload: dict[str, Any],
    requested_urls: list[str] | None = None,
) -> list[dict[str, Any]]:
    results = payload.get("results", [])
    if not isinstance(results, list):
        return []
    pages: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        raw_url = result.get("url")
        input_url = result.get("requested_url") or result.get("input_url")
        if not isinstance(input_url, str):
            input_url = (
                requested_urls[index]
                if requested_urls and index < len(requested_urls)
                else raw_url
            )
        final_url = (
            result.get("final_url")
            or result.get("redirected_url")
            or raw_url
        )
        structured_values = tuple(
            value
            for value in (
                result,
                result.get("job"),
                result.get("structured_data"),
                result.get("metadata"),
            )
            if isinstance(value, Mapping)
        )
        page = {
            "url": final_url,
            "requested_url": input_url,
            "final_url": final_url,
            "title": result.get("title", ""),
            "text": result.get("text", result.get("content", "")),
        }
        for key, aliases, limit in (
            ("company", ("company", "company_name", "employer"), 300),
            ("job_title", ("job_title", "position_title", "role_title"), 500),
            ("job_id", ("job_id", "requisition_id", "req_id", "position_id"), 200),
            ("description", ("job_description", "description"), 8000),
            (
                "application_details",
                ("application_details", "application_instructions", "how_to_apply"),
                2000,
            ),
            ("application_url", ("application_url", "apply_url"), 1000),
        ):
            value = _first_string(structured_values, aliases, limit=limit)
            if value:
                page[key] = value
        pages.append(page)
    return [
        {key: value for key, value in page.items() if key != "canonical_url"}
        for page in deduplicate_url_items(pages)
    ]


def _normalized_text(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _mentions_company(value: str, company_name: str) -> bool:
    value_tokens = set(_normalized_text(value).split())
    company_tokens = {
        token
        for token in _normalized_text(company_name).split()
        if token not in COMPANY_NAME_SUFFIXES
    }
    return bool(company_tokens and company_tokens.issubset(value_tokens))


def _listing_identifier(value: str) -> str | None:
    parsed = urlsplit(value)
    query = parse_qs(parsed.query)
    for key, values in query.items():
        if re.search(r"(?:job|req|requisition|position).*id|id.*(?:job|req)", key, re.I):
            if values:
                return unquote(values[0]).casefold()
    candidates = [unquote(part) for part in parsed.path.split("/") if part]
    for candidate in candidates:
        match = re.search(
            r"(?<![a-z0-9])(?:req|job|jr)[-_]?[a-z0-9]{4,}(?![a-z0-9])|(?<!\d)\d{5,}(?!\d)",
            candidate,
            re.IGNORECASE,
        )
        if match:
            return match.group(0).casefold()
    return None


def _recruitment_platform(host: str) -> str | None:
    normalized_host = host.casefold().rstrip(".").removeprefix("www.")
    for domain, platform in RECRUITMENT_PLATFORMS.items():
        if normalized_host == domain or normalized_host.endswith(f".{domain}"):
            return platform
    return None


def _brand_is_only_in_unverified_subdomain(company_name: str, host: str) -> bool:
    labels = [label for label in host.casefold().rstrip(".").split(".") if label]
    if len(labels) < 3 or _recruitment_platform(host):
        return False
    company_tokens = {
        token
        for token in _normalized_text(company_name).split()
        if token not in COMPANY_NAME_SUFFIXES
    }
    distinctive_tokens = {token for token in company_tokens if len(token) >= 4}
    brand_tokens = distinctive_tokens or company_tokens
    host_tokens = {
        token for label in labels for token in re.findall(r"[a-z0-9]+", label)
    }
    two_part_suffixes = {
        "co.uk",
        "com.au",
        "co.in",
        "com.sg",
        "com.br",
        "co.jp",
        "com.cn",
        "co.nz",
        "com.mx",
    }
    suffix = ".".join(labels[-2:])
    registrable_labels = labels[-3:] if suffix in two_part_suffixes else labels[-2:]
    registrable_tokens = {
        token
        for label in registrable_labels
        for token in re.findall(r"[a-z0-9]+", label)
    }
    return bool(brand_tokens & host_tokens and not brand_tokens & registrable_tokens)


def _page_is_relevant_to_offer(
    offer_url: str,
    page: dict[str, Any],
) -> bool:
    if not domain_matches_url(offer_url, str(page.get("final_url") or "")):
        final_host = urlsplit(str(page.get("final_url") or "")).hostname or ""
        if not _recruitment_platform(final_host):
            return False
    return canonicalize_url(str(page.get("requested_url") or "")) == canonicalize_url(
        offer_url
    )


def _role_matches(job_title: str, offer_description: str, company_name: str) -> bool:
    company_tokens = set(_normalized_text(company_name).split())
    ignored_tokens = ROLE_STOPWORDS | {
        "career",
        "careers",
        "job",
        "jobs",
        "opening",
    }

    def role_tokens(value: str) -> set[str]:
        return {
            ROLE_SYNONYMS.get(token, token)
            for token in re.findall(r"[a-z0-9]+", value.casefold())
            if len(token) > 2 and token not in ignored_tokens
        }

    title_tokens = role_tokens(job_title) - company_tokens
    description_tokens = role_tokens(offer_description)
    return bool(title_tokens and len(title_tokens & description_tokens) / len(title_tokens) >= 0.6)


def _job_search_result_is_relevant(
    result: dict[str, Any],
    *,
    company_name: str,
    offer_url: str | None,
) -> bool:
    if _mentions_company(
        f"{result.get('title', '')}\n{result.get('snippet', '')}",
        company_name,
    ):
        return True
    if not offer_url:
        return False
    if canonicalize_url(str(result.get("url") or "")) == canonicalize_url(offer_url):
        return True
    submitted_id = _listing_identifier(offer_url)
    result_id = _listing_identifier(str(result.get("url") or "")) or (
        _labeled_listing_identifier(
            f"{result.get('title', '')} {result.get('snippet', '')}"
        )
    )
    return bool(submitted_id and result_id == submitted_id)


def _recruiter_details(
    recruiter_contact: str | None,
    offer_url: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    email_match = re.search(r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})", recruiter_contact or "")
    if not email_match:
        return (
            {
                "status": "not_provided" if not recruiter_contact else "not_independently_verified",
                "email_domain": None,
                "explanation": "Recruiter identity and email ownership were not independently verified.",
            },
            [],
        )

    email_domain = email_match.group(1).casefold().rstrip(".")
    if email_domain in FREE_EMAIL_DOMAINS:
        return (
            {
                "status": "free_email_provider_warning",
                "email_domain": email_domain,
                "explanation": "The contact uses a public email provider; this alone does not establish fraud or recruiter identity.",
            },
            [
                {
                    "name": "Recruiter uses a public email provider",
                    "explanation": "A free email provider is not independently tied to the employer. Verify the recruiter through contact details found on the official careers site.",
                    "evidence": f"Email domain: {email_domain}",
                    "score_contribution": 6,
                    "classification": "inference",
                    "severity": "low",
                }
            ],
        )

    offer_host = (urlsplit(offer_url).hostname or "").casefold().removeprefix("www.") if offer_url else ""
    email_domain = email_domain.removeprefix("www.")
    differs_from_offer_host = bool(
        offer_host
        and email_domain != offer_host
        and not email_domain.endswith("." + offer_host)
        and not offer_host.endswith("." + email_domain)
    )
    warning = []
    status = "not_independently_verified"
    explanation = "An email domain alone does not verify recruiter identity or employer authorization."
    if differs_from_offer_host:
        status = "domain_differs_from_offer_site_unverified"
        explanation = "The recruiter email domain differs from the submitted offer site's host; no ownership or authorization link was independently established."
        warning.append(
            {
                "name": "Recruiter email domain differs from offer site",
                "explanation": "The difference warrants independent verification but does not prove impersonation.",
                "evidence": f"Email domain: {email_domain}; offer host: {offer_host}",
                "score_contribution": 0,
                "classification": "inference",
                "severity": "low",
            }
        )
    return (
        {
            "status": status,
            "email_domain": email_domain,
            "explanation": explanation,
        },
        warning,
    )


def _job_verification(
    *,
    company_name: str,
    description: str,
    offer_url: str | None,
    pages: list[dict[str, Any]],
    fetch_errors: list[Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not offer_url:
        return (
            {
                "submitted_company": company_name,
                "submitted_offer_url": None,
                "final_fetched_url": None,
                "page_title": None,
                "page_company": None,
                "job_title": None,
                "job_id": None,
                "submitted_job_id": _labeled_listing_identifier(description),
                "job_id_match": None,
                "job_description": None,
                "available_description": None,
                "application_details": None,
                "application_url": None,
                "company_status": "not_independently_verified",
                "offer_domain_status": "not_applicable_no_offer_url",
                "hosting_status": "not_checked",
                "recruitment_platform": None,
                "official_careers_domain_status": "not_verified",
                "exact_listing_status": "not_checked_no_offer_url",
                "explanation": "No offer URL was provided; company-level search results cannot verify a particular listing.",
            },
            [],
        )

    canonical_offer_url = canonicalize_url(offer_url)
    submitted_job_ids = [
        item
        for item in (
            _listing_identifier(offer_url),
            _labeled_listing_identifier(description),
        )
        if item
    ]
    submitted_job_id = submitted_job_ids[0] if submitted_job_ids else None
    submitted_job_ids_match_each_other = len(set(submitted_job_ids)) <= 1
    exact_requested_pages = [
        page
        for page in pages
        if canonical_offer_url
        and canonicalize_url(str(page.get("requested_url") or ""))
        == canonical_offer_url
    ]
    page = exact_requested_pages[0] if exact_requested_pages else None
    if page is None:
        status = (
            "fetch_failed"
            if fetch_errors
            else "page_unavailable_or_access_limited"
            if not pages
            else "requested_url_not_confirmed"
        )
        return (
            {
                "submitted_company": company_name,
                "submitted_offer_url": offer_url,
                "final_fetched_url": pages[0].get("final_url") if pages else None,
                "page_title": None,
                "page_company": None,
                "job_title": None,
                "job_id": None,
                "submitted_job_id": submitted_job_id,
                "job_id_match": None,
                "job_description": None,
                "available_description": None,
                "application_details": None,
                "application_url": None,
                "company_status": "not_independently_verified",
                "offer_domain_status": "not_verified",
                "hosting_status": "not_verified",
                "recruitment_platform": None,
                "official_careers_domain_status": "not_verified",
                "exact_listing_status": status,
                "explanation": "TinyFish did not return a page tied to the exact submitted offer URL; company search results are not listing verification.",
            },
            [],
        )

    final_url = str(page.get("final_url") or "")
    final_host = urlsplit(final_url).hostname or ""
    recruitment_platform = _recruitment_platform(final_host)
    redirected_to_other_domain = bool(
        final_url and not domain_matches_url(offer_url, final_url)
    )
    page_can_be_checked = bool(
        final_url
        and (
            domain_matches_url(offer_url, final_url)
            or recruitment_platform is not None
        )
    )
    if not page_can_be_checked:
        return (
            {
                "submitted_company": company_name,
                "submitted_offer_url": offer_url,
                "final_fetched_url": final_url or None,
                "page_title": str(page.get("title") or "") or None,
                "page_company": None,
                "job_title": str(page.get("title") or "") or None,
                "job_id": _listing_identifier(final_url) if final_url else None,
                "submitted_job_id": submitted_job_id,
                "job_id_match": None,
                "job_description": str(page.get("description") or "")[:8000] or None,
                "available_description": str(page.get("text") or "")[:1200] or None,
                "application_details": None,
                "application_url": None,
                "company_status": "not_independently_verified",
                "offer_domain_status": "not_verified",
                "hosting_status": "unrecognized_redirect_domain",
                "recruitment_platform": None,
                "official_careers_domain_status": "not_verified",
                "exact_listing_status": "redirected_to_different_domain",
                "explanation": "The remote fetch ended on a different domain. Its page content was not used to verify the submitted listing.",
            },
            [],
        )

    title = str(page.get("title") or "")
    page_text = str(page.get("text") or "")
    page_description = str(page.get("description") or "")
    combined_text = f"{title}\n{page_text}\n{page_description}"
    page_company = str(page.get("company") or "").strip() or None
    if page_company is None:
        page_company = _labeled_page_field(
            page_text,
            ("company", "employer", "organization"),
            limit=200,
        )
    company_match = (
        _mentions_company(page_company, company_name)
        if page_company
        else _mentions_company(combined_text, company_name)
    )
    offer_host = (urlsplit(offer_url).hostname or "").casefold()
    company_host_tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", offer_host)
        if token not in COMPANY_NAME_SUFFIXES
    }
    company_tokens = {
        token
        for token in _normalized_text(company_name).split()
        if token not in COMPANY_NAME_SUFFIXES
    }
    offer_domain_status = (
        "company_name_appears_in_host_but_domain_unverified"
        if company_host_tokens & company_tokens
        else "recognized_third_party_recruitment_platform"
        if recruitment_platform
        else "host_does_not_identify_company_domain_unverified"
    )
    company_status = "company_name_found_on_page" if company_match else "company_name_not_found_on_page"
    page_title = title or None
    page_job_title = str(page.get("job_title") or "").strip()
    if not page_job_title:
        page_job_title = _labeled_page_field(
            page_text,
            ("job title", "position", "role"),
            limit=250,
        )
    page_job_title = page_job_title or title
    page_job_title = page_job_title.strip()
    if not page_description:
        page_description = _labeled_page_field(
            page_text,
            ("job description", "position description", "description"),
            limit=8000,
        ) or ""
    job_id = (
        str(page.get("job_id") or "").strip().casefold()
        or _listing_identifier(final_url)
        or _labeled_listing_identifier(page_text)
    )
    application_details = str(page.get("application_details") or "").strip()
    if not application_details:
        application_details = (
            _labeled_page_field(
                page_text,
                ("how to apply", "application instructions", "application process"),
                limit=1000,
            )
            or ""
        )
    application_url = str(page.get("application_url") or "").strip()
    if not application_url and application_details:
        application_url_match = re.search(
            r"https?://[^\s<>\"']+",
            application_details,
            re.IGNORECASE,
        )
        application_url = application_url_match.group(0) if application_url_match else ""
    job_id_match = (
        bool(job_id and all(job_id == item for item in submitted_job_ids))
        and submitted_job_ids_match_each_other
        if submitted_job_ids
        else None
    )
    role_match = (
        _role_matches(page_job_title, description, company_name)
        if page_job_title
        else False
    )

    mismatches = []
    if not company_match:
        mismatches.append("The fetched page did not identify the submitted company name.")
    if page_job_title and not role_match:
        mismatches.append("The fetched job title did not sufficiently match the submitted offer details.")
    if submitted_job_id and job_id_match is False:
        mismatches.append("The fetched page job identifier did not match the identifier supplied with the offer.")

    details_match = bool(company_match and role_match and job_id_match is not False)
    if details_match:
        listing_status = "page_details_match_not_officially_verified"
    elif mismatches:
        listing_status = "page_details_mismatch"
    else:
        listing_status = "page_fetched_details_insufficient"

    positives = []
    if details_match:
        hosting_note = (
            f"The listing was returned on the recognized {recruitment_platform} recruitment platform."
            if recruitment_platform
            else "The hosting domain has not been independently authenticated."
        )
        positives.append(
            {
                "name": "Fetched page details are consistent",
                "explanation": "The page returned for the submitted URL contains details consistent with the submitted company and role. "
                f"{hosting_note} Listing authenticity and the employer's authority remain unverified, so this signal does not lower the score.",
                "evidence": f"Page title: {title}; job title: {page_job_title or 'not available'}",
                "classification": "verified_fact",
                "score_adjustment": 0,
            }
        )
    verification = {
        "submitted_company": company_name,
        "submitted_offer_url": offer_url,
        "final_fetched_url": final_url or None,
        "page_title": page_title,
        "page_company": page_company or (company_name if company_match else None),
        "job_title": page_job_title or None,
        "job_id": job_id,
        "submitted_job_id": submitted_job_id,
        "job_description": page_description[:8000] or None,
        "available_description": (page_description or page_text)[:1200] or None,
        "application_details": application_details[:2000] or None,
        "application_url": application_url[:1000] or None,
        "company_status": company_status,
        "offer_domain_status": offer_domain_status,
        "hosting_status": (
            "recognized_third_party_recruitment_platform"
            if recruitment_platform
            else "employer_domain_unverified"
        ),
        "recruitment_platform": recruitment_platform,
        "redirect_detected": redirected_to_other_domain,
        "official_careers_domain_status": "not_independently_verified",
        "exact_listing_status": listing_status,
        "company_name_match": company_match,
        "role_details_match": role_match,
        "job_id_match": job_id_match,
        "explanation": (
            " ".join(mismatches)
            if mismatches
            else "Fetched page details match the submitted company and offer text; the company domain and listing authenticity remain unverified."
        ),
    }
    return verification, positives


def _website_indicators(text: str) -> list[dict[str, Any]]:
    analysis = analyze_text(text, kind="website")
    for indicator in analysis["indicators"]:
        indicator["evidence"] = f"Page text: {indicator['evidence']}"
    return analysis["indicators"]


def _report(
    *,
    investigation_type: str,
    target: str,
    indicators: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    sources: list[str],
    live_research: str,
    missing: list[str],
    next_steps: list[str],
    completeness: str,
    positive_indicators: list[dict[str, Any]] | None = None,
    job_verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    contribution_total = sum(item["score_contribution"] for item in indicators)
    adjustment = sum(
        int(item.get("score_adjustment", 0))
        for item in (positive_indicators or [])
    )
    score = max(0, min(100, contribution_total - adjustment))
    from app.analyzers.rules import classify_score, DISCLAIMER

    now = datetime.now(timezone.utc).isoformat()
    report = {
        "id": str(uuid.uuid4()),
        "created_at": now,
        "investigation_type": investigation_type,
        "target": target,
        "analysis_method": "rule_based",
        "risk_score": score,
        "risk_category": classify_score(score),
        "confidence": "limited" if live_research != "completed" else "moderate",
        "information_completeness": completeness,
        "scoring_explanation": (
            f"Risk indicators contribute {contribution_total} points; supported consistency signals adjust the score by -{adjustment} points. "
            f"The result is bounded to 0–100 ({score}). Missing information alone contributes no risk points."
        ),
        "indicators": indicators,
        "positive_indicators": positive_indicators or [],
        "evidence": evidence,
        "sources": sources,
        "live_research": live_research,
        "missing_information": missing,
        "recommended_next_steps": next_steps,
        "disclaimer": DISCLAIMER,
    }
    if job_verification is not None:
        report["job_verification"] = job_verification
    return report


async def investigate_website(url: str, search: Search, fetch: Fetch) -> dict[str, Any]:
    hostname = urlsplit(url).hostname or url
    search_payload = await search(f'"{hostname}" scam OR complaints OR reviews')
    search_items = _search_results(search_payload)
    fetch_payload = await fetch([url])
    pages = _fetch_results(fetch_payload)
    failed_fetches = fetch_payload.get("errors", [])
    relevant_search_items = [
        result
        for result in search_items
        if domain_evidence_is_relevant(
            url,
            source_url=result["url"],
            title=result["title"],
            snippet=result["snippet"],
        )
    ]
    for result in search_items:
        result["relevance"] = (
            "target_related" if result in relevant_search_items else "unrelated_not_scored"
        )
    relevant_pages = [
        page for page in pages if domain_matches_url(url, str(page.get("url") or ""))
    ]
    for page in pages:
        page["relevance"] = (
            "target_related"
            if page in relevant_pages
            else "redirected_to_other_domain_not_scored"
        )
        page["redirect_detected"] = not domain_matches_url(
            url,
            str(page.get("url") or ""),
        )
    page_text = "\n".join(str(page.get("text", "")) for page in relevant_pages)
    indicators = _website_indicators(page_text)

    for result in relevant_search_items:
        text = f"{result['title']} {result['snippet']}"
        if re.search(r"\b(scam|fraud|complaint|warning)\b", text, re.IGNORECASE):
            indicators.append(
                {
                    "name": "Public warning or allegation in search result",
                    "explanation": "A search result contains warning-related language; this is an allegation, not proof.",
                    "evidence": text[:500],
                    "source": result["url"],
                    "score_contribution": 8,
                    "classification": "public_allegation",
                    "severity": "low",
                }
            )

    sources = [result["url"] for result in search_items]
    sources.extend(str(page["url"]) for page in pages if page.get("url"))
    evidence = [
        {
            "title": result["title"],
            "url": result["url"],
            "excerpt": result["snippet"],
            "source_type": "search_result",
            "relevance": result.get("relevance"),
        }
        for result in search_items
    ]
    evidence.extend(
        {
            "title": page.get("title", ""),
            "url": page.get("url"),
            "excerpt": str(page.get("text", ""))[:1200],
            "source_type": "fetched_page",
            "relevance": page.get("relevance"),
            "redirect_detected": page.get("redirect_detected", False),
        }
        for page in pages
    )
    evidence = deduplicate_url_items(evidence)
    evidence = [
        {key: value for key, value in item.items() if key != "canonical_url"}
        for item in evidence
    ]
    fetch_ok = bool(relevant_pages)
    search_ok = bool(relevant_search_items)
    live_status = "completed" if fetch_ok and search_ok else "partial"
    missing = []
    if not search_ok:
        missing.append("Search returned no target-related public results.")
    if not fetch_ok:
        missing.append(
            "Target-domain page content was not available from TinyFish Fetch."
        )
    if pages and not relevant_pages:
        missing.append(
            "Fetch returned a different final domain; its page content was excluded from scoring."
        )
    if failed_fetches:
        missing.append("TinyFish reported one or more per-URL fetch errors.")
    if not indicators:
        missing.append("No configured rule-based warning patterns matched the fetched text.")

    return _report(
        investigation_type="website",
        target=url,
        indicators=indicators,
        evidence=evidence,
        sources=deduplicate_urls(sources),
        live_research=live_status,
        missing=missing,
        next_steps=[
            "Verify the organization and contact details independently.",
            "Review the cited pages and their publication dates before drawing conclusions.",
        ],
        completeness="public search and fetched page" if fetch_ok and search_ok else "partial",
    )


async def investigate_job(
    *,
    company_name: str,
    description: str,
    recruiter_contact: str | None,
    offer_url: str | None,
    search: Search,
    fetch: Fetch,
) -> dict[str, Any]:
    url_reference = f'"{offer_url}"' if offer_url else ""
    description_terms = " ".join(re.findall(r"[a-z0-9]{3,}", description.casefold())[:12])
    query = " ".join(
        part
        for part in (
            f'"{company_name}"',
            url_reference,
            f'"{description_terms}"' if description_terms else "",
            "official careers job listing recruitment fee warning",
        )
        if part
    )[:500]
    search_call = search(query)
    fetch_call = fetch([offer_url]) if offer_url else None
    if fetch_call is not None:
        search_payload, fetch_payload = await asyncio.gather(search_call, fetch_call)
    else:
        search_payload = await search_call
        fetch_payload = {"results": [], "errors": []}
    results = _search_results(search_payload)
    pages = _fetch_results(fetch_payload, [offer_url] if offer_url else None)
    raw_fetch_errors = fetch_payload.get("errors", [])
    fetch_errors = raw_fetch_errors if isinstance(raw_fetch_errors, list) else []

    submitted_text = "\n".join(
        part for part in (description, recruiter_contact or "") if part
    )
    indicators = analyze_text(submitted_text, kind="job")["indicators"]
    for item in indicators:
        item["classification"] = "inference"
    recruiter_verification, recruiter_indicators = _recruiter_details(
        recruiter_contact,
        offer_url,
    )
    indicators.extend(recruiter_indicators)

    relevant_results = [
        result
        for result in results
        if _job_search_result_is_relevant(
            result,
            company_name=company_name,
            offer_url=offer_url,
        )
    ]
    for result in results:
        result_job_id = _listing_identifier(result["url"]) or (
            _labeled_listing_identifier(
                f"{result['title']} {result['snippet']}"
            )
        )
        submitted_job_id = _listing_identifier(offer_url or "") or (
            _labeled_listing_identifier(description)
        )
        exact_listing_reference = bool(
            offer_url
            and (
                canonicalize_url(result["url"]) == canonicalize_url(offer_url)
                or submitted_job_id and result_job_id == submitted_job_id
            )
        )
        result["relevance"] = (
            "target_related" if result in relevant_results else "unrelated_not_scored"
        )
        result["evidence_scope"] = (
            "listing_reference_not_verified"
            if exact_listing_reference
            else "company_level_not_listing_verification"
            if result in relevant_results
            else "unrelated"
        )

    job_verification, positive_indicators = _job_verification(
        company_name=company_name,
        description=description,
        offer_url=offer_url,
        pages=pages,
        fetch_errors=fetch_errors,
    )
    job_verification["recruiter"] = recruiter_verification
    offer_host = urlsplit(offer_url or "").hostname or ""
    if offer_url and _brand_is_only_in_unverified_subdomain(company_name, offer_host):
        indicators.append(
            {
                "name": "Company branding appears only in an unverified subdomain",
                "explanation": "The company name appears in a subdomain, while the registered-domain portion does not contain that name. This is a rule-based impersonation warning, not authoritative proof of fraud.",
                "evidence": f"Submitted offer host: {offer_host}",
                "source": offer_url,
                "score_contribution": 12,
                "classification": "inference",
                "severity": "medium",
            }
        )
        job_verification["offer_domain_status"] = (
            "brand_in_unverified_subdomain"
        )
        job_verification["hosting_status"] = (
            "company_name_in_unverified_subdomain"
        )
    requested_offer_pages = [
        page
        for page in pages
        if offer_url and _page_is_relevant_to_offer(offer_url, page)
    ]
    relevant_pages = requested_offer_pages
    job_verification["research_providers"] = {
        "search": {
            "provider": "TinyFish Search",
            "status": "completed" if isinstance(search_payload, dict) else "unavailable",
        },
        "fetch": {
            "provider": "TinyFish Fetch",
            "status": (
                "not_requested"
                if not offer_url
                else "errors_reported"
                if fetch_errors
                else "page_returned"
                if pages
                else "completed_no_page_returned"
            ),
        },
    }
    for page in pages:
        page["relevance"] = (
            "target_related"
            if page in relevant_pages
            else "redirected_to_other_domain_not_scored"
        )
        page["redirect_detected"] = bool(
            offer_url and not domain_matches_url(offer_url, str(page.get("final_url") or ""))
        )
        page["evidence_scope"] = (
            "submitted_offer_page"
            if page in relevant_pages
            else "not_verified_as_submitted_listing"
        )
        page["provider"] = "TinyFish Fetch"

    for result in relevant_results:
        snippet = f"{result['title']} {result['snippet']}"
        if (
            _mentions_company(snippet, company_name)
            and re.search(r"\b(scam|fraud|complaint|warning)\b", snippet, re.IGNORECASE)
            and re.search(
                r"\b(recruit(?:ment|er|ing)?|job|internship|placement|offer)\b",
                snippet,
                re.IGNORECASE,
            )
        ):
            indicators.append(
                {
                    "name": "Public recruitment warning or allegation",
                    "explanation": "A company-level search result contains recruitment warning language; it is an allegation and does not verify or prove anything about this specific offer.",
                    "evidence": snippet[:500],
                    "source": result["url"],
                    "score_contribution": 8,
                    "classification": "public_allegation",
                    "severity": "low",
                }
            )

    if job_verification["exact_listing_status"] == "page_details_match_not_officially_verified":
        matched_rule_names = {
            str(item.get("name"))
            for item in indicators
            if item.get("classification") == "inference"
        }
        for page in relevant_pages:
            for item in _website_indicators(str(page.get("text", ""))):
                if item["name"] in matched_rule_names:
                    continue
                item["source"] = page.get("final_url")
                indicators.append(item)
                matched_rule_names.add(item["name"])

    sources = [result["url"] for result in results]
    sources.extend(str(page["final_url"]) for page in pages if page.get("final_url"))
    evidence = [
        {
            "title": result["title"],
            "url": result["url"],
            "excerpt": result["snippet"],
            "source_type": "search_result",
            "provider": "TinyFish Search",
            "relevance": result.get("relevance"),
            "evidence_scope": result.get("evidence_scope"),
        }
        for result in results
    ]
    evidence.extend(
        {
            "title": page.get("title", ""),
            "url": page.get("final_url"),
            "submitted_url": page.get("requested_url"),
            "final_url": page.get("final_url"),
            "excerpt": str(page.get("text", ""))[:1200],
            "source_type": "fetched_page",
            "provider": "TinyFish Fetch",
            "relevance": page.get("relevance"),
            "redirect_detected": page.get("redirect_detected", False),
            "evidence_scope": page.get("evidence_scope"),
        }
        for page in pages
    )
    evidence = deduplicate_url_items(evidence)
    evidence = [
        {key: value for key, value in item.items() if key != "canonical_url"}
        for item in evidence
    ]
    search_ok = bool(relevant_results)
    exact_listing_checked = bool(offer_url)
    exact_listing_available = bool(relevant_pages)
    live_status = (
        "completed"
        if search_ok and (not exact_listing_checked or exact_listing_available)
        else "partial"
    )
    missing = []
    if not results:
        missing.append("TinyFish Search returned no results for this job-specific query.")
    elif not relevant_results:
        missing.append("Search returned no company-related public results.")
    elif offer_url:
        missing.append("Company-level search results are not evidence that the submitted job listing is genuine.")
    if offer_url and not relevant_pages:
        missing.append("The exact submitted offer URL did not return page content from the submitted domain or a recognized recruitment platform.")
    if pages and not relevant_pages and any(
        canonicalize_url(str(page.get("requested_url") or ""))
        == canonicalize_url(offer_url or "")
        for page in pages
    ):
        missing.append(
            "Fetch redirected to an unrecognized domain; its page content was excluded from listing verification and scoring."
        )
    if not recruiter_contact:
        missing.append("Recruiter identity and contact could not be independently checked.")
    if recruiter_contact:
        missing.append("Recruiter identity and email-domain ownership were not independently verified.")
    if offer_url:
        missing.append("The company domain and its official-careers status were not independently verified.")
    else:
        missing.append(job_verification["explanation"])
    if job_verification["exact_listing_status"] in {
        "page_details_mismatch",
        "page_fetched_details_insufficient",
        "requested_url_not_confirmed",
        "fetch_failed",
    }:
        missing.append(job_verification["explanation"])
    if fetch_errors:
        missing.append("TinyFish reported one or more per-URL fetch errors; no exact-listing verification is claimed.")
    if job_verification.get("recruitment_platform"):
        missing.append(
            "The listing is hosted by a recognized recruitment platform; this does not independently verify the employer's authority or the offer."
        )
    if relevant_pages:
        if not job_verification.get("job_description"):
            missing.append("The fetched page did not expose a distinct job description.")
        if not job_verification.get("job_id"):
            missing.append("No job identifier was available on the fetched page.")
        elif not job_verification.get("submitted_job_id"):
            missing.append("No submitted job identifier was available for comparison.")
        if not job_verification.get("application_details"):
            missing.append("Application instructions were not available in the fetched page data.")

    report = _report(
        investigation_type="job",
        target=company_name,
        indicators=indicators,
        evidence=evidence,
        sources=deduplicate_urls(sources),
        live_research=live_status,
        missing=missing,
        next_steps=[
            "Open the company's official careers site using a URL located independently, and confirm the same title and job ID there.",
            "Verify recruiter identity using contact information published by the company, not only the submitted email or offer.",
            "Do not pay recruitment, registration, or training fees before verifying the offer.",
        ],
        completeness=(
            "submitted offer details and fetched page"
            if relevant_pages
            else "submitted offer details; listing evidence unavailable"
            if offer_url
            else "submitted offer details; no URL provided for listing verification"
        ),
        positive_indicators=positive_indicators,
        job_verification=job_verification,
    )
    report["confidence"] = "limited"
    report["risk_indicator_band"] = report["risk_category"]
    if report["risk_score"] < 25:
        report["risk_category"] = "Insufficient evidence"
        report["risk_assessment_status"] = "insufficient_evidence"
    else:
        report["risk_assessment_status"] = "warning_signals_detected"
    return report
