import asyncio
import re
import uuid
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
        requested_url = result.get("url")
        if not isinstance(requested_url, str) and requested_urls and index < len(requested_urls):
            requested_url = requested_urls[index]
        final_url = result.get("final_url") or result.get("url")
        pages.append(
            {
                "url": final_url,
                "requested_url": requested_url,
                "final_url": final_url,
                "title": result.get("title", ""),
                "text": result.get("text", ""),
            }
        )
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
    candidates.append(value)
    for candidate in candidates:
        match = re.search(
            r"(?<![a-z0-9])(?:req|job|jr)[-_]?[a-z0-9]{4,}(?![a-z0-9])|(?<!\d)\d{5,}(?!\d)",
            candidate,
            re.IGNORECASE,
        )
        if match:
            return match.group(0).casefold()
    return None


def _role_matches(job_title: str, offer_description: str, company_name: str) -> bool:
    company_tokens = set(_normalized_text(company_name).split())
    title_tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", job_title.casefold())
        if len(token) > 2
        and token not in {"career", "careers", "job", "jobs", "opening"}
        and token not in company_tokens
    }
    description_tokens = set(re.findall(r"[a-z0-9]+", offer_description.casefold()))
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
    result_id = _listing_identifier(
        f"{result.get('url', '')} {result.get('title', '')} {result.get('snippet', '')}"
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
                "score_contribution": 5,
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
                "submitted_offer_url": None,
                "final_fetched_url": None,
                "page_title": None,
                "page_company": None,
                "job_title": None,
                "job_id": None,
                "available_description": None,
                "company_status": "not_independently_verified",
                "offer_domain_status": "not_applicable_no_offer_url",
                "official_careers_domain_status": "not_verified",
                "exact_listing_status": "not_checked_no_offer_url",
                "explanation": "No offer URL was provided; company-level search results cannot verify a particular listing.",
            },
            [],
        )

    canonical_offer_url = canonicalize_url(offer_url)
    exact_requested_pages = [
        page for page in pages
        if canonical_offer_url
        and canonicalize_url(str(page.get("requested_url") or "")) == canonical_offer_url
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
                "submitted_offer_url": offer_url,
                "final_fetched_url": pages[0].get("final_url") if pages else None,
                "page_title": None,
                "page_company": None,
                "job_title": None,
                "job_id": None,
                "available_description": None,
                "company_status": "not_independently_verified",
                "offer_domain_status": "not_verified",
                "official_careers_domain_status": "not_verified",
                "exact_listing_status": status,
                "explanation": "TinyFish did not return a page tied to the exact submitted offer URL; company search results are not listing verification.",
            },
            [],
        )

    final_url = str(page.get("final_url") or "")
    final_host_matches = bool(final_url and domain_matches_url(offer_url, final_url))
    if not final_host_matches:
        return (
            {
                "submitted_offer_url": offer_url,
                "final_fetched_url": final_url or None,
                "page_title": str(page.get("title") or "") or None,
                "page_company": None,
                "job_title": str(page.get("title") or "") or None,
                "job_id": _listing_identifier(final_url) if final_url else None,
                "available_description": str(page.get("text") or "")[:1200] or None,
                "company_status": "not_independently_verified",
                "offer_domain_status": "not_verified",
                "official_careers_domain_status": "not_verified",
                "exact_listing_status": "redirected_to_different_domain",
                "explanation": "The remote fetch ended on a different domain. Its page content was not used to verify the submitted listing.",
            },
            [],
        )

    title = str(page.get("title") or "")
    page_text = str(page.get("text") or "")
    combined_text = f"{title}\n{page_text}"
    company_match = _mentions_company(combined_text, company_name)
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
        else "host_does_not_identify_company_domain_unverified"
    )
    company_status = "company_name_found_on_page" if company_match else "company_name_not_found_on_page"
    page_title = title or None
    job_id = _listing_identifier(final_url) or _listing_identifier(page_text)
    submitted_job_id = _listing_identifier(offer_url)
    job_id_match = (
        job_id == submitted_job_id
        if submitted_job_id
        else None
    )
    role_match = _role_matches(title, description, company_name) if title else False

    mismatches = []
    if not company_match:
        mismatches.append("The fetched page did not identify the submitted company name.")
    if title and not role_match:
        mismatches.append("The fetched page title did not sufficiently match the submitted offer details.")
    if submitted_job_id and job_id_match is False:
        mismatches.append("The fetched page job identifier did not match the identifier in the submitted URL.")

    details_match = bool(company_match and role_match and job_id_match is not False)
    if details_match:
        listing_status = "page_details_match_not_officially_verified"
    elif mismatches:
        listing_status = "page_details_mismatch"
    else:
        listing_status = "page_fetched_details_insufficient"

    positives = []
    if details_match:
        positives.append(
            {
                "name": "Fetched page details are consistent",
                "explanation": "The page returned for the submitted URL contains the submitted company and role details. The employer's domain ownership and listing authenticity remain unverified, so this signal does not lower the score.",
                "evidence": f"Page title: {title}",
                "classification": "verified_fact",
                "score_adjustment": 0,
            }
        )
    verification = {
        "submitted_offer_url": offer_url,
        "final_fetched_url": final_url or None,
        "page_title": page_title,
        "page_company": company_name if company_match else None,
        "job_title": title or None,
        "job_id": job_id,
        "available_description": page_text[:1200] or None,
        "company_status": company_status,
        "offer_domain_status": offer_domain_status,
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
        result_job_id = _listing_identifier(result["url"]) or _listing_identifier(
            f"{result['title']} {result['snippet']}"
        )
        submitted_job_id = _listing_identifier(offer_url or "")
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
    requested_offer_pages = [
        page
        for page in pages
        if offer_url
        and canonicalize_url(str(page.get("requested_url") or "")) == canonicalize_url(offer_url)
    ]
    relevant_pages = [
        page
        for page in requested_offer_pages
        if domain_matches_url(offer_url or "", str(page.get("final_url") or ""))
    ]
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
        missing.append("The exact submitted offer URL did not return verifiable page content from the submitted site's domain.")
    if requested_offer_pages and not relevant_pages:
        missing.append(
            "Fetch returned a different final domain; its page content was excluded from scoring."
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
    return report
