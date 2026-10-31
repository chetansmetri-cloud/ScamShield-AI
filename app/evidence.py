import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


TRACKING_PARAMETERS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
}


def _normalized_host(host: str | None) -> str:
    if not host:
        return ""
    try:
        return host.rstrip(".").encode("idna").decode("ascii").lower().removeprefix("www.")
    except UnicodeError:
        return ""


def canonicalize_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.strip())
        host = parsed.hostname
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        host_ascii = host.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port
    except (UnicodeError, ValueError):
        return None

    scheme = parsed.scheme.lower()
    if port == (80 if scheme == "http" else 443):
        port = None
    host_display = f"[{host_ascii}]" if ":" in host_ascii else host_ascii
    netloc = f"{host_display}:{port}" if port is not None else host_display
    path = parsed.path or "/"
    query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if not key.lower().startswith("utm_") and key.lower() not in TRACKING_PARAMETERS
    ]
    query.sort()
    return urlunsplit((scheme, netloc, path, urlencode(query, doseq=True), ""))


def deduplicate_url_items(items: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    deduplicated: list[dict[str, object]] = []
    indices: dict[str, int] = {}
    for item in items:
        raw_url = item.get("url")
        canonical = canonicalize_url(raw_url) if isinstance(raw_url, str) else None
        if canonical is None:
            continue
        current = {**item, "canonical_url": canonical}
        existing_index = indices.get(canonical)
        if existing_index is None:
            indices[canonical] = len(deduplicated)
            deduplicated.append(current)
            continue

        existing = deduplicated[existing_index]
        existing_type = str(existing.get("source_type", ""))
        current_type = str(current.get("source_type", ""))
        if existing_type == "search_result" and current_type == "fetched_page":
            current["search_excerpt"] = existing.get("excerpt", "")
            current["source_type"] = "search_result_and_fetched_page"
            deduplicated[existing_index] = current
        elif existing_type == "fetched_page" and current_type == "search_result":
            existing["search_excerpt"] = current.get("excerpt", "")
            existing["source_type"] = "search_result_and_fetched_page"
    return deduplicated


def deduplicate_urls(urls: Iterable[str]) -> list[str]:
    unique_urls: list[str] = []
    seen: set[str] = set()
    for url in urls:
        canonical = canonicalize_url(url)
        if canonical is None or canonical in seen:
            continue
        seen.add(canonical)
        unique_urls.append(url)
    return unique_urls


def domain_matches_url(target_url: str, candidate_url: str | None) -> bool:
    if not candidate_url or canonicalize_url(candidate_url) is None:
        return False
    target_host = _normalized_host(urlsplit(target_url).hostname)
    candidate_host = _normalized_host(urlsplit(candidate_url).hostname)
    return bool(
        target_host
        and candidate_host
        and (
            candidate_host == target_host
            or candidate_host.endswith(f".{target_host}")
        )
    )


def text_mentions_domain(text: str, target_url: str) -> bool:
    target_host = _normalized_host(urlsplit(target_url).hostname)
    if not target_host:
        return False
    pattern = rf"(?<![\w-])(?:[\w-]+\.)*{re.escape(target_host)}(?![\w-]|\.[\w-])"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def domain_evidence_is_relevant(
    target_url: str,
    *,
    source_url: str,
    title: str,
    snippet: str,
) -> bool:
    return domain_matches_url(target_url, source_url) or text_mentions_domain(
        f"{title}\n{snippet}",
        target_url,
    )


def company_evidence_is_relevant(
    company_name: str,
    *,
    title: str,
    snippet: str,
    source_url: str,
    offer_url: str | None,
) -> bool:
    if offer_url and domain_matches_url(offer_url, source_url):
        return True
    normalized_name = " ".join(company_name.split())
    if not normalized_name:
        return False
    phrase = r"\s+".join(re.escape(part) for part in normalized_name.split())
    pattern = rf"(?<!\w){phrase}(?!\w)"
    return re.search(
        pattern,
        f"{title}\n{snippet}",
        flags=re.IGNORECASE,
    ) is not None
