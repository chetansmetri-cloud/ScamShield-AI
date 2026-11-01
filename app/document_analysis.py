import io
import ipaddress
import os
import re
import shutil
import statistics
import warnings
from collections.abc import Mapping
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlsplit

import cv2
import numpy as np
import pytesseract
from PIL import Image, ImageOps, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError, PyPdfError

from app.analyzers.rules import analyze_text, classify_score
from app.evidence import canonicalize_url

MAX_UPLOAD_BYTES = 8 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000
MAX_PDF_PAGES = 30
MAX_EXTRACTED_CHARACTERS = 100_000
MAX_OCR_SECONDS = 15
ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}
EMAIL_ATTACHMENT_PATTERN = re.compile(
    r"\b[\w.-]+\.(?:exe|scr|bat|cmd|com|msi|js|vbs|ps1|jar|zip|rar|7z|iso|img)\b",
    re.IGNORECASE,
)
EMAIL_PHISHING_PATTERN = re.compile(
    r"\b(?:click|open|visit)\s+(?:here|the link|this link)\s+to\s+"
    r"(?:verify|confirm|restore|unlock|validate)\b|"
    r"\b(?:verify|confirm)\s+(?:your\s+)?(?:account|password|identity|payment)\b",
    re.IGNORECASE,
)
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
}
KNOWN_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "tiny.cc",
    "t.co",
    "ow.ly",
    "is.gd",
    "rb.gy",
}


class DocumentInputError(ValueError):
    pass


def _validate_filename(filename: str | None) -> str:
    if not filename or len(filename) > 255:
        raise DocumentInputError("Upload a file with a supported filename.")
    sanitized = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if sanitized in {"", ".", ".."} or "\x00" in sanitized:
        raise DocumentInputError("The uploaded filename is invalid.")
    return sanitized


def validate_upload(filename: str | None, content: bytes) -> tuple[str, str]:
    safe_name = _validate_filename(filename)
    if not content:
        raise DocumentInputError("The uploaded file is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise DocumentInputError("Uploaded files must be 8 MB or smaller.")

    extension = os.path.splitext(safe_name)[1].casefold()
    if extension == ".pdf":
        if not content.startswith(b"%PDF-"):
            raise DocumentInputError("The file contents do not match a PDF document.")
        return safe_name, "application/pdf"
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise DocumentInputError("Supported file types are PDF, JPG, JPEG, and PNG.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            image = Image.open(io.BytesIO(content))
            image_format = image.format
            width, height = image.size
            image.verify()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise DocumentInputError("The image is invalid or exceeds safe processing limits.") from exc
    expected_format = "PNG" if extension == ".png" else "JPEG"
    if image_format != expected_format:
        raise DocumentInputError("The file extension does not match the image contents.")
    if width * height > MAX_IMAGE_PIXELS:
        raise DocumentInputError("Images must contain 20 megapixels or fewer.")
    return safe_name, "image/png" if image_format == "PNG" else "image/jpeg"


def _read_pdf(content: bytes) -> str:
    try:
        reader = PdfReader(io.BytesIO(content), strict=True)
        if reader.is_encrypted:
            raise DocumentInputError("Encrypted PDFs are not supported.")
        if len(reader.pages) > MAX_PDF_PAGES:
            raise DocumentInputError("PDF offer letters may contain at most 30 pages.")
        parts: list[str] = []
        total_characters = 0
        for page in reader.pages:
            page_text = page.extract_text() or ""
            remaining = MAX_EXTRACTED_CHARACTERS - total_characters
            if remaining <= 0:
                break
            parts.append(page_text[:remaining])
            total_characters += min(len(page_text), remaining)
        extracted = "\n".join(parts).strip()
    except DocumentInputError:
        raise
    except (PdfReadError, PyPdfError, ValueError, OSError, KeyError) as exc:
        raise DocumentInputError("The PDF could not be safely read.") from exc
    if not extracted:
        raise DocumentInputError(
            "No selectable text was found in the PDF. Upload a screenshot instead."
        )
    return extracted


def extract_document_text(filename: str | None, content: bytes) -> tuple[str, str]:
    safe_name, detected_type = validate_upload(filename, content)
    if detected_type == "application/pdf":
        return _read_pdf(content), safe_name
    return "", safe_name


def extract_eml_fields(content: bytes) -> tuple[str | None, str | None, str]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(content, headersonly=False)
    except (ValueError, TypeError) as exc:
        raise DocumentInputError("The email file could not be safely parsed.") from exc

    sender = str(message.get("From", ""))[:500] or None
    subject = str(message.get("Subject", ""))[:300] or None
    text_parts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart" or part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() != "text/plain":
                continue
            try:
                body = part.get_content()
            except (LookupError, UnicodeDecodeError, KeyError):
                continue
            if isinstance(body, str):
                text_parts.append(body)
    elif message.get_content_type() == "text/plain":
        try:
            body = message.get_content()
        except (LookupError, UnicodeDecodeError, KeyError) as exc:
            raise DocumentInputError("The email text could not be decoded.") from exc
        if isinstance(body, str):
            text_parts.append(body)

    body_text = "\n".join(text_parts)[:MAX_EXTRACTED_CHARACTERS].strip()
    if not body_text and not subject:
        raise DocumentInputError("The email file did not contain readable plain text.")
    return sender, subject, body_text


def _open_validated_image(content: bytes) -> Image.Image:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            image = Image.open(io.BytesIO(content))
            if image.format not in {"JPEG", "PNG"}:
                raise DocumentInputError("Only JPEG and PNG images are supported.")
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise DocumentInputError("Images must contain 20 megapixels or fewer.")
            image.load()
            return ImageOps.exif_transpose(image).convert("RGB")
    except DocumentInputError:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise DocumentInputError("The image is invalid or exceeds safe processing limits.") from exc


def _configure_tesseract() -> None:
    configured = os.getenv("TESSERACT_CMD", "").strip()
    executable = configured or shutil.which("tesseract")
    if executable:
        pytesseract.pytesseract.tesseract_cmd = executable
    elif os.name == "nt":
        default_windows_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        if os.path.isfile(default_windows_path):
            pytesseract.pytesseract.tesseract_cmd = default_windows_path


def extract_image_text(content: bytes) -> tuple[str, float | None]:
    image = _open_validated_image(content)
    _configure_tesseract()
    try:
        result: Mapping[str, Any] = pytesseract.image_to_data(
            image,
            output_type=pytesseract.Output.DICT,
            config="--psm 6",
            timeout=MAX_OCR_SECONDS,
        )
    except pytesseract.TesseractNotFoundError as exc:
        raise DocumentInputError(
            "OCR is unavailable. Install Tesseract or set TESSERACT_CMD."
        ) from exc
    except (pytesseract.TesseractError, RuntimeError, OSError) as exc:
        raise DocumentInputError("OCR could not read this image.") from exc

    words = [
        str(word)
        for word in result.get("text", [])
        if isinstance(word, str) and word.strip()
    ]
    confidences = []
    for raw_confidence in result.get("conf", []):
        try:
            confidence = float(raw_confidence)
        except (TypeError, ValueError):
            continue
        if confidence >= 0:
            confidences.append(confidence)
    extracted = " ".join(words)[:MAX_EXTRACTED_CHARACTERS].strip()
    mean_confidence = round(statistics.fmean(confidences), 2) if confidences else None
    if not extracted:
        raise DocumentInputError("OCR did not detect readable text in this image.")
    return extracted, mean_confidence


def decode_qr_image(content: bytes) -> list[str]:
    image = _open_validated_image(content)
    matrix = cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    try:
        found, decoded_values, _, _ = detector.detectAndDecodeMulti(matrix)
        values = list(decoded_values) if found else []
    except cv2.error:
        values = []
    if not values:
        value, _, _ = detector.detectAndDecode(matrix)
        values = [value] if value else []
    return list(dict.fromkeys(value.strip() for value in values if value.strip()))


def normalize_qr_urls(text: str) -> list[str]:
    candidates = re.findall(r"https?://[^\s<>'\"\]\[(){}]+", text, re.IGNORECASE)
    normalized = []
    for candidate in candidates:
        value = canonicalize_url(candidate.rstrip(".,;:!?"))
        if value and value not in normalized:
            normalized.append(value)
    return normalized[:10]


def url_warning_indicators(urls: list[str]) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in urls:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").casefold().rstrip(".")
        if not hostname:
            continue
        warning: dict[str, Any] | None = None
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if any(label.startswith("xn--") for label in hostname.split(".")):
                warning = {
                    "name": "Internationalized domain requires careful inspection",
                    "explanation": "The link contains an IDN punycode label. This can be legitimate, but visually similar domains should be checked independently.",
                    "score_contribution": 10,
                    "severity": "medium",
                }
        else:
            warning = {
                "name": "Link uses an IP-address host",
                "explanation": "The URL points directly to an IP address rather than a named domain; verify the destination before proceeding.",
                "score_contribution": 10,
                "severity": "medium",
            }
        if warning is None and hostname in KNOWN_SHORTENER_DOMAINS:
            warning = {
                "name": "Link shortener obscures the destination",
                "explanation": "The link uses a URL-shortening service, so the final destination is not visible from the submitted URL alone.",
                "score_contribution": 6,
                "severity": "low",
            }
        if warning is None and parsed.scheme.casefold() == "http":
            warning = {
                "name": "Email link does not use HTTPS",
                "explanation": "The submitted link uses unencrypted HTTP. This does not prove maliciousness, but information may not be protected in transit.",
                "score_contribution": 4,
                "severity": "low",
            }
        if warning is not None and warning["name"] not in seen:
            seen.add(warning["name"])
            warnings.append(
                {
                    **warning,
                    "evidence": url,
                    "classification": "inference",
                }
            )
    return warnings


def extract_offer_details(text: str) -> dict[str, str | None]:
    fields: dict[str, str | None] = {}
    labels = {
        "company": r"(?:company|employer|organization|organisation)",
        "recruiter": r"(?:recruiter|hiring manager|contact person|hr representative)",
        "job_title": r"(?:job title|position|role|designation|internship role)",
        "job_id": r"(?:job id|requisition id|req id|position id)",
        "salary_or_stipend": r"(?:salary|stipend|compensation|annual package|ctc)",
        "offer_date": r"(?:offer date|date of offer|issued on)",
        "joining_date": r"(?:joining date|date of joining|start date|commencement date)",
    }
    for key, label in labels.items():
        match = re.search(
            rf"(?im)^\s*(?:{label})\s*[:=-]\s*(.{{2,250}}?)\s*$",
            text,
        )
        fields[key] = match.group(1).strip() if match else None

    urls = normalize_qr_urls(text)
    fields["offer_url"] = urls[0] if urls else None
    fields["application_url"] = next(
        (url for url in urls if re.search(r"\b(?:apply|application|careers?)\b", url, re.I)),
        None,
    )
    return fields


def analyze_email_content(
    *,
    sender: str | None,
    subject: str | None,
    body: str,
) -> dict[str, Any]:
    text = "\n".join(part for part in (subject or "", body) if part)
    offer_context = bool(
        re.search(r"\b(job|internship|recruit(?:ment|er)|placement|offer letter)\b", text, re.I)
    )
    analysis = analyze_text(text, kind="job" if offer_context else "message")
    indicators = analysis["indicators"]
    for indicator in indicators:
        indicator["classification"] = "inference"
    if EMAIL_PHISHING_PATTERN.search(text):
        indicators.append(
            {
                "name": "Credential or account verification language",
                "explanation": "The email asks the recipient to verify an account or credentials through a link; navigate independently to the service instead.",
                "evidence": EMAIL_PHISHING_PATTERN.search(text).group(0),
                "score_contribution": 18,
                "classification": "inference",
                "severity": "high",
            }
        )
    attachments = list(dict.fromkeys(match.group(0) for match in EMAIL_ATTACHMENT_PATTERN.finditer(text)))
    if attachments:
        indicators.append(
            {
                "name": "Potentially risky attachment mentioned",
                "explanation": "The email mentions an executable, archive, or disk-image attachment. No attachment was opened or scanned.",
                "evidence": ", ".join(attachments[:5]),
                "score_contribution": 12,
                "classification": "inference",
                "severity": "medium",
            }
        )
    links = normalize_qr_urls(body)
    existing_names = {item["name"] for item in indicators}
    for indicator in url_warning_indicators(links):
        if indicator["name"] not in existing_names:
            indicators.append(indicator)
            existing_names.add(indicator["name"])
    sender_address = parseaddr(sender or "")[1]
    sender_domain = sender_address.rsplit("@", 1)[-1].casefold() if "@" in sender_address else ""
    if sender_domain in FREE_EMAIL_DOMAINS and re.search(
        r"\b(microsoft|google|amazon|bank|recruitment|careers?)\b",
        text,
        re.IGNORECASE,
    ):
        indicators.append(
            {
                "name": "Public email provider used for an organization claim",
                "explanation": "A public mailbox is used in a message discussing an organization or recruitment claim; this warrants independent verification but does not prove impersonation.",
                "evidence": f"Sender domain: {sender_domain}",
                "score_contribution": 6,
                "classification": "inference",
                "severity": "low",
            }
        )

    sender_domain_status = "not_provided_or_invalid"
    if sender_domain:
        link_hosts = {
            (urlsplit(url).hostname or "").casefold().removeprefix("www.")
            for url in links
        }
        sender_domain_status = (
            "no_link_domain_to_compare"
            if not link_hosts
            else "sender_differs_from_link_domain_unverified"
            if not any(
                host == sender_domain or host.endswith(f".{sender_domain}")
                for host in link_hosts
            )
            else "sender_matches_link_domain_unverified"
        )
    score = min(100, sum(item["score_contribution"] for item in indicators))
    analysis.update(
        {
            "risk_score": score,
            "risk_category": classify_score(score),
            "indicators": indicators,
            "email_details": {
                "sender": sender_address or None,
                "sender_domain_status": sender_domain_status,
                "subject": (subject or "").strip()[:300] or None,
                "links": links,
                "mentioned_attachments": attachments[:5],
            },
            "missing_information": [
                "Sender identity and domain ownership were not independently verified.",
                "Email authentication headers were not provided for DMARC/SPF/DKIM analysis.",
                "Mentioned attachments were not downloaded, opened, or scanned.",
            ],
            "recommended_next_steps": [
                "Verify the sender using a contact channel found independently.",
                "Do not open unexpected attachments or share credentials, OTPs, or payments.",
                "Navigate to services directly instead of following untrusted email links.",
            ],
        }
    )
    total = sum(item["score_contribution"] for item in indicators)
    analysis["scoring_explanation"] = (
        f"Email rules matched {len(indicators)} indicator(s) contributing {total} points, "
        "capped at 100. Sender identity and link ownership remain unverified."
    )
    return analysis


def offer_missing_information(details: dict[str, str | None]) -> list[str]:
    fields = {
        "company": "Company name was not extracted from the offer.",
        "recruiter": "Recruiter name was not extracted from the offer.",
        "job_title": "Job title or internship role was not extracted from the offer.",
        "salary_or_stipend": "Salary or stipend was not extracted from the offer.",
        "offer_date": "Offer date was not extracted from the offer.",
        "joining_date": "Joining date was not extracted from the offer.",
    }
    return [message for key, message in fields.items() if not details.get(key)]


def offer_date_warnings(details: dict[str, str | None]) -> list[str]:
    offer_date = details.get("offer_date")
    joining_date = details.get("joining_date")
    if not offer_date or not joining_date:
        return []
    parsed_dates = []
    for value in (offer_date, joining_date):
        parsed = None
        for date_format in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%B %d, %Y", "%d %B %Y"):
            try:
                parsed = datetime.strptime(value.strip(), date_format).date()
                break
            except ValueError:
                continue
        if parsed is None:
            return ["Offer or joining date could not be consistently interpreted."]
        parsed_dates.append(parsed)
    if parsed_dates[0] > parsed_dates[1]:
        return ["The extracted offer date occurs after the joining date."]
    if (parsed_dates[1] - parsed_dates[0]).days > 365:
        return ["The joining date is more than one year after the offer date; confirm both dates."]
    return []
