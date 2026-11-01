import asyncio
import io
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import cv2
import httpx
import pytesseract
from fastapi import HTTPException
from fastapi.testclient import TestClient
from PIL import Image
from reportlab.pdfgen import canvas

from app.database import InvestigationStore
from app.document_analysis import (
    DocumentInputError,
    analyze_email_content,
    decode_qr_image,
    extract_document_text,
    extract_eml_fields,
    extract_image_text,
    normalize_qr_urls,
    url_warning_indicators,
    validate_upload,
)
from app.main import app, get_current_user, lifespan
from app.watchlist_monitoring import WatchlistMonitoring


def _png_bytes(*, qr_value: str | None = None) -> bytes:
    if qr_value is not None:
        matrix = cv2.QRCodeEncoder_create().encode(qr_value)
        matrix = cv2.copyMakeBorder(
            matrix,
            4,
            4,
            4,
            4,
            cv2.BORDER_CONSTANT,
            value=255,
        )
        matrix = cv2.resize(
            matrix,
            None,
            fx=8,
            fy=8,
            interpolation=cv2.INTER_NEAREST,
        )
        success, encoded = cv2.imencode(".png", matrix)
        if not success:
            raise RuntimeError("Could not encode the QR test image.")
        return encoded.tobytes()
    image = Image.new("RGB", (240, 100), "white")
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _pdf_with_text(text: str) -> bytes:
    output = io.BytesIO()
    document = canvas.Canvas(output)
    document.drawString(40, 760, text)
    document.save()
    return output.getvalue()


class DocumentAnalysisTests(unittest.TestCase):
    def test_upload_validation_checks_filename_type_and_content(self) -> None:
        content = _png_bytes()
        filename, media_type = validate_upload(r"C:\fakepath\offer.png", content)
        self.assertEqual(filename, "offer.png")
        self.assertEqual(media_type, "image/png")
        with self.assertRaisesRegex(DocumentInputError, "contents do not match"):
            validate_upload("offer.pdf", content)
        with self.assertRaisesRegex(DocumentInputError, "(?i)supported file types"):
            validate_upload("offer.exe", b"not an executable")
        with self.assertRaisesRegex(DocumentInputError, "8 MB or smaller"):
            validate_upload("oversized.png", b"\x89PNG\r\n\x1a\n" + b"x" * (8 * 1024 * 1024))

    def test_pdf_text_extraction_reads_offer_claims(self) -> None:
        text, filename = extract_document_text(
            "offer.pdf",
            _pdf_with_text("Company: Example Corp | Job Title: Analyst"),
        )
        self.assertEqual(filename, "offer.pdf")
        self.assertIn("Company: Example Corp", text)

    def test_eml_parser_ignores_attachment_payload(self) -> None:
        message = (
            b"From: recruiter@example.com\r\n"
            b"Subject: Urgent job offer\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=example\r\n\r\n"
            b"--example\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Pay a registration fee to secure placement.\r\n"
            b"--example\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=payload.exe\r\n\r\n"
            b"must-not-be-read\r\n--example--\r\n"
        )
        sender, subject, body = extract_eml_fields(message)
        self.assertEqual(sender, "recruiter@example.com")
        self.assertEqual(subject, "Urgent job offer")
        self.assertIn("registration fee", body)
        self.assertNotIn("must-not-be-read", body)

    def test_ocr_reports_confidence_and_surfaces_engine_failure(self) -> None:
        mocked_result = {
            "text": ["Pay", "fee"],
            "conf": ["90", "70", "-1"],
        }
        with patch(
            "app.document_analysis.pytesseract.image_to_data",
            return_value=mocked_result,
        ):
            text, confidence = extract_image_text(_png_bytes())
        self.assertEqual(text, "Pay fee")
        self.assertEqual(confidence, 80.0)

        with patch(
            "app.document_analysis.pytesseract.image_to_data",
            side_effect=pytesseract.TesseractNotFoundError(),
        ):
            with self.assertRaisesRegex(DocumentInputError, "OCR is unavailable"):
                extract_image_text(_png_bytes())

    def test_qr_decode_returns_destination_without_opening_it(self) -> None:
        destination = "https://example.test/claim?fee=1"
        decoded = decode_qr_image(_png_bytes(qr_value=destination))
        self.assertEqual(decoded, [destination])
        self.assertEqual(
            normalize_qr_urls("Visit https://example.test/pay)."),
            ["https://example.test/pay"],
        )

    def test_malformed_or_empty_qr_image_has_no_decoded_content(self) -> None:
        self.assertEqual(decode_qr_image(_png_bytes()), [])
        with self.assertRaises(DocumentInputError):
            decode_qr_image(b"not an image")

    def test_email_screening_reports_phishing_and_sender_limitations(self) -> None:
        report = analyze_email_content(
            sender="recruiter@gmail.com",
            subject="Microsoft Careers: Verify your account",
            body="Click here to verify your account and send your OTP.",
        )
        names = {item["name"] for item in report["indicators"]}
        self.assertIn("Credential or account verification language", names)
        self.assertIn("Public email provider used for an organization claim", names)
        self.assertIn(
            "sender identity and domain ownership were not independently verified",
            " ".join(report["missing_information"]).lower(),
        )

    def test_suspicious_link_structures_are_labeled_as_inferences(self) -> None:
        report = analyze_email_content(
            sender=None,
            subject="Review this message",
            body="Open https://bit.ly/claim",
        )
        warning = next(
            item
            for item in report["indicators"]
            if item["name"] == "Link shortener obscures the destination"
        )
        self.assertEqual(warning["classification"], "inference")
        self.assertIn("https://bit.ly/claim", warning["evidence"])
        self.assertTrue(url_warning_indicators(["http://192.0.2.1/login"]))


class AdvancedApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = InvestigationStore(os.path.join(self.temp_dir.name, "advanced.sqlite"))
        self.store_patch = patch("app.main.store", self.store)
        self.store_patch.start()
        self.addCleanup(self.store_patch.stop)
        self.addCleanup(self.temp_dir.cleanup)
        app.dependency_overrides[get_current_user] = lambda: {
            "id": "test-owner",
            "email": "owner@example.test",
            "display_name": "Test Owner",
            "role": "user",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        self.addCleanup(app.dependency_overrides.pop, get_current_user, None)
        self.client = TestClient(app)

    def test_offer_text_analysis_does_not_retain_sensitive_document_by_default(self) -> None:
        report = {
            "id": str(uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "investigation_type": "job",
            "target": "Example Corp",
            "risk_score": 0,
            "risk_category": "Insufficient evidence",
            "scoring_explanation": "No warning rules matched.",
            "indicators": [],
            "positive_indicators": [],
            "evidence": [],
            "sources": [],
            "live_research": "partial",
        }
        with patch("app.main.investigate_job", new=AsyncMock(return_value=report)):
            response = self.client.post(
                "/api/investigations/offer-letter",
                data={
                    "company_name": "Example Corp",
                    "pasted_text": (
                        "Company: Example Corp\nJob Title: Analyst\n"
                        "Pay a registration fee to secure your placement."
                    ),
                },
            )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertFalse(result["retained_in_history"])
        self.assertTrue(result["indicators"])
        self.assertEqual(result["extracted_details"]["company"], "Example Corp")
        self.assertEqual(self.store.list_recent(user_id="test-owner"), [])

    def test_offer_without_warning_signals_is_not_classified_as_low_risk(self) -> None:
        report = {
            "id": str(uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "investigation_type": "job",
            "target": "Example Corp",
            "risk_score": 0,
            "risk_category": "Insufficient evidence",
            "risk_assessment_status": "insufficient_evidence",
            "risk_indicator_band": "Insufficient evidence",
            "scoring_explanation": "No warning rules matched.",
            "indicators": [],
            "positive_indicators": [],
            "evidence": [],
            "sources": [],
            "live_research": "partial",
        }
        with patch("app.main.investigate_job", new=AsyncMock(return_value=report)):
            response = self.client.post(
                "/api/investigations/offer-letter",
                data={
                    "company_name": "Example Corp",
                    "pasted_text": "Company: Example Corp\nJob Title: Analyst",
                },
            )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["risk_category"], "Insufficient evidence")
        self.assertEqual(result["risk_assessment_status"], "insufficient_evidence")
        self.assertEqual(result["risk_indicator_band"], "Insufficient evidence")

    def test_offer_extracts_and_researches_embedded_listing_url_and_job_id(self) -> None:
        report = {
            "id": str(uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "investigation_type": "job",
            "target": "Example Corp",
            "risk_score": 0,
            "risk_category": "Insufficient evidence",
            "scoring_explanation": "No warning rules matched.",
            "indicators": [],
            "positive_indicators": [],
            "evidence": [],
            "sources": [],
            "live_research": "partial",
        }
        investigator = AsyncMock(return_value=report)
        public_address = (2, 1, 6, "", ("93.184.216.34", 443))
        with patch("app.main.socket.getaddrinfo", return_value=[public_address]):
            with patch("app.main.investigate_job", new=investigator):
                response = self.client.post(
                    "/api/investigations/offer-letter",
                    data={
                        "company_name": "Example Corp",
                        "pasted_text": (
                            "Job Title: Analyst\nJob ID: REQ-123\n"
                            "https://example.com/jobs/REQ-123"
                        ),
                        "retain_report": "false",
                    },
                )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["extracted_details"]["job_id"], "REQ-123")
        self.assertEqual(
            response.json()["extracted_details"]["offer_url"],
            "https://example.com/jobs/REQ-123",
        )
        self.assertIn("Job ID: REQ-123", investigator.await_args.kwargs["description"])
        self.assertEqual(
            investigator.await_args.kwargs["offer_url"],
            "https://example.com/jobs/REQ-123",
        )

    def test_watchlist_can_be_listed_after_adding_unconfigured_entry(self) -> None:
        account = self.store.register_user(
            "watchlist-owner@example.test",
            "Watchlist Owner",
            "correct-horse-battery-staple",
        )
        app.dependency_overrides[get_current_user] = lambda: {
            "id": account["id"],
            "email": account["email"],
            "display_name": account["display_name"],
            "role": "user",
            "created_at": account["created_at"],
        }

        created = self.client.post(
            "/api/watchlist",
            json={"value": "example.test", "item_type": "domain"},
        )
        self.assertEqual(created.status_code, 201)
        entries = self.client.get("/api/watchlist")
        self.assertEqual(entries.status_code, 200)
        self.assertEqual(len(entries.json()), 1)
        self.assertEqual(entries.json()[0]["value"], "example.test")
        self.assertIsNone(entries.json()[0]["interval_hours"])

    def test_email_analysis_returns_report_and_does_not_store_raw_body(self) -> None:
        response = self.client.post(
            "/api/analyze/email",
            json={
                "sender": "recruiter@gmail.com",
                "subject": "Microsoft Careers job offer",
                "body": "Pay a registration fee and send your OTP.",
            },
        )
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["investigation_type"], "email")
        self.assertGreater(report["risk_score"], 0)
        self.assertFalse(report["retained_in_history"])
        self.assertEqual(self.store.list_recent(user_id="test-owner"), [])

    def test_qr_upload_rejects_malformed_image(self) -> None:
        response = self.client.post(
            "/api/analyze/qr",
            files={"file": ("invalid.png", b"not an image", "image/png")},
        )
        self.assertEqual(response.status_code, 422)

    def test_qr_endpoint_decodes_shortened_link_without_fetching_it(self) -> None:
        with patch("app.main.fetch_pages", new=AsyncMock()) as fetch:
            response = self.client.post(
                "/api/analyze/qr",
                files={
                    "file": (
                        "destination.png",
                        _png_bytes(qr_value="https://bit.ly/claim"),
                        "image/png",
                    )
                },
            )
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["decoded_urls"], ["https://bit.ly/claim"])
        self.assertEqual(report["live_research"], "not_requested")
        self.assertTrue(
            any(
                item["name"] == "Link shortener obscures the destination"
                for item in report["indicators"]
            )
        )
        fetch.assert_not_awaited()

    def test_screenshot_api_reports_ocr_confidence_without_retaining_report(self) -> None:
        with patch(
            "app.main.extract_image_text",
            return_value=("Pay a registration fee", 73.5),
        ):
            response = self.client.post(
                "/api/analyze/screenshot",
                files={"file": ("message.png", _png_bytes(), "image/png")},
                data={"context": "message", "retain_report": "false"},
            )
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["ocr_confidence"], 73.5)
        self.assertEqual(report["extracted_text"], "Pay a registration fee")
        self.assertFalse(report["retained_in_history"])
        self.assertEqual(self.store.list_recent(user_id="test-owner"), [])

    def test_ai_unavailable_and_malformed_provider_responses_are_explicit(self) -> None:
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            unavailable = self.client.post(
                "/api/analyze/ai",
                json={"text": "An offer requests an urgent payment."},
            )
        self.assertEqual(unavailable.status_code, 503)
        self.assertIn("not configured", unavailable.json()["detail"])

        class InvalidGeminiClient:
            async def __aenter__(self) -> "InvalidGeminiClient":
                return self

            async def __aexit__(self, *_: object) -> None:
                return None

            async def post(
                self,
                url: str,
                *,
                headers: dict[str, str],
                json: dict[str, object],
            ) -> httpx.Response:
                if (
                    "generativelanguage.googleapis.com" not in url
                    or "x-goog-api-key" not in headers
                    or "contents" not in json
                ):
                    raise AssertionError("Gemini request was not configured correctly.")
                return httpx.Response(200, json={"candidates": []})

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch(
                "app.main.httpx.AsyncClient",
                return_value=InvalidGeminiClient(),
            ):
                malformed = self.client.post(
                    "/api/analyze/ai",
                    json={"text": "An offer requests an urgent payment."},
                )
        self.assertEqual(malformed.status_code, 502)
        self.assertEqual(
            malformed.json()["detail"],
            "Gemini returned an invalid structured response.",
        )

    def test_batch_isolates_failed_url_and_deduplicates(self) -> None:
        def fake_report(url: str) -> dict[str, object]:
            return {
                "id": str(uuid4()),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "investigation_type": "website",
                "target": url,
                "risk_score": 0,
                "risk_category": "Insufficient evidence",
                "scoring_explanation": "No warning rules matched.",
                "indicators": [],
                "evidence": [],
                "sources": [],
                "live_research": "partial",
            }

        investigator = AsyncMock(
            side_effect=[
                HTTPException(status_code=502, detail="provider failed"),
                fake_report("https://good.example/"),
            ]
        )
        with patch("app.main.validate_external_url", side_effect=lambda url: url):
            with patch("app.main.investigate_website", new=investigator):
                response = self.client.post(
                    "/api/investigations/batch",
                    json={
                        "urls": [
                            "https://bad.example",
                            "https://good.example",
                            "https://GOOD.example/",
                        ]
                    },
                )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(
            result["summary"],
            {"total": 3, "completed": 1, "failed": 1, "duplicates": 1},
        )
        self.assertEqual(result["results"][0]["status"], "failed")
        self.assertEqual(
            result["results"][1]["report"]["target"],
            "https://good.example/",
        )
        self.assertEqual(result["results"][2]["status"], "duplicate")

    def test_batch_endpoint_applies_per_user_rate_limit(self) -> None:
        for _ in range(3):
            response = self.client.post(
                "/api/investigations/batch",
                json={"urls": ["ftp://invalid.example"]},
            )
            self.assertEqual(response.status_code, 200)
        limited = self.client.post(
            "/api/investigations/batch",
            json={"urls": ["ftp://invalid.example"]},
        )
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.headers["Retry-After"], "60")


class WatchlistMonitoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_dir.name, "monitoring.sqlite")
        self.store = InvestigationStore(self.database_path)
        self.first_user = self.store.register_user(
            "first@example.test", "First", "correct-horse-battery-staple"
        )
        self.second_user = self.store.register_user(
            "second@example.test", "Second", "correct-horse-battery-staple"
        )
        self.item = self.store.add_watchlist_item(
            self.first_user["id"],
            "example.test",
            "domain",
        )
        self.search = AsyncMock(return_value={"results": []})
        self.fetch = AsyncMock(return_value={"results": [], "errors": []})
        self.service = WatchlistMonitoring(
            self.database_path,
            search=self.search,
            fetch=self.fetch,
            validate_url=lambda url: url,
        )
        self.addCleanup(self.temp_dir.cleanup)
        self.addCleanup(self.service.shutdown)

    def test_scheduler_starts_stops_and_persists_opt_in_settings(self) -> None:
        self.service.start()
        self.assertTrue(self.service.running)
        settings = self.service.configure(
            self.first_user["id"],
            self.item["id"],
            enabled=True,
            interval_hours=6,
        )
        self.assertTrue(settings["enabled"])
        self.assertTrue(settings["job_scheduled"])
        self.assertEqual(settings["interval_hours"], 6)
        with self.assertRaises(ValueError):
            self.service.configure(
                self.first_user["id"],
                self.item["id"],
                enabled=True,
                interval_hours=2,
            )
        self.service.shutdown()
        self.assertFalse(self.service.running)

    def test_monitoring_settings_and_checks_are_user_scoped(self) -> None:
        with self.assertRaises(LookupError):
            self.service.settings(self.second_user["id"], self.item["id"])
        with self.assertRaises(LookupError):
            asyncio.run(
                self.service.perform_check(
                    self.item["id"],
                    owner_id=self.second_user["id"],
                )
            )

    def test_fastapi_lifespan_starts_and_stops_the_scheduler(self) -> None:
        previous_service = __import__("app.main", fromlist=["monitoring_service"]).monitoring_service
        try:
            with patch("app.main.monitoring_service", self.service):
                async def run_lifespan() -> None:
                    async with lifespan(app):
                        self.assertTrue(self.service.running)
                asyncio.run(run_lifespan())
            self.assertFalse(self.service.running)
        finally:
            if previous_service.running:
                previous_service.shutdown()

    def test_monitoring_routes_enforce_owner_access_and_delete_schedules_safely(self) -> None:
        first = self.store.register_user(
            "monitor-owner@example.test",
            "Monitor Owner",
            "correct-horse-battery-staple",
        )
        second = self.store.register_user(
            "other-owner@example.test",
            "Other Owner",
            "correct-horse-battery-staple",
        )
        item = self.store.add_watchlist_item(
            first["id"],
            "example.test",
            "domain",
        )
        service = WatchlistMonitoring(
            self.database_path,
            search=self.search,
            fetch=self.fetch,
            validate_url=lambda url: url,
        )
        service.start()
        self.addCleanup(service.shutdown)
        client = TestClient(app)
        service.configure(
            first["id"],
            item["id"],
            enabled=True,
            interval_hours=24,
        )
        with patch("app.main.monitoring_service", service):
            app.dependency_overrides[get_current_user] = lambda: {
                "id": second["id"],
                "email": second["email"],
                "display_name": second["display_name"],
                "role": "user",
                "created_at": second["created_at"],
            }
            forbidden = client.get(
                f"/api/watchlist/{item['id']}/monitoring",
            )
            delete = client.delete(f"/api/watchlist/{item['id']}")
            self.assertEqual(forbidden.status_code, 404)
            self.assertEqual(delete.status_code, 404)
            self.assertIsNotNone(service.scheduler.get_job(f"watchlist:{item['id']}"))
            app.dependency_overrides[get_current_user] = lambda: {
                "id": first["id"],
                "email": first["email"],
                "display_name": first["display_name"],
                "role": "user",
                "created_at": first["created_at"],
            }
            with patch("app.main.store", self.store):
                account_deleted = client.delete("/api/auth/account")
            self.assertEqual(account_deleted.status_code, 204)
            self.assertIsNone(service.scheduler.get_job(f"watchlist:{item['id']}"))
        with self.store._connection() as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM watchlist WHERE id = ?",
                    (item["id"],),
                ).fetchone()
            )
        app.dependency_overrides[get_current_user] = lambda: {
            "id": "test-owner",
            "email": "owner@example.test",
            "display_name": "Test Owner",
            "role": "user",
            "created_at": "2026-01-01T00:00:00+00:00",
        }


if __name__ == "__main__":
    unittest.main()
