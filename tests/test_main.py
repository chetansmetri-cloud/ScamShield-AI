import os
import socket
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.main import get_current_user
from app.analyzers.rules import analyze_text, classify_score
from app.database import InvestigationStore
from app.reporting import build_pdf_report


class FakeAsyncClient:
    def __init__(self, *, response: httpx.Response, **_: object) -> None:
        self.response = response
        self.request_args: tuple[object, ...] | None = None
        self.request_kwargs: dict[str, object] | None = None

    async def __aenter__(self) -> "FakeAsyncClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def request(self, *args: object, **kwargs: object) -> httpx.Response:
        self.request_args = args
        self.request_kwargs = kwargs
        return self.response


class TinyFishRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        app.dependency_overrides[get_current_user] = lambda: {
            "id": "test-user",
            "email": "test@example.com",
            "display_name": "Test User",
            "role": "user",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        self.addCleanup(app.dependency_overrides.pop, get_current_user, None)
        self.key_patch = patch("app.main.dotenv_values", return_value={"TINYFISH_API_KEY": "test-key"})
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)

    def test_search_uses_official_get_format_and_api_key_header(self) -> None:
        fake_client = FakeAsyncClient(
            response=httpx.Response(200, json={"query": "scam", "results": []})
        )
        with self.assertLogs("app.main", level="INFO") as captured:
            with patch("app.main.httpx.AsyncClient", return_value=fake_client):
                response = self.client.get("/api/search", params={"query": " scam "})

        self.assertEqual(response.status_code, 200)
        self.assertIn("provider=TinyFish operation=search request_status=completed", captured.output[0])
        self.assertIn("response_status=200", captured.output[0])
        self.assertIn("result_count=0", captured.output[0])
        self.assertEqual(fake_client.request_args, ("GET", "https://api.search.tinyfish.ai"))
        self.assertEqual(
            fake_client.request_kwargs,
            {
                "headers": {"X-API-Key": "test-key"},
                "params": {"query": "scam"},
                "json": None,
            },
        )

    def test_fetch_uses_official_post_json_format(self) -> None:
        fake_client = FakeAsyncClient(
            response=httpx.Response(200, json={"results": [], "errors": []})
        )
        public_address = (2, 1, 6, "", ("93.184.216.34", 443))
        with patch("app.main.socket.getaddrinfo", return_value=[public_address]):
            with patch("app.main.httpx.AsyncClient", return_value=fake_client):
                response = self.client.post(
                    "/api/fetch",
                    json={"urls": ["https://example.com"]},
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(fake_client.request_args, ("POST", "https://api.fetch.tinyfish.ai"))
        self.assertEqual(
            fake_client.request_kwargs,
            {
                "headers": {
                    "X-API-Key": "test-key",
                    "Content-Type": "application/json",
                },
                "params": None,
                "json": {"urls": ["https://example.com/"]},
            },
        )

    def test_fetch_rejects_non_public_ip_addresses(self) -> None:
        response = self.client.post(
            "/api/fetch",
            json={"urls": ["http://127.0.0.1/"]},
        )

        self.assertEqual(response.status_code, 422)

    def test_missing_api_key_returns_explicit_error(self) -> None:
        with patch("app.main.dotenv_values", return_value={}):
            response = self.client.get("/api/search", params={"query": "scam"})

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"],
            "TinyFish is not configured. Set TINYFISH_API_KEY on the server.",
        )

    def test_api_failure_does_not_return_upstream_body(self) -> None:
        fake_client = FakeAsyncClient(
            response=httpx.Response(429, text="sensitive upstream response")
        )
        with self.assertLogs("app.main", level="WARNING") as captured:
            with patch("app.main.httpx.AsyncClient", return_value=fake_client):
                response = self.client.get("/api/search", params={"query": "scam"})

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("sensitive upstream response", response.text)
        self.assertIn("provider=TinyFish operation=search request_status=rate_limited", captured.output[0])
        self.assertIn("response_status=429", captured.output[0])
        self.assertNotIn("test-key", captured.output[0])

    def test_malformed_provider_response_is_rejected(self) -> None:
        fake_client = FakeAsyncClient(
            response=httpx.Response(200, json={"unexpected": "shape"})
        )
        with self.assertLogs("app.main", level="WARNING") as captured:
            with patch("app.main.httpx.AsyncClient", return_value=fake_client):
                response = self.client.get("/api/search", params={"query": "scam"})

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "TinyFish returned an invalid response.")
        self.assertIn("request_status=invalid_response", captured.output[0])

    def test_fetch_rejects_local_hostname(self) -> None:
        response = self.client.post(
            "/api/fetch",
            json={"urls": ["http://localhost/admin"]},
        )

        self.assertEqual(response.status_code, 422)

    def test_fetch_rejects_embedded_url_credentials(self) -> None:
        response = self.client.post(
            "/api/fetch",
            json={"urls": ["https://user:password@example.com/"]},
        )

        self.assertEqual(response.status_code, 422)

    def test_message_analysis_is_rule_based_and_explains_score(self) -> None:
        report = analyze_text(
            "Act now: pay registration fee and send your OTP",
            kind="message",
        )

        self.assertEqual(report["analysis_method"], "rule_based")
        self.assertEqual(report["risk_score"], 62)
        self.assertEqual(
            report["scoring_explanation"],
            "Score is the sum of matched rule contributions (62), capped at 100. No points are added for missing information.",
        )
        self.assertEqual(len(report["indicators"]), 3)
        self.assertEqual(classify_score(74), "Suspicious")
        self.assertEqual(classify_score(75), "High risk indicators")

    def test_history_store_saves_and_retrieves_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(os.path.join(directory, "history.sqlite"))
            report = {
                "id": "test-id",
                "created_at": "2026-10-31T12:00:00+00:00",
                "investigation_type": "message",
                "target": "Suspicious message",
                "risk_score": 12,
                "risk_category": "Low risk indicators",
                "scoring_explanation": "One indicator matched.",
                "evidence": [],
                "indicators": [],
            }
            store.save(report)

            self.assertEqual(store.get("test-id"), report)
            self.assertEqual(store.list_recent()[0]["id"], "test-id")

    def test_pdf_report_is_built_from_real_report_data(self) -> None:
        report = {
            "id": "test-pdf",
            "created_at": "2026-10-31T12:00:00+00:00",
            "investigation_type": "message",
            "target": "Suspicious message",
            "risk_score": 37,
            "risk_category": "Some concerns",
            "confidence": "limited",
            "information_completeness": "text-only",
            "analysis_method": "rule_based",
            "live_research": "not_requested",
            "scoring_explanation": "Two configured indicators contributed 37 points.",
            "indicators": [
                {
                    "name": "Advance payment request",
                    "score_contribution": 25,
                    "classification": "inference",
                    "explanation": "Payment was requested.",
                    "evidence": "[redacted user-submitted text]",
                }
            ],
            "evidence": [],
            "recommended_next_steps": ["Verify the sender independently."],
            "missing_information": [],
            "disclaimer": "Rule-based screening is not a legal finding.",
        }

        pdf = build_pdf_report(report)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)

    def test_saved_report_pdf_endpoint_returns_pdf_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(os.path.join(directory, "pdf-history.sqlite"))
            store.save(
                {
                    "id": "saved-pdf-id",
                    "created_at": "2026-10-31T12:00:00+00:00",
                    "investigation_type": "message",
                    "target": "Saved user report",
                    "risk_score": 0,
                    "risk_category": "Low risk indicators",
                    "confidence": "limited",
                    "information_completeness": "text-only",
                    "analysis_method": "rule_based",
                    "live_research": "not_requested",
                    "scoring_explanation": "No configured rules matched.",
                    "indicators": [],
                    "evidence": [],
                    "recommended_next_steps": [],
                    "missing_information": [],
                    "disclaimer": "Not a legal finding.",
                },
                user_id="test-user",
            )
            with patch("app.main.store", store):
                response = self.client.get("/api/history/saved-pdf-id/pdf")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF-"))

    def test_analytics_are_based_on_saved_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(os.path.join(directory, "analytics.sqlite"))
            with patch("app.main.store", store):
                response = self.client.get("/api/analytics")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total_investigations"], 0)
        self.assertEqual(response.json()["risk_categories"], [])

    def test_message_history_redacts_submitted_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(os.path.join(directory, "history.sqlite"))
            with patch("app.main.store", store):
                response = self.client.post(
                    "/api/analyze/message",
                    json={"text": "Act now: send your OTP 123456"},
                )

            self.assertEqual(response.status_code, 200)
            report_id = response.json()["id"]
            stored = store.get(report_id)
            self.assertIsNotNone(stored)
            self.assertNotIn("123456", str(stored))
            self.assertEqual(
                stored["indicators"][0]["evidence"],
                "[redacted user-submitted text]",
            )

    def test_website_investigation_returns_search_and_fetch_evidence(self) -> None:
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Example official site",
                        "snippet": "Company information",
                        "url": "https://example.com/about",
                    }
                ]
            }
        )
        fetch = AsyncMock(
            return_value={
                "results": [
                    {
                        "url": "https://example.com/",
                        "final_url": "https://example.com/",
                        "title": "Example",
                        "text": "Welcome to Example.",
                    }
                ],
                "errors": [],
            }
        )
        public_address = (2, 1, 6, "", ("93.184.216.34", 443))
        with tempfile.TemporaryDirectory() as directory:
            with patch("app.main.store", InvestigationStore(os.path.join(directory, "history.sqlite"))):
                with patch("app.main.socket.getaddrinfo", return_value=[public_address]):
                    with patch("app.main.search_web", search):
                        with patch("app.main.fetch_pages", fetch):
                            response = self.client.post(
                                "/api/investigations/website",
                                json={"url": "https://example.com"},
                            )

        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["live_research"], "completed")
        self.assertEqual(
            {item["source_type"] for item in report["evidence"]},
            {"search_result", "fetched_page"},
        )
        search.assert_awaited_once()
        fetch.assert_awaited_once()

    def test_job_offer_analysis_is_rule_based_and_cites_search(self) -> None:
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Company careers",
                        "snippet": "Official careers page",
                        "url": "https://example.com/careers",
                    }
                ]
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(os.path.join(directory, "history.sqlite"))
            with patch("app.main.store", store):
                with patch("app.main.search_web", search):
                    response = self.client.post(
                        "/api/investigations/job",
                        json={
                            "company_name": "Example Company",
                            "description": "Pay registration fee immediately",
                        },
                    )

        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["analysis_method"], "rule_based")
        self.assertEqual(report["risk_score"], 37)
        self.assertEqual(report["evidence"][0]["source_type"], "search_result")
        self.assertEqual(report["indicators"][0]["classification"], "inference")

    def test_message_link_research_is_opt_in(self) -> None:
        search = AsyncMock(return_value={"results": []})
        fetch = AsyncMock(return_value={"results": [], "errors": []})
        public_address = (2, 1, 6, "", ("93.184.216.34", 443))
        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(os.path.join(directory, "history.sqlite"))
            with patch("app.main.store", store):
                with patch("app.main.socket.getaddrinfo", return_value=[public_address]):
                    with patch("app.main.search_web", search):
                        with patch("app.main.fetch_pages", fetch):
                            response = self.client.post(
                                "/api/analyze/message",
                                json={
                                    "text": "See https://example.com",
                                    "research_links": True,
                                },
                            )

        self.assertEqual(response.status_code, 200)
        search.assert_awaited_once()
        fetch.assert_awaited_once_with(["https://example.com"])

    def test_unrelated_merchant_warning_results_do_not_add_payment_risk(self) -> None:
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Contoso Bank scam warning",
                        "snippet": "Fraud complaints about Contoso Bank.",
                        "url": "https://alerts.example/contoso",
                    }
                ]
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(os.path.join(directory, "payment.sqlite"))
            with patch("app.main.store", store):
                with patch("app.main.search_web", search):
                    response = self.client.post(
                        "/api/analyze/payment",
                        json={"text": "Please review this payment.", "merchant_name": "Example Bank"},
                    )

        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["risk_score"], 0)
        self.assertFalse(
            any(
                item["classification"] == "public_allegation"
                for item in report["indicators"]
            )
        )
        self.assertEqual(report["evidence"][0]["relevance"], "unrelated_not_scored")
        self.assertEqual(report["evidence"][0]["provider"], "TinyFish Search")
        self.assertIn("no merchant-related", " ".join(report["missing_information"]))
        self.assertEqual(report["research_providers"]["search"]["status"], "completed")

    def test_duplicate_payment_allegations_add_only_one_contribution(self) -> None:
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Example Bank fraud complaint",
                        "snippet": "A warning about Example Bank.",
                        "url": "https://alerts.example/example-bank?utm_source=search",
                    },
                    {
                        "title": "Example Bank fraud complaint",
                        "snippet": "A warning about Example Bank.",
                        "url": "https://alerts.example/example-bank",
                    },
                    {
                        "title": "Example Bank scam warning",
                        "snippet": "A separate allegation against Example Bank.",
                        "url": "https://reports.example/example-bank",
                    },
                ]
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(os.path.join(directory, "payment.sqlite"))
            with patch("app.main.store", store):
                with patch("app.main.search_web", search):
                    response = self.client.post(
                        "/api/analyze/payment",
                        json={"text": "Please review this payment.", "merchant_name": "Example Bank"},
                    )

        self.assertEqual(response.status_code, 200)
        report = response.json()
        allegations = [
            item
            for item in report["indicators"]
            if item["classification"] == "public_allegation"
        ]
        self.assertEqual(report["risk_score"], 8)
        self.assertEqual(len(allegations), 1)
        self.assertEqual(allegations[0]["score_contribution"], 8)
        self.assertEqual(len(report["evidence"]), 2)
        self.assertTrue(
            all(item["relevance"] == "merchant_related" for item in report["evidence"])
        )
        self.assertEqual(report["target"], "Payment request: Example Bank")

    def test_payment_allegation_without_a_valid_source_url_is_not_scored(self) -> None:
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Example Bank fraud warning",
                        "snippet": "An allegation about Example Bank.",
                        "url": "javascript:alert(1)",
                    }
                ]
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(os.path.join(directory, "payment.sqlite"))
            with patch("app.main.store", store):
                with patch("app.main.search_web", search):
                    response = self.client.post(
                        "/api/analyze/payment",
                        json={"text": "Please review this payment.", "merchant_name": "Example Bank"},
                    )

        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["evidence"], [])
        self.assertEqual(report["sources"], [])

    def test_dns_lookup_failing_is_rejected(self) -> None:
        from app.main import validate_external_url

        with patch(
            "app.main.socket.getaddrinfo",
            side_effect=socket.gaierror("private detail"),
        ):
            with self.assertRaises(Exception) as context:
                validate_external_url("https://unresolvable.invalid/")

        self.assertNotIn("private detail", str(context.exception))


class AuthRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = InvestigationStore(os.path.join(self.directory.name, "accounts.sqlite"))
        self.store_patch = patch("app.main.store", self.store)
        self.store_patch.start()
        self.addCleanup(self.store_patch.stop)
        app.dependency_overrides.pop(get_current_user, None)
        self.client = TestClient(app)
        self.addCleanup(self.directory.cleanup)

    def register(self, email: str = "analyst@example.com") -> dict[str, object]:
        response = self.client.post(
            "/api/auth/register",
            json={
                "email": email,
                "display_name": "Analyst",
                "password": "a-strong-password-123",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_authentication_protects_investigation_routes(self) -> None:
        self.assertEqual(self.client.get("/api/analytics").status_code, 401)
        account = self.register()
        token = account["access_token"]
        response = self.client.post(
            "/api/analyze/message",
            headers={"Authorization": f"Bearer {token}"},
            json={"text": "Please send your OTP to claim your prize"},
        )
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertNotIn("_owner_id", report)
        self.assertEqual(self.store.get(report["id"], user_id=account["user"]["id"])["id"], report["id"])
        self.assertEqual(self.client.get("/api/history").status_code, 401)

    def test_reports_are_isolated_between_accounts(self) -> None:
        first = self.register("first@example.com")
        second = self.register("second@example.com")
        report = self.client.post(
            "/api/analyze/message",
            headers={"Authorization": f"Bearer {first['access_token']}"},
            json={"text": "An ordinary message"},
        ).json()
        second_headers = {"Authorization": f"Bearer {second['access_token']}"}
        self.assertEqual(self.client.get("/api/history", headers=second_headers).json(), [])
        self.assertEqual(
            self.client.get(f"/api/history/{report['id']}", headers=second_headers).status_code,
            404,
        )

    def test_job_reports_are_isolated_between_accounts(self) -> None:
        first = self.register("first-job@example.com")
        second = self.register("second-job@example.com")
        first_headers = {"Authorization": f"Bearer {first['access_token']}"}
        second_headers = {"Authorization": f"Bearer {second['access_token']}"}
        search = AsyncMock(return_value={"results": []})
        with patch("app.main.search_web", search):
            response = self.client.post(
                "/api/investigations/job",
                headers=first_headers,
                json={
                    "company_name": "Fictional Robotics",
                    "description": "Robotics Intern. Job ID: 123456.",
                },
            )

        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["job_verification"]["submitted_company"], "Fictional Robotics")
        self.assertEqual(self.client.get("/api/history", headers=second_headers).json(), [])
        self.assertEqual(
            self.client.get(
                f"/api/history/{report['id']}",
                headers=second_headers,
            ).status_code,
            404,
        )

    def test_watchlist_and_saved_report_are_owner_scoped(self) -> None:
        first = self.register("first@example.com")
        second = self.register("second@example.com")
        first_headers = {"Authorization": f"Bearer {first['access_token']}"}
        second_headers = {"Authorization": f"Bearer {second['access_token']}"}
        added = self.client.post(
            "/api/watchlist",
            headers=first_headers,
            json={"value": "example.com", "item_type": "domain"},
        )
        self.assertEqual(added.status_code, 201)
        self.assertEqual(self.client.get("/api/watchlist", headers=second_headers).json(), [])
        report = self.client.post(
            "/api/analyze/message",
            headers=first_headers,
            json={"text": "An ordinary message"},
        ).json()
        saved = self.client.put(
            f"/api/saved/{report['id']}",
            headers=first_headers,
            json={"note": "Review later"},
        )
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(self.client.get("/api/saved", headers=first_headers).json()[0]["note"], "Review later")
        self.assertEqual(self.client.get("/api/saved", headers=second_headers).json(), [])

    def test_public_intelligence_requires_consent_for_personal_identifiers(self) -> None:
        account = self.register()
        headers = {"Authorization": f"Bearer {account['access_token']}"}
        search = AsyncMock(return_value={"results": []})
        with patch("app.main.search_web", search):
            rejected = self.client.post(
                "/api/investigations/intelligence",
                headers=headers,
                json={"entity_type": "email", "value": "person@example.com"},
            )
        self.assertEqual(rejected.status_code, 400)
        search.assert_not_awaited()

    def test_public_intelligence_stores_search_evidence_without_a_risk_score(self) -> None:
        account = self.register()
        headers = {"Authorization": f"Bearer {account['access_token']}"}
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Public company page",
                        "snippet": "Company information",
                        "url": "https://example.com/about",
                    },
                    {
                        "title": "Invalid source",
                        "snippet": "Not a safe link",
                        "url": "javascript:alert(1)",
                    },
                ]
            }
        )
        with patch("app.main.search_web", search):
            response = self.client.post(
                "/api/investigations/intelligence",
                headers=headers,
                json={
                    "entity_type": "company",
                    "value": "Example Company",
                },
            )
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["analysis_method"], "evidence_only")
        self.assertEqual(report["risk_category"], "Evidence gathered; not scored")
        self.assertEqual(len(report["evidence"]), 1)
        self.assertEqual(self.store.get(report["id"], user_id=account["user"]["id"])["id"], report["id"])

    def test_history_deletion_is_owner_scoped(self) -> None:
        first = self.register("first@example.com")
        second = self.register("second@example.com")
        report = self.client.post(
            "/api/analyze/message",
            headers={"Authorization": f"Bearer {first['access_token']}"},
            json={"text": "ordinary note"},
        ).json()
        rejected = self.client.delete(
            f"/api/history/{report['id']}",
            headers={"Authorization": f"Bearer {second['access_token']}"},
        )
        self.assertEqual(rejected.status_code, 404)
        accepted = self.client.delete(
            f"/api/history/{report['id']}",
            headers={"Authorization": f"Bearer {first['access_token']}"},
        )
        self.assertEqual(accepted.status_code, 204)

    def test_logout_revokes_the_server_side_session(self) -> None:
        account = self.register()
        headers = {"Authorization": f"Bearer {account['access_token']}"}
        response = self.client.post("/api/auth/logout", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=headers).status_code, 401)

    def test_admin_routes_enforce_role_server_side(self) -> None:
        account = self.register()
        response = self.client.get(
            "/api/admin/analytics",
            headers={"Authorization": f"Bearer {account['access_token']}"},
        )
        self.assertEqual(response.status_code, 403)

    def test_registration_validation_does_not_echo_submitted_values(self) -> None:
        password = "short"
        response = self.client.post(
            "/api/auth/register",
            json={
                "email": "analyst@example.com",
                "display_name": "Analyst",
                "password": password,
            },
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(
            response.json()["detail"],
            "Request input is invalid. Check the provided fields.",
        )
        self.assertNotIn(password, response.text)

    def test_password_change_revokes_old_sessions(self) -> None:
        account = self.register()
        old_headers = {"Authorization": f"Bearer {account['access_token']}"}
        response = self.client.post(
            "/api/auth/password",
            headers=old_headers,
            json={
                "current_password": "a-strong-password-123",
                "new_password": "another-strong-password-456",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=old_headers).status_code, 401)
        login = self.client.post(
            "/api/auth/login",
            json={"email": "analyst@example.com", "password": "another-strong-password-456"},
        )
        self.assertEqual(login.status_code, 200)

    def test_allowlisted_email_does_not_grant_admin_on_public_registration(self) -> None:
        with patch.dict(os.environ, {"SCAMSHIELD_ADMIN_EMAILS": "admin@example.com"}):
            account = self.register("admin@example.com")
        self.assertEqual(account["user"]["role"], "user")
        response = self.client.get(
            "/api/admin/analytics",
            headers={"Authorization": f"Bearer {account['access_token']}"},
        )
        self.assertEqual(response.status_code, 403)

        with self.store._connection() as connection:
            connection.execute(
                "UPDATE users SET role = 'admin' WHERE email = ?",
                ("admin@example.com",),
            )
        response = self.client.get(
            "/api/admin/analytics",
            headers={"Authorization": f"Bearer {account['access_token']}"},
        )
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
