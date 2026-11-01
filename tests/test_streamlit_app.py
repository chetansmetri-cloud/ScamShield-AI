import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest


class FakeResponse:
    status_code = 204
    is_success = True
    content = b""

    @staticmethod
    def json() -> dict[str, str]:
        return {"status": "ok"}


class StreamlitSessionIsolationTests(unittest.TestCase):
    def test_landing_includes_animated_cyber_scene_and_requested_heading(self) -> None:
        app_path = Path(__file__).resolve().parents[1] / "frontend" / "streamlit_app.py"
        app = AppTest.from_file(str(app_path), default_timeout=30)

        with patch("httpx.get", return_value=FakeResponse()):
            app.run()

        self.assertEqual(len(app.exception), 0)
        markup = "\n".join(element.value for element in app.markdown)
        self.assertIn("Your Digital World.", markup)
        self.assertIn("Protected by Intelligence.", markup)
        self.assertIn("ambient-aurora", markup)
        self.assertIn("ambient-particle--field", markup)
        self.assertIn("hero-radar", markup)

    def test_auth_portal_initializes_radio_state_without_exception(self) -> None:
        app_path = Path(__file__).resolve().parents[1] / "frontend" / "streamlit_app.py"
        app = AppTest.from_file(str(app_path), default_timeout=30)

        with patch("httpx.get", return_value=FakeResponse()):
            with patch("httpx.request", return_value=FakeResponse()):
                app.session_state["show_auth_portal"] = True
                app.run()

        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.session_state["auth_mode"], "Sign in")

    def test_create_account_screen_has_confirmation_and_password_requirements(self) -> None:
        app_path = Path(__file__).resolve().parents[1] / "frontend" / "streamlit_app.py"
        app = AppTest.from_file(str(app_path), default_timeout=30)

        with patch("httpx.get", return_value=FakeResponse()):
            with patch("httpx.request", return_value=FakeResponse()):
                app.session_state["show_auth_portal"] = True
                app.session_state["auth_mode"] = "Create account"
                app.run()

        self.assertEqual(len(app.exception), 0)
        input_labels = {element.label for element in app.text_input}
        self.assertIn("Display name", input_labels)
        self.assertIn("Confirm password", input_labels)
        self.assertTrue(any("12+ characters" in item.value for item in app.caption))

    def test_overview_greets_authenticated_user(self) -> None:
        app_path = Path(__file__).resolve().parents[1] / "frontend" / "streamlit_app.py"
        app = AppTest.from_file(str(app_path), default_timeout=30)

        with patch("httpx.get", return_value=FakeResponse()):
            with patch("httpx.request", return_value=FakeResponse()):
                app.session_state["auth_token"] = "test-session"
                app.session_state["account"] = {
                    "id": "test-user",
                    "display_name": "Test Analyst",
                    "role": "user",
                }
                app.session_state["main_navigation"] = "Overview"
                app.run()

        self.assertEqual(len(app.exception), 0)
        self.assertTrue(
            any("Welcome back, Test Analyst." in element.value for element in app.markdown)
        )

    def test_sign_out_clears_previous_users_job_report(self) -> None:
        app_path = Path(__file__).resolve().parents[1] / "frontend" / "streamlit_app.py"
        app = AppTest.from_file(str(app_path), default_timeout=30)

        with patch("httpx.get", return_value=FakeResponse()):
            with patch("httpx.request", return_value=FakeResponse()):
                app.session_state["auth_token"] = "test-session"
                app.session_state["account"] = {
                    "id": "user-a",
                    "display_name": "Test User",
                    "role": "user",
                }
                app.session_state["main_navigation"] = "Job scam detector"
                app.session_state["active_report"] = {
                    "id": "microsoft-report",
                    "created_at": "2026-10-31T00:00:00+00:00",
                    "investigation_type": "job",
                    "target": "Microsoft",
                    "risk_score": 0,
                    "risk_category": "Insufficient evidence",
                    "risk_assessment_status": "insufficient_evidence",
                    "risk_indicator_band": "Low risk indicators",
                    "confidence": "limited",
                    "information_completeness": "partial",
                    "analysis_method": "rule_based",
                    "live_research": "partial",
                    "scoring_explanation": "No matching warning rules were found.",
                    "job_verification": {
                        "submitted_company": "Microsoft",
                        "submitted_offer_url": "https://careers.microsoft.example/job/123456",
                        "final_fetched_url": None,
                        "exact_listing_status": "page_unavailable_or_access_limited",
                        "official_careers_domain_status": "not_verified",
                        "company_status": "not_independently_verified",
                        "offer_domain_status": "not_verified",
                        "hosting_status": "not_verified",
                        "recruitment_platform": None,
                        "research_providers": {},
                        "recruiter": {},
                        "explanation": "The listing could not be verified.",
                    },
                    "indicators": [],
                    "positive_indicators": [],
                    "evidence": [],
                    "missing_information": ["The listing could not be verified."],
                    "recommended_next_steps": ["Check the employer's careers site."],
                    "disclaimer": "Screening aid only.",
                }
                app.session_state["active_report_mode"] = "Offer"
                app.run()

                self.assertEqual(len(app.exception), 0)
                self.assertIn("active_report", app.session_state)
                self.assertTrue(
                    any(
                        "does not support a low-risk conclusion" in element.value
                        for element in app.caption
                    )
                )

                sign_out = [
                    button
                    for button in app.sidebar.button
                    if button.label == "Sign out"
                ]
                self.assertEqual(len(sign_out), 1)
                sign_out[0].click().run()

        self.assertNotIn("auth_token", app.session_state)
        self.assertNotIn("active_report", app.session_state)
        self.assertNotIn("active_report_mode", app.session_state)
        self.assertEqual(len(app.exception), 0)

    def test_advanced_screens_load_without_streamlit_exceptions(self) -> None:
        app_path = Path(__file__).resolve().parents[1] / "frontend" / "streamlit_app.py"
        pages = [
            "Job scam detector",
            "Email scam detection",
            "Screenshot analyzer",
            "QR scanner",
            "AI security assistant",
            "Batch URL investigation",
            "Watchlist",
            "Scam alerts",
        ]
        for page in pages:
            with self.subTest(page=page):
                app = AppTest.from_file(str(app_path), default_timeout=30)
                with patch("httpx.get", return_value=FakeResponse()):
                    with patch("httpx.request", return_value=FakeResponse()):
                        app.session_state["auth_token"] = "test-session"
                        app.session_state["account"] = {
                            "id": "test-user",
                            "display_name": "Test User",
                            "role": "user",
                        }
                        app.session_state["main_navigation"] = page
                        app.run()
                self.assertEqual(len(app.exception), 0)

    def test_batch_renders_multiple_reports_with_repeated_charts(self) -> None:
        app_path = Path(__file__).resolve().parents[1] / "frontend" / "streamlit_app.py"
        app = AppTest.from_file(str(app_path), default_timeout=30)
        urls = ["https://first.example", "https://second.example"]

        def make_report(report_id: str, url: str) -> dict[str, object]:
            return {
                "id": report_id,
                "created_at": "2026-10-31T00:00:00+00:00",
                "investigation_type": "website",
                "target": url,
                "risk_score": 0,
                "risk_category": "Insufficient evidence",
                "risk_assessment_status": "insufficient_evidence",
                "risk_indicator_band": "Insufficient evidence",
                "confidence": "limited",
                "information_completeness": "partial",
                "analysis_method": "rule_based",
                "live_research": "partial",
                "scoring_explanation": "No warning rules matched.",
                "disclaimer": "Screening aid only.",
                "indicators": [
                    {
                        "name": "Example signal",
                        "explanation": "A test rule matched.",
                        "evidence": "Test evidence.",
                        "score_contribution": 8,
                        "classification": "inference",
                        "severity": "low",
                    }
                ],
                "positive_indicators": [],
                "evidence": [],
                "sources": [],
                "missing_information": [],
                "recommended_next_steps": [],
            }

        app.session_state["auth_token"] = "test-session"
        app.session_state["account"] = {
            "id": "test-user",
            "display_name": "Test User",
            "role": "user",
        }
        app.session_state["main_navigation"] = "Batch URL investigation"
        app.session_state["batch_result"] = {
            "summary": {"total": 2, "completed": 2, "failed": 0, "duplicates": 0},
            "results": [
                {
                    "submitted_url": url,
                    "status": "completed",
                    "report": make_report(f"report-{index}", url),
                }
                for index, url in enumerate(urls)
            ],
        }

        with patch("httpx.get", return_value=FakeResponse()):
            with patch("httpx.request", return_value=FakeResponse()):
                app.run()

        self.assertEqual(len(app.exception), 0)
