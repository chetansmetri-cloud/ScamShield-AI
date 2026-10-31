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
