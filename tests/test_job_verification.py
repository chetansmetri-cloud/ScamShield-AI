import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.database import InvestigationStore
from app.main import app, get_current_user
from app.investigations import investigate_job


class JobVerificationTests(unittest.IsolatedAsyncioTestCase):
    async def investigate(
        self,
        *,
        company: str = "Acme Robotics",
        description: str = "Robotics Intern role, job ID 123456.",
        offer_url: str | None = "https://careers.acmerobotics.test/jobs/123456",
        recruiter: str | None = None,
        search_results: list[dict[str, str]] | None = None,
        fetch_results: list[dict[str, str]] | None = None,
        fetch_errors: list[dict[str, str]] | None = None,
    ) -> tuple[dict[str, object], AsyncMock, AsyncMock]:
        search = AsyncMock(return_value={"results": search_results or []})
        fetch = AsyncMock(
            return_value={
                "results": fetch_results or [],
                "errors": fetch_errors or [],
            }
        )
        report = await investigate_job(
            company_name=company,
            description=description,
            recruiter_contact=recruiter,
            offer_url=offer_url,
            search=search,
            fetch=fetch,
        )
        return report, search, fetch

    def page(
        self,
        *,
        url: str = "https://careers.acmerobotics.test/jobs/123456",
        final_url: str | None = None,
        title: str = "Robotics Intern - Acme Robotics",
        text: str = "Acme Robotics is hiring a Robotics Intern. Job ID: 123456. Build robot prototypes.",
    ) -> dict[str, str]:
        return {
            "url": url,
            "final_url": final_url or url,
            "title": title,
            "text": text,
        }

    async def test_genuine_company_listing_is_fetched_and_details_are_checked(self) -> None:
        offer_url = "https://careers.acmerobotics.test/jobs/123456"
        report, _, fetch = await self.investigate(
            offer_url=offer_url,
            search_results=[
                {
                    "title": "Acme Robotics careers",
                    "snippet": "Robotics Intern, job 123456",
                    "url": offer_url,
                }
            ],
            fetch_results=[self.page(url=offer_url)],
        )

        self.assertEqual(fetch.await_args.args[0], [offer_url])
        verification = report["job_verification"]
        self.assertEqual(verification["submitted_offer_url"], offer_url)
        self.assertEqual(verification["final_fetched_url"], offer_url)
        self.assertEqual(verification["exact_listing_status"], "page_details_match_not_officially_verified")
        self.assertEqual(verification["job_id"], "123456")
        self.assertTrue(verification["company_name_match"])
        self.assertTrue(verification["role_details_match"])
        self.assertEqual(verification["official_careers_domain_status"], "not_independently_verified")
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["risk_category"], "Insufficient evidence")
        self.assertEqual(report["risk_assessment_status"], "insufficient_evidence")
        self.assertIn("not lower the score", report["positive_indicators"][0]["explanation"])

    async def test_google_listing_fields_are_extracted_without_claiming_domain_ownership(self) -> None:
        offer_url = "https://careers.google.com/jobs/results/123456"
        report, _, _ = await self.investigate(
            company="Google",
            description="Software Engineer, Cloud Infrastructure. Job ID: 123456.",
            offer_url=offer_url,
            fetch_results=[{
                "url": offer_url,
                "final_url": offer_url,
                "title": "Google Careers",
                "text": "Google is hiring a Software Engineer, Cloud Infrastructure. Job ID: 123456.",
                "company_name": "Google",
                "job_title": "Software Engineer, Cloud Infrastructure",
                "job_id": "123456",
                "job_description": "Build cloud infrastructure.",
                "application_instructions": "Apply through the careers portal.",
                "application_url": "https://careers.google.com/apply/123456",
            }],
        )

        verification = report["job_verification"]
        self.assertEqual(verification["submitted_company"], "Google")
        self.assertEqual(verification["submitted_offer_url"], offer_url)
        self.assertEqual(verification["job_title"], "Software Engineer, Cloud Infrastructure")
        self.assertEqual(verification["job_id"], "123456")
        self.assertTrue(verification["job_id_match"])
        self.assertEqual(verification["job_description"], "Build cloud infrastructure.")
        self.assertEqual(verification["application_details"], "Apply through the careers portal.")
        self.assertEqual(verification["application_url"], "https://careers.google.com/apply/123456")
        self.assertEqual(verification["official_careers_domain_status"], "not_independently_verified")
        self.assertEqual(report["evidence"][0]["provider"], "TinyFish Fetch")

    async def test_microsoft_listing_matches_submitted_title_and_job_id(self) -> None:
        offer_url = "https://jobs.careers.microsoft.com/global/en/job/123456"
        report, _, _ = await self.investigate(
            company="Microsoft",
            description="Software Engineer, Cloud Infrastructure. Job ID: 123456.",
            offer_url=offer_url,
            fetch_results=[{
                "url": offer_url,
                "final_url": offer_url,
                "title": "Microsoft Careers",
                "text": "Microsoft is hiring a Software Engineer, Cloud Infrastructure. Job ID: 123456.",
                "company": "Microsoft",
                "job_title": "Software Engineer, Cloud Infrastructure",
                "job_id": "123456",
            }],
        )

        verification = report["job_verification"]
        self.assertTrue(verification["company_name_match"])
        self.assertTrue(verification["role_details_match"])
        self.assertTrue(verification["job_id_match"])
        self.assertEqual(
            verification["exact_listing_status"],
            "page_details_match_not_officially_verified",
        )
        self.assertEqual(verification["official_careers_domain_status"], "not_independently_verified")

    async def test_recognized_third_party_platform_can_verify_listing_details_neutrally(self) -> None:
        offer_url = "https://jobs.acmerobotics.test/openings/123456"
        final_url = "https://boards.greenhouse.io/acmerobotics/jobs/123456"
        report, _, _ = await self.investigate(
            offer_url=offer_url,
            fetch_results=[{
                "url": offer_url,
                "final_url": final_url,
                "title": "Robotics Intern",
                "text": "Acme Robotics Robotics Intern. Job ID: 123456.",
                "company": "Acme Robotics",
                "job_title": "Robotics Intern",
                "job_id": "123456",
            }],
        )

        verification = report["job_verification"]
        self.assertEqual(verification["recruitment_platform"], "Greenhouse")
        self.assertEqual(
            verification["exact_listing_status"],
            "page_details_match_not_officially_verified",
        )
        self.assertTrue(verification["redirect_detected"])
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["evidence"][0]["relevance"], "target_related")
        self.assertIn(
            "recognized Greenhouse recruitment platform",
            report["positive_indicators"][0]["explanation"],
        )

    async def test_job_id_in_offer_description_is_compared_when_url_has_no_id(self) -> None:
        offer_url = "https://careers.acmerobotics.test/openings/robotics-intern"
        report, _, _ = await self.investigate(
            description="Robotics Intern role. Job ID: 123456.",
            offer_url=offer_url,
            fetch_results=[{
                "url": offer_url,
                "final_url": offer_url,
                "title": "Robotics Intern",
                "text": "Company: Acme Robotics\nJob Title: Robotics Intern\nJob ID: 123456",
            }],
        )

        verification = report["job_verification"]
        self.assertEqual(verification["submitted_job_id"], "123456")
        self.assertEqual(verification["job_id"], "123456")
        self.assertTrue(verification["job_id_match"])

    async def test_internship_listing_is_not_mislabeled_as_a_job_mismatch(self) -> None:
        url = "https://jobs.orbitlabs.test/intern/987654"
        page = self.page(
            url=url,
            title="Data Science Intern - Orbit Labs",
            text="Orbit Labs internship. Data Science Intern program. Job ID 987654.",
        )
        report, _, _ = await self.investigate(
            company="Orbit Labs",
            description="Data Science Intern internship program, job ID 987654.",
            offer_url=url,
            fetch_results=[page],
        )

        verification = report["job_verification"]
        self.assertEqual(verification["exact_listing_status"], "page_details_match_not_officially_verified")
        self.assertTrue(verification["role_details_match"])
        self.assertEqual(verification["job_id"], "987654")

    async def test_impersonation_like_page_is_not_treated_as_official_from_brand_name(self) -> None:
        url = "https://amazon-careers-apply.example.net/jobs/123456"
        page = self.page(
            url=url,
            title="Software Engineer - Amazon",
            text="Amazon Software Engineer role. Job ID: 123456.",
        )
        report, _, _ = await self.investigate(
            company="Amazon",
            description="Software Engineer position, job ID 123456.",
            offer_url=url,
            fetch_results=[page],
        )

        verification = report["job_verification"]
        self.assertEqual(verification["official_careers_domain_status"], "not_independently_verified")
        self.assertEqual(
            verification["offer_domain_status"],
            "brand_in_unverified_subdomain",
        )
        self.assertEqual(verification["exact_listing_status"], "page_details_match_not_officially_verified")
        self.assertEqual(report["risk_score"], 12)
        self.assertEqual(report["risk_category"], "Insufficient evidence")
        self.assertFalse(any("official" in item["name"].casefold() for item in report["positive_indicators"]))

    async def test_real_company_name_does_not_offset_a_registration_fee_rule(self) -> None:
        report, _, _ = await self.investigate(
            company="Acme Robotics",
            description="Pay registration fee immediately to start this Robotics Intern role.",
            offer_url=None,
        )

        self.assertEqual(report["risk_score"], 37)
        names = {item["name"] for item in report["indicators"]}
        self.assertIn("Advance payment request", names)
        self.assertIn("Urgent pressure", names)
        self.assertEqual(report["risk_category"], "Some concerns")

    async def test_guaranteed_internship_without_interview_and_training_fee_is_flagged(self) -> None:
        report, _, _ = await self.investigate(
            company="Orbit Labs",
            description=(
                "Guaranteed internship placement with no interview or selection process. "
                "Pay the training fee before your direct joining."
            ),
            offer_url=None,
        )

        names = {item["name"] for item in report["indicators"]}
        self.assertIn("Guaranteed placement claim", names)
        self.assertIn("Advance payment request", names)
        self.assertIn("Hiring process bypassed despite unusual promises", names)
        self.assertGreaterEqual(report["risk_score"], 50)

    async def test_same_fee_signal_in_offer_and_page_is_scored_once(self) -> None:
        offer_url = "https://careers.acmerobotics.test/jobs/123456"
        report, _, _ = await self.investigate(
            description="Robotics Intern role 123456. Pay registration fee.",
            offer_url=offer_url,
            fetch_results=[
                self.page(
                    url=offer_url,
                    text="Acme Robotics Robotics Intern. Job ID: 123456. Pay registration fee.",
                )
            ],
        )

        fee_indicators = [
            item for item in report["indicators"]
            if item["name"] == "Advance payment request"
        ]
        self.assertEqual(len(fee_indicators), 1)
        self.assertEqual(report["risk_score"], 25)

    async def test_unrelated_offer_domain_is_not_verified_by_famous_company_name(self) -> None:
        url = "https://unrelated-careers.example.net/req/567890"
        report, _, _ = await self.investigate(
            company="Amazon",
            description="Software Engineer role, job ID 567890.",
            offer_url=url,
            search_results=[
                {
                    "title": "Amazon software engineering jobs",
                    "snippet": "Generic Amazon careers and hiring information",
                    "url": "https://www.amazon.jobs/en/",
                }
            ],
            fetch_results=[
                self.page(
                    url=url,
                    title="Software Engineer - Amazon",
                    text="Amazon Software Engineer position, job ID 567890.",
                )
            ],
        )

        self.assertEqual(report["job_verification"]["official_careers_domain_status"], "not_independently_verified")
        self.assertEqual(
            report["job_verification"]["offer_domain_status"],
            "host_does_not_identify_company_domain_unverified",
        )
        self.assertEqual(report["evidence"][0]["evidence_scope"], "company_level_not_listing_verification")
        self.assertFalse(any(
            item.get("source_type") == "search_result"
            and item.get("evidence_scope") == "listing_reference_not_verified"
            for item in report["evidence"]
        ))

    async def test_mismatched_fetched_role_is_not_scored_as_the_submitted_job(self) -> None:
        offer_url = "https://careers.acmerobotics.test/jobs/123456"
        report, _, _ = await self.investigate(
            description="Robotics Intern role 123456.",
            fetch_results=[
                self.page(
                    url=offer_url,
                    title="Data Scientist - Acme Robotics",
                    text="Acme Robotics Data Scientist. Pay registration fee immediately.",
                )
            ],
        )

        self.assertEqual(report["job_verification"]["exact_listing_status"], "page_details_mismatch")
        self.assertFalse(report["job_verification"]["role_details_match"])
        self.assertEqual(report["risk_score"], 0)
        self.assertFalse(any(item["name"] == "Advance payment request" for item in report["indicators"]))

    async def test_fetched_company_mismatch_is_reported(self) -> None:
        offer_url = "https://careers.acmerobotics.test/jobs/123456"
        report, _, _ = await self.investigate(
            offer_url=offer_url,
            fetch_results=[{
                "url": offer_url,
                "final_url": offer_url,
                "title": "Robotics Intern",
                "text": "Other Systems is hiring a Robotics Intern. Job ID: 123456.",
                "company_name": "Other Systems",
                "job_title": "Robotics Intern",
                "job_id": "123456",
            }],
        )

        verification = report["job_verification"]
        self.assertFalse(verification["company_name_match"])
        self.assertEqual(verification["page_company"], "Other Systems")
        self.assertEqual(verification["exact_listing_status"], "page_details_mismatch")
        self.assertEqual(report["risk_score"], 0)

    async def test_fetched_job_id_mismatch_is_reported(self) -> None:
        offer_url = "https://careers.acmerobotics.test/jobs/123456"
        report, _, _ = await self.investigate(
            offer_url=offer_url,
            fetch_results=[{
                "url": offer_url,
                "final_url": offer_url,
                "title": "Robotics Intern",
                "text": "Acme Robotics Robotics Intern. Job ID: 654321.",
                "company_name": "Acme Robotics",
                "job_title": "Robotics Intern",
                "job_id": "654321",
            }],
        )

        verification = report["job_verification"]
        self.assertEqual(verification["submitted_job_id"], "123456")
        self.assertEqual(verification["job_id"], "654321")
        self.assertFalse(verification["job_id_match"])
        self.assertEqual(verification["exact_listing_status"], "page_details_mismatch")

    async def test_generic_company_search_does_not_verify_the_job_listing(self) -> None:
        report, _, fetch = await self.investigate(
            search_results=[
                {
                    "title": "Acme Robotics official careers",
                    "snippet": "Explore career opportunities at Acme Robotics.",
                    "url": "https://careers.acmerobotics.test/",
                }
            ]
        )

        fetch.assert_awaited_once_with(["https://careers.acmerobotics.test/jobs/123456"])
        self.assertEqual(report["job_verification"]["exact_listing_status"], "page_unavailable_or_access_limited")
        self.assertFalse(report["positive_indicators"])
        self.assertEqual(report["live_research"], "partial")
        self.assertTrue(any("not evidence that the submitted job listing is genuine" in item for item in report["missing_information"]))

    async def test_unrelated_company_search_result_is_retained_but_not_scored(self) -> None:
        report, _, _ = await self.investigate(
            company="Acme Robotics",
            search_results=[{
                "title": "Amazon software engineering jobs",
                "snippet": "Amazon careers and hiring information.",
                "url": "https://www.amazon.jobs/",
            }],
        )

        self.assertEqual(report["evidence"][0]["relevance"], "unrelated_not_scored")
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["job_verification"]["exact_listing_status"], "page_unavailable_or_access_limited")

    async def test_unrecognized_redirect_content_is_not_used_to_verify_or_score_listing(self) -> None:
        offer_url = "https://careers.acmerobotics.test/jobs/123456"
        report, _, _ = await self.investigate(
            offer_url=offer_url,
            fetch_results=[self.page(
                url=offer_url,
                final_url="https://unrecognized.example.net/jobs/123456",
                text="Acme Robotics Robotics Intern. Job ID: 123456. Pay registration fee.",
            )],
        )

        self.assertEqual(
            report["job_verification"]["exact_listing_status"],
            "redirected_to_different_domain",
        )
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["evidence"][0]["relevance"], "redirected_to_other_domain_not_scored")

    async def test_missing_page_description_is_reported_without_claiming_it_was_extracted(self) -> None:
        offer_url = "https://careers.acmerobotics.test/jobs/123456"
        report, _, _ = await self.investigate(
            offer_url=offer_url,
            fetch_results=[{
                "url": offer_url,
                "final_url": offer_url,
                "title": "Robotics Intern",
                "text": "Company: Acme Robotics\nJob Title: Robotics Intern\nJob ID: 123456",
            }],
        )

        verification = report["job_verification"]
        self.assertEqual(verification["page_company"], "Acme Robotics")
        self.assertEqual(verification["job_title"], "Robotics Intern")
        self.assertEqual(verification["job_id"], "123456")
        self.assertIsNone(verification["job_description"])
        self.assertEqual(verification["exact_listing_status"], "page_details_match_not_officially_verified")

    async def test_per_url_fetch_failure_is_reported_without_penalizing_missing_evidence(self) -> None:
        report, _, _ = await self.investigate(
            fetch_errors=[{"url": "https://careers.acmerobotics.test/jobs/123456", "error": "access denied"}]
        )

        self.assertEqual(report["job_verification"]["exact_listing_status"], "fetch_failed")
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["live_research"], "partial")
        self.assertTrue(any("per-URL fetch errors" in item for item in report["missing_information"]))

    async def test_free_recruiter_email_is_a_low_weight_unverified_warning(self) -> None:
        report, _, _ = await self.investigate(recruiter="recruiter@gmail.com")

        recruiter = report["job_verification"]["recruiter"]
        self.assertEqual(recruiter["status"], "free_email_provider_warning")
        self.assertEqual(recruiter["email_domain"], "gmail.com")
        self.assertEqual(report["risk_score"], 6)
        self.assertIn("does not establish fraud", recruiter["explanation"])

    async def test_company_like_recruiter_domain_is_not_assumed_genuine(self) -> None:
        report, _, _ = await self.investigate(
            recruiter="recruiter@acmerobotics-careers.example",
        )

        recruiter = report["job_verification"]["recruiter"]
        self.assertEqual(recruiter["status"], "domain_differs_from_offer_site_unverified")
        mismatch_indicator = next(
            item
            for item in report["indicators"]
            if item["name"] == "Recruiter email domain differs from offer site"
        )
        self.assertEqual(mismatch_indicator["score_contribution"], 0)
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["confidence"], "limited")

    async def test_sequential_jobs_keep_evidence_scoped_to_the_current_offer(self) -> None:
        first_url = "https://jobs.careers.microsoft.com/global/en/job/123456"
        first, _, _ = await self.investigate(
            company="Microsoft",
            description="Software Engineer role, job ID 123456.",
            offer_url=first_url,
            fetch_results=[self.page(
                url=first_url,
                title="Software Engineer - Microsoft",
                text="Microsoft is hiring a Software Engineer. Job ID: 123456.",
            )],
            search_results=[{
                "title": "Microsoft careers",
                "snippet": "Software Engineer role, job 123456.",
                "url": first_url,
            }],
        )

        second_url = "https://jobs.fictionalcompany.test/roles/987654"
        second, _, _ = await self.investigate(
            company="Fictional Company",
            description="Data Science Intern, job ID 987654.",
            offer_url=second_url,
            fetch_results=[self.page(
                url=second_url,
                title="Data Science Intern - Fictional Company",
                text="Fictional Company Data Science Intern. Job ID 987654.",
            )],
            search_results=[{
                "title": "Fictional Company Data Science Intern",
                "snippet": "A current internship listing.",
                "url": second_url,
            }],
        )

        self.assertTrue(all("microsoft" not in source for source in second["sources"]))
        self.assertTrue(all("microsoft" not in item.get("excerpt", "").casefold() for item in second["evidence"]))
        self.assertEqual(first["job_verification"]["submitted_offer_url"], first_url)
        self.assertEqual(second["job_verification"]["submitted_offer_url"], second_url)

    async def test_amazon_evidence_does_not_leak_into_a_later_unrelated_investigation(self) -> None:
        amazon_url = "https://amazon.jobs/en/jobs/123456"
        await self.investigate(
            company="Amazon",
            description="Software Engineer role, job ID 123456.",
            offer_url=amazon_url,
            fetch_results=[self.page(
                url=amazon_url,
                title="Software Engineer - Amazon",
                text="Amazon is hiring a Software Engineer. Job ID: 123456.",
            )],
            search_results=[{
                "title": "Amazon software engineering jobs",
                "snippet": "Amazon careers and hiring information.",
                "url": amazon_url,
            }],
        )

        fictional_report, _, _ = await self.investigate(
            company="Fictional Company",
            description="Data Science Intern role, job ID 987654.",
            offer_url="https://careers.fictionalcompany.test/jobs/987654",
        )

        self.assertEqual(fictional_report["target"], "Fictional Company")
        self.assertTrue(all("amazon" not in source.casefold() for source in fictional_report["sources"]))
        self.assertTrue(all(
            "amazon" not in str(item.get("excerpt", "")).casefold()
            for item in fictional_report["evidence"]
        ))

    async def test_provider_failure_propagates_instead_of_creating_a_success_report(self) -> None:
        search = AsyncMock(side_effect=HTTPException(status_code=502, detail="TinyFish request failed."))
        fetch = AsyncMock(return_value={"results": [], "errors": []})

        with self.assertRaises(HTTPException) as raised:
            await investigate_job(
                company_name="Acme Robotics",
                description="Robotics Intern, job ID 123456.",
                recruiter_contact=None,
                offer_url="https://careers.acmerobotics.test/jobs/123456",
                search=search,
                fetch=fetch,
            )

        self.assertEqual(raised.exception.status_code, 502)
        search.assert_awaited_once()
        fetch.assert_awaited_once_with(["https://careers.acmerobotics.test/jobs/123456"])


class JobInvestigationRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = InvestigationStore(os.path.join(self.directory.name, "jobs.sqlite"))
        self.store_patch = patch("app.main.store", self.store)
        self.store_patch.start()
        self.addCleanup(self.store_patch.stop)
        app.dependency_overrides[get_current_user] = lambda: {
            "id": "job-test-user",
            "email": "jobs@example.test",
            "display_name": "Job Test",
            "role": "user",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        self.addCleanup(app.dependency_overrides.pop, get_current_user, None)
        self.client = TestClient(app)
        self.addCleanup(self.directory.cleanup)

    def test_invalid_non_public_offer_url_is_rejected(self) -> None:
        with patch("app.main.search_web", new_callable=AsyncMock) as search:
            response = self.client.post(
                "/api/investigations/job",
                json={
                    "company_name": "Acme Robotics",
                    "description": "Robotics Intern.",
                    "offer_url": "http://127.0.0.1/admin",
                },
            )

        self.assertEqual(response.status_code, 422)
        search.assert_not_awaited()
        self.assertEqual(self.store.list_recent(user_id="job-test-user"), [])

    def test_job_route_sends_the_exact_offer_url_to_fetch(self) -> None:
        offer_url = "https://careers.acmerobotics.test/jobs/123456"
        search = AsyncMock(return_value={
            "results": [{
                "title": "Acme Robotics careers",
                "snippet": "Robotics Intern role 123456.",
                "url": offer_url,
            }]
        })
        fetch = AsyncMock(return_value={
            "results": [{
                "url": offer_url,
                "final_url": offer_url,
                "title": "Robotics Intern - Acme Robotics",
                "text": "Acme Robotics Robotics Intern. Job ID: 123456.",
            }],
            "errors": [],
        })
        public_address = (2, 1, 6, "", ("93.184.216.34", 443))
        with patch("app.main.socket.getaddrinfo", return_value=[public_address]):
            with patch("app.main.search_web", search):
                with patch("app.main.fetch_pages", fetch):
                    response = self.client.post(
                        "/api/investigations/job",
                        json={
                            "company_name": "Acme Robotics",
                            "description": "Robotics Intern role 123456.",
                            "offer_url": offer_url,
                        },
                    )

        self.assertEqual(response.status_code, 200)
        search.assert_awaited_once()
        self.assertIn(offer_url, search.await_args.args[0])
        fetch.assert_awaited_once_with([offer_url])
        self.assertEqual(
            response.json()["job_verification"]["submitted_offer_url"],
            offer_url,
        )
        self.assertEqual(len(self.store.list_recent(user_id="job-test-user")), 1)

    def test_provider_failure_returns_error_without_saving_a_report(self) -> None:
        search = AsyncMock(side_effect=HTTPException(
            status_code=502,
            detail="TinyFish request failed with HTTP 503.",
        ))
        fetch = AsyncMock(return_value={"results": [], "errors": []})
        public_address = (2, 1, 6, "", ("93.184.216.34", 443))
        with patch("app.main.socket.getaddrinfo", return_value=[public_address]):
            with patch("app.main.search_web", search):
                with patch("app.main.fetch_pages", fetch):
                    response = self.client.post(
                        "/api/investigations/job",
                        json={
                            "company_name": "Acme Robotics",
                            "description": "Robotics Intern role.",
                            "offer_url": "https://careers.acmerobotics.test/jobs/123456",
                        },
                    )

        self.assertEqual(response.status_code, 502)
        search.assert_awaited_once()
        fetch.assert_awaited_once()
        self.assertEqual(self.store.list_recent(user_id="job-test-user"), [])
