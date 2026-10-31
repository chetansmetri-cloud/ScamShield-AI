import unittest
from unittest.mock import AsyncMock

from app.evidence import (
    canonicalize_url,
    company_evidence_is_relevant,
    deduplicate_url_items,
    deduplicate_urls,
    domain_evidence_is_relevant,
    domain_matches_url,
    text_mentions_domain,
)
from app.investigations import investigate_job, investigate_website


class EvidenceRelevanceTests(unittest.IsolatedAsyncioTestCase):
    async def test_unrelated_warning_result_does_not_change_website_score(self) -> None:
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Fraud warning about a different site",
                        "snippet": "Users report a scam at unrelated.test.",
                        "url": "https://news.example.net/report",
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
                        "text": "Welcome to our website.",
                    }
                ],
                "errors": [],
            }
        )

        report = await investigate_website(
            "https://example.com",
            search,
            fetch,
        )

        self.assertEqual(report["risk_score"], 0)
        self.assertFalse(report["indicators"])
        self.assertEqual(report["evidence"][0]["relevance"], "unrelated_not_scored")
        self.assertEqual(report["live_research"], "partial")

    async def test_relevant_public_allegation_is_labeled_and_low_contribution(self) -> None:
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Warning: example.com",
                        "snippet": "A forum post alleges suspicious activity.",
                        "url": "https://forum.example.net/post/1",
                    }
                ]
            }
        )
        fetch = AsyncMock(return_value={"results": [], "errors": []})

        report = await investigate_website("https://example.com", search, fetch)

        self.assertEqual(report["risk_score"], 8)
        self.assertEqual(len(report["indicators"]), 1)
        self.assertEqual(report["indicators"][0]["classification"], "public_allegation")
        self.assertNotIn("fraudulent", report["risk_category"].lower())

    async def test_redirected_page_content_is_not_scored(self) -> None:
        search = AsyncMock(return_value={"results": []})
        fetch = AsyncMock(
            return_value={
                "results": [
                    {
                        "url": "https://example.com",
                        "final_url": "https://unrelated.test/landing",
                        "title": "External destination",
                        "text": "Send your password immediately.",
                    }
                ],
                "errors": [],
            }
        )

        report = await investigate_website("https://example.com", search, fetch)

        self.assertEqual(report["risk_score"], 0)
        self.assertFalse(report["indicators"])
        self.assertTrue(report["evidence"][0]["redirect_detected"])
        self.assertEqual(
            report["evidence"][0]["relevance"],
            "redirected_to_other_domain_not_scored",
        )
        self.assertTrue(any("different final domain" in item for item in report["missing_information"]))

    async def test_unrelated_job_search_warning_does_not_add_risk(self) -> None:
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Scam warning involving another company",
                        "snippet": "A different organization is reported.",
                        "url": "https://news.example.net/report",
                    }
                ]
            }
        )

        report = await investigate_job(
            company_name="Acme Holdings",
            description="A standard role description.",
            recruiter_contact=None,
            offer_url=None,
            search=search,
            fetch=AsyncMock(),
        )

        self.assertEqual(report["risk_score"], 0)
        self.assertFalse(report["indicators"])
        self.assertEqual(report["evidence"][0]["relevance"], "unrelated_not_scored")

    async def test_relevant_job_allegation_is_explicitly_classified(self) -> None:
        search = AsyncMock(
            return_value={
                "results": [
                    {
                        "title": "Acme Holdings recruitment warning",
                        "snippet": "A public post alleges a recruitment scam.",
                        "url": "https://news.example.net/report",
                    }
                ]
            }
        )

        report = await investigate_job(
            company_name="Acme Holdings",
            description="A standard role description.",
            recruiter_contact=None,
            offer_url=None,
            search=search,
            fetch=AsyncMock(),
        )

        self.assertEqual(report["risk_score"], 8)
        self.assertEqual(report["indicators"][0]["classification"], "public_allegation")


class EvidenceNormalizationTests(unittest.TestCase):
    def test_canonical_url_removes_fragments_defaults_and_tracking(self) -> None:
        self.assertEqual(
            canonicalize_url(
                "HTTPS://Example.COM:443/path?utm_source=news&id=2#section"
            ),
            "https://example.com/path?id=2",
        )

    def test_canonical_url_rejects_credentials_and_unsupported_schemes(self) -> None:
        self.assertIsNone(canonicalize_url("javascript:alert(1)"))
        self.assertIsNone(canonicalize_url("https://user:pass@example.com/"))

    def test_domain_match_is_exact_or_a_subdomain_not_a_suffix_attack(self) -> None:
        self.assertTrue(domain_matches_url("https://example.com", "https://www.example.com/a"))
        self.assertTrue(domain_matches_url("https://example.com", "https://shop.example.com"))
        self.assertFalse(domain_matches_url("https://example.com", "https://badexample.com"))
        self.assertFalse(domain_matches_url("https://example.com", "https://example.com.evil.test"))

    def test_text_domain_match_requires_domain_boundaries(self) -> None:
        self.assertTrue(text_mentions_domain("Report about example.com.", "https://example.com"))
        self.assertFalse(text_mentions_domain("Report about badexample.com.", "https://example.com"))
        self.assertFalse(text_mentions_domain("example.com.evil.test", "https://example.com"))
        self.assertTrue(text_mentions_domain("Report about shop.example.com.", "https://example.com"))

    def test_domain_relevance_uses_exact_target_reference(self) -> None:
        self.assertTrue(
            domain_evidence_is_relevant(
                "https://example.com",
                source_url="https://news.test/story",
                title="example.com review",
                snippet="A discussion.",
            )
        )
        self.assertFalse(
            domain_evidence_is_relevant(
                "https://example.com",
                source_url="https://news.test/story",
                title="badexample.com review",
                snippet="A discussion.",
            )
        )

    def test_company_relevance_requires_exact_name_or_offer_domain(self) -> None:
        self.assertTrue(
            company_evidence_is_relevant(
                "Acme Holdings",
                title="Acme Holdings warning",
                snippet="",
                source_url="https://news.test/story",
                offer_url=None,
            )
        )
        self.assertFalse(
            company_evidence_is_relevant(
                "Acme Holdings",
                title="Acme competitor warning",
                snippet="",
                source_url="https://news.test/story",
                offer_url=None,
            )
        )
        self.assertTrue(
            company_evidence_is_relevant(
                "Acme Holdings",
                title="Careers page",
                snippet="",
                source_url="https://careers.acme.test/job",
                offer_url="https://acme.test/offer",
            )
        )

    def test_duplicate_urls_merge_tracking_and_fragments(self) -> None:
        items = deduplicate_url_items(
            [
                {
                    "url": "https://example.com/?utm_source=search#top",
                    "source_type": "search_result",
                    "provider": "TinyFish Search",
                    "excerpt": "Search snippet",
                },
                {
                    "url": "https://example.com/",
                    "source_type": "fetched_page",
                    "provider": "TinyFish Fetch",
                    "excerpt": "Fetched content",
                },
            ]
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["source_type"], "search_result_and_fetched_page")
        self.assertEqual(items[0]["search_excerpt"], "Search snippet")
        self.assertEqual(items[0]["providers"], ["TinyFish Search", "TinyFish Fetch"])
        self.assertEqual(
            deduplicate_urls(
                [
                    "https://example.com/?utm_source=search#top",
                    "https://example.com/",
                ]
            ),
            ["https://example.com/?utm_source=search#top"],
        )
