import unittest

from frontend.api_client import authorization_headers


class AuthorizationHeaderTests(unittest.TestCase):
    def test_builds_bearer_header_without_logging_or_transforming_token(self) -> None:
        headers = authorization_headers("session-token", {"Accept": "application/json"})

        self.assertEqual(headers["Authorization"], "Bearer session-token")
        self.assertEqual(headers["Accept"], "application/json")

    def test_removes_stale_authorization_when_signed_out(self) -> None:
        headers = authorization_headers(
            None,
            {"Authorization": "Bearer stale-token", "Accept": "application/json"},
        )

        self.assertNotIn("Authorization", headers)
        self.assertEqual(headers["Accept"], "application/json")
