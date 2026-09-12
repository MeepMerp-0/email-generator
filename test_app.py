import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app import Config, FailedAuthLockout, SlidingWindowRateLimiter, create_app, new_password, page


class MailboxGeneratorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = Config("admin", "password", "example.test", "domain", "https://mail.example.test/jmap/", "token", "https://admin.example.test")
        self.client = TestClient(create_app(self.config), base_url="https://testserver")

    def test_generated_password_has_expected_shape(self) -> None:
        password = new_password()
        self.assertRegex(password, r"^[A-Za-z0-9_-]{32}$")

    def test_post_requires_matching_origin(self) -> None:
        self.client.post("/login", data={"password": "password"})
        response = self.client.post("/api/mailboxes", headers={"Origin": "https://wrong.example.test"})
        self.assertEqual(response.status_code, 403)

    def test_create_mailbox_requires_and_saves_name_and_address(self) -> None:
        self.client.post("/login", data={"password": "password"})
        with patch("app.provision", new_callable=AsyncMock, return_value={"email": "alex@example.test", "password": "generated"}) as provision:
            response = self.client.post("/api/mailboxes", headers={"Origin": "https://admin.example.test"}, json={"name": "Alex Smith", "mailboxAddress": "alex"})
        self.assertEqual(response.status_code, 201)
        provision.assert_awaited_once_with(self.config, "alex", "Alex Smith")

    def test_create_mailbox_rejects_missing_required_fields(self) -> None:
        self.client.post("/login", data={"password": "password"})
        response = self.client.post("/api/mailboxes", headers={"Origin": "https://admin.example.test"}, json={"name": "", "mailboxAddress": ""})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"], "name_and_mailbox_address_required")

    def test_mailbox_ui_uses_name_labels(self) -> None:
        rendered = page("example.test")
        self.assertIn('id="mailbox-display-name"', rendered)
        self.assertIn('@example.test', rendered)
        self.assertIn("No name", rendered)

    def test_missing_credentials_redirects_to_password_login(self) -> None:
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], "/login")

    def test_password_login_sets_secure_session_cookie(self) -> None:
        response = self.client.post("/login", data={"password": "password"}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("icr_admin_session=", response.headers["set-cookie"])
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertIn("Secure", response.headers["set-cookie"])

    def test_api_requires_password_session(self) -> None:
        response = self.client.get("/api/accounts")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "authentication_required")
        self.assertEqual(self.client.get("/api/dns-health").status_code, 401)

    def test_authenticated_session_is_not_throttled_by_page_requests(self) -> None:
        self.client.post("/login", data={"password": "password"})
        for _ in range(20):
            self.assertNotEqual(self.client.get("/").status_code, 429)

    def test_security_headers_are_present(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_auth_requests_are_rate_limited_per_ip(self) -> None:
        for _ in range(10):
            self.assertEqual(self.client.get("/", follow_redirects=False).status_code, 307)
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json()["detail"], "authentication_rate_limited")
        self.assertIn("Retry-After", response.headers)

    def test_failed_auth_is_locked_out_without_leaking_credentials(self) -> None:
        for _ in range(5):
            response = self.client.post("/login", data={"password": "wrong-password"})
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)
        locked = self.client.post("/login", data={"password": "wrong-password"})
        self.assertEqual(locked.status_code, 429)
        self.assertNotIn("wrong-password", locked.text)
        self.assertNotIn("token", locked.text)

    def test_secret_fields_are_hidden_from_config_repr(self) -> None:
        rendered = repr(self.config)
        self.assertNotIn("password", rendered)
        self.assertNotIn("token", rendered)


class SecurityPrimitiveTest(unittest.TestCase):
    def test_sliding_window_expires_old_events(self) -> None:
        now = [0.0]
        limiter = SlidingWindowRateLimiter(1, 10, clock=lambda: now[0])
        self.assertEqual(limiter.allow("ip"), (True, 0))
        self.assertEqual(limiter.allow("ip")[0], False)
        now[0] = 10.0
        self.assertEqual(limiter.allow("ip"), (True, 0))

    def test_failed_auth_lockout_backoff_expires(self) -> None:
        now = [0.0]
        lockout = FailedAuthLockout(2, 10, clock=lambda: now[0])
        self.assertEqual(lockout.record_failure("credential"), 0)
        self.assertEqual(lockout.record_failure("credential"), 10)
        self.assertEqual(lockout.retry_after("credential"), 10)
        now[0] = 10.0
        self.assertEqual(lockout.retry_after("credential"), 0)


if __name__ == "__main__":
    unittest.main()
