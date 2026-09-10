import unittest

from fastapi.testclient import TestClient

from app import Config, FailedAuthLockout, SlidingWindowRateLimiter, create_app, new_mailbox


class MailboxGeneratorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = Config("admin", "password", "example.test", "domain", "https://mail.example.test/jmap/", "token", "https://admin.example.test")
        self.client = TestClient(create_app(self.config))

    def test_random_mailbox_has_expected_shape(self) -> None:
        name, password = new_mailbox()
        self.assertRegex(name, r"^icr-[a-f0-9]{12}$")
        self.assertRegex(password, r"^[A-Za-z0-9_-]{32}$")

    def test_post_requires_matching_origin(self) -> None:
        response = self.client.post("/api/mailboxes", auth=("admin", "password"), headers={"Origin": "https://wrong.example.test"})
        self.assertEqual(response.status_code, 403)

    def test_missing_credentials_returns_basic_auth_challenge(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["WWW-Authenticate"], "Basic")
        self.assertEqual(response.json()["detail"], "authentication_required")

    def test_security_headers_are_present(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_auth_requests_are_rate_limited_per_ip(self) -> None:
        for _ in range(10):
            self.assertEqual(self.client.get("/", auth=("admin", "password")).status_code, 200)
        response = self.client.get("/", auth=("admin", "password"))
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json()["detail"], "authentication_rate_limited")
        self.assertIn("Retry-After", response.headers)

    def test_failed_auth_is_locked_out_without_leaking_credentials(self) -> None:
        for _ in range(5):
            response = self.client.get("/", auth=("admin", "wrong-password"))
        self.assertEqual(response.status_code, 401)
        self.assertIn("Retry-After", response.headers)
        locked = self.client.get("/", auth=("admin", "wrong-password"))
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
