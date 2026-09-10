import unittest

from fastapi.testclient import TestClient

from app import Config, create_app, new_mailbox


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


if __name__ == "__main__":
    unittest.main()
