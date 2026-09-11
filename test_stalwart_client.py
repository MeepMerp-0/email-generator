import json
import unittest

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from stalwart_client import StalwartClient, StalwartError, create_account_router


class StalwartClientTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.requests: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            self.requests.append(body)
            method = body["methodCalls"][0][0]
            if method == "x:Account/query":
                return httpx.Response(200, json={"methodResponses": [[method, {"ids": ["a1"]}, "c1"]]})
            if method == "x:Account/get":
                return httpx.Response(200, json={"methodResponses": [[method, {"list": [{"id": "a1", "name": "alice"}]}, "c1"]]})
            if method == "x:Account/set":
                args = body["methodCalls"][0][1]
                if "create" in args:
                    return httpx.Response(200, json={"methodResponses": [[method, {"created": {"new": {"id": "a1"}}}, "c1"]]})
                if "destroy" in args:
                    return httpx.Response(200, json={"methodResponses": [[method, {"destroyed": ["a1"]}, "c1"]]})
                return httpx.Response(200, json={"methodResponses": [[method, {"updated": {"a1": {"id": "a1"}}}, "c1"]]})
            return httpx.Response(400)

        self.client = StalwartClient("https://mail.test/api", "secret", transport=httpx.MockTransport(handler))

    async def test_list_search_create_update_password_and_delete(self) -> None:
        self.assertEqual(await self.client.search_accounts("ali", "domain"), [{"id": "a1", "name": "alice"}])
        await self.client.create_mailbox("alice", "password", "domain", description="A", quotas={"maxDiskQuota": 1})
        await self.client.update_account("a1", description="B", quotas={"maxDiskQuota": 2})
        await self.client.change_password("a1", "new-password")
        await self.client.delete_account("a1")
        self.assertEqual([request["methodCalls"][0][0] for request in self.requests], [
            "x:Account/query", "x:Account/get", "x:Account/set", "x:Account/set", "x:Account/set", "x:Account/set",
        ])
        create = self.requests[2]["methodCalls"][0][1]["create"]["new"]
        self.assertEqual(create["credentials"]["0"]["secret"], "password")
        self.assertEqual(self.requests[4]["methodCalls"][0][1]["update"]["a1"]["credentials"]["0"]["secret"], "new-password")

    async def test_jmap_error_does_not_leak_response_details(self) -> None:
        def error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"methodResponses": [["error", {"type": "forbidden", "description": "secret"}, "c1"]]})

        client = StalwartClient("https://mail.test/api", "secret", transport=httpx.MockTransport(error_handler))
        with self.assertRaisesRegex(StalwartError, "jmap_forbidden"):
            await client.list_accounts()

    async def test_updates_accept_stalwart_null_success_values(self) -> None:
        def null_update(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"methodResponses": [["x:Account/set", {"updated": {"a1": None}}, "c1"]]})

        client = StalwartClient("https://mail.test/api", "secret", transport=httpx.MockTransport(null_update))
        self.assertEqual((await client.update_account("a1", description="new"))["id"], "a1")
        self.assertEqual((await client.change_password("a1", "new"))["id"], "a1")


class AccountRouterTest(unittest.TestCase):
    def test_router_exposes_account_management(self) -> None:
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(json.loads(request.content))
            method = requests[-1]["methodCalls"][0][0]
            if method == "x:Account/query":
                result = {"accountIds": []}
            elif method == "x:Account/set":
                result = {"updated": {"a1": {"id": "a1"}}}
            else:
                result = {}
            return httpx.Response(200, json={"methodResponses": [[method, result, "c1"]]})

        app = FastAPI()
        app.include_router(create_account_router(StalwartClient("https://mail.test/api", "secret", transport=httpx.MockTransport(handler))))
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/accounts").status_code, 200)
            self.assertEqual(client.patch("/api/accounts/a1", json={"description": "new"}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
