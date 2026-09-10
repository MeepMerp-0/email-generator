"""Small async client for Stalwart's management JMAP API."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

JMAP_USING = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]
ACCOUNT_FIELDS = [
    "id",
    "name",
    "emailAddress",
    "domainId",
    "description",
    "quotas",
    "usedDiskQuota",
    "createdAt",
]
_MISSING = object()


class StalwartError(RuntimeError):
    """An upstream HTTP or JMAP error."""


class StalwartClient:
    def __init__(
        self,
        jmap_url: str,
        api_key: str,
        *,
        timeout: float = 15.0,
        client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if client is not None and transport is not None:
            raise ValueError("client_and_transport_are_mutually_exclusive")
        self.jmap_url = jmap_url
        self.api_key = api_key
        self.timeout = timeout
        self._client = client
        self._transport = transport

    async def _call(self, method: str, arguments: Mapping[str, Any], call_id: str = "c1") -> dict[str, Any]:
        payload = {"using": JMAP_USING, "methodCalls": [[method, dict(arguments), call_id]]}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            if self._client is not None:
                response = await self._client.post(self.jmap_url, headers=headers, json=payload)
            else:
                async with httpx.AsyncClient(timeout=self.timeout, transport=self._transport) as client:
                    response = await client.post(self.jmap_url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            raise StalwartError("upstream_unavailable") from exc
        if response.is_error:
            raise StalwartError(f"upstream_http_{response.status_code}")
        try:
            body = response.json()
            method_response = body["methodResponses"][0]
            result = method_response[1]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise StalwartError("invalid_jmap_response") from exc
        if method_response[0] == "error":
            error_type = result.get("type", "request_failed") if isinstance(result, dict) else "request_failed"
            raise StalwartError(f"jmap_{error_type}")
        if method_response[0] != method or not isinstance(result, dict):
            raise StalwartError("invalid_jmap_response")
        return result

    async def list_accounts(self, search: str | None = None, domain_id: str | None = None) -> list[dict[str, Any]]:
        filters: list[dict[str, Any]] = []
        if search:
            filters.append({"text": search})
        if domain_id:
            filters.append({"domainId": domain_id})
        account_filter: dict[str, Any] = {}
        if len(filters) == 1:
            account_filter = filters[0]
        elif filters:
            account_filter = {"operator": "AND", "conditions": filters}
        query = await self._call("x:Account/query", {"filter": account_filter})
        account_ids = query.get("accountIds", [])
        if not isinstance(account_ids, list):
            raise StalwartError("invalid_account_query_response")
        if not account_ids:
            return []
        result = await self._call(
            "x:Account/get",
            {"ids": account_ids, "properties": ACCOUNT_FIELDS},
        )
        accounts = result.get("list", [])
        if not isinstance(accounts, list):
            raise StalwartError("invalid_account_get_response")
        return accounts

    async def search_accounts(self, search: str, domain_id: str | None = None) -> list[dict[str, Any]]:
        return await self.list_accounts(search=search, domain_id=domain_id)

    async def create_account(
        self,
        name: str,
        password: str,
        domain_id: str,
        *,
        description: str | None = None,
        quotas: Mapping[str, int] | None = None,
    ) -> dict[str, Any]:
        self._validate_account_input(name, password, domain_id)
        normalized_quotas = self._validate_quotas(quotas)
        account: dict[str, Any] = {
            "@type": "User",
            "name": name,
            "domainId": domain_id,
            "aliases": {},
            "credentials": {"0": {"@type": "Password", "secret": password, "allowedIps": {}}},
            "encryptionAtRest": {"@type": "Disabled"},
            "memberGroupIds": {},
            "permissions": {"@type": "Inherit"},
            "quotas": normalized_quotas,
            "roles": {"@type": "User"},
        }
        if description is not None:
            account["description"] = description
        result = await self._call("x:Account/set", {"create": {"new": account}})
        created = result.get("created", {}).get("new")
        if not isinstance(created, dict) or not created.get("id"):
            raise StalwartError("account_creation_failed")
        return created

    async def create_mailbox(
        self,
        name: str,
        password: str,
        domain_id: str,
        *,
        description: str | None = None,
        quotas: Mapping[str, int] | None = None,
    ) -> dict[str, Any]:
        return await self.create_account(
            name,
            password,
            domain_id,
            description=description,
            quotas=quotas,
        )

    async def update_account(
        self,
        account_id: str,
        *,
        description: str | None | object = _MISSING,
        quotas: Mapping[str, int] | None | object = _MISSING,
    ) -> dict[str, Any]:
        if not account_id:
            raise ValueError("account_id_required")
        fields: dict[str, Any] = {}
        if description is not _MISSING:
            if description is not None and not isinstance(description, str):
                raise ValueError("description_must_be_string_or_null")
            fields["description"] = description
        if quotas is not _MISSING:
            fields["quotas"] = self._validate_quotas(quotas)
        if not fields:
            raise ValueError("account_update_requires_description_or_quotas")
        result = await self._call("x:Account/set", {"update": {account_id: fields}})
        updated = result.get("updated", {}).get(account_id)
        if not isinstance(updated, dict):
            raise StalwartError("account_update_failed")
        return updated

    async def change_password(self, account_id: str, new_password: str) -> dict[str, Any]:
        if not account_id:
            raise ValueError("account_id_required")
        if not isinstance(new_password, str) or not new_password:
            raise ValueError("password_required")
        result = await self._call(
            "x:Account/set",
            {
                "update": {
                    account_id: {
                        "credentials": {"0": {"@type": "Password", "secret": new_password}}
                    }
                }
            },
        )
        updated = result.get("updated", {}).get(account_id)
        if not isinstance(updated, dict):
            raise StalwartError("password_change_failed")
        return updated

    async def delete_account(self, account_id: str) -> None:
        if not account_id:
            raise ValueError("account_id_required")
        result = await self._call("x:Account/set", {"destroy": [account_id]})
        destroyed = result.get("destroyed", [])
        if account_id not in destroyed:
            raise StalwartError("account_deletion_failed")

    @staticmethod
    def _validate_account_input(name: str, password: str, domain_id: str) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("account_name_required")
        if not isinstance(password, str) or not password:
            raise ValueError("password_required")
        if not isinstance(domain_id, str) or not domain_id.strip():
            raise ValueError("domain_id_required")

    @staticmethod
    def _validate_quotas(quotas: Mapping[str, int] | None | object) -> dict[str, int]:
        if quotas is None or quotas is _MISSING:
            return {}
        if not isinstance(quotas, Mapping):
            raise ValueError("quotas_must_be_an_object")
        if any(not isinstance(key, str) or not key for key in quotas):
            raise ValueError("quota_names_must_be_nonempty_strings")
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in quotas.values()):
            raise ValueError("quota_values_must_be_nonnegative_integers")
        return dict(quotas)


class AccountCreateRequest(BaseModel):
    name: str
    password: str
    domain_id: str
    description: str | None = None
    quotas: dict[str, int] = Field(default_factory=dict)


class AccountUpdateRequest(BaseModel):
    description: str | None = None
    quotas: dict[str, int] | None = None


class PasswordChangeRequest(BaseModel):
    new_password: str


def create_account_router(
    client: StalwartClient,
    *,
    prefix: str = "/api/accounts",
    dependencies: Sequence[Any] = (),
) -> APIRouter:
    """Build account-management routes; callers supply authentication dependencies."""
    router = APIRouter(prefix=prefix, dependencies=list(dependencies))

    @router.get("")
    async def list_accounts(
        search: str | None = Query(default=None, max_length=200),
        domain_id: str | None = Query(default=None, max_length=200),
    ) -> list[dict[str, Any]]:
        try:
            return await client.list_accounts(search=search, domain_id=domain_id)
        except StalwartError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="stalwart_request_failed") from exc

    @router.post("", status_code=status.HTTP_201_CREATED)
    async def create_account(request: AccountCreateRequest) -> dict[str, Any]:
        try:
            return await client.create_account(
                request.name,
                request.password,
                request.domain_id,
                description=request.description,
                quotas=request.quotas,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        except StalwartError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="stalwart_request_failed") from exc

    @router.patch("/{account_id}")
    async def update_account(account_id: str, request: AccountUpdateRequest) -> dict[str, Any]:
        fields = getattr(request, "model_fields_set", getattr(request, "__fields_set__", set()))
        if not fields:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="account_update_required")
        try:
            return await client.update_account(
                account_id,
                description=request.description if "description" in fields else _MISSING,
                quotas=request.quotas if "quotas" in fields else _MISSING,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        except StalwartError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="stalwart_request_failed") from exc

    @router.post("/{account_id}/password")
    async def change_password(account_id: str, request: PasswordChangeRequest) -> Response:
        try:
            await client.change_password(account_id, request.new_password)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        except StalwartError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="stalwart_request_failed") from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_account(account_id: str) -> Response:
        try:
            await client.delete_account(account_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        except StalwartError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="stalwart_request_failed") from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router
