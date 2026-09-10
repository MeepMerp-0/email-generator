import base64
import html
import logging
import os
import secrets
from dataclasses import dataclass

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

security = HTTPBasic(auto_error=False)
logger = logging.getLogger("email-generator")


@dataclass(frozen=True)
class Config:
    admin_username: str
    admin_password: str
    domain: str
    domain_id: str
    jmap_url: str
    api_key: str
    public_origin: str

    @property
    def configured(self) -> bool:
        return all((self.admin_username, self.admin_password, self.domain, self.domain_id, self.jmap_url, self.api_key, self.public_origin))


def load_config() -> Config:
    return Config(
        admin_username=os.getenv("ADMIN_USERNAME", ""),
        admin_password=os.getenv("ADMIN_PASSWORD", ""),
        domain=os.getenv("MAIL_DOMAIN", "innercirclerealtors.cloud"),
        domain_id=os.getenv("STALWART_DOMAIN_ID", ""),
        jmap_url=os.getenv("STALWART_JMAP_URL", ""),
        api_key=os.getenv("STALWART_API_KEY", ""),
        public_origin=os.getenv("PUBLIC_ORIGIN", ""),
    )


def new_mailbox() -> tuple[str, str]:
    return f"icr-{secrets.token_hex(6)}", base64.urlsafe_b64encode(secrets.token_bytes(24)).rstrip(b"=").decode()


async def provision(config: Config) -> dict[str, str]:
    if not config.configured:
        raise RuntimeError("service_not_configured")
    name, password = new_mailbox()
    payload = {
        "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
        "methodCalls": [["x:Account/set", {"create": {"mailbox": {
            "@type": "User", "name": name, "domainId": config.domain_id,
            "aliases": {},
            "credentials": [{"@type": "Password", "secret": password, "allowedIps": []}],
            "encryptionAtRest": {"@type": "Disabled"}, "memberGroupIds": {},
            "permissions": {"@type": "Inherit"}, "quotas": {}, "roles": {"@type": "User"},
        }}}, "mailbox-create"]],
    }
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(config.jmap_url, headers={"Authorization": f"Bearer {config.api_key}"}, json=payload)
    if response.is_error:
        raise RuntimeError("upstream_unavailable")
    method_responses = response.json().get("methodResponses", [])
    result = method_responses[0][1] if method_responses else {}
    if not result.get("created", {}).get("mailbox", {}).get("id"):
        raise RuntimeError("mailbox_creation_failed")
    return {"email": f"{name}@{config.domain}", "password": password}


def page(domain: str) -> str:
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mailbox generator</title><style>body{{max-width:42rem;margin:10vh auto;padding:1.5rem;font:16px system-ui;background:#111827;color:#f9fafb}}main{{padding:2rem;border:1px solid #374151;border-radius:1rem}}button{{padding:.8rem 1rem;border:0;border-radius:.5rem;background:#e11d48;color:white;font-weight:700;cursor:pointer}}pre{{overflow-wrap:anywhere;white-space:pre-wrap;background:#030712;padding:1rem;border-radius:.5rem}}p{{color:#d1d5db}}</style><main><h1>Generate mailbox</h1><p>Creates a random address at {html.escape(domain)}. The password is shown once and is not stored here.</p><button id="generate">Generate mailbox</button><pre id="result" aria-live="polite"></pre></main><script>document.querySelector('#generate').onclick=async()=>{{const b=document.querySelector('button'),r=document.querySelector('#result');b.disabled=true;r.textContent='Creating…';try{{const x=await fetch('/api/mailboxes',{{method:'POST'}}),j=await x.json();if(!x.ok)throw Error('Unable to create mailbox');r.textContent='Email: '+j.email+'\\nPassword: '+j.password}}catch(e){{r.textContent=e.message}}finally{{b.disabled=false}}}};</script></html>'''


def create_app(config: Config | None = None) -> FastAPI:
    config = config or load_config()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def require_admin(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
        valid = credentials and secrets.compare_digest(credentials.username, config.admin_username) and secrets.compare_digest(credentials.password, config.admin_password)
        if not valid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication_required", headers={"WWW-Authenticate": "Basic"})

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "configured": config.configured}, headers={"Cache-Control": "no-store"})

    @app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
    async def home() -> HTMLResponse:
        return HTMLResponse(page(config.domain), headers={"Cache-Control": "no-store"})

    @app.post("/api/mailboxes", dependencies=[Depends(require_admin)])
    async def create_mailbox(request: Request) -> JSONResponse:
        if request.headers.get("origin") != config.public_origin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="origin_not_allowed")
        try:
            created = await provision(config)
        except Exception:
            logger.exception("Mailbox provisioning failed")
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="mailbox_creation_failed") from None
        return JSONResponse(created, status_code=status.HTTP_201_CREATED, headers={"Cache-Control": "no-store"})

    return app


app = create_app()
