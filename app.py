import base64
import html
import logging
import os
import secrets
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from math import ceil
from threading import Lock
from time import monotonic
from typing import Callable
from urllib.parse import parse_qs

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from stalwart_client import StalwartClient, create_account_router

logger = logging.getLogger("email-generator")

AUTH_RATE_LIMIT = 10
AUTH_RATE_WINDOW_SECONDS = 60.0
AUTH_FAILURE_LIMIT = 5
AUTH_LOCKOUT_SECONDS = 300.0
SESSION_TTL_SECONDS = 8 * 60 * 60


class SlidingWindowRateLimiter:
    """Small per-process limiter for the protected HTTP boundary.

    ponytail: per-process state, use a shared store such as Redis if multiple
    workers or instances need one global limit.
    """

    def __init__(self, limit: int, window_seconds: float, clock: Callable[[], float] = monotonic) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock
        self._events: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        now = self.clock()
        with self._lock:
            events = self._events[key]
            while events and events[0] <= now - self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                return False, max(1, ceil(events[0] + self.window_seconds - now))
            events.append(now)
            return True, 0


class FailedAuthLockout:
    def __init__(self, failure_limit: int, lockout_seconds: float, clock: Callable[[], float] = monotonic) -> None:
        self.failure_limit = failure_limit
        self.lockout_seconds = lockout_seconds
        self.clock = clock
        self._failures: dict[str, tuple[int, float]] = {}
        self._lock = Lock()

    def retry_after(self, key: str) -> int:
        now = self.clock()
        with self._lock:
            state = self._failures.get(key)
            if not state or state[1] <= now:
                return 0
            return max(1, ceil(state[1] - now))

    def record_failure(self, key: str) -> int:
        now = self.clock()
        with self._lock:
            failures, _ = self._failures.get(key, (0, 0.0))
            failures += 1
            if failures < self.failure_limit:
                self._failures[key] = (failures, 0.0)
                return 0
            delay = min(self.lockout_seconds * 2 ** (failures - self.failure_limit), 3600.0)
            self._failures[key] = (failures, now + delay)
            return ceil(delay)

    def clear(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


@dataclass(frozen=True)
class Config:
    admin_username: str
    admin_password: str = field(repr=False)
    domain: str
    domain_id: str
    jmap_url: str = field(repr=False)
    api_key: str = field(repr=False)
    public_origin: str

    @property
    def configured(self) -> bool:
        return all((self.admin_password, self.domain, self.domain_id, self.jmap_url, self.api_key, self.public_origin))


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


async def provision(config: Config, requested_name: str = "", display_name: str = "") -> dict[str, str]:
    if not config.configured:
        raise RuntimeError("service_not_configured")
    name = requested_name.strip().lower() or new_mailbox()[0]
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?", name):
        raise ValueError("invalid_mailbox_name")
    password = new_mailbox()[1]
    account = {
        "@type": "User", "name": name, "domainId": config.domain_id,
        "aliases": {},
        "credentials": {"0": {"@type": "Password", "secret": password, "allowedIps": {}}},
        "encryptionAtRest": {"@type": "Disabled"}, "memberGroupIds": {},
        "permissions": {"@type": "Inherit"}, "quotas": {}, "roles": {"@type": "User"},
    }
    if display_name := display_name.strip():
        account["description"] = display_name[:200]
    payload = {
        "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
        "methodCalls": [["x:Account/set", {"create": {"mailbox": account}}, "mailbox-create"]],
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
    template = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0b1220">
  <title>Mailbox operations</title>
  <style>
    :root {
      color-scheme: dark;
      --ink: #e8edf7;
      --muted: #8995aa;
      --line: rgba(148, 163, 184, .15);
      --panel: rgba(19, 30, 51, .78);
      --panel-strong: #15233d;
      --canvas: #0b1220;
      --accent: #8b7cff;
      --accent-2: #5eead4;
      --danger: #fb7185;
      --radius: 18px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-width: 320px;
      background: radial-gradient(circle at 78% -10%, #273b69 0, transparent 35%), var(--canvas);
      color: var(--ink);
      font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    button, input { font: inherit; }
    button { cursor: pointer; }
    button:disabled { cursor: not-allowed; opacity: .55; }
    .shell { display: grid; grid-template-columns: 252px minmax(0, 1fr); min-height: 100vh; }
    .sidebar { display: flex; flex-direction: column; gap: 30px; padding: 28px 18px 20px; border-right: 1px solid var(--line); background: rgba(8, 15, 28, .72); }
    .brand { display: flex; align-items: center; gap: 11px; padding: 0 10px; color: #fff; font-weight: 750; letter-spacing: -.02em; }
    .brand-mark { display: grid; width: 34px; height: 34px; place-items: center; border-radius: 11px; background: linear-gradient(145deg, var(--accent), #4d67dc); box-shadow: 0 8px 25px rgba(112, 104, 255, .3); }
    .brand-mark svg { width: 19px; }
    .brand small { display: block; color: var(--muted); font-size: 10px; font-weight: 500; letter-spacing: .08em; text-transform: uppercase; }
    nav { display: grid; gap: 6px; }
    .nav-item { display: flex; align-items: center; gap: 12px; width: 100%; padding: 11px 12px; border: 0; border-radius: 11px; color: var(--muted); background: transparent; text-align: left; transition: .2s ease; }
    .nav-item:hover, .nav-item.active { color: var(--ink); background: rgba(139, 124, 255, .13); }
    .nav-item.active { box-shadow: inset 2px 0 var(--accent); }
    .nav-item svg { width: 17px; height: 17px; flex: 0 0 auto; }
    .side-note { margin-top: auto; padding: 14px; border: 1px solid var(--line); border-radius: 14px; background: linear-gradient(150deg, rgba(94, 234, 212, .08), rgba(139, 124, 255, .08)); }
    .side-note p { margin: 5px 0 0; color: var(--muted); font-size: 12px; }
    .side-note strong { color: var(--accent-2); font-size: 12px; }
    .content { width: min(1440px, 100%); margin: 0 auto; padding: 29px clamp(20px, 4vw, 58px) 56px; }
    .topbar { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 35px; }
    .kicker { margin: 0 0 6px; color: var(--accent-2); font-size: 11px; font-weight: 700; letter-spacing: .15em; text-transform: uppercase; }
    h1, h2, h3, p { margin-top: 0; }
    h1 { margin-bottom: 7px; font-size: clamp(25px, 3vw, 34px); line-height: 1.1; letter-spacing: -.045em; }
    .lede { max-width: 570px; margin-bottom: 0; color: var(--muted); }
    .operator { display: flex; align-items: center; gap: 11px; color: var(--muted); white-space: nowrap; }
    .avatar { display: grid; width: 35px; height: 35px; place-items: center; border: 1px solid rgba(139, 124, 255, .45); border-radius: 50%; color: #fff; background: #1c2a48; font-weight: 700; }
    .hero { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 18px; margin-bottom: 18px; }
    .card { border: 1px solid var(--line); border-radius: var(--radius); background: var(--panel); box-shadow: 0 18px 50px rgba(0, 0, 0, .12); }
    .hero-card { position: relative; overflow: hidden; min-height: 224px; padding: 30px; background: linear-gradient(120deg, rgba(56, 72, 150, .75), rgba(23, 35, 62, .86) 60%, rgba(22, 45, 68, .78)); }
    .hero-card::after { position: absolute; right: -40px; bottom: -95px; width: 300px; height: 300px; border: 1px solid rgba(94, 234, 212, .18); border-radius: 50%; box-shadow: 0 0 0 32px rgba(94, 234, 212, .04), 0 0 0 64px rgba(94, 234, 212, .03); content: ""; }
    .hero-card h2 { max-width: 490px; margin-bottom: 10px; font-size: clamp(21px, 2.5vw, 29px); line-height: 1.16; letter-spacing: -.035em; }
    .hero-card p { max-width: 520px; margin-bottom: 24px; color: #b7c1d4; }
    .mailbox-name { width: min(100%, 360px); height: 41px; margin-bottom: 12px; padding: 0 13px; border: 1px solid var(--line); border-radius: 10px; outline: 0; color: var(--ink); background: rgba(255, 255, 255, .04); }
    .mailbox-name:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(139, 124, 255, .14); }
    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; min-height: 41px; padding: 0 16px; border: 1px solid transparent; border-radius: 10px; color: #fff; background: var(--accent); font-weight: 700; transition: transform .2s, background .2s; }
    .btn:hover { transform: translateY(-1px); background: #9b8eff; }
    .btn.secondary { border-color: var(--line); color: var(--ink); background: rgba(255, 255, 255, .04); }
    .btn.secondary:hover { background: rgba(255, 255, 255, .09); }
    .status-card { padding: 22px; }
    .status-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; }
    .status-head h3 { margin: 0; font-size: 14px; }
    .pulse { width: 9px; height: 9px; border-radius: 50%; background: var(--accent-2); box-shadow: 0 0 0 5px rgba(94, 234, 212, .12); }
    .status-card strong { display: block; margin-bottom: 5px; font-size: 21px; letter-spacing: -.03em; }
    .status-card span { color: var(--muted); font-size: 12px; }
    .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 13px; margin-bottom: 25px; }
    .metric { padding: 18px 19px; }
    .metric-label { display: flex; align-items: center; justify-content: space-between; color: var(--muted); font-size: 12px; }
    .metric-value { display: block; margin: 15px 0 4px; font-size: 25px; letter-spacing: -.05em; }
    .metric-note { color: var(--muted); font-size: 11px; }
    .metric-note.ready { color: var(--accent-2); }
    .lower-grid { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(280px, .75fr); gap: 18px; }
    .panel { padding: 22px; }
    .panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; margin-bottom: 20px; }
    .panel h2 { margin-bottom: 4px; font-size: 16px; letter-spacing: -.02em; }
    .panel-subtitle { margin: 0; color: var(--muted); font-size: 12px; }
    .text-link { border: 0; color: var(--accent-2); background: none; font-size: 12px; font-weight: 700; }
    .activity { display: grid; gap: 2px; }
    .activity-row { display: flex; align-items: center; gap: 12px; padding: 13px 0; border-bottom: 1px solid var(--line); }
    .activity-row:last-child { border: 0; }
    .activity-icon { display: grid; width: 31px; height: 31px; place-items: center; border-radius: 10px; color: var(--accent-2); background: rgba(94, 234, 212, .1); }
    .activity-row p { margin: 0; font-size: 13px; }
    .activity-row small { display: block; margin-top: 2px; color: var(--muted); font-size: 11px; }
    .activity-row time { margin-left: auto; color: var(--muted); font-size: 11px; }
    .actions { display: grid; gap: 9px; }
    .action { display: flex; align-items: center; gap: 12px; width: 100%; padding: 12px; border: 1px solid var(--line); border-radius: 12px; color: var(--ink); background: rgba(255, 255, 255, .025); text-align: left; }
    .action:hover { border-color: rgba(139, 124, 255, .55); background: rgba(139, 124, 255, .08); }
    .action-icon { display: grid; width: 29px; height: 29px; place-items: center; border-radius: 8px; color: var(--accent); background: rgba(139, 124, 255, .12); }
    .action strong { display: block; font-size: 12px; }
    .action small { color: var(--muted); font-size: 11px; }
    .view { display: none; }
    .view.active { display: block; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; }
    .search { position: relative; flex: 1 1 240px; }
    .search svg { position: absolute; top: 12px; left: 13px; width: 16px; color: var(--muted); }
    .search input { width: 100%; height: 41px; padding: 0 13px 0 39px; border: 1px solid var(--line); border-radius: 10px; outline: 0; color: var(--ink); background: rgba(255, 255, 255, .04); }
    .search input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(139, 124, 255, .14); }
    .table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 13px; }
    .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
    table { width: 100%; min-width: 680px; border-collapse: collapse; text-align: left; }
    th { padding: 12px 15px; color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; background: rgba(255, 255, 255, .025); }
    td { padding: 14px 15px; border-top: 1px solid var(--line); font-size: 12px; }
    .row-actions { display: flex; gap: 6px; }
    .table-action { padding: 5px 8px; border: 1px solid var(--line); border-radius: 6px; color: var(--muted); background: transparent; font-size: 10px; }
    .table-action:hover { border-color: var(--accent); color: var(--ink); }
    .empty { padding: 54px 20px; color: var(--muted); text-align: center; }
    .empty svg { width: 35px; margin-bottom: 11px; color: var(--accent); }
    .empty strong { display: block; margin-bottom: 4px; color: var(--ink); }
    .tag { display: inline-flex; padding: 4px 8px; border-radius: 99px; color: var(--accent-2); background: rgba(94, 234, 212, .1); font-size: 10px; font-weight: 700; }
    .settings-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
    .setting { padding: 21px; }
    .setting h3 { margin-bottom: 4px; font-size: 15px; }
    .setting p { margin-bottom: 16px; color: var(--muted); font-size: 12px; }
    code { padding: 3px 6px; border-radius: 5px; color: #c8c2ff; background: rgba(139, 124, 255, .12); font-size: 11px; }
    .toast { position: fixed; right: 22px; bottom: 22px; z-index: 4; max-width: min(370px, calc(100vw - 44px)); padding: 13px 16px; border: 1px solid rgba(94, 234, 212, .25); border-radius: 11px; color: var(--ink); background: #172641; box-shadow: 0 14px 35px rgba(0, 0, 0, .3); opacity: 0; pointer-events: none; transform: translateY(10px); transition: .2s ease; }
    .toast.show { opacity: 1; transform: translateY(0); }
    [hidden] { display: none !important; }
    .modal-backdrop { position: fixed; inset: 0; z-index: 10; display: grid; place-items: center; padding: 20px; background: rgba(2, 7, 18, .72); backdrop-filter: blur(8px); }
    .modal-card { width: min(440px, 100%); padding: 24px; border: 1px solid rgba(148, 163, 184, .22); border-radius: 18px; background: #14213a; box-shadow: 0 25px 80px rgba(0, 0, 0, .5); }
    .modal-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 18px; }
    .modal-head h2 { margin: 0; font-size: 18px; }
    .modal-close { width: 30px; height: 30px; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); background: transparent; font-size: 20px; line-height: 1; }
    .modal-close:hover { color: var(--ink); background: rgba(255,255,255,.06); }
    .modal-label { display: block; margin: 0 0 8px; color: var(--muted); font-size: 12px; font-weight: 700; }
    .modal-input { width: 100%; height: 43px; padding: 0 12px; border: 1px solid var(--line); border-radius: 9px; outline: 0; color: var(--ink); background: rgba(255,255,255,.05); }
    .modal-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(139,124,255,.14); }
    .modal-help { margin: 8px 0 0; color: var(--muted); font-size: 11px; }
    .modal-error { margin: 14px 0 0; color: var(--danger); font-size: 12px; }
    .modal-actions { display: flex; justify-content: flex-end; gap: 9px; margin-top: 22px; }
    .modal-actions .btn { min-width: 100px; }
    .result { display: none; margin-top: 16px; padding: 15px; border: 1px solid rgba(94, 234, 212, .2); border-radius: 12px; background: rgba(3, 12, 27, .4); }
    .result.show { display: block; }
    .result p { margin-bottom: 9px; color: var(--muted); font-size: 11px; }
    .credential { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 8px 0; border-top: 1px solid var(--line); }
    .credential span { overflow-wrap: anywhere; color: #fff; font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }
    .copy { padding: 5px 8px; border: 1px solid var(--line); border-radius: 6px; color: var(--muted); background: transparent; font-size: 10px; }
    @media (max-width: 1100px) { .shell { grid-template-columns: 218px minmax(0, 1fr); } .content { padding-inline: clamp(18px, 3vw, 34px); } .hero, .lower-grid { grid-template-columns: 1fr; } .status-card { min-height: 0; } }
    @media (max-width: 760px) { .shell { display: block; } .sidebar { gap: 16px; padding: 14px; border-right: 0; border-bottom: 1px solid var(--line); } nav { display: flex; overflow-x: auto; scrollbar-width: none; } nav::-webkit-scrollbar { display: none; } .nav-item { width: auto; white-space: nowrap; } .side-note { display: none; } .content { padding: 22px 14px 38px; } .topbar { align-items: center; margin-bottom: 22px; } .topbar h1 { font-size: 26px; } .lede { font-size: 13px; } .operator span { display: none; } .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; } .metric { padding: 14px; } .metric-value { font-size: 21px; } .settings-grid { grid-template-columns: 1fr; } .hero-card, .panel, .status-card { padding: 20px; } .toolbar { gap: 8px; } .search { flex-basis: 100%; } .search input, #refresh-accounts { width: 100%; } .table-wrap { margin-inline: -2px; } }
    @media (max-width: 420px) { .brand { padding-inline: 4px; } .brand-mark { width: 30px; height: 30px; } .nav-item { padding: 9px 10px; font-size: 12px; } .metrics { grid-template-columns: 1fr 1fr; } .metric-label { font-size: 11px; } .metric-note { font-size: 10px; } .hero-card h2 { font-size: 22px; } .btn { width: 100%; } .mailbox-name { width: 100%; } .panel-head { flex-direction: column; } .panel-head .btn { width: 100%; } .row-actions { flex-wrap: wrap; } }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7.5 12 12l8-4.5M4 7.5v9L12 21l8-4.5v-9M4 7.5 12 3l8 4.5"/></svg></span>
        <span>ICR Mail<small>Operations console</small></span>
      </div>
      <nav aria-label="Primary">
        <button class="nav-item active" data-view="dashboard" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>Dashboard</button>
        <button class="nav-item" data-view="mailboxes" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 6.5h16v13H4zM4 7l8 6 8-6M8 3.5h8"/></svg>Mailboxes</button>
        <button class="nav-item" data-view="settings" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1"/><circle cx="12" cy="12" r="4"/></svg>Settings</button>
      </nav>
      <div class="side-note"><strong>Secure session</strong><p>Passwords are generated on demand and never stored by this console.</p></div>
    </aside>
    <main class="content" data-domain="__DOMAIN__">
      <header class="topbar">
        <div><p class="kicker">Workspace / Overview</p><h1>Mailbox operations</h1><p class="lede">A calm place to provision and monitor team mailboxes at <strong>__DOMAIN__</strong>.</p></div>
        <div class="operator"><span>Admin session</span><span class="avatar" aria-hidden="true">A</span></div>
      </header>

      <section class="view active" data-section="dashboard">
        <div class="hero">
          <div class="card hero-card"><p class="kicker">Provisioning</p><h2>Give every conversation a proper home.</h2><p>Create a mailbox with your chosen address or leave it blank for a generated one.</p><label for="mailbox-name" class="sr-only">Mailbox address</label><input id="mailbox-name" class="mailbox-name" placeholder="Mailbox address (optional)" autocomplete="off" maxlength="64"><label for="mailbox-display-name" class="sr-only">Mailbox name</label><input id="mailbox-display-name" class="mailbox-name" placeholder="Name (optional)" autocomplete="name" maxlength="200"><button class="btn create" type="button"><span>＋</span> Create mailbox</button><div class="result" aria-live="polite"></div></div>
          <div class="card status-card"><div class="status-head"><h3>Service status</h3><span class="pulse" aria-label="Operational"></span></div><strong>Provisioning ready</strong><span>Connected to the admin service</span><hr style="border:0;border-top:1px solid var(--line);margin:22px 0"><span>Default domain</span><strong style="font-size:14px;margin-top:5px;overflow-wrap:anywhere">__DOMAIN__</strong></div>
        </div>
        <div class="metrics">
          <div class="card metric"><div class="metric-label">Active mailboxes <span>↗</span></div><strong class="metric-value" id="active-count">—</strong><span class="metric-note" id="active-note">Loading directory…</span></div>
          <div class="card metric"><div class="metric-label">Storage used <span>◌</span></div><strong class="metric-value" id="storage-used">—</strong><span class="metric-note" id="storage-note">From account quotas</span></div>
          <div class="card metric"><div class="metric-label">New this month <span>＋</span></div><strong class="metric-value" id="new-count">—</strong><span class="metric-note" id="new-note">From account history</span></div>
          <div class="card metric"><div class="metric-label">Service health <span>●</span></div><strong class="metric-value">Ready</strong><span class="metric-note ready">API is responding</span></div>
        </div>
        <div class="lower-grid">
          <div class="card panel"><div class="panel-head"><div><h2>Recent activity</h2><p class="panel-subtitle">Provisioning events from this workspace</p></div><button class="text-link" data-placeholder="Activity history">View all</button></div><div class="activity"><div class="activity-row"><span class="activity-icon">＋</span><div><p>Mailbox activity will appear here</p><small>Connect a list endpoint to show history</small></div><time>—</time></div><div class="activity-row"><span class="activity-icon">✓</span><div><p>Admin session authenticated</p><small>Password-only access is enabled</small></div><time>Now</time></div></div></div>
          <div class="card panel"><div class="panel-head"><div><h2>Operator actions</h2><p class="panel-subtitle">Common mailbox controls</p></div></div><div class="actions"><button class="action create" type="button"><span class="action-icon">＋</span><span><strong>Create mailbox</strong><small>Generate address and password</small></span></button><button class="action account-action" data-action="edit" type="button"><span class="action-icon">↗</span><span><strong>Edit mailbox</strong><small>Choose an account to edit</small></span></button><button class="action account-action" data-action="quota" type="button"><span class="action-icon">◒</span><span><strong>Quota policy</strong><small>Set an account storage limit</small></span></button><button class="action account-action" data-action="password" type="button"><span class="action-icon">⌁</span><span><strong>Password reset</strong><small>Rotate an account password</small></span></button></div></div>
        </div>
      </section>

      <section class="view" data-section="mailboxes">
        <div class="card panel"><div class="panel-head"><div><p class="kicker">Directory</p><h2>Mailboxes</h2><p class="panel-subtitle">Search, inspect, and manage workspace addresses.</p></div><button class="btn create" type="button">＋ Create mailbox</button></div><div class="toolbar"><label class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg><input id="search" type="search" placeholder="Search mailboxes" aria-label="Search mailboxes"></label><button class="btn secondary" id="refresh-accounts" type="button">↻ Refresh</button></div><div class="table-wrap"><table><thead><tr><th>Address</th><th>Status</th><th>Quota</th><th>Last activity</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody id="mailbox-list"><tr><td colspan="5"><div class="empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 6.5h16v13H4zM4 7l8 6 8-6"/></svg><strong>Loading mailbox directory…</strong>Fetching accounts from the management API.</div></td></tr></tbody></table></div></div>
      </section>

      <section class="view" data-section="settings">
        <div class="settings-grid"><div class="card setting"><p class="kicker">Access</p><h3>Password-only admin session</h3><p>This console uses a secure, expiring session cookie. Rotate the admin password in Coolify when needed.</p><button id="logout" class="btn secondary" type="button">Log out</button></div><div class="card setting"><p class="kicker">Connection</p><h3>Stalwart service</h3><p>Mailbox provisioning and account management are connected through the protected REST API.</p><span class="tag">Connected</span></div><div class="card setting"><p class="kicker">Domain</p><h3>Default mailbox domain</h3><p>New generated addresses use the configured service domain.</p><code>__DOMAIN__</code></div><div class="card setting"><p class="kicker">Account lifecycle</p><h3>Management controls</h3><p>Mailbox email addresses are fixed after creation; display names, quotas, passwords, and deletion are managed in Mailboxes.</p><span class="tag">REST enabled</span></div></div>
      </section>
    </main>
  </div>
  <div class="toast" role="status" aria-live="polite"></div>
  <div id="manager-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="manager-title" hidden><div class="modal-card"><div class="modal-head"><h2 id="manager-title">Manage mailbox</h2><button id="manager-close" class="modal-close" type="button" aria-label="Close">×</button></div><form id="manager-form"><div id="manager-fields"></div><p id="manager-error" class="modal-error" role="alert" hidden></p><div class="modal-actions"><button id="manager-cancel" class="btn secondary" type="button">Cancel</button><button id="manager-submit" class="btn" type="submit">Save changes</button></div></form></div></div>
  <script>
    const toast = document.querySelector('.toast');
    let toastTimer;
    function showToast(message) {
      toast.textContent = message;
      toast.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toast.classList.remove('show'), 3200);
    }
    document.querySelectorAll('.nav-item').forEach((item) => item.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach((nav) => nav.classList.toggle('active', nav === item));
      document.querySelectorAll('.view').forEach((view) => view.classList.toggle('active', view.dataset.section === item.dataset.view));
    }));
    document.querySelectorAll('[data-placeholder]').forEach((button) => button.addEventListener('click', () => showToast(`${button.dataset.placeholder} will activate when its REST endpoint is available.`)));
    const mailboxList = document.querySelector('#mailbox-list');
    const activity = document.querySelector('.activity');
    const managerModal = document.querySelector('#manager-modal');
    const managerForm = document.querySelector('#manager-form');
    const managerFields = document.querySelector('#manager-fields');
    const managerError = document.querySelector('#manager-error');
    const managerTitle = document.querySelector('#manager-title');
    const managerSubmit = document.querySelector('#manager-submit');
    let selectedAccount;
    let accountsById = new Map();
    const safe = (value) => String(value ?? '—').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
    const accountRows = (accounts) => accounts.map((account) => `<tr><td><strong>${safe(account.emailAddress || account.name)}</strong><br><small style="color:var(--muted)">${safe(account.description || 'No name')}</small></td><td><span class="tag">Active</span></td><td>${account.quotas?.maxDiskQuota ? Math.round(account.quotas.maxDiskQuota / 1048576) + ' MB' : 'Default'}</td><td>${account.createdAt ? safe(new Date(account.createdAt).toLocaleDateString()) : '—'}</td><td><div class="row-actions"><button class="table-action manage-account" data-action="edit" data-id="${safe(account.id)}" type="button">Edit</button><button class="table-action manage-account" data-action="quota" data-id="${safe(account.id)}" type="button">Quota</button><button class="table-action manage-account" data-action="password" data-id="${safe(account.id)}" type="button">Password</button><button class="table-action manage-account" data-action="delete" data-id="${safe(account.id)}" type="button">Delete</button></div></td></tr>`).join('');
    async function loadAccounts(search = '') {
      try {
        const response = await fetch('/api/accounts?search=' + encodeURIComponent(search), { credentials: 'same-origin' });
        if (!response.ok) throw new Error('Account directory unavailable');
        const accounts = await response.json();
        accountsById = new Map(accounts.map((account) => [account.id, account]));
        document.querySelector('#active-count').textContent = accounts.length;
        const used = accounts.reduce((sum, account) => sum + Number(account.usedDiskQuota || 0), 0);
        document.querySelector('#storage-used').textContent = used >= 1073741824 ? (used / 1073741824).toFixed(1) + ' GB' : Math.round(used / 1048576) + ' MB';
        const month = new Date();
        const newThisMonth = accounts.filter((account) => { const created = account.createdAt && new Date(account.createdAt); return created && created.getMonth() === month.getMonth() && created.getFullYear() === month.getFullYear(); }).length;
        document.querySelector('#new-count').textContent = newThisMonth;
        document.querySelector('#active-note').textContent = 'From Stalwart directory';
        document.querySelector('#storage-note').textContent = 'Live account usage';
        document.querySelector('#new-note').textContent = 'Created this month';
        if (activity && accounts.length) activity.innerHTML = accounts.slice(0, 3).map((account) => `<div class="activity-row"><span class="activity-icon">✓</span><div><p>${safe(account.emailAddress || account.name)}</p><small>${safe(account.description || 'Mailbox account')}</small></div><time>${account.createdAt ? safe(new Date(account.createdAt).toLocaleDateString()) : '—'}</time></div>`).join('');
        mailboxList.innerHTML = accounts.length ? accountRows(accounts) : '<tr><td colspan="5"><div class="empty"><strong>No mailboxes found</strong>Try a different search.</div></td></tr>';
      } catch (error) { showToast(error.message); }
    }
    document.querySelector('#search').addEventListener('input', (event) => loadAccounts(event.target.value));
    document.querySelector('[data-view="mailboxes"]').addEventListener('click', () => loadAccounts());
    document.querySelectorAll('.account-action').forEach((button) => button.addEventListener('click', () => { document.querySelector('[data-view="mailboxes"]').click(); showToast('Choose an account action from the mailbox directory.'); }));
    function closeManager() { managerModal.hidden = true; managerForm.reset(); selectedAccount = null; }
    function openManager(action, id) {
      selectedAccount = accountsById.get(id);
      if (!selectedAccount) return;
      managerTitle.textContent = action === 'delete' ? 'Delete mailbox' : action === 'password' ? 'Change mailbox password' : action === 'quota' ? 'Storage quota' : 'Edit mailbox';
      managerSubmit.textContent = action === 'delete' ? 'Delete mailbox' : action === 'password' ? 'Change password' : 'Save changes';
      managerSubmit.classList.toggle('danger', action === 'delete');
      managerFields.innerHTML = action === 'edit' ? `<p class="modal-help">Address: <strong>${safe(selectedAccount.emailAddress || selectedAccount.name)}</strong></p><label class="modal-label" for="manager-description">Display name</label><input id="manager-description" class="modal-input" value="${safe(selectedAccount.description || '')}" maxlength="200"><p class="modal-help">The email address cannot be changed after creation.</p>` : action === 'quota' ? `<label class="modal-label" for="manager-quota">Storage limit (GB)</label><input id="manager-quota" class="modal-input" type="number" min="0" step="0.01" value="${selectedAccount.quotas?.maxDiskQuota ? (selectedAccount.quotas.maxDiskQuota / 1073741824).toFixed(2) : ''}"><p class="modal-help">1 GB = 1024 MB. Enter 0 or leave blank for the default quota.</p>` : action === 'password' ? `<label class="modal-label" for="manager-password">New password</label><input id="manager-password" class="modal-input" type="password" minlength="12" autocomplete="new-password" required><p class="modal-help">Use at least 12 characters. The password will not be shown again.</p>` : `<p>Delete <strong>${safe(selectedAccount.emailAddress || selectedAccount.name)}</strong>? This permanently removes the account and its mailbox.</p><label class="modal-label" for="manager-confirm">Re-enter the full email address to confirm</label><input id="manager-confirm" class="modal-input" type="email" placeholder="${safe(selectedAccount.emailAddress || selectedAccount.name)}" autocomplete="off" required>`;
      managerError.hidden = true;
      managerModal.hidden = false;
      (managerFields.querySelector('input') || managerSubmit).focus();
    }
    document.querySelector('#manager-close').addEventListener('click', closeManager);
    document.querySelector('#manager-cancel').addEventListener('click', closeManager);
    managerModal.addEventListener('click', (event) => { if (event.target === managerModal) closeManager(); });
    managerForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const action = managerSubmit.textContent === 'Delete mailbox' ? 'delete' : managerSubmit.textContent === 'Change password' ? 'password' : managerFields.querySelector('#manager-quota') ? 'quota' : 'edit';
      const id = selectedAccount.id;
      let endpoint = '/api/accounts/' + encodeURIComponent(id), options = { credentials: 'same-origin' };
      if (action === 'delete') { if (managerFields.querySelector('#manager-confirm').value.trim().toLowerCase() !== (selectedAccount.emailAddress || selectedAccount.name).toLowerCase()) { managerError.textContent = 'Enter the exact mailbox email address to confirm.'; managerError.hidden = false; return; } options.method = 'DELETE'; }
      if (action === 'edit') { options.method = 'PATCH'; options.headers = {'Content-Type':'application/json'}; options.body = JSON.stringify({description: managerFields.querySelector('#manager-description').value}); }
      if (action === 'quota') { const value = Number(managerFields.querySelector('#manager-quota').value || 0); if (!Number.isFinite(value) || value < 0) { managerError.textContent = 'Enter a valid non-negative number.'; managerError.hidden = false; return; } options.method = 'PATCH'; options.headers = {'Content-Type':'application/json'}; options.body = JSON.stringify({quotas: value ? {maxDiskQuota: Math.round(value * 1073741824)} : {}}); }
      if (action === 'password') { options.method = 'POST'; options.headers = {'Content-Type':'application/json'}; options.body = JSON.stringify({new_password: managerFields.querySelector('#manager-password').value}); }
      managerSubmit.disabled = true;
      try { const response = await fetch(action === 'password' ? endpoint + '/password' : endpoint, options); if (!response.ok) throw new Error('The mailbox operation failed.'); closeManager(); await loadAccounts(document.querySelector('#search').value); showToast(action === 'delete' ? 'Mailbox deleted.' : action === 'password' ? 'Password changed.' : 'Mailbox updated.'); } catch (error) { managerError.textContent = error.message; managerError.hidden = false; } finally { managerSubmit.disabled = false; }
    });
    document.querySelector('#logout').addEventListener('click', async () => { const button = document.querySelector('#logout'); button.disabled = true; button.textContent = 'Logging out…'; await fetch('/logout', {method:'POST', credentials:'same-origin'}); window.location.href = '/login'; });
    mailboxList.addEventListener('click', async (event) => {
      const button = event.target.closest('.manage-account');
      if (!button) return;
      const id = button.dataset.id;
      const action = button.dataset.action;
      openManager(action, id);
      return;
      /* legacy prompt flow intentionally unreachable */
      try {
        if (action === 'delete') {
          if (!window.confirm('Delete this mailbox permanently?')) return;
          const response = await fetch('/api/accounts/' + encodeURIComponent(id), { method: 'DELETE', credentials: 'same-origin' });
          if (!response.ok) throw new Error('Unable to delete mailbox.');
        } else if (action === 'edit') {
          const description = window.prompt('Mailbox description (leave blank to clear):');
          if (description === null) return;
          const response = await fetch('/api/accounts/' + encodeURIComponent(id), { method: 'PATCH', credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify({description}) });
          if (!response.ok) throw new Error('Unable to update mailbox.');
        } else if (action === 'quota') {
          const mb = window.prompt('Storage limit in MB (0 removes the limit):');
          if (mb === null) return;
          const value = Number(mb);
          if (!Number.isInteger(value) || value < 0) throw new Error('Enter a non-negative whole number.');
          const response = await fetch('/api/accounts/' + encodeURIComponent(id), { method: 'PATCH', credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify({quotas: value ? {maxDiskQuota: value * 1048576} : {}}) });
          if (!response.ok) throw new Error('Unable to update quota.');
        } else if (action === 'password') {
          const password = window.prompt('Enter the new mailbox password:');
          if (!password) return;
          const response = await fetch('/api/accounts/' + encodeURIComponent(id) + '/password', { method: 'POST', credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify({new_password: password}) });
          if (!response.ok) throw new Error('Unable to change password.');
          showToast('Password changed. Save it securely; it is not shown again.');
        }
        await loadAccounts(document.querySelector('#search').value);
        if (action !== 'password') showToast('Mailbox updated.');
      } catch (error) { showToast(error.message); }
    });
    document.querySelectorAll('.create').forEach((button) => button.addEventListener('click', async () => {
      if (!button.closest('[data-section="dashboard"]')) document.querySelector('.nav-item[data-view="dashboard"]').click();
      const result = document.querySelector('.result');
      document.querySelectorAll('.create').forEach((item) => { item.disabled = true; });
      result.classList.add('show');
      result.textContent = 'Creating mailbox…';
        try {
        const requestedName = document.querySelector('#mailbox-name').value.trim();
        const displayName = document.querySelector('#mailbox-display-name').value.trim();
        const response = await fetch('/api/mailboxes', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ name: requestedName, displayName }) });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.detail || 'Unable to create mailbox.');
        result.innerHTML = `<p>Save these credentials now. The password is not stored here.</p><div class="credential"><span>${data.email}</span><button class="copy" data-copy="${data.email}" type="button">Copy</button></div><div class="credential"><span>${data.password}</span><button class="copy" data-copy="${data.password}" type="button">Copy</button></div>`;
        result.querySelectorAll('.copy').forEach((copy) => copy.addEventListener('click', async () => { await navigator.clipboard?.writeText(copy.dataset.copy); copy.textContent = 'Copied'; showToast('Copied to clipboard.'); }));
        showToast('Mailbox created successfully.');
      } catch (error) { result.textContent = error.message; showToast('Mailbox creation failed.'); }
      finally { document.querySelectorAll('.create').forEach((item) => { item.disabled = false; }); }
    }));
    loadAccounts();
  </script>
</body>
</html>'''
    return template.replace("__DOMAIN__", html.escape(domain))


def login_page(error: str = "") -> str:
    message = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ICR Mail · Sign in</title><style>
    :root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 50% -10%,#293b68 0,transparent 45%),#0b1220;color:#e8edf7;font:15px system-ui,sans-serif}}main{{width:min(420px,calc(100% - 32px));padding:34px;border:1px solid #263552;border-radius:22px;background:rgba(19,30,51,.86);box-shadow:0 25px 80px #0006}}h1{{margin:0 0 8px;font-size:27px;letter-spacing:-.04em}}p{{color:#8995aa;margin:0 0 25px}}label{{display:block;margin:0 0 9px;color:#c8d1e3;font-size:12px;font-weight:700}}input{{width:100%;height:46px;padding:0 14px;border:1px solid #32415d;border-radius:11px;outline:0;color:#fff;background:#0d1729;font:inherit}}input:focus{{border-color:#8b7cff;box-shadow:0 0 0 3px #8b7cff26}}button{{width:100%;height:46px;margin-top:17px;border:0;border-radius:11px;color:#fff;background:#8b7cff;font-weight:700;cursor:pointer}}.error{{margin:-8px 0 18px;padding:10px 12px;border:1px solid #9f4155;border-radius:9px;color:#ff9aae;background:#4a1f2d;font-size:13px}}
    </style></head><body><main><h1>ICR Mail</h1><p>Sign in to the mailbox operations console.</p>{message}<form id="login-form" method="post" action="/login"><label for="password">Admin password</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button id="login-button" type="submit">Sign in</button></form><script>const form=document.querySelector('#login-form'),button=document.querySelector('#login-button');form.addEventListener('submit',async(event)=>{{event.preventDefault();button.disabled=true;button.textContent='Signing in…';try{{const response=await fetch(form.action,{{method:'POST',body:new URLSearchParams(new FormData(form)),redirect:'manual',headers:{{'Accept':'text/html'}}}});if(response.type==='opaqueredirect'||response.status===303){{window.location.href='/';return}}document.open();document.write(await response.text());document.close()}}catch(_error){{button.disabled=false;button.textContent='Sign in';}}}});</script></main></body></html>'''


def create_app(config: Config | None = None) -> FastAPI:
    config = config or load_config()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    rate_limiter = SlidingWindowRateLimiter(AUTH_RATE_LIMIT, AUTH_RATE_WINDOW_SECONDS)
    failed_auth = FailedAuthLockout(AUTH_FAILURE_LIMIT, AUTH_LOCKOUT_SECONDS)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    sessions: dict[str, float] = {}
    sessions_lock = Lock()

    def require_admin(request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        token = request.cookies.get("icr_admin_session", "")
        now = monotonic()
        with sessions_lock:
            valid_session = bool(token and sessions.get(token, 0) > now)
            if token and not valid_session:
                sessions.pop(token, None)
        if valid_session:
            return
        allowed, retry_after = rate_limiter.allow(ip)
        if not allowed:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="authentication_rate_limited", headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"})
        lockout_key = ip
        retry_after = failed_auth.retry_after(lockout_key)
        if retry_after:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="authentication_temporarily_unavailable", headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"})
        if request.url.path.startswith("/api/"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication_required", headers={"Cache-Control": "no-store"})
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/login", "Cache-Control": "no-store"})

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "configured": config.configured}, headers={"Cache-Control": "no-store"})

    @app.get("/login", response_class=HTMLResponse)
    async def login() -> HTMLResponse:
        return HTMLResponse(login_page(), headers={"Cache-Control": "no-store"})

    @app.post("/login")
    async def login_submit(request: Request):
        ip = request.client.host if request.client else "unknown"
        allowed, retry_after = rate_limiter.allow(ip)
        if not allowed:
            return HTMLResponse(login_page(f"Too many attempts. Try again in {retry_after} seconds."), status_code=429, headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"})
        lockout_key = ip
        retry_after = failed_auth.retry_after(lockout_key)
        if retry_after:
            return HTMLResponse(login_page(f"Sign-in temporarily locked. Try again in {retry_after} seconds."), status_code=429, headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"})
        fields = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
        password = fields.get("password", [""])[0]
        if not secrets.compare_digest(password, config.admin_password):
            retry_after = failed_auth.record_failure(lockout_key)
            return HTMLResponse(login_page("Incorrect password."), status_code=429 if retry_after else 401, headers={"Retry-After": str(retry_after)} if retry_after else {})
        failed_auth.clear(lockout_key)
        token = secrets.token_urlsafe(32)
        with sessions_lock:
            sessions[token] = monotonic() + SESSION_TTL_SECONDS
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie("icr_admin_session", token, max_age=SESSION_TTL_SECONDS, httponly=True, secure=True, samesite="strict", path="/")
        return response

    @app.post("/logout")
    async def logout(request: Request):
        token = request.cookies.get("icr_admin_session", "")
        with sessions_lock:
            sessions.pop(token, None)
        response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie("icr_admin_session", path="/")
        return response

    @app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
    async def home() -> HTMLResponse:
        return HTMLResponse(page(config.domain), headers={"Cache-Control": "no-store"})

    @app.post("/api/mailboxes", dependencies=[Depends(require_admin)])
    async def create_mailbox(request: Request) -> JSONResponse:
        if request.headers.get("origin") != config.public_origin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="origin_not_allowed")
        try:
            payload = await request.json()
            requested_name = str(payload.get("name", "")) if isinstance(payload, dict) else ""
            display_name = str(payload.get("displayName", "")) if isinstance(payload, dict) else ""
            created = await provision(config, requested_name, display_name)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid_mailbox_name") from None
        except Exception:
            logger.error("Mailbox provisioning failed")
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="mailbox_creation_failed") from None
        return JSONResponse(created, status_code=status.HTTP_201_CREATED, headers={"Cache-Control": "no-store"})

    app.include_router(
        create_account_router(
            StalwartClient(config.jmap_url, config.api_key),
            dependencies=[Depends(require_admin)],
        )
    )

    return app


app = create_app()
