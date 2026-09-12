# ICR mailbox generator

Standalone FastAPI service that creates a named `@innercirclerealtors.cloud`
Stalwart mailbox and shows its generated password once.

Configure the service in Coolify; keep secret values private:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `STALWART_JMAP_URL`
- `STALWART_API_KEY`
- `STALWART_DOMAIN_ID`
- `PUBLIC_ORIGIN` (`https://mailbox-admin.innercirclerealtors.cloud`)
- `MAIL_DOMAIN` (defaults to `innercirclerealtors.cloud`)
- `MAIL_DKIM_SELECTORS` (optional comma-separated selectors; defaults to the current RSA and Ed25519 selectors)

The admin console exposes `GET /api/accounts`, `POST /api/accounts`,
`PATCH /api/accounts/{id}`, `POST /api/accounts/{id}/password`, and
`DELETE /api/accounts/{id}` behind the admin session. The authenticated
`GET /api/dns-health` checks MX, mail-host A, client-setup CNAME, SPF, DKIM,
DMARC, and PTR records; it does not prove message delivery. The Stalwart key
must be scoped for the operations you enable: `sysAccountQuery`,
`sysAccountGet`, `sysAccountCreate`, `sysAccountUpdate`, and optionally
`sysAccountDestroy`.

Never commit a `.env` file or a generated mailbox password.
