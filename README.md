# ICR mailbox generator

Standalone FastAPI service that creates an `@innercirclerealtors.cloud` Stalwart
mailbox and shows its generated password once.

All secrets belong in Coolify environment variables:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `STALWART_JMAP_URL`
- `STALWART_API_KEY`
- `STALWART_DOMAIN_ID`
- `PUBLIC_ORIGIN` (`https://mailbox-admin.innercirclerealtors.cloud`)

The admin console exposes `GET /api/accounts`, `POST /api/accounts`,
`PATCH /api/accounts/{id}`, `POST /api/accounts/{id}/password`, and
`DELETE /api/accounts/{id}` behind HTTP Basic authentication. The Stalwart key
must be scoped for the operations you enable: `sysAccountQuery`,
`sysAccountGet`, `sysAccountCreate`, `sysAccountUpdate`, and optionally
`sysAccountDestroy`.

Never commit a `.env` file or a generated mailbox password.
