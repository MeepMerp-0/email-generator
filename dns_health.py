"""Read-only checks for the DNS records used by this mail domain."""

import asyncio
import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

DEFAULT_DKIM_SELECTORS = ("v1-rsa-20260910", "v1-ed25519-20260910")


async def _lookup(name: str, record_type: str) -> list[str] | None:
    try:
        answer = await dns.asyncresolver.resolve(name, record_type, lifetime=3, search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError):
        return None
    if record_type == "TXT":
        return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]
    if record_type == "MX":
        return [str(record.exchange).rstrip(".").lower() for record in answer]
    if record_type == "A":
        return [str(record.address) for record in answer]
    return [str(record.target).rstrip(".").lower() for record in answer]


def _tags(record: str) -> dict[str, str]:
    return {
        key.strip().lower(): value.strip()
        for part in record.split(";")
        if "=" in part
        for key, value in [part.split("=", 1)]
    }


def _check(label: str, ok: bool | None, detail: str, name: str) -> dict[str, str]:
    return {
        "label": label,
        "status": "unknown" if ok is None else "connected" if ok else "disconnected",
        "detail": "DNS lookup unavailable" if ok is None else detail,
        "name": name,
    }


async def check_dns_health(
    domain: str,
    dkim_selectors: tuple[str, ...] = DEFAULT_DKIM_SELECTORS,
) -> list[dict[str, str]]:
    domain = domain.rstrip(".").lower()
    mail_host = f"mail.{domain}"
    aliases = (f"autoconfig.{domain}", f"autodiscover.{domain}")
    queries = [
        (domain, "MX"),
        (mail_host, "A"),
        *((alias, "CNAME") for alias in aliases),
        (domain, "TXT"),
        (f"_dmarc.{domain}", "TXT"),
        *((f"{selector}._domainkey.{domain}", "TXT") for selector in dkim_selectors),
    ]
    answers = dict(zip(queries, await asyncio.gather(*(_lookup(*query) for query in queries))))
    mx = answers[(domain, "MX")]
    ips = answers[(mail_host, "A")]
    cnames = [answers[(alias, "CNAME")] for alias in aliases]
    domain_txt = answers[(domain, "TXT")]
    dmarc_txt = answers[(f"_dmarc.{domain}", "TXT")]
    dkim_txt = [answers[(f"{selector}._domainkey.{domain}", "TXT")] for selector in dkim_selectors]

    spf = [record for record in domain_txt or [] if record.lower().startswith("v=spf1 ")]
    dmarc = [record for record in dmarc_txt or [] if _tags(record).get("v", "").lower() == "dmarc1"]
    policy = _tags(dmarc[0]).get("p", "").lower() if len(dmarc) == 1 else ""
    dkim_found = sum(bool(records and any(
        _tags(record).get("v", "").lower() == "dkim1" and _tags(record).get("p")
        for record in records
    )) for records in dkim_txt)

    if ips is None:
        ptr_ok = None
    elif not ips:
        ptr_ok = False
    else:
        reverse = await asyncio.gather(*(
            _lookup(dns.reversename.from_address(ip).to_text(), "PTR") for ip in ips
        ))
        ptr_ok = None if any(records is None for records in reverse) else all(
            mail_host in records for records in reverse
        )

    return [
        _check("MX", None if mx is None else bool(mx) and set(mx) == {mail_host}, f"Expected only {mail_host}", domain),
        _check("A", None if ips is None else bool(ips), ", ".join(ips or []) or "No mail-host A record", mail_host),
        _check("CNAME", None if any(records is None for records in cnames) else all(records == [mail_host] for records in cnames), "Autoconfig + autodiscover → mail host" if all(records == [mail_host] for records in cnames) else "Client setup aliases missing or mismatched", domain),
        _check("SPF", None if domain_txt is None else len(spf) == 1, "One SPF TXT record published" if len(spf) == 1 else "Missing or duplicate SPF TXT record", domain),
        _check("DKIM", None if any(records is None for records in dkim_txt) else dkim_found == len(dkim_selectors), f"{dkim_found}/{len(dkim_selectors)} public keys published", domain),
        _check("DMARC", None if dmarc_txt is None else policy in {"none", "quarantine", "reject"}, f"p={policy}" + (" (monitoring)" if policy == "none" else "") if policy else "Missing or invalid policy", f"_dmarc.{domain}"),
        _check("PTR", ptr_ok, f"Mail IPs point back to {mail_host}" if ptr_ok else "Reverse DNS does not match mail host", mail_host),
    ]
