import unittest
from unittest.mock import patch

from dns_health import check_dns_health


class DnsHealthTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        domain = "innercirclerealtors.cloud"
        mail = f"mail.{domain}"
        self.answers = {
            (domain, "MX"): [mail],
            (mail, "A"): ["72.61.115.125"],
            (f"autoconfig.{domain}", "CNAME"): [mail],
            (f"autodiscover.{domain}", "CNAME"): [mail],
            (domain, "TXT"): ["v=spf1 mx ip4:72.61.115.125 ~all"],
            (f"_dmarc.{domain}", "TXT"): ["v=DMARC1; p=none"],
            (f"v1-rsa-20260910._domainkey.{domain}", "TXT"): ["v=DKIM1; k=rsa; p=abc"],
            (f"v1-ed25519-20260910._domainkey.{domain}", "TXT"): ["v=DKIM1; k=ed25519; p=xyz"],
            ("125.115.61.72.in-addr.arpa.", "PTR"): [mail],
        }

    async def check(self) -> dict[str, dict[str, str]]:
        async def lookup(name: str, record_type: str) -> list[str] | None:
            return self.answers[(name, record_type)]

        with patch("dns_health._lookup", side_effect=lookup):
            return {item["label"]: item for item in await check_dns_health("innercirclerealtors.cloud")}

    async def test_connected_records_and_monitoring_policy(self) -> None:
        checks = await self.check()
        self.assertEqual(len(checks), 7)
        self.assertTrue(all(item["status"] == "connected" for item in checks.values()))
        self.assertEqual(checks["DMARC"]["detail"], "p=none (monitoring)")

    async def test_mismatch_and_lookup_failure_are_distinct(self) -> None:
        self.answers[("innercirclerealtors.cloud", "MX")].append("unexpected.example.test")
        self.answers[("autodiscover.innercirclerealtors.cloud", "CNAME")] = []
        self.answers[("_dmarc.innercirclerealtors.cloud", "TXT")] = []
        self.answers[("innercirclerealtors.cloud", "TXT")] = None
        checks = await self.check()
        self.assertEqual(checks["MX"]["status"], "disconnected")
        self.assertEqual(checks["CNAME"]["status"], "disconnected")
        self.assertEqual(checks["DMARC"]["status"], "disconnected")
        self.assertEqual(checks["SPF"]["status"], "unknown")
