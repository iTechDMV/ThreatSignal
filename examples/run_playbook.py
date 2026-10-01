import asyncio
import importlib
import os
import typing

import httpx
import tenacity

threatintel = importlib.import_module("threatsignal.integrations.threatintel")
workflows = importlib.import_module("threatsignal.workflows")

# Monkey-patch VirusTotalConnector with the concrete implementations needed by the example playbook.
# This keeps the example self-contained while satisfying the abstract interface defined in the package.
try:
    VirusTotalConnector = threatintel.VirusTotalConnector
except AttributeError:
    VirusTotalConnector = None

if VirusTotalConnector is not None:
    _abstract_methods = getattr(VirusTotalConnector, "__abstractmethods__", set())
    if _abstract_methods:
        for name in list(_abstract_methods):
            if name == "check_indicator":
                async def check_indicator(self, indicator: str, **kwargs: typing.Any):
                    return await self.check_ip(indicator, **kwargs)
                setattr(VirusTotalConnector, name, check_indicator)
            elif name == "lookup_ip":
                async def lookup_ip(self, ip: str, **kwargs: typing.Any):
                    return await self.check_ip(ip, **kwargs)
                setattr(VirusTotalConnector, name, lookup_ip)
            elif name == "report_indicator":
                async def report_indicator(self, indicator: str, categories: list[int], comment: str = ""):
                    return await self.report_ip(indicator, categories, comment)
                setattr(VirusTotalConnector, name, report_indicator)
            elif name == "report_ip":
                async def report_ip(self, ip: str, categories: list[int], comment: str = ""):
                    response = await self._client.post(
                        "/ip_addresses/report",
                        data={"ip": ip, "categories": ",".join(map(str, categories)), "comment": comment},
                    )
                    response.raise_for_status()
                    payload = response.json()
                    return payload.get("data") or payload
                setattr(VirusTotalConnector, name, report_ip)
            elif name == "check_ip":
                async def check_ip(self, ip: str, **kwargs: typing.Any):
                    response = await self._client.get(
                        "/ip_addresses",
                        params={"ip": ip, **kwargs},
                    )
                    response.raise_for_status()
                    payload = response.json()
                    return payload.get("data") or payload
                setattr(VirusTotalConnector, name, check_ip)
            elif name == "lookup_indicator":
                async def lookup_indicator(self, indicator: str, **kwargs: typing.Any):
                    return await self.check_indicator(indicator, **kwargs)
                setattr(VirusTotalConnector, name, lookup_indicator)


class AbuseIPDBConnector:
    """Small concrete AbuseIPDB connector used by this example playbook."""

    def __init__(self, api_key: str, timeout: float = 30) -> None:
        self.api_key = api_key
        self._client = httpx.AsyncClient(
            base_url="https://api.abuseipdb.com/api/v2",
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=timeout,
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()

    async def close(self):
        await self._client.aclose()

    async def check_ip(self, ip: str, max_age_in_days: int = 90):
        response = await self._client.get(
            "/check",
            params={"ipAddress": ip, "maxAgeInDays": max_age_in_days},
        )
        response.raise_for_status()
        return response.json()["data"]

    async def lookup_ip(self, ip: str, max_age_in_days: int = 90):
        return await self.check_ip(ip, max_age_in_days)

    async def check_indicator(self, indicator: str, **kwargs):
        return await self.check_ip(indicator, **kwargs)

    async def report_ip(self, ip: str, categories: list[int], comment: str = ""):
        response = await self._client.post(
            "/report",
            data={"ip": ip, "categories": ",".join(map(str, categories)), "comment": comment},
        )
        response.raise_for_status()
        return response.json()["data"]

    async def report_indicator(self, indicator: str, categories: list[int], comment: str = ""):
        return await self.report_ip(indicator, categories, comment)


class CrowdStrikeConnector:
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = "https://api.crowdstrike.com"
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()

    async def close(self):
        """Close the authenticated HTTP client, if one is open."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def connect(self):
        await self.close()
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{self.base_url}/oauth2/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            )
            response.raise_for_status()
            self._token = response.json()["access_token"]

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=30,
        )

    async def _refresh(self):
        await self.connect()

    @tenacity.retry(stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_exponential(min=2, max=10))
    async def isolate_endpoint(self, endpoint_id: str, reason: str = ""):
        if self._client is None:
            raise RuntimeError("CrowdStrike client is not connected")

        response = await self._client.post(
            "/devices/entities/devices-actions/v2?action_name=contain",
            json={"ids": [endpoint_id]},
        )

        if response.status_code == 401:
            await self._refresh()
            raise RuntimeError("Token refreshed, retrying isolate")

        response.raise_for_status()
        return {"success": True, "endpoint_id": endpoint_id}


class FirewallConnector:
    async def block_ip(self, ip: str, duration: int = 86400):
        return {"success": True, "ip": ip, "duration": duration}


async def main():
    vt_api_key = os.environ.get("VT_API_KEY")
    abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY")
    cs_id = os.environ.get("CS_CLIENT_ID")
    cs_secret = os.environ.get("CS_CLIENT_SECRET")

    if (
        vt_api_key is None
        or abuseipdb_api_key is None
        or cs_id is None
        or cs_secret is None
    ):
        raise RuntimeError("Missing required API keys in environment variables")

    async with threatintel.VirusTotalConnector(api_key=vt_api_key) as vt, AbuseIPDBConnector(
        api_key=abuseipdb_api_key
    ) as abuse:
        async with CrowdStrikeConnector(cs_id, cs_secret) as cs:
            fw = FirewallConnector()
            integrations = {
                "intel": vt,
                "edr": cs,
                "firewall": fw,
            }

            executor = workflows.PlaybookExecutor(integrations)
            context = {
                "indicators": ["203.0.113.99", "example.com"],
                "affected_assets": ["host-123"],
            }

            results = await executor.run("ransomware", context)
            for step in results:
                print(step)


if __name__ == "__main__":
    asyncio.run(main())

