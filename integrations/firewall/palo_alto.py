import httpx
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential


class PaloAltoFirewallConnector:
    """
    Real Palo Alto Networks firewall connector using PAN-OS REST API.
    Supports dynamic block rules with TTL.
    """

    def __init__(self, host: str, api_key: str):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.base_url = f"https://{self.host}/api"
        self._client = httpx.AsyncClient(verify=False, timeout=30)

    async def _request(self, params: dict):
        params["key"] = self.api_key
        r = await self._client.get(self.base_url, params=params)
        r.raise_for_status()
        return r.json()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def block_ip(self, ip: str, duration: int = 86400):
        """
        Creates a dynamic block rule using an Address Object + Security Rule.
        TTL is implemented via a scheduled removal task.
        """

        # 1. Create address object
        addr_params = {
            "type": "config",
            "action": "set",
            "xpath": f"/config/shared/address/entry[@name='TS-{ip}']",
            "element": f"<ip-netmask>{ip}</ip-netmask>",
        }
        await self._request(addr_params)

        # 2. Add to block rule
        rule_params = {
            "type": "config",
            "action": "set",
            "xpath": "/config/shared/security/rules/entry[@name='ThreatSignal-Block']/source",
            "element": f"<member>TS-{ip}</member>",
        }
        await self._request(rule_params)

        # 3. Commit
        await self._request({"type": "commit"})

        # 4. Schedule TTL removal
        asyncio.create_task(self._expire(ip, duration))

        return {"success": True, "ip": ip, "duration": duration}

    async def _expire(self, ip: str, duration: int):
        await asyncio.sleep(duration)

        # Remove address object
        del_params = {
            "type": "config",
            "action": "delete",
            "xpath": f"/config/shared/address/entry[@name='TS-{ip}']",
        }
        await self._request(del_params)

        # Remove from rule
        rule_del_params = {
            "type": "config",
            "action": "delete",
            "xpath": f"/config/shared/security/rules/entry[@name='ThreatSignal-Block']/source/member[text()='TS-{ip}']",
        }
        await self._request(rule_del_params)

        # Commit
        await self._request({"type": "commit"})
