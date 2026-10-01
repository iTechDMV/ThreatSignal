import httpx
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential


class FortiGateConnector:
    """
    FortiGate firewall connector using FortiOS REST API.
    Creates an address object + policy entry and supports TTL auto-expire.
    """

    def __init__(self, host: str, token: str, vdom: str = "root"):
        self.host = host.rstrip("/")
        self.token = token
        self.vdom = vdom
        self.base_url = f"https://{self.host}/api/v2"
        self._client = httpx.AsyncClient(verify=False, timeout=30)

    async def _request(self, method: str, path: str, **kwargs):
        headers = {
            "Authorization": f"Bearer {self.token}",
        }
        url = f"{self.base_url}{path}"
        r = await self._client.request(method, url, headers=headers, params={"vdom": self.vdom}, **kwargs)
        r.raise_for_status()
        return r.json()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def block_ip(self, ip: str, duration: int = 86400):
        """
        Creates an address object and adds it to a deny policy.
        TTL auto-removes the object and updates the policy.
        """

        addr_name = f"TS_{ip.replace('.', '_')}"

        # 1. Create address object
        await self._request(
            "POST",
            "/cmdb/firewall/address",
            json={
                "name": addr_name,
                "subnet": f"{ip} 255.255.255.255",
                "type": "ipmask",
                "comment": f"ThreatSignal block for {ip}",
            },
        )

        # 2. Add to existing deny policy (assumes a policy named ThreatSignal-Block exists)
        await self._request(
            "PUT",
            "/cmdb/firewall/policy/ThreatSignal-Block",
            json={
                "srcaddr": [{"name": addr_name}],
            },
        )

        # 3. Schedule TTL removal
        asyncio.create_task(self._expire(ip, addr_name, duration))

        return {"success": True, "ip": ip, "duration": duration}

    async def _expire(self, ip: str, addr_name: str, duration: int):
        await asyncio.sleep(duration)

        # Remove address object
        await self._request(
            "DELETE",
            f"/cmdb/firewall/address/{addr_name}",
        )

        # Remove from policy (best-effort; assumes same policy name)
        await self._request(
            "PUT",
            "/cmdb/firewall/policy/ThreatSignal-Block",
            json={
                "srcaddr": [],
            },
        )
