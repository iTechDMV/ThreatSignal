import httpx
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential


class PfSenseConnector:
    """
    pfSense firewall connector using the pfSense-API package.
    Supports IP block/unblock with TTL auto-expire.
    """

    def __init__(self, host: str, api_key: str, api_secret: str):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = f"https://{self.host}/api/v1"
        self._client = httpx.AsyncClient(verify=False, timeout=30)

    async def _request(self, method: str, endpoint: str, **kwargs):
        headers = {
            "Authorization": f"Bearer {self.api_key}:{self.api_secret}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/{endpoint}"

        r = await self._client.request(method, url, headers=headers, **kwargs)

        if r.status_code == 401:
            raise RuntimeError("pfSense API authentication failed")

        r.raise_for_status()
        return r.json()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def block_ip(self, ip: str, duration: int = 86400):
        """
        Adds an IP to a pfSense firewall alias called 'ThreatSignalBlock'
        and reloads filter rules. TTL auto-removes the IP later.
        """

        # 1. Add IP to alias
        await self._request(
            "POST",
            "firewall/alias/add",
            json={
                "name": "ThreatSignalBlock",
                "type": "host",
                "address": ip,
                "descr": f"ThreatSignal block for {ip}",
            },
        )

        # 2. Reload filter rules
        await self._request("POST", "firewall/filter/apply")

        # 3. Schedule TTL removal
        asyncio.create_task(self._expire(ip, duration))

        return {"success": True, "ip": ip, "duration": duration}

    async def _expire(self, ip: str, duration: int):
        await asyncio.sleep(duration)

        # Remove IP from alias
        await self._request(
            "POST",
            "firewall/alias/delete",
            json={"name": "ThreatSignalBlock", "address": ip},
        )

        # Reload filter rules
        await self._request("POST", "firewall/filter/apply")
