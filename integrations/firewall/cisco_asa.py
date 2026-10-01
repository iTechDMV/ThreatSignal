import httpx
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential


class CiscoASAConnector:
    """
    Real Cisco ASA REST API firewall connector.
    Supports dynamic ACL block rules with TTL auto-expire.
    """

    def __init__(self, host: str, username: str, password: str):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.base_url = f"https://{self.host}/api"
        self._client = httpx.AsyncClient(
            verify=False,
            timeout=30,
            auth=(self.username, self.password)
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def block_ip(self, ip: str, duration: int = 86400):
        """
        Creates a deny ACL entry for the given IP.
        TTL auto-removes the ACL entry after duration seconds.
        """

        payload = {
            "kind": "object#AccessRule",
            "sourceAddress": {"kind": "IPv4Address", "value": ip},
            "destinationAddress": {"kind": "AnyIPAddress"},
            "action": "deny",
            "active": True,
            "logging": "default",
            "remarks": [f"ThreatSignal block for {ip}"],
        }

        r = await self._client.post(
            f"{self.base_url}/access/in",
            json=payload
        )

        if r.status_code == 401:
            raise RuntimeError("ASA authentication failed")

        r.raise_for_status()

        # Schedule TTL removal
        asyncio.create_task(self._expire(ip, duration))

        return {"success": True, "ip": ip, "duration": duration}

    async def _expire(self, ip: str, duration: int):
        await asyncio.sleep(duration)

        # Remove ACL entry
        r = await self._client.delete(
            f"{self.base_url}/access/in/{ip}"
        )

        # ASA returns 204 on success
        if r.status_code not in (200, 204):
            raise RuntimeError(f"Failed to remove ACL for {ip}")
