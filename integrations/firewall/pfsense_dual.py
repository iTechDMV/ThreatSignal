import asyncio
import httpx
import asyncssh
from tenacity import retry, stop_after_attempt, wait_exponential


class PfSenseDualConnector:
    """
    pfSense dual-mode connector.
    1. Attempts pfSense-API first (fast, clean, JSON).
    2. Falls back to SSH + pfctl if API is unavailable.
    Supports TTL auto-expire for both modes.
    """

    def __init__(
        self,
        host: str,
        api_key: str = None,
        api_secret: str = None,
        ssh_user: str = None,
        ssh_pass: str = None,
    ):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass

        self.api_base = f"https://{self.host}/api/v1"
        self.table_name = "ThreatSignalBlock"

        self._api_available = False
        self._client = httpx.AsyncClient(verify=False, timeout=30)

    async def detect_mode(self):
        """
        Detect whether pfSense-API is available.
        If API returns 200, use API mode.
        Otherwise fall back to SSH mode.
        """
        if not self.api_key or not self.api_secret:
            self._api_available = False
            return False

        try:
            r = await self._client.get(
                f"{self.api_base}/system/info",
                headers={
                    "Authorization": f"Bearer {self.api_key}:{self.api_secret}"
                },
            )
            self._api_available = r.status_code == 200
        except Exception:
            self._api_available = False

        return self._api_available

    async def _ssh(self, command: str):
        async with asyncssh.connect(
            self.host,
            username=self.ssh_user,
            password=self.ssh_pass,
            known_hosts=None,
        ) as conn:
            result = await conn.run(command, check=True)
            return result.stdout

    async def _ensure_table_ssh(self):
        await self._ssh(f"sudo pfctl -t {self.table_name} -T show || true")

    async def _api_request(self, method: str, endpoint: str, **kwargs):
        headers = {
            "Authorization": f"Bearer {self.api_key}:{self.api_secret}",
            "Content-Type": "application/json",
        }
        url = f"{self.api_base}/{endpoint}"
        r = await self._client.request(method, url, headers=headers, **kwargs)
        r.raise_for_status()
        return r.json()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def block_ip(self, ip: str, duration: int = 86400):
        """
        Unified block_ip() that chooses API or SSH automatically.
        """

        # Detect mode on first call
        await self.detect_mode()

        if self._api_available:
            return await self._block_ip_api(ip, duration)
        else:
            return await self._block_ip_ssh(ip, duration)

    async def _block_ip_api(self, ip: str, duration: int):
        # Add IP to alias
        await self._api_request(
            "POST",
            "firewall/alias/add",
            json={
                "name": "ThreatSignalBlock",
                "type": "host",
                "address": ip,
                "descr": f"ThreatSignal block for {ip}",
            },
        )

        # Reload filter rules
        await self._api_request("POST", "firewall/filter/apply")

        # TTL removal
        asyncio.create_task(self._expire_api(ip, duration))

        return {"success": True, "mode": "api", "ip": ip, "duration": duration}

    async def _expire_api(self, ip: str, duration: int):
        await asyncio.sleep(duration)

        await self._api_request(
            "POST",
            "firewall/alias/delete",
            json={"name": "ThreatSignalBlock", "address": ip},
        )

        await self._api_request("POST", "firewall/filter/apply")

    async def _block_ip_ssh(self, ip: str, duration: int):
        # Ensure table exists
        await self._ensure_table_ssh()

        # Add IP to table
        await self._ssh(f"sudo pfctl -t {self.table_name} -T add {ip}")

        # Reload pf rules
        await self._ssh("sudo pfctl -f /etc/pf.conf")

        # TTL removal
        asyncio.create_task(self._expire_ssh(ip, duration))

        return {"success": True, "mode": "ssh", "ip": ip, "duration": duration}

    async def _expire_ssh(self, ip: str, duration: int):
        await asyncio.sleep(duration)

        await self._ssh(f"sudo pfctl -t {self.table_name} -T delete {ip}")
        await self._ssh("sudo pfctl -f /etc/pf.conf")
