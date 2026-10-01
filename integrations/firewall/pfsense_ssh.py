import asyncio
import asyncssh
from tenacity import retry, stop_after_attempt, wait_exponential


class PfSenseSSHConnector:
    """
    pfSense SSH-based firewall connector.
    Uses pfctl + tables to block/unblock IPs with TTL auto-expire.
    Requires SSH access to pfSense with privileges to run pfctl.
    """

    def __init__(self, host: str, username: str, password: str):
        self.host = host
        self.username = username
        self.password = password
        self.table_name = "ThreatSignalBlock"

    async def _run(self, command: str):
        async with asyncssh.connect(
            self.host,
            username=self.username,
            password=self.password,
            known_hosts=None
        ) as conn:
            result = await conn.run(command, check=True)
            return result.stdout

    async def _ensure_table(self):
        """
        Creates the table if it doesn't exist.
        pfSense pfctl tables are dynamic and can be created on the fly.
        """
        await self._run(f"sudo pfctl -t {self.table_name} -T show || true")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
    async def block_ip(self, ip: str, duration: int = 86400):
        """
        Adds an IP to the ThreatSignalBlock table and reloads pf rules.
        TTL auto-removes the IP later.
        """

        # Ensure table exists
        await self._ensure_table()

        # Add IP to table
        await self._run(f"sudo pfctl -t {self.table_name} -T add {ip}")

        # Reload pf rules
        await self._run("sudo pfctl -f /etc/pf.conf")

        # Schedule TTL removal
        asyncio.create_task(self._expire(ip, duration))

        return {"success": True, "ip": ip, "duration": duration}

    async def _expire(self, ip: str, duration: int):
        await asyncio.sleep(duration)

        # Remove IP from table
        await self._run(f"sudo pfctl -t {self.table_name} -T delete {ip}")

        # Reload pf rules
        await self._run("sudo pfctl -f /etc/pf.conf")
