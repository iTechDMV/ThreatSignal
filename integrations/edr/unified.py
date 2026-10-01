import os

from .crowdstrike import CrowdStrikeConnector
from .sentinelone import SentinelOneConnector
from .defender import DefenderConnector


class UnifiedEDR:
    """
    Unified EDR abstraction layer.
    Auto-detects EDR vendor and exposes normalized actions:
    - isolate_endpoint
    - lift_isolation
    - get_host_info
    """

    def __init__(self, vendor: str | None = None):
        self.vendor = vendor or os.environ.get("EDR_VENDOR", "").lower()
        self.impl = self._init_impl()

    def _init_impl(self):
        if self.vendor == "crowdstrike":
            cs_id = os.environ["CS_CLIENT_ID"]
            cs_secret = os.environ["CS_CLIENT_SECRET"]
            cs = CrowdStrikeConnector(cs_id, cs_secret)
            return cs

        if self.vendor == "sentinelone":
            return SentinelOneConnector(
                host=os.environ["S1_HOST"],
                token=os.environ["S1_TOKEN"]
            )

        if self.vendor == "defender":
            return DefenderConnector(
                tenant=os.environ["MD_TENANT"],
                client_id=os.environ["MD_CLIENT_ID"],
                client_secret=os.environ["MD_CLIENT_SECRET"]
            )

        raise RuntimeError(f"Unsupported or missing EDR_VENDOR: {self.vendor}")

    async def connect(self):
        if hasattr(self.impl, "connect"):
            await self.impl.connect()

    async def isolate_endpoint(self, endpoint_id: str):
        return await self.impl.isolate_endpoint(endpoint_id)

    async def lift_isolation(self, endpoint_id: str):
        return await self.impl.lift_isolation(endpoint_id)

    async def get_host_info(self, endpoint_id: str):
        return await self.impl.get_host_info(endpoint_id)
