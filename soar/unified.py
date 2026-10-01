import os
import asyncio

from threatsignal.workflows import PlaybookExecutor
from threatsignal.integrations.threatintel import (
    VirusTotalConnector,
    AbuseIPDBConnector,
)
from threatsignal.integrations.firewall.unified import UnifiedFirewall
from threatsignal.integrations.edr.crowdstrike import CrowdStrikeConnector


class UnifiedSOAR:
    """
    Unified SOAR wrapper that bundles:
    - Threat Intel (VT + AbuseIPDB)
    - EDR (CrowdStrike)
    - Firewall (UnifiedFirewall auto-detect)
    - PlaybookExecutor
    """

    def __init__(self):
        self.intel = None
        self.edr = None
        self.firewall = None
        self.executor = None

    async def init(self):
        # --- Threat Intel ---
        vt_key = os.environ.get("VT_API_KEY")
        abuse_key = os.environ.get("ABUSEIPDB_API_KEY")

        self.intel = {
            "vt": VirusTotalConnector(api_key=vt_key),
            "abuseipdb": AbuseIPDBConnector(api_key=abuse_key),
        }

        # --- EDR (CrowdStrike) ---
        cs_id = os.environ.get("CS_CLIENT_ID")
        cs_secret = os.environ.get("CS_CLIENT_SECRET")

        self.edr = CrowdStrikeConnector(
            client_id=cs_id,
            client_secret=cs_secret,
        )
        await self.edr.connect()


        # --- Firewall (auto-detect) ---
        self.firewall = UnifiedFirewall()

        # --- Playbook Executor ---
        self.executor = PlaybookExecutor(
            {
                "intel": self.intel["vt"],   # primary intel provider
                "edr": self.edr,
                "firewall": self.firewall,
            }
        )

    async def run_playbook(self, name: str, context: dict):
        if self.executor is None:
            await self.init()
        return await self.executor.run(name, context)
