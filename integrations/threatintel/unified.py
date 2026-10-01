import os
import asyncio

from .virus_total import VirusTotalConnector
from .abuseipdb import AbuseIPDBConnector
from .otx import OTXConnector
from .greynoise import GreyNoiseConnector


class UnifiedThreatIntel:
    """
    Unified Threat Intel abstraction layer.
    Bundles:
    - VirusTotal
    - AbuseIPDB
    - OTX (AlienVault)
    - GreyNoise

    Exposes normalized:
    - lookup(indicator)
    - reputation(indicator)
    - classify(indicator)
    """

    def __init__(self):
        self.vt = VirusTotalConnector(api_key=os.environ.get("VT_API_KEY"))
        self.abuse = AbuseIPDBConnector(api_key=os.environ.get("ABUSEIPDB_API_KEY"))
        self.otx = OTXConnector(api_key=os.environ.get("OTX_API_KEY"))
        self.greynoise = GreyNoiseConnector(api_key=os.environ.get("GREYNOISE_API_KEY"))

    async def lookup(self, indicator: str):
        """
        Runs all intel providers in parallel and returns a merged result.
        """

        vt_task = asyncio.create_task(self.vt.lookup(indicator))
        abuse_task = asyncio.create_task(self.abuse.lookup(indicator))
        otx_task = asyncio.create_task(self.otx.lookup(indicator))
        gn_task = asyncio.create_task(self.greynoise.lookup(indicator))

        vt, abuse, otx, gn = await asyncio.gather(
            vt_task, abuse_task, otx_task, gn_task
        )

        return {
            "indicator": indicator,
            "virus_total": vt,
            "abuseipdb": abuse,
            "otx": otx,
            "greynoise": gn,
        }

    async def reputation(self, indicator: str):
        """
        Normalized reputation score across providers.
        """

        data = await self.lookup(indicator)

        return {
            "indicator": indicator,
            "scores": {
                "vt": data["virus_total"].get("score"),
                "abuseipdb": data["abuseipdb"].get("score"),
                "otx": data["otx"].get("pulse_count"),
                "greynoise": data["greynoise"].get("classification"),
            },
        }

    async def classify(self, indicator: str):
        """
        Returns a normalized classification based on all providers.
        """

        data = await self.lookup(indicator)

        return {
            "indicator": indicator,
            "classification": {
                "vt": data["virus_total"].get("malicious"),
                "abuseipdb": data["abuseipdb"].get("abuse_confidence_score"),
                "otx": data["otx"].get("malicious"),
                "greynoise": data["greynoise"].get("noise"),
            },
        }
