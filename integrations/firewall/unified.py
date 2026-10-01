import os

from .palo_alto import PaloAltoFirewallConnector
from .cisco_asa import CiscoASAConnector
from .pfsense_dual import PfSenseDualConnector
from .fortigate import FortiGateConnector


class UnifiedFirewall:
    """
    Auto-detects firewall vendor based on env/config and exposes a unified block_ip().
    Supported vendors: paloalto, asa, pfsense, fortigate.
    """

    def __init__(self, vendor: str | None = None):
        self.vendor = vendor or os.environ.get("FW_VENDOR", "").lower()
        self.impl = self._init_impl()

    def _init_impl(self):
        if self.vendor == "paloalto":
            return PaloAltoFirewallConnector(
                host=os.environ["PAN_HOST"],
                api_key=os.environ["PAN_API_KEY"],
            )

        if self.vendor == "asa":
            return CiscoASAConnector(
                host=os.environ["ASA_HOST"],
                username=os.environ["ASA_USER"],
                password=os.environ["ASA_PASS"],
            )

        if self.vendor == "pfsense":
            return PfSenseDualConnector(
                host=os.environ["PFSENSE_HOST"],
                api_key=os.environ.get("PFSENSE_API_KEY"),
                api_secret=os.environ.get("PFSENSE_API_SECRET"),
                ssh_user=os.environ.get("PFSENSE_SSH_USER"),
                ssh_pass=os.environ.get("PFSENSE_SSH_PASS"),
            )

        if self.vendor == "fortigate":
            return FortiGateConnector(
                host=os.environ["FG_HOST"],
                token=os.environ["FG_TOKEN"],
                vdom=os.environ.get("FG_VDOM", "root"),
            )

        raise RuntimeError(f"Unsupported or missing FW_VENDOR: {self.vendor}")

    async def block_ip(self, ip: str, duration: int = 86400):
        return await self.impl.block_ip(ip, duration=duration)
