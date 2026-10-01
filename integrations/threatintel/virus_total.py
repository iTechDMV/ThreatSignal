from .base import ThreatIntelConnector, IntelResult


class VirusTotalConnector(ThreatIntelConnector):
    BASE = "https://www.virustotal.com/api/v3"

    async def lookup(self, indicator: str) -> IntelResult:
        ioc_type = self.detect_type(indicator)

        if ioc_type == "hash":
            url = f"{self.BASE}/files/{indicator}"
        elif ioc_type == "ip":
            url = f"{self.BASE}/ip_addresses/{indicator}"
        elif ioc_type == "domain":
            url = f"{self.BASE}/domains/{indicator}"
        elif ioc_type == "url":
            # VT requires URL ID (base64-url)
            import base64
            vt_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            url = f"{self.BASE}/urls/{vt_id}"
        else:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")

        data = await self._request(
            "GET",
            url,
            headers={"x-apikey": self.api_key},
        )

        score = self._extract_score(data)
        return IntelResult(
            indicator=indicator,
            source="VirusTotal",
            malicious_score=score,
            raw=data,
        )

    @staticmethod
    def _extract_score(data: dict) -> int:
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        total = malicious + suspicious + harmless
        if total == 0:
            return 0

        return int((malicious * 100) / total)
