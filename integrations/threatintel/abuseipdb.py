from .base import ThreatIntelConnector, IntelResult


class AbuseIPDBConnector(ThreatIntelConnector):
    BASE = "https://api.abuseipdb.com/api/v2/check"

    async def lookup(self, indicator: str) -> IntelResult:
        if self.detect_type(indicator) != "ip":
            raise NotImplementedError("AbuseIPDB only supports IP indicators")

        data = await self._request(
            "GET",
            self.BASE,
            params={"ipAddress": indicator, "maxAgeInDays": 90},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )

        score = data.get("data", {}).get("abuseConfidenceScore", 0)

        return IntelResult(
            indicator=indicator,
            source="AbuseIPDB",
            malicious_score=score,
            raw=data,
        )
