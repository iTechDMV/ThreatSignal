import abc
import aiohttp
import asyncio
import time
import re
from dataclasses import dataclass
from typing import Optional, Dict, Any, List


HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


@dataclass
class IntelResult:
    indicator: str
    source: str
    malicious_score: int
    raw: Dict[str, Any]

    @property
    def is_malicious(self) -> bool:
        return self.malicious_score >= 70

    @property
    def is_suspicious(self) -> bool:
        return 30 <= self.malicious_score < 70

    @property
    def is_clean(self) -> bool:
        return self.malicious_score < 30

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "source": self.source,
            "malicious_score": self.malicious_score,
            "raw": self.raw,
            "verdict": (
                "malicious" if self.is_malicious
                else "suspicious" if self.is_suspicious
                else "clean"
            ),
        }


class ThreatIntelConnector(abc.ABC):
    """Abstract base class for all threat intel providers."""

    def __init__(self, api_key: str, min_request_interval: float = 1.0):
        self.api_key = api_key
        self.min_request_interval = min_request_interval
        self._last_request_ts = 0.0
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._session:
            await self._session.close()

    async def _throttle(self):
        now = time.time()
        delta = now - self._last_request_ts
        if delta < self.min_request_interval:
            await asyncio.sleep(self.min_request_interval - delta)
        self._last_request_ts = time.time()

    async def _request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        await self._throttle()
        async with self._session.request(method, url, **kwargs) as resp:
            if resp.status == 429:
                retry_after = int(resp.headers.get("Retry-After", "2"))
                await asyncio.sleep(retry_after)
                return await self._request(method, url, **kwargs)
            resp.raise_for_status()
            return await resp.json()

    @staticmethod
    def detect_type(indicator: str) -> str:
        if IP_RE.match(indicator):
            return "ip"
        if HASH_RE.match(indicator):
            return "hash"
        if DOMAIN_RE.match(indicator):
            return "domain"
        if indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"
        raise ValueError(f"Unknown indicator type: {indicator}")

    @abc.abstractmethod
    async def lookup(self, indicator: str) -> IntelResult:
        ...

    async def lookup_many(self, indicators: List[str], concurrency: int = 5) -> List[IntelResult]:
        sem = asyncio.Semaphore(concurrency)

        async def _task(ind):
            async with sem:
                try:
                    return await self.lookup(ind)
                except Exception as e:
                    return IntelResult(
                        indicator=ind,
                        source=self.__class__.__name__,
                        malicious_score=0,
                        raw={"error": str(e)},
                    )

        return await asyncio.gather(*[_task(i) for i in indicators])
