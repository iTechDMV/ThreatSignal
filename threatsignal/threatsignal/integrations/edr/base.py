"""
EDR (Endpoint Detection & Response) Integration Module
Abstract base class for EDR connectors
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

class EDRConnector(ABC):
    """Abstract base class for EDR connectors"""
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to EDR platform"""
        pass
    
    @abstractmethod
    async def get_endpoint_threats(self, endpoint_id: str, time_range: Dict) -> List[Dict]:
        """Get threats detected on specific endpoint"""
        pass
    
    @abstractmethod
    async def isolate_endpoint(self, endpoint_id: str, reason: str) -> Dict:
        """Isolate endpoint from network"""
        pass
    
    @abstractmethod
    async def restore_endpoint(self, endpoint_id: str) -> Dict:
        """Restore endpoint connectivity"""
        pass
    
    @abstractmethod
    async def get_file_details(self, file_hash: str) -> Dict:
        """Get detailed file analysis"""
        pass