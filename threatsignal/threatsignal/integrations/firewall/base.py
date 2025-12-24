"""
Firewall Integration Module
Abstract base class for firewall connectors
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

class FirewallConnector(ABC):
    """Abstract base class for firewall connectors"""
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to firewall"""
        pass
    
    @abstractmethod
    async def get_traffic_logs(self, time_range: Dict, filters: Dict = None) -> List[Dict]:
        """Get network traffic logs"""
        pass
    
    @abstractmethod
    async def block_ip(self, ip_address: str, reason: str, duration: int = 3600) -> Dict:
        """Block IP address"""
        pass
    
    @abstractmethod
    async def unblock_ip(self, ip_address: str) -> Dict:
        """Unblock IP address"""
        pass
    
    @abstractmethod
    async def get_blocked_ips(self) -> List[Dict]:
        """Get list of currently blocked IPs"""
        pass