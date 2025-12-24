"""
Time and date utility functions for ThreatSignal
"""

from datetime import datetime, timedelta
from typing import Dict

def get_time_range(hours: int = 24) -> Dict[str, str]:
    """Get time range for the last N hours"""
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)
    
    return {
        "start": start_time.isoformat(),
        "end": end_time.isoformat()
    }

def format_timestamp(timestamp: datetime) -> str:
    """Format datetime to ISO string"""
    return timestamp.isoformat()

def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse ISO string to datetime"""
    return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))