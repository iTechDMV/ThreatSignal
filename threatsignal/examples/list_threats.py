#!/usr/bin/env python3
"""
Example: List threats from an EDR platform
"""

import asyncio
from threatsignal.integrations.edr import CrowdStrikeConnector

async def main():
    # Initialize EDR connector
    edr = CrowdStrikeConnector(
        client_id="your-client-id",
        client_secret="your-client-secret"
    )
    
    # Connect to EDR
    connected = await edr.connect()
    if connected:
        print("✅ Connected to CrowdStrike")
        
        # Get threats for an endpoint
        threats = await edr.get_endpoint_threats(
            endpoint_id="DESKTOP-123",
            time_range={"start": "2024-01-01T00:00:00Z", "end": "2024-01-02T00:00:00Z"}
        )
        
        print(f"🔍 Found {len(threats)} threats")
        for threat in threats:
            print(f"  - {threat.get('title', 'Unknown')}")
    else:
        print("❌ Failed to connect to CrowdStrike")

if __name__ == "__main__":
    asyncio.run(main())