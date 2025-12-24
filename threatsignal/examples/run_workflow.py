#!/usr/bin/env python3
"""
Example: Run a ransomware incident response workflow
"""

import asyncio
from threatsignal.response import IncidentWorkflowEngine

async def main():
    # Initialize workflow engine
    workflow = IncidentWorkflowEngine()
    
    # Create a ransomware incident
    incident_id = await workflow.create_incident(
        title="Ransomware Detection - WannaCry Variant",
        description="Detected ransomware encryption activity on endpoint DESKTOP-123",
        severity="CRITICAL",
        affected_assets=["DESKTOP-123", "FILE-SERVER-01"],
        incident_type="ransomware"
    )
    
    print(f"🚨 Created incident: {incident_id}")
    
    # Get incident status
    status = await workflow.get_incident_status(incident_id)
    print(f"📊 Incident Status: {status['status']}")
    print(f"🎯 Current Phase: {status['current_phase']}")
    print(f"📋 Affected Assets: {', '.join(status['affected_assets'])}")

if __name__ == "__main__":
    asyncio.run(main())