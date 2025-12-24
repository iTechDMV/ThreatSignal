"""
Incident Response Workflow Engine
Manages complex incident response workflows and playbooks
"""

import json
import asyncio
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from datetime import datetime, timedelta

class IncidentStatus(Enum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"

class WorkflowPhase(Enum):
    DETECTION = "detection"
    ANALYSIS = "analysis"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"

@dataclass
class Incident:
    incident_id: str
    title: str
    description: str
    severity: str
    status: IncidentStatus
    detected_at: datetime
    assigned_to: Optional[str]
    affected_assets: List[str]
    current_phase: WorkflowPhase
    playbook_executed: List[str]
    evidence: List[Dict]
    resolution_notes: Optional[str]

@dataclass
class WorkflowStep:
    step_id: str
    title: str
    description: str
    phase: WorkflowPhase
    required_approvals: List[str]
    automated_actions: List[Dict]
    manual_tasks: List[str]
    estimated_duration: int  # minutes
    dependencies: List[str]

class IncidentWorkflowEngine:
    """Manages incident response workflows and playbooks"""
    
    def __init__(self):
        self.incidents: Dict[str, Incident] = {}
        self.workflows: Dict[str, List[WorkflowStep]] = {}
        self.workflow_handlers: Dict[WorkflowPhase, Callable] = {}
        self.logger = logging.getLogger(__name__)
        
        self._load_default_workflows()
        self._register_workflow_handlers()
    
    def _load_default_workflows(self):
        """Load default incident response workflows"""
        # Ransomware response workflow
        ransomware_workflow = [
            WorkflowStep(
                step_id="R1",
                title="Initial Detection",
                description="Confirm ransomware detection and assess scope",
                phase=WorkflowPhase.DETECTION,
                required_approvals=["SOC Manager"],
                automated_actions=[{"action": "isolate_endpoint", "target": "affected_assets"}],
                manual_tasks=["Verify encryption indicators", "Identify patient zero"],
                estimated_duration=15,
                dependencies=[]
            ),
            WorkflowStep(
                step_id="R2", 
                title="Scope Assessment",
                description="Determine extent of infection and affected systems",
                phase=WorkflowPhase.ANALYSIS,
                required_approvals=["CISO"],
                automated_actions=[{"action": "scan_network", "target": "all_assets"}],
                manual_tasks=["Review backup integrity", "Identify critical systems"],
                estimated_duration=30,
                dependencies=["R1"]
            ),
            WorkflowStep(
                step_id="R3",
                title="Containment",
                description="Isolate affected systems to prevent spread",
                phase=WorkflowPhase.CONTAINMENT,
                required_approvals=["CISO", "Infrastructure Manager"],
                automated_actions=[
                    {"action": "isolate_network_segment", "target": "affected_networks"},
                    {"action": "disable_accounts", "target": "compromised_accounts"}
                ],
                manual_tasks=["Document containment actions", "Prepare communication"],
                estimated_duration=45,
                dependencies=["R2"]
            )
        ]
        
        self.workflows["ransomware"] = ransomware_workflow
    
    def _register_workflow_handlers(self):
        """Register handlers for each workflow phase"""
        self.workflow_handlers[WorkflowPhase.DETECTION] = self._handle_detection_phase
        self.workflow_handlers[WorkflowPhase.ANALYSIS] = self._handle_analysis_phase
        self.workflow_handlers[WorkflowPhase.CONTAINMENT] = self._handle_containment_phase
    
    async def create_incident(self, title: str, description: str, severity: str, 
                            affected_assets: List[str], incident_type: str = "generic") -> str:
        """Create new incident and start workflow"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{len(self.incidents) + 1:04d}"
        
        incident = Incident(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.DETECTED,
            detected_at=datetime.now(),
            assigned_to=None,
            affected_assets=affected_assets,
            current_phase=WorkflowPhase.DETECTION,
            playbook_executed=[],
            evidence=[],
            resolution_notes=None
        )
        
        self.incidents[incident_id] = incident
        
        # Start workflow execution
        asyncio.create_task(self._execute_workflow(incident_id, incident_type))
        
        self.logger.info(f"Created incident {incident_id} with type {incident_type}")
        return incident_id
    
    async def _execute_workflow(self, incident_id: str, incident_type: str):
        """Execute incident response workflow"""
        if incident_type not in self.workflows:
            self.logger.error(f"Unknown incident type: {incident_type}")
            return
        
        incident = self.incidents[incident_id]
        workflow = self.workflows[incident_type]
        
        # Execute workflow steps in order
        for step in workflow:
            if step.phase != incident.current_phase:
                continue
            
            # Check dependencies
            if not self._check_step_dependencies(incident, step):
                continue
            
            # Execute step
            await self._execute_workflow_step(incident_id, step)
    
    async def _execute_workflow_step(self, incident_id: str, step: WorkflowStep):
        """Execute a single workflow step"""
        incident = self.incidents[incident_id]
        
        self.logger.info(f"Executing step {step.step_id} for incident {incident_id}")
        
        # Execute automated actions
        for action in step.automated_actions:
            try:
                result = await self._execute_automated_action(action, incident)
                self.logger.info(f"Action {action['action']} completed: {result}")
            except Exception as e:
                self.logger.error(f"Action {action['action']} failed: {e}")
        
        # Mark step as executed
        incident.playbook_executed.append(step.step_id)
    
    def _check_step_dependencies(self, incident: Incident, step: WorkflowStep) -> bool:
        """Check if all step dependencies are met"""
        for dep in step.dependencies:
            if dep not in incident.playbook_executed:
                return False
        return True
    
    async def _execute_automated_action(self, action: Dict, incident: Incident) -> Dict:
        """Execute automated response action"""
        action_type = action['action']
        target = action['target']
        
        if action_type == "isolate_endpoint":
            # This would integrate with EDR systems
            return {"success": True, "message": f"Isolated endpoints: {incident.affected_assets}"}
        
        elif action_type == "scan_network":
            # This would integrate with scanning tools
            return {"success": True, "message": "Network scan completed"}
        
        return {"success": False, "message": f"Unknown action: {action_type}"}
    
    async def get_incident_status(self, incident_id: str) -> Dict:
        """Get current incident status and progress"""
        if incident_id not in self.incidents:
            return {"error": "Incident not found"}
        
        incident = self.incidents[incident_id]
        
        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "status": incident.status.value,
            "severity": incident.severity,
            "current_phase": incident.current_phase.value,
            "detected_at": incident.detected_at.isoformat(),
            "affected_assets": incident.affected_assets,
            "evidence": incident.evidence,
        }
    
    # Placeholder handlers
    def _handle_detection_phase(self, incident_id: str): pass
    def _handle_analysis_phase(self, incident_id: str): pass
    def _handle_containment_phase(self, incident_id: str): pass