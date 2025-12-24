import pytest
from threatsignal.response import IncidentWorkflowEngine, IncidentStatus

@pytest.fixture
def workflow_engine():
    return IncidentWorkflowEngine()

def test_workflow_engine_init(workflow_engine):
    assert len(workflow_engine.workflows) > 0
    assert "ransomware" in workflow_engine.workflows

@pytest.mark.asyncio
async def test_create_incident(workflow_engine):
    incident_id = await workflow_engine.create_incident(
        title="Test Incident",
        description="Test description",
        severity="HIGH",
        affected_assets=["test-asset"],
        incident_type="ransomware"
    )
    
    assert incident_id.startswith("INC-")
    assert incident_id in workflow_engine.incidents