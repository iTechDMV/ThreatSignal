import pytest
from threatsignal.integrations.edr import CrowdStrikeConnector

@pytest.fixture
def crowdstrike_connector():
    return CrowdStrikeConnector("test_id", "test_secret")

def test_crowdstrike_init(crowdstrike_connector):
    assert crowdstrike_connector.client_id == "test_id"
    assert crowdstrike_connector.client_secret == "test_secret"
    assert crowdstrike_connector.base_url == "https://api.crowdstrike.com"

@pytest.mark.asyncio
async def test_crowdstrike_connect(crowdstrike_connector):
    # Mock the actual API call
    result = await crowdstrike_connector.connect()
    assert isinstance(result, bool)