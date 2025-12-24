import pytest
from threatsignal.integrations.edr import SentinelOneConnector

@pytest.fixture
def sentinelone_connector():
    return SentinelOneConnector("test_token", "https://test.sentinelone.net")

def test_sentinelone_init(sentinelone_connector):
    assert sentinelone_connector.api_token == "test_token"
    assert sentinelone_connector.base_url == "https://test.sentinelone.net"