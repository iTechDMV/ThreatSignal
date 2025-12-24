import pytest
from threatsignal.integrations.firewall import PaloAltoConnector

@pytest.fixture
def palo_alto_connector():
    return PaloAltoConnector("192.168.1.1", "test_api_key")

def test_palo_alto_init(palo_alto_connector):
    assert palo_alto_connector.firewall_ip == "192.168.1.1"
    assert palo_alto_connector.api_key == "test_api_key"