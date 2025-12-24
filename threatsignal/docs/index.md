# ThreatSignal Documentation

## Overview

ThreatSignal is a comprehensive security automation framework designed for SOC teams, MSSPs, and security engineers. It provides a modular architecture for integrating with various security tools and orchestrating incident response workflows.

## Quick Start

### Installation

```bash
git clone https://github.com/yourusername/threatsignal.git
cd threatsignal
pip install -r requirements.txt
```

### Basic Usage

```python
from threatsignal.integrations.edr import CrowdStrikeConnector
from threatsignal.response import IncidentWorkflowEngine

# Initialize EDR connection
edr = CrowdStrikeConnector(
    client_id="your-client-id",
    client_secret="your-client-secret"
)

# Create workflow engine
workflow = IncidentWorkflowEngine()

# Execute ransomware response playbook
incident_id = workflow.create_incident(
    title="Ransomware Detection",
    description="Suspicious encryption activity detected",
    severity="HIGH",
    affected_assets=["endpoint-123", "server-456"],
    incident_type="ransomware"
)
```

## Architecture

### Core Components

1. **Integrations Layer**
   - EDR Connectors (CrowdStrike, SentinelOne)
   - Firewall Connectors (Palo Alto, Cisco ASA)
   - Extensible base classes for custom integrations

2. **Incident Response Engine**
   - Workflow orchestration
   - Playbook automation
   - Multi-phase incident handling

3. **Utilities**
   - Centralized logging
   - Time/date utilities
   - Configuration management

## API Reference

### EDR Connectors

#### CrowdStrikeConnector

```python
connector = CrowdStrikeConnector(client_id, client_secret)
await connector.connect()
threats = await connector.get_endpoint_threats(endpoint_id, time_range)
```

#### SentinelOneConnector

```python
connector = SentinelOneConnector(api_token, base_url)
await connector.connect()
threats = await connector.get_endpoint_threats(endpoint_id, time_range)
```

### Firewall Connectors

#### PaloAltoConnector

```python
connector = PaloAltoConnector(firewall_ip, api_key)
await connector.connect()
await connector.block_ip(ip_address, reason)
```

### Incident Response

#### IncidentWorkflowEngine

```python
engine = IncidentWorkflowEngine()
incident_id = await engine.create_incident(
    title="Incident Title",
    description="Incident Description",
    severity="HIGH",
    affected_assets=["asset1", "asset2"],
    incident_type="ransomware"
)
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure your API credentials:

```bash
CROWDSTRIKE_CLIENT_ID=your_client_id
CROWDSTRIKE_CLIENT_SECRET=your_client_secret
SENTINELONE_API_TOKEN=your_api_token
PALO_ALTO_IP=192.168.1.1
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License

MIT License - see LICENSE file for details.