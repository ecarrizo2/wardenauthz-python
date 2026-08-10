# WardenAuthz Python SDK

Python client for the WardenAuthz managed authorization API.

## Installation

```bash
pip install wardenauthz
```

## Quick Start

```python
from access_control import Client

client = Client(
    api_url="https://api.wardenauthz.com",
    api_key="sk_your_api_key"
)

result = client.access.has_access(
    subject_id="user-123",
    scope_id="scope-456",
    resource="documents",
    action="read"
)
print(f"Allowed: {result['allowed']}")
```
