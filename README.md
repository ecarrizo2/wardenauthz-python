# WardenAuth Python SDK

[![CI](https://github.com/ecarrizo2/wardenauthz-python/actions/workflows/ci.yml/badge.svg)](https://github.com/ecarrizo2/wardenauthz-python/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/wardenauthz)](https://pypi.org/project/wardenauthz/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Official Python client for the [WardenAuth](https://wardenauthz.com) managed authorization API: authorization for your users and your AI agents.

## Installation

```bash
pip install wardenauthz
```

## Quick Start

```python
from access_control import AccessControlClient

client = AccessControlClient(
    api_url="https://api.wardenauthz.com",
    api_key="sk_your_api_key"
)

# Check if a user can access a resource
result = client.access.has_access({
    "subjectId": "user-123",
    "scopeId": "scope-456",
    "resource": "documents",
    "action": "read"
})

if result.allowed:
    print("Access granted")
else:
    print(f"Access denied: {result.error}")
```

## Resources

| Resource | Methods |
|----------|---------|
| `client.scopes` | `create(input)`, `list(limit, next_token, type)`, `get_by_id(scope_id)`, `update(scope_id, input)`, `delete(scope_id)`, `apply_manifest(scope_id, manifest)`, `export(scope_id)` |
| `client.permissions` | `create(scope_id, input)`, `bulk_create(scope_id, inputs)`, `list(scope_id, limit, next_token)`, `get_by_id(scope_id, perm_id)`, `update(scope_id, perm_id, input)`, `delete(scope_id, perm_id)`, `bulk_delete(scope_id, ids)` |
| `client.roles` | `create(scope_id, input)`, `bulk_create(scope_id, inputs)`, `list(scope_id, limit, next_token)`, `get_by_id(scope_id, role_id)`, `update(scope_id, role_id, input)`, `delete(scope_id, role_id)`, `bulk_delete(scope_id, ids)` |
| `client.access_policies` | `create(scope_id, input)`, `list_by_scope(scope_id)`, `list_by_subject(subject_id)`, `get_by_id(scope_id, policy_id)`, `update(scope_id, policy_id, input)`, `delete(scope_id, policy_id)`, `import_csv(scope_id, csv_content)` |
| `client.api_keys` | `create(scope_id, input)`, `list(scope_id)`, `get_by_id(scope_id, key_id)`, `delete(scope_id, key_id)`, `rotate(scope_id, key_id)`, `reveal_rotation(scope_id, key_id, rotation_ref)`, `update_auto_rotation(scope_id, key_id, input)` |
| `client.webhooks` | `create(scope_id, input)`, `list(scope_id, limit, next_token)`, `get_by_id(scope_id, endpoint_id)`, `update(scope_id, endpoint_id, input)`, `delete(scope_id, endpoint_id)`, `rotate_secret(scope_id, endpoint_id)`, `test(scope_id, endpoint_id)`, `list_deliveries(scope_id, endpoint_id, limit, next_token)` |
| `client.access` | `has_access(input)`, `has_access_bulk(inputs)`, `list_permissions(input)`, `list_roles(input)`, `simulate(input)` |
| `client.audit` | `list(scope_id, limit, next_token)`, `export(**filters)` |
| `client.billing` | `get_subscription()`, `update_subscription(input)`, `create_checkout_session(input)`, `create_customer_portal_session()` |
| `client.dashboard` | `get_stats(scope_id)` |
| `client.session_tokens` | `mint(input)` |
| `client.sod_constraints` | `create(scope_id, input)`, `list(scope_id)`, `delete(scope_id, constraint_id)` |
| `client.sso` | `create(org_id, input)`, `list(org_id)`, `get(org_id, idp_id)`, `update(org_id, idp_id, input)`, `delete(org_id, idp_id)`, `test(org_id, idp_id)`, `rotate_scim_token(org_id)` |
| `client.team_members` | `add(scope_id, input)`, `list(scope_id)`, `remove(scope_id, subject_id)` |
| `client.resource_types` | `create(scope_id, input)`, `list(scope_id, limit, next_token)`, `get_by_id(scope_id, type_id)`, `delete(scope_id, type_id)` |
| `client.organization` | `get()`, `update(input)`, `delete()`, `get_ip_allowlist(org_id)`, `update_ip_allowlist(org_id, input)` |

### Pagination

List endpoints support cursor-based pagination with `limit` and `next_token` parameters:

```python
result = client.permissions.list("scope-1", limit="50")
print(f"Items: {len(result.items)}, Next: {result.next_token}")

# Fetch next page
if result.next_token:
    page2 = client.permissions.list("scope-1", limit="50", next_token=result.next_token)
```

## Error Handling

All API errors (4xx and 5xx) raise `AccessControlApiError` with the following properties:

```python
from access_control import AccessControlApiError, AccessControlClient

client = AccessControlClient(api_url="https://api.wardenauthz.com", api_key="sk_test")

try:
    client.scopes.get_by_id("nonexistent")
except AccessControlApiError as e:
    print(f"Status: {e.status_code}")   # 404
    print(f"Body: {e.body}")            # {"error": "not found"}
    print(f"Message: {e.message}")      # "Not Found"
    print(str(e))                        # "access-control api error 404: ..."
```

## Type Definitions

The SDK includes strongly-typed dataclasses for all API responses:

- `ScopeItem`, `PermissionItem`, `RoleItem`, `AccessPolicyItem`
- `ApiKeyItem`, `ApiKeyCreatedItem`
- `WebhookEndpointItem`, `WebhookEndpointCreatedItem`, `WebhookDeliveryItem`
- `AccessCheckResult`, `SimulateAccessResult`
- `AuditLogItem`, `SubscriptionSummary`, `DashboardStats`
- `TeamMemberItem`, `SSOConfigItem`, `SodConstraintItem`
- `MintSessionTokenResult`, `OrganizationItem`

All types include a `from_dict(data)` static factory method for deserialization.

## API Reference

For full API documentation, visit the [WardenAuth documentation](https://docs.wardenauthz.com).

## License

MIT
