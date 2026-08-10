from .client import HttpClient, PaginatedResult
from .types import (
    ScopeItem, PermissionItem, RoleItem, AccessPolicyItem,
    ApiKeyItem, ApiKeyCreatedItem, WebhookEndpointItem, WebhookEndpointCreatedItem,
    WebhookDeliveryItem, AccessCheckResult, AuditLogItem, SubscriptionSummary,
    DashboardStats, TeamMemberItem, SSOConfigItem, SodConstraintItem,
    MintSessionTokenResult, SimulateAccessResult, OrganizationItem,
)
from typing import Optional, List, Dict, Any


class ScopesResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def create(self, input: dict) -> ScopeItem:
        return ScopeItem.from_dict(self._c.post("/v1/scope", input))

    def list(self, limit: str = "", next_token: str = "", type: str = "") -> PaginatedResult:
        params = []
        if limit: params.append(f"limit={limit}")
        if next_token: params.append(f"nextToken={next_token}")
        if type: params.append(f"type={type}")
        qs = "?" + "&".join(params) if params else ""
        data = self._c.get(f"/v1/scope{qs}")
        return PaginatedResult.from_dict(data, ScopeItem)

    def get_by_id(self, scope_id: str) -> ScopeItem:
        return ScopeItem.from_dict(self._c.get(f"/v1/scope/{scope_id}"))

    def update(self, scope_id: str, input: dict) -> ScopeItem:
        return ScopeItem.from_dict(self._c.patch(f"/v1/scope/{scope_id}", input))

    def delete(self, scope_id: str) -> None:
        self._c.delete(f"/v1/scope/{scope_id}")

    def apply_manifest(self, scope_id: str, manifest: dict) -> dict:
        return self._c.post(f"/v1/scope/{scope_id}/apply", manifest)

    def export(self, scope_id: str) -> dict:
        return self._c.get(f"/v1/admin/scope/{scope_id}/export")


class PermissionsResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def create(self, scope_id: str, input: dict) -> PermissionItem:
        input["scopeId"] = scope_id
        return PermissionItem.from_dict(self._c.post(f"/v1/scope/{scope_id}/permission", input))

    def bulk_create(self, scope_id: str, inputs: list) -> None:
        for i in inputs: i["scopeId"] = scope_id
        self._c.post(f"/v1/scope/{scope_id}/permission/bulk", inputs)

    def list(self, scope_id: str, limit: str = "", next_token: str = "") -> PaginatedResult:
        params = []
        if limit: params.append(f"limit={limit}")
        if next_token: params.append(f"nextToken={next_token}")
        qs = "?" + "&".join(params) if params else ""
        data = self._c.get(f"/v1/scope/{scope_id}/permission{qs}")
        return PaginatedResult.from_dict(data, PermissionItem)

    def get_by_id(self, scope_id: str, perm_id: str) -> PermissionItem:
        return PermissionItem.from_dict(self._c.get(f"/v1/scope/{scope_id}/permission/{perm_id}"))

    def update(self, scope_id: str, perm_id: str, input: dict) -> PermissionItem:
        return PermissionItem.from_dict(self._c.patch(f"/v1/scope/{scope_id}/permission/{perm_id}", input))

    def delete(self, scope_id: str, perm_id: str) -> None:
        self._c.delete(f"/v1/scope/{scope_id}/permission/{perm_id}")

    def bulk_delete(self, scope_id: str, ids: list) -> None:
        self._c._request("DELETE", f"/v1/scope/{scope_id}/permission/bulk", {"ids": ids})


class RolesResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def create(self, scope_id: str, input: dict) -> RoleItem:
        input["scopeId"] = scope_id
        return RoleItem.from_dict(self._c.post(f"/v1/scope/{scope_id}/role", input))

    def bulk_create(self, scope_id: str, inputs: list) -> None:
        for i in inputs: i["scopeId"] = scope_id
        self._c.post(f"/v1/scope/{scope_id}/role/bulk", inputs)

    def list(self, scope_id: str, limit: str = "", next_token: str = "") -> PaginatedResult:
        params = []
        if limit: params.append(f"limit={limit}")
        if next_token: params.append(f"nextToken={next_token}")
        qs = "?" + "&".join(params) if params else ""
        data = self._c.get(f"/v1/scope/{scope_id}/role{qs}")
        return PaginatedResult.from_dict(data, RoleItem)

    def get_by_id(self, scope_id: str, role_id: str) -> RoleItem:
        return RoleItem.from_dict(self._c.get(f"/v1/scope/{scope_id}/role/{role_id}"))

    def update(self, scope_id: str, role_id: str, input: dict) -> RoleItem:
        return RoleItem.from_dict(self._c.patch(f"/v1/scope/{scope_id}/role/{role_id}", input))

    def delete(self, scope_id: str, role_id: str) -> None:
        self._c.delete(f"/v1/scope/{scope_id}/role/{role_id}")

    def bulk_delete(self, scope_id: str, ids: list) -> None:
        self._c._request("DELETE", f"/v1/scope/{scope_id}/role/bulk", {"ids": ids})


class AccessPoliciesResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def create(self, scope_id: str, input: dict) -> AccessPolicyItem:
        input["scopeId"] = scope_id
        return AccessPolicyItem.from_dict(self._c.post(f"/v1/scope/{scope_id}/access-policy", input))

    def list_by_scope(self, scope_id: str) -> list:
        data = self._c.get(f"/v1/scope/{scope_id}/access-policy")
        return [AccessPolicyItem.from_dict(i) for i in data.get("items", [])]

    def list_by_subject(self, subject_id: str) -> list:
        data = self._c.get(f"/v1/access-policy/subject/{subject_id}")
        return [AccessPolicyItem.from_dict(i) for i in data.get("items", [])]

    def get_by_id(self, scope_id: str, policy_id: str) -> AccessPolicyItem:
        return AccessPolicyItem.from_dict(self._c.get(f"/v1/scope/{scope_id}/access-policy/{policy_id}"))

    def update(self, scope_id: str, policy_id: str, input: dict) -> AccessPolicyItem:
        return AccessPolicyItem.from_dict(self._c.patch(f"/v1/scope/{scope_id}/access-policy/{policy_id}", input))

    def delete(self, scope_id: str, policy_id: str) -> None:
        self._c.delete(f"/v1/scope/{scope_id}/access-policy/{policy_id}")

    def import_csv(self, scope_id: str, csv_content: str) -> dict:
        return self._c.post(f"/v1/scope/{scope_id}/access-policy/import-csv", {"csv": csv_content})


class ApiKeysResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def create(self, scope_id: str, input: dict) -> ApiKeyCreatedItem:
        return ApiKeyCreatedItem.from_dict(self._c.post(f"/v1/scope/{scope_id}/api-key", input))

    def list(self, scope_id: str) -> list:
        data = self._c.get(f"/v1/scope/{scope_id}/api-key")
        return [ApiKeyItem.from_dict(i) for i in data.get("items", [])]

    def get_by_id(self, scope_id: str, key_id: str) -> ApiKeyItem:
        return ApiKeyItem.from_dict(self._c.get(f"/v1/scope/{scope_id}/api-key/{key_id}"))

    def delete(self, scope_id: str, key_id: str) -> None:
        self._c.delete(f"/v1/scope/{scope_id}/api-key/{key_id}")

    def rotate(self, scope_id: str, key_id: str) -> dict:
        return self._c.post(f"/v1/scope/{scope_id}/api-key/{key_id}/rotate")

    def reveal_rotation(self, scope_id: str, key_id: str, rotation_ref: str) -> dict:
        return self._c.post(f"/v1/scope/{scope_id}/api-key/{key_id}/rotation/reveal", {"rotationRef": rotation_ref})

    def update_auto_rotation(self, scope_id: str, key_id: str, input: dict) -> ApiKeyItem:
        return ApiKeyItem.from_dict(self._c.patch(f"/v1/scope/{scope_id}/api-key/{key_id}/auto-rotation", input))


class WebhooksResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def create(self, scope_id: str, input: dict) -> WebhookEndpointCreatedItem:
        return WebhookEndpointCreatedItem.from_dict(self._c.post(f"/v1/scope/{scope_id}/webhooks", input))

    def list(self, scope_id: str, limit: str = "", next_token: str = "") -> PaginatedResult:
        params = []
        if limit: params.append(f"limit={limit}")
        if next_token: params.append(f"nextToken={next_token}")
        qs = "?" + "&".join(params) if params else ""
        data = self._c.get(f"/v1/scope/{scope_id}/webhooks{qs}")
        return PaginatedResult.from_dict(data, WebhookEndpointItem)

    def get_by_id(self, scope_id: str, endpoint_id: str) -> WebhookEndpointItem:
        return WebhookEndpointItem.from_dict(self._c.get(f"/v1/scope/{scope_id}/webhooks/{endpoint_id}"))

    def update(self, scope_id: str, endpoint_id: str, input: dict) -> WebhookEndpointItem:
        return WebhookEndpointItem.from_dict(self._c.patch(f"/v1/scope/{scope_id}/webhooks/{endpoint_id}", input))

    def delete(self, scope_id: str, endpoint_id: str) -> None:
        self._c.delete(f"/v1/scope/{scope_id}/webhooks/{endpoint_id}")

    def rotate_secret(self, scope_id: str, endpoint_id: str) -> dict:
        return self._c.post(f"/v1/scope/{scope_id}/webhooks/{endpoint_id}/rotate-secret")

    def test(self, scope_id: str, endpoint_id: str) -> dict:
        return self._c.post(f"/v1/scope/{scope_id}/webhooks/{endpoint_id}/test")

    def list_deliveries(self, scope_id: str, endpoint_id: str, limit: str = "", next_token: str = "") -> PaginatedResult:
        params = []
        if limit: params.append(f"limit={limit}")
        if next_token: params.append(f"nextToken={next_token}")
        qs = "?" + "&".join(params) if params else ""
        data = self._c.get(f"/v1/scope/{scope_id}/webhooks/{endpoint_id}/deliveries{qs}")
        return PaginatedResult.from_dict(data, WebhookDeliveryItem)


class AccessResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def has_access(self, input: dict) -> AccessCheckResult:
        return AccessCheckResult.from_dict(self._c.post("/v1/access/check", input))

    def has_access_bulk(self, inputs: list) -> list:
        data = self._c.post("/v1/access/check-bulk", inputs)
        return [AccessCheckResult.from_dict(i) for i in data]

    def list_permissions(self, input: dict) -> dict:
        return self._c.post("/v1/access/list-permissions", input)

    def list_roles(self, input: dict) -> dict:
        return self._c.post("/v1/access/list-roles", input)

    def simulate(self, input: dict) -> SimulateAccessResult:
        return SimulateAccessResult.from_dict(self._c.post("/v1/access/simulate", input))


class AuditResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def list(self, scope_id: str, limit: str = "", next_token: str = "") -> PaginatedResult:
        params = []
        if limit: params.append(f"limit={limit}")
        if next_token: params.append(f"nextToken={next_token}")
        qs = "?" + "&".join(params) if params else ""
        data = self._c.get(f"/v1/scope/{scope_id}/audit{qs}")
        return PaginatedResult.from_dict(data, AuditLogItem)

    def export(self, scope_id: str = "", actor_id: str = "", resource_type: str = "",
               resource_id: str = "", start_date: str = "", end_date: str = "",
               max_rows: str = "", format: str = "") -> str:
        params = []
        for k, v in [("scopeId", scope_id), ("actorId", actor_id), ("resourceType", resource_type),
                      ("resourceId", resource_id), ("startDate", start_date), ("endDate", end_date),
                      ("maxRows", max_rows), ("format", format)]:
            if v: params.append(f"{k}={v}")
        qs = "?" + "&".join(params) if params else ""
        return self._c.get_raw(f"/v1/audit/export{qs}")


class BillingResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def get_subscription(self) -> SubscriptionSummary:
        return SubscriptionSummary.from_dict(self._c.get("/v1/admin/billing/subscription"))

    def update_subscription(self, input: dict) -> SubscriptionSummary:
        return SubscriptionSummary.from_dict(self._c.patch("/v1/admin/billing/subscription", input))

    def create_checkout_session(self, input: dict) -> dict:
        return self._c.post("/v1/admin/billing/checkout", input)

    def create_customer_portal_session(self) -> dict:
        return self._c.post("/v1/admin/billing/portal")


class DashboardResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def get_stats(self, scope_id: str) -> DashboardStats:
        return DashboardStats.from_dict(self._c.get(f"/v1/admin/scope/{scope_id}/stats"))


class SessionTokensResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def mint(self, input: dict = None) -> MintSessionTokenResult:
        return MintSessionTokenResult.from_dict(self._c.post("/v1/session-token/mint", input or {}))


class SodConstraintsResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def create(self, scope_id: str, input: dict) -> SodConstraintItem:
        return SodConstraintItem.from_dict(self._c.post(f"/v1/scope/{scope_id}/sod-constraint", input))

    def list(self, scope_id: str) -> list:
        data = self._c.get(f"/v1/scope/{scope_id}/sod-constraint")
        return [SodConstraintItem.from_dict(i) for i in data.get("items", [])]

    def delete(self, scope_id: str, constraint_id: str) -> None:
        self._c.delete(f"/v1/scope/{scope_id}/sod-constraint/{constraint_id}")


class SsoResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def create(self, org_id: str, input: dict) -> SSOConfigItem:
        return SSOConfigItem.from_dict(self._c.post(f"/v1/admin/org/{org_id}/sso/configs", input))

    def list(self, org_id: str) -> list:
        return [SSOConfigItem.from_dict(i) for i in self._c.get(f"/v1/admin/org/{org_id}/sso/configs")]

    def get(self, org_id: str, idp_id: str) -> SSOConfigItem:
        return SSOConfigItem.from_dict(self._c.get(f"/v1/admin/org/{org_id}/sso/configs/{idp_id}"))

    def update(self, org_id: str, idp_id: str, input: dict) -> SSOConfigItem:
        return SSOConfigItem.from_dict(self._c.patch(f"/v1/admin/org/{org_id}/sso/configs/{idp_id}", input))

    def delete(self, org_id: str, idp_id: str) -> None:
        self._c.delete(f"/v1/admin/org/{org_id}/sso/configs/{idp_id}")

    def test(self, org_id: str, idp_id: str) -> dict:
        return self._c.post(f"/v1/admin/org/{org_id}/sso/configs/{idp_id}/test")

    def rotate_scim_token(self, org_id: str) -> dict:
        return self._c.post(f"/v1/admin/org/{org_id}/sso/scim-token")


class TeamMembersResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def add(self, scope_id: str, input: dict) -> TeamMemberItem:
        return TeamMemberItem.from_dict(self._c.post(f"/v1/scope/{scope_id}/team-members", input))

    def list(self, scope_id: str) -> list:
        data = self._c.get(f"/v1/scope/{scope_id}/team-members")
        return [TeamMemberItem.from_dict(i) for i in data.get("items", [])]

    def remove(self, scope_id: str, subject_id: str) -> None:
        self._c.delete(f"/v1/scope/{scope_id}/team-members/{subject_id}")


class ResourceTypesResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def create(self, scope_id: str, input: dict) -> dict:
        return self._c.post(f"/v1/scope/{scope_id}/resource-type", input)

    def list(self, scope_id: str, limit: str = "", next_token: str = "") -> PaginatedResult:
        params = []
        if limit: params.append(f"limit={limit}")
        if next_token: params.append(f"nextToken={next_token}")
        qs = "?" + "&".join(params) if params else ""
        data = self._c.get(f"/v1/scope/{scope_id}/resource-type{qs}")
        return PaginatedResult.from_dict(data, lambda d: d)

    def get_by_id(self, scope_id: str, type_id: str) -> dict:
        return self._c.get(f"/v1/scope/{scope_id}/resource-type/{type_id}")

    def delete(self, scope_id: str, type_id: str) -> None:
        self._c.delete(f"/v1/scope/{scope_id}/resource-type/{type_id}")


class OrganizationResource:
    def __init__(self, client: HttpClient):
        self._c = client

    def get(self) -> OrganizationItem:
        return OrganizationItem.from_dict(self._c.get("/v1/organization"))

    def update(self, input: dict) -> OrganizationItem:
        return OrganizationItem.from_dict(self._c.patch("/v1/organization", input))

    def delete(self) -> None:
        self._c.delete("/v1/organization")

    def get_ip_allowlist(self, org_id: str) -> dict:
        return self._c.get(f"/v1/admin/org/{org_id}/ip-allowlist")

    def update_ip_allowlist(self, org_id: str, input: dict) -> dict:
        return self._c.put(f"/v1/admin/org/{org_id}/ip-allowlist", input)
