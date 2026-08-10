from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union


@dataclass
class ScopeItem:
    id: str
    name: str
    type: str  # organization | workspace | application
    parent_id: Optional[str] = field(default=None, metadata={"json": "parentId"})
    description: Optional[str] = None
    allow_role_inheritance: bool = field(default=False, metadata={"json": "allowRoleInheritance"})

    @staticmethod
    def from_dict(d: dict):
        return ScopeItem(
            id=d["id"], name=d["name"], type=d["type"],
            parent_id=d.get("parentId"), description=d.get("description"),
            allow_role_inheritance=d.get("allowRoleInheritance", False),
        )


@dataclass
class PermissionItem:
    id: str
    scope_id: str
    resource: str
    action: str
    effect: str
    name: str
    description: Optional[str] = None

    @staticmethod
    def from_dict(d: dict):
        return PermissionItem(
            id=d["id"], scope_id=d.get("scopeId", ""), resource=d.get("resource", ""),
            action=d.get("action", ""), effect=d.get("effect", "allow"),
            name=d.get("name", ""), description=d.get("description"),
        )


@dataclass
class RoleItem:
    id: str
    scope_id: str
    name: str
    description: Optional[str] = None
    permission_ids: List[str] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict):
        return RoleItem(
            id=d["id"], scope_id=d.get("scopeId", ""), name=d.get("name", ""),
            description=d.get("description"), permission_ids=d.get("permissionIds", []),
        )


@dataclass
class AccessPolicyItem:
    id: str
    subject_id: str
    scope_id: str
    role_ids: List[str] = field(default_factory=list)
    permission_ids: List[str] = field(default_factory=list)
    expires_at: Optional[str] = None
    valid_from: Optional[str] = None

    @staticmethod
    def from_dict(d: dict):
        return AccessPolicyItem(
            id=d.get("id", ""), subject_id=d.get("subjectId", ""), scope_id=d.get("scopeId", ""),
            role_ids=d.get("roleIds", []), permission_ids=d.get("permissionIds", []),
            expires_at=d.get("expiresAt"), valid_from=d.get("validFrom"),
        )


@dataclass
class ApiKeyItem:
    key_id: str
    type: str
    masked_key: str
    created_at: str
    subject_id: str
    name: str
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None

    @staticmethod
    def from_dict(d: dict):
        return ApiKeyItem(
            key_id=d.get("keyId", ""), type=d.get("type", ""), masked_key=d.get("maskedKey", ""),
            created_at=d.get("createdAt", ""), subject_id=d.get("subjectId", ""),
            name=d.get("name", ""), expires_at=d.get("expiresAt"), last_used_at=d.get("lastUsedAt"),
        )


@dataclass
class ApiKeyCreatedItem(ApiKeyItem):
    key: str = ""

    @staticmethod
    def from_dict(d: dict):
        return ApiKeyCreatedItem(
            key_id=d.get("keyId", ""), type=d.get("type", ""), masked_key=d.get("maskedKey", ""),
            created_at=d.get("createdAt", ""), subject_id=d.get("subjectId", ""),
            name=d.get("name", ""), expires_at=d.get("expiresAt"), last_used_at=d.get("lastUsedAt"),
            key=d.get("key", ""),
        )


@dataclass
class WebhookEndpointItem:
    id: str
    scope_id: str
    url: str
    events: List[str] = field(default_factory=list)
    active: bool = True
    created_at: str = ""
    updated_at: Optional[str] = None

    @staticmethod
    def from_dict(d: dict):
        return WebhookEndpointItem(
            id=d.get("id", ""), scope_id=d.get("scopeId", ""), url=d.get("url", ""),
            events=d.get("events", []), active=d.get("active", True),
            created_at=d.get("createdAt", ""), updated_at=d.get("updatedAt"),
        )


@dataclass
class WebhookEndpointCreatedItem(WebhookEndpointItem):
    secret: str = ""

    @staticmethod
    def from_dict(d: dict):
        return WebhookEndpointCreatedItem(
            id=d.get("id", ""), scope_id=d.get("scopeId", ""), url=d.get("url", ""),
            events=d.get("events", []), active=d.get("active", True),
            created_at=d.get("createdAt", ""), updated_at=d.get("updatedAt"),
            secret=d.get("secret", ""),
        )


@dataclass
class WebhookDeliveryItem:
    id: str
    endpoint_id: str
    scope_id: str
    event_type: str
    success: bool = False
    http_status: Optional[int] = None
    duration_ms: int = 0
    attempts: int = 0
    error_message: Optional[str] = None
    request_body: str = ""
    response_body: Optional[str] = None
    created_at: str = ""

    @staticmethod
    def from_dict(d: dict):
        return WebhookDeliveryItem(
            id=d.get("id", ""), endpoint_id=d.get("endpointId", ""), scope_id=d.get("scopeId", ""),
            event_type=d.get("eventType", ""), success=d.get("success", False),
            http_status=d.get("httpStatus"), duration_ms=d.get("durationMs", 0),
            attempts=d.get("attempts", 0), error_message=d.get("errorMessage"),
            request_body=d.get("requestBody", ""), response_body=d.get("responseBody"),
            created_at=d.get("createdAt", ""),
        )


@dataclass
class AccessCheckResult:
    subject_id: str
    scope_id: str
    type: str
    id: str
    allowed: bool = False
    resource: Optional[str] = None
    action: Optional[str] = None
    error: Optional[str] = None
    inherited_from_scope: Optional[str] = None
    reasoning: Optional[Dict[str, Any]] = None

    @staticmethod
    def from_dict(d: dict):
        return AccessCheckResult(
            subject_id=d.get("subjectId", ""),
            scope_id=d.get("scopeId", ""),
            type=d.get("type", ""),
            id=d.get("id", ""),
            allowed=d.get("allowed", False),
            resource=d.get("resource"),
            action=d.get("action"),
            error=d.get("error"),
            inherited_from_scope=d.get("inheritedFromScope"),
            reasoning=d.get("reasoning"),
        )


@dataclass
class AuditLogItem:
    id: str
    scope_id: str
    actor_id: str
    action: str
    resource_type: str
    resource_id: str
    created_at: str = ""
    changes: Optional[Dict[str, Any]] = None

    @staticmethod
    def from_dict(d: dict):
        return AuditLogItem(
            id=d.get("id", ""), scope_id=d.get("scopeId", ""), actor_id=d.get("actorId", ""),
            action=d.get("action", ""), resource_type=d.get("resourceType", ""),
            resource_id=d.get("resourceId", ""), created_at=d.get("createdAt", ""),
            changes=d.get("changes"),
        )


@dataclass
class SubscriptionSummary:
    tier: str
    tier_name: str
    monthly_limit: Optional[int] = None
    current_month_count: int = 0
    percent_used: Optional[int] = None
    notification_emails: List[str] = field(default_factory=list)
    alert_threshold_percent: int = 80
    stripe_status: Optional[str] = None

    @staticmethod
    def from_dict(d: dict):
        return SubscriptionSummary(
            tier=d.get("tier", "free"), tier_name=d.get("tierName", ""),
            monthly_limit=d.get("monthlyLimit"), current_month_count=d.get("currentMonthCount", 0),
            percent_used=d.get("percentUsed"), notification_emails=d.get("notificationEmails", []),
            alert_threshold_percent=d.get("alertThresholdPercent", 80),
            stripe_status=d.get("stripeStatus"),
        )


@dataclass
class DashboardStats:
    scope_name: str = ""
    counts: Dict[str, int] = field(default_factory=dict)
    usage: Dict[str, Any] = field(default_factory=dict)
    recent_activity: List[Dict[str, Any]] = field(default_factory=list)
    organization: Optional[Dict[str, Any]] = None

    @staticmethod
    def from_dict(d: dict):
        return DashboardStats(
            scope_name=d.get("scopeName", ""), counts=d.get("counts", {}),
            usage=d.get("usage", {}), recent_activity=d.get("recentActivity", []),
            organization=d.get("organization"),
        )


@dataclass
class TeamMemberItem:
    subject_id: str
    scope_id: str
    role: str
    added_at: str = ""

    @staticmethod
    def from_dict(d: dict):
        return TeamMemberItem(
            subject_id=d.get("subjectId", ""), scope_id=d.get("scopeId", ""),
            role=d.get("role", ""), added_at=d.get("addedAt", ""),
        )


@dataclass
class SSOConfigItem:
    idp_id: str
    org_id: str
    provider: str
    protocol: str
    metadata_url: Optional[str] = None
    metadata_xml: Optional[str] = None
    client_id: Optional[str] = None
    issuer_url: Optional[str] = None
    created_at: str = ""

    @staticmethod
    def from_dict(d: dict):
        return SSOConfigItem(
            idp_id=d.get("idpId", ""), org_id=d.get("orgId", ""), provider=d.get("provider", ""),
            protocol=d.get("protocol", ""), metadata_url=d.get("metadataUrl"),
            metadata_xml=d.get("metadataXml"), client_id=d.get("clientId"),
            issuer_url=d.get("issuerUrl"), created_at=d.get("createdAt", ""),
        )


@dataclass
class SodConstraintItem:
    id: str
    scope_id: str
    role_id_a: str
    role_id_b: str
    description: Optional[str] = None

    @staticmethod
    def from_dict(d: dict):
        return SodConstraintItem(
            id=d.get("id", ""), scope_id=d.get("scopeId", ""),
            role_id_a=d.get("roleIdA", ""), role_id_b=d.get("roleIdB", ""),
            description=d.get("description"),
        )


@dataclass
class MintSessionTokenResult:
    token: str = ""
    token_type: str = "Bearer"
    principal_id: str = ""
    scope_id: str = ""
    issued_at: int = 0
    expires_at: str = ""
    permission_ids: List[str] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict):
        return MintSessionTokenResult(
            token=d.get("token", ""), token_type=d.get("tokenType", "Bearer"),
            principal_id=d.get("principalId", ""), scope_id=d.get("scopeId", ""),
            issued_at=d.get("issuedAt", 0), expires_at=d.get("expiresAt", ""),
            permission_ids=d.get("permissionIds", []),
        )


@dataclass
class SimulateAccessResult:
    subject_id: str
    scope_id: str
    results: List[Dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict):
        return SimulateAccessResult(
            subject_id=d.get("subjectId", ""), scope_id=d.get("scopeId", ""),
            results=d.get("results", []),
        )


@dataclass
class OrganizationItem:
    id: str
    name: str
    type: str
    description: Optional[str] = None
    parent_id: Optional[str] = None

    @staticmethod
    def from_dict(d: dict):
        return OrganizationItem(
            id=d.get("id", ""), name=d.get("name", ""), type=d.get("type", ""),
            description=d.get("description"), parent_id=d.get("parentId"),
        )
