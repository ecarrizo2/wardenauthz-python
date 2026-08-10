from .client import HttpClient, AccessControlApiError, PaginatedResult
from .resources import (
    ScopesResource, PermissionsResource, RolesResource, AccessPoliciesResource,
    ApiKeysResource, WebhooksResource, AccessResource, AuditResource,
    BillingResource, DashboardResource, SessionTokensResource,
    SodConstraintsResource, SsoResource, TeamMembersResource,
    ResourceTypesResource, OrganizationResource,
)


class AccessControlClient:
    def __init__(self, api_url: str, api_key: str):
        self._http = HttpClient(api_url, api_key)
        self.scopes = ScopesResource(self._http)
        self.permissions = PermissionsResource(self._http)
        self.roles = RolesResource(self._http)
        self.access_policies = AccessPoliciesResource(self._http)
        self.api_keys = ApiKeysResource(self._http)
        self.webhooks = WebhooksResource(self._http)
        self.access = AccessResource(self._http)
        self.audit = AuditResource(self._http)
        self.billing = BillingResource(self._http)
        self.dashboard = DashboardResource(self._http)
        self.session_tokens = SessionTokensResource(self._http)
        self.sod_constraints = SodConstraintsResource(self._http)
        self.sso = SsoResource(self._http)
        self.team_members = TeamMembersResource(self._http)
        self.resource_types = ResourceTypesResource(self._http)
        self.organization = OrganizationResource(self._http)
