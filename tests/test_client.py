import json
import urllib.error
from io import BytesIO
from unittest.mock import patch, MagicMock

import pytest

from access_control import (
    AccessControlClient,
    HttpClient,
    AccessControlApiError,
    PaginatedResult,
)
from access_control.types import (
    AccessCheckResult,
    SimulateAccessResult,
    PermissionItem,
    ScopeItem,
    RoleItem,
    AccessPolicyItem,
    ApiKeyItem,
    ApiKeyCreatedItem,
    WebhookEndpointItem,
    WebhookEndpointCreatedItem,
    WebhookDeliveryItem,
    AuditLogItem,
    SubscriptionSummary,
    DashboardStats,
    TeamMemberItem,
    SSOConfigItem,
    SodConstraintItem,
    MintSessionTokenResult,
    OrganizationItem,
)

BASE_URL = "https://api.wardenauthz.com"
API_KEY = "sk_test_12345"
AUTH_HEADERS = {"Content-Type": "application/json", "X-api-key": API_KEY}


def _make_response(body, status=200):
    resp = MagicMock()
    resp.read.return_value = json.dumps(body).encode()
    resp.status = status
    return resp


def _make_http_error(status_code, body, reason="Error"):
    fp = BytesIO(json.dumps(body).encode() if not isinstance(body, str) else body.encode())
    return urllib.error.HTTPError("http://test", status_code, reason, {}, fp)


class TestHttpClient:
    def test_constructor_stores_base_url_and_api_key(self):
        client = HttpClient(BASE_URL, API_KEY)
        assert client.base_url == BASE_URL
        assert client.api_key == API_KEY

    def test_constructor_strips_trailing_slash(self):
        client = HttpClient("https://api.test.com/", "key")
        assert client.base_url == "https://api.test.com"

    @patch("urllib.request.urlopen")
    def test_get_sends_correct_request_and_returns_json(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"id": "1"})

        client = HttpClient(BASE_URL, API_KEY)
        result = client.get("/v1/scope")

        assert result == {"id": "1"}
        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.full_url == BASE_URL + "/v1/scope"
        assert req.get_header("Content-type") == "application/json"
        assert req.get_header("X-api-key") == API_KEY

    @patch("urllib.request.urlopen")
    def test_get_returns_none_for_empty_body(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response("")
        # Patch read to return empty bytes
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = HttpClient(BASE_URL, API_KEY)
        result = client.get("/v1/empty")

        assert result is None

    @patch("urllib.request.urlopen")
    def test_post_sends_body_and_returns_json(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response(
            {"id": "new-scope", "name": "prod"}
        )

        client = HttpClient(BASE_URL, API_KEY)
        body = {"name": "prod", "type": "workspace"}
        result = client.post("/v1/scope", body)

        assert result["id"] == "new-scope"
        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert json.loads(req.data) == body
        assert req.get_header("Content-type") == "application/json"

    @patch("urllib.request.urlopen")
    def test_post_without_body(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"ok": True})

        client = HttpClient(BASE_URL, API_KEY)
        result = client.post("/v1/billing/portal")

        assert result == {"ok": True}
        req = mock_urlopen.call_args[0][0]
        assert req.data is None

    @patch("urllib.request.urlopen")
    def test_patch_sends_body_and_returns_json(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"id": "1", "name": "updated"})

        client = HttpClient(BASE_URL, API_KEY)
        body = {"name": "updated"}
        result = client.patch("/v1/scope/1", body)

        assert result["name"] == "updated"
        req = mock_urlopen.call_args[0][0]
        assert req.method == "PATCH"
        assert json.loads(req.data) == body

    @patch("urllib.request.urlopen")
    def test_put_sends_body_and_returns_json(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"ipAllowlist": ["1.2.3.4"]})

        client = HttpClient(BASE_URL, API_KEY)
        body = {"ipAllowlist": ["1.2.3.4"]}
        result = client.put("/v1/admin/org/org1/ip-allowlist", body)

        assert result["ipAllowlist"] == ["1.2.3.4"]
        req = mock_urlopen.call_args[0][0]
        assert req.method == "PUT"
        assert json.loads(req.data) == body

    @patch("urllib.request.urlopen")
    def test_delete(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = HttpClient(BASE_URL, API_KEY)
        result = client.delete("/v1/scope/1")

        assert result is None
        req = mock_urlopen.call_args[0][0]
        assert req.method == "DELETE"
        assert req.data is None

    @patch("urllib.request.urlopen")
    def test_delete_with_json_response(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"deleted": True})

        client = HttpClient(BASE_URL, API_KEY)
        result = client.delete("/v1/scope/1")

        assert result == {"deleted": True}

    @patch("urllib.request.urlopen")
    def test_http_400_error_raises_access_control_api_error(self, mock_urlopen):
        http_error = _make_http_error(400, {"error": "bad request", "message": "Invalid scope"})
        mock_urlopen.side_effect = http_error

        client = HttpClient(BASE_URL, API_KEY)
        with pytest.raises(AccessControlApiError) as exc_info:
            client.get("/v1/scope/bad")

        assert exc_info.value.status_code == 400
        assert exc_info.value.body == {"error": "bad request", "message": "Invalid scope"}

    @patch("urllib.request.urlopen")
    def test_http_404_error_raises_access_control_api_error(self, mock_urlopen):
        http_error = _make_http_error(404, {"error": "not found"})
        mock_urlopen.side_effect = http_error

        client = HttpClient(BASE_URL, API_KEY)
        with pytest.raises(AccessControlApiError) as exc_info:
            client.get("/v1/scope/nonexistent")

        assert exc_info.value.status_code == 404

    @patch("urllib.request.urlopen")
    def test_http_500_error_raises_access_control_api_error(self, mock_urlopen):
        http_error = _make_http_error(500, {"error": "internal error"}, "Internal Server Error")
        mock_urlopen.side_effect = http_error

        client = HttpClient(BASE_URL, API_KEY)
        with pytest.raises(AccessControlApiError) as exc_info:
            client.post("/v1/scope", {"name": "test"})

        assert exc_info.value.status_code == 500
        assert exc_info.value.message == "Internal Server Error"

    @patch("urllib.request.urlopen")
    def test_http_403_error_raises_access_control_api_error(self, mock_urlopen):
        http_error = _make_http_error(403, {"error": "forbidden"})
        mock_urlopen.side_effect = http_error

        client = HttpClient(BASE_URL, API_KEY)
        with pytest.raises(AccessControlApiError) as exc_info:
            client.delete("/v1/scope/protected")

        assert exc_info.value.status_code == 403

    @patch("urllib.request.urlopen")
    def test_error_with_non_json_body(self, mock_urlopen):
        http_error = _make_http_error(502, "Bad Gateway", "Bad Gateway")
        mock_urlopen.side_effect = http_error

        client = HttpClient(BASE_URL, API_KEY)
        with pytest.raises(AccessControlApiError) as exc_info:
            client.get("/v1/scope/error")

        assert exc_info.value.status_code == 502
        assert exc_info.value.body == "Bad Gateway"

    @patch("urllib.request.urlopen")
    def test_get_raw_returns_string(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"csv,data,here\n1,2,3\n"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = HttpClient(BASE_URL, API_KEY)
        result = client.get_raw("/v1/audit/export?format=csv")

        assert result == "csv,data,here\n1,2,3\n"
        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.get_header("X-api-key") == API_KEY
        assert req.full_url == BASE_URL + "/v1/audit/export?format=csv"


class TestAccessControlClient:
    def test_constructor_creates_http_client_with_url_and_key(self):
        client = AccessControlClient(BASE_URL, API_KEY)
        assert isinstance(client._http, HttpClient)
        assert client._http.base_url == BASE_URL
        assert client._http.api_key == API_KEY

    def test_all_resource_attributes_are_initialized(self):
        client = AccessControlClient(BASE_URL, API_KEY)

        from access_control import (
            ScopesResource, PermissionsResource, RolesResource,
            AccessPoliciesResource, ApiKeysResource, WebhooksResource,
            AccessResource, AuditResource, BillingResource, DashboardResource,
            SessionTokensResource, SodConstraintsResource, SsoResource,
            TeamMembersResource, ResourceTypesResource, OrganizationResource,
        )

        assert isinstance(client.scopes, ScopesResource)
        assert isinstance(client.permissions, PermissionsResource)
        assert isinstance(client.roles, RolesResource)
        assert isinstance(client.access_policies, AccessPoliciesResource)
        assert isinstance(client.api_keys, ApiKeysResource)
        assert isinstance(client.webhooks, WebhooksResource)
        assert isinstance(client.access, AccessResource)
        assert isinstance(client.audit, AuditResource)
        assert isinstance(client.billing, BillingResource)
        assert isinstance(client.dashboard, DashboardResource)
        assert isinstance(client.session_tokens, SessionTokensResource)
        assert isinstance(client.sod_constraints, SodConstraintsResource)
        assert isinstance(client.sso, SsoResource)
        assert isinstance(client.team_members, TeamMembersResource)
        assert isinstance(client.resource_types, ResourceTypesResource)
        assert isinstance(client.organization, OrganizationResource)


class TestAccessResource:
    @patch("urllib.request.urlopen")
    def test_has_access_sends_correct_request(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "subjectId": "user-1",
            "scopeId": "scope-1",
            "type": "access_check",
            "id": "check-1",
            "allowed": True,
            "resource": "documents",
            "action": "read",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        input_data = {
            "subjectId": "user-1",
            "scopeId": "scope-1",
            "resource": "documents",
            "action": "read",
        }
        result = client.access.has_access(input_data)

        assert isinstance(result, AccessCheckResult)
        assert result.allowed is True
        assert result.subject_id == "user-1"
        assert result.resource == "documents"
        assert result.action == "read"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert json.loads(req.data) == input_data

    @patch("urllib.request.urlopen")
    def test_has_access_returns_denied_result(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "subjectId": "user-1",
            "scopeId": "scope-1",
            "type": "access_check",
            "id": "check-2",
            "allowed": False,
            "resource": "admin",
            "action": "write",
            "reasoning": {"matchedPolicies": [], "matchedRoles": []},
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access.has_access({
            "subjectId": "user-1",
            "scopeId": "scope-1",
            "resource": "admin",
            "action": "write",
        })

        assert result.allowed is False
        assert result.reasoning is not None

    @patch("urllib.request.urlopen")
    def test_has_access_bulk_returns_list_of_results(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response([
            {
                "subjectId": "user-1",
                "scopeId": "scope-1",
                "type": "access_check",
                "id": "check-1",
                "allowed": True,
                "resource": "docs",
                "action": "read",
            },
            {
                "subjectId": "user-1",
                "scopeId": "scope-1",
                "type": "access_check",
                "id": "check-2",
                "allowed": False,
                "resource": "docs",
                "action": "delete",
            },
        ])

        client = AccessControlClient(BASE_URL, API_KEY)
        inputs = [
            {"subjectId": "user-1", "scopeId": "scope-1", "resource": "docs", "action": "read"},
            {"subjectId": "user-1", "scopeId": "scope-1", "resource": "docs", "action": "delete"},
        ]
        results = client.access.has_access_bulk(inputs)

        assert len(results) == 2
        assert results[0].allowed is True
        assert results[1].allowed is False
        assert all(isinstance(r, AccessCheckResult) for r in results)

        req = mock_urlopen.call_args[0][0]
        assert json.loads(req.data) == inputs

    @patch("urllib.request.urlopen")
    def test_list_permissions(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "permissions": [
                {"id": "perm-1", "resource": "docs", "action": "read", "effect": "allow"}
            ]
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access.list_permissions({
            "subjectId": "user-1",
            "scopeId": "scope-1",
        })

        assert result["permissions"][0]["id"] == "perm-1"

    @patch("urllib.request.urlopen")
    def test_list_roles(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "roles": [{"id": "role-1", "name": "admin"}]
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access.list_roles({
            "subjectId": "user-1",
            "scopeId": "scope-1",
        })

        assert result["roles"][0]["name"] == "admin"

    @patch("urllib.request.urlopen")
    def test_simulate_returns_access_simulation_result(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "subjectId": "user-1",
            "scopeId": "scope-1",
            "results": [
                {"resource": "docs", "action": "read", "allowed": True},
                {"resource": "docs", "action": "write", "allowed": False},
            ],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access.simulate({
            "subjectId": "user-1",
            "scopeId": "scope-1",
            "checks": [
                {"resource": "docs", "action": "read"},
                {"resource": "docs", "action": "write"},
            ],
        })

        assert isinstance(result, SimulateAccessResult)
        assert result.subject_id == "user-1"
        assert len(result.results) == 2
        assert result.results[0]["allowed"] is True


class TestAccessControlApiError:
    def test_str_representation_includes_status_code_and_body(self):
        error = AccessControlApiError(400, {"error": "bad request"})
        error_str = str(error)
        assert "400" in error_str
        assert "bad request" in error_str

    def test_str_representation_uses_message_when_body_not_informative(self):
        error = AccessControlApiError(500, {}, "Internal Server Error")
        error_str = str(error)
        assert "500" in error_str
        assert "Internal Server Error" in error_str

    def test_body_accessible_as_property(self):
        error = AccessControlApiError(403, {"error": "forbidden"})
        assert error.body == {"error": "forbidden"}
        assert error.status_code == 403

    def test_message_accessible_as_property(self):
        error = AccessControlApiError(502, "Bad Gateway", "Bad Gateway")
        assert error.message == "Bad Gateway"


class TestPaginatedResult:
    def test_from_dict_with_items(self):
        data = {
            "items": [
                {"id": "perm-1", "resource": "docs", "action": "read", "effect": "allow", "name": "Read Docs"},
                {"id": "perm-2", "resource": "docs", "action": "write", "effect": "allow", "name": "Write Docs"},
            ],
        }
        result = PaginatedResult.from_dict(data, PermissionItem)

        assert len(result.items) == 2
        assert all(isinstance(i, PermissionItem) for i in result.items)
        assert result.items[0].id == "perm-1"
        assert result.next_token is None

    def test_from_dict_with_next_token(self):
        data = {
            "items": [{"id": "scope-1", "name": "prod", "type": "workspace"}],
            "nextToken": "token-abc-123",
        }
        result = PaginatedResult.from_dict(data, ScopeItem)

        assert len(result.items) == 1
        assert result.next_token == "token-abc-123"
        assert isinstance(result.items[0], ScopeItem)

    def test_from_dict_with_empty_items(self):
        data = {"items": []}
        result = PaginatedResult.from_dict(data, ScopeItem)

        assert result.items == []
        assert result.next_token is None

    def test_from_dict_missing_items_key(self):
        data = {}
        result = PaginatedResult.from_dict(data, PermissionItem)

        assert result.items == []
        assert result.next_token is None


class TestScopesResource:
    @patch("urllib.request.urlopen")
    def test_create(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "scope-new", "name": "my-workspace", "type": "workspace",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.scopes.create({"name": "my-workspace", "type": "workspace"})

        assert isinstance(result, ScopeItem)
        assert result.id == "scope-new"
        assert result.name == "my-workspace"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope"

    @patch("urllib.request.urlopen")
    def test_get_by_id(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "scope-1", "name": "prod", "type": "workspace",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.scopes.get_by_id("scope-1")

        assert isinstance(result, ScopeItem)
        assert result.id == "scope-1"

    @patch("urllib.request.urlopen")
    def test_delete(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.scopes.delete("scope-1")

        assert result is None
        req = mock_urlopen.call_args[0][0]
        assert req.method == "DELETE"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1"


class TestSessionTokensResource:
    @patch("urllib.request.urlopen")
    def test_mint(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "token": "sess-token-abc",
            "tokenType": "Bearer",
            "principalId": "user-1",
            "scopeId": "scope-1",
            "issuedAt": 1690000000,
            "expiresAt": "2025-12-31T23:59:59Z",
            "permissionIds": ["perm-1", "perm-2"],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.session_tokens.mint({
            "subjectId": "user-1",
            "scopeId": "scope-1",
        })

        assert isinstance(result, MintSessionTokenResult)
        assert result.token == "sess-token-abc"
        assert result.token_type == "Bearer"
        assert result.principal_id == "user-1"
        assert len(result.permission_ids) == 2
