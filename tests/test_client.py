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
    TuplesResource,
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
            TuplesResource,
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
        assert isinstance(client.tuples, TuplesResource)


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


class TestPermissionsResource:
    @patch("urllib.request.urlopen")
    def test_list(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [
                {"id": "p1", "resource": "docs", "action": "read", "effect": "allow", "name": "Read Docs", "scopeId": "scope-1"},
                {"id": "p2", "resource": "docs", "action": "write", "effect": "deny", "name": "Deny Write", "scopeId": "scope-1"},
            ],
            "nextToken": "token-next",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.permissions.list(scope_id="scope-1", limit="10", next_token="token-abc")

        assert len(result.items) == 2
        assert isinstance(result.items[0], PermissionItem)
        assert result.items[0].id == "p1"
        assert result.items[0].effect == "allow"
        assert result.items[1].id == "p2"
        assert result.items[1].effect == "deny"
        assert result.next_token == "token-next"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert "limit=10" in req.full_url
        assert "nextToken=token-abc" in req.full_url
        assert "scope-1/permission" in req.full_url

    @patch("urllib.request.urlopen")
    def test_list_without_pagination(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [{"id": "p1", "resource": "docs", "action": "read", "effect": "allow", "name": "Read", "scopeId": "scope-1"}],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.permissions.list(scope_id="scope-1")

        assert len(result.items) == 1
        assert result.next_token is None

    @patch("urllib.request.urlopen")
    def test_get_by_id(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "perm-1", "resource": "docs", "action": "read", "effect": "allow",
            "name": "Read Docs", "scopeId": "scope-1",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.permissions.get_by_id("scope-1", "perm-1")

        assert isinstance(result, PermissionItem)
        assert result.id == "perm-1"
        assert result.resource == "docs"
        assert result.action == "read"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/permission/perm-1"

    @patch("urllib.request.urlopen")
    def test_create(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "perm-new", "resource": "admin", "action": "manage", "effect": "allow",
            "name": "Manage Admin", "scopeId": "scope-1",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        input_data = {"id": "perm-new", "resource": "admin", "action": "manage", "effect": "allow", "name": "Manage Admin"}
        result = client.permissions.create("scope-1", input_data)

        assert isinstance(result, PermissionItem)
        assert result.id == "perm-new"
        assert result.effect == "allow"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/permission"
        sent = json.loads(req.data)
        assert sent["scopeId"] == "scope-1"

    @patch("urllib.request.urlopen")
    def test_update(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "perm-1", "resource": "docs", "action": "read", "effect": "deny",
            "name": "Read Docs Updated", "scopeId": "scope-1",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.permissions.update("scope-1", "perm-1", {"effect": "deny", "name": "Read Docs Updated"})

        assert isinstance(result, PermissionItem)
        assert result.effect == "deny"
        assert result.name == "Read Docs Updated"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "PATCH"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/permission/perm-1"

    @patch("urllib.request.urlopen")
    def test_delete(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.permissions.delete("scope-1", "perm-1")

        assert result is None
        req = mock_urlopen.call_args[0][0]
        assert req.method == "DELETE"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/permission/perm-1"

    @patch("urllib.request.urlopen")
    def test_bulk_create(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"ok": True})

        client = AccessControlClient(BASE_URL, API_KEY)
        inputs = [
            {"id": "p1", "resource": "docs", "action": "read", "effect": "allow", "name": "Read"},
            {"id": "p2", "resource": "docs", "action": "write", "effect": "allow", "name": "Write"},
        ]
        result = client.permissions.bulk_create("scope-1", inputs)

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/permission/bulk"
        sent = json.loads(req.data)
        assert len(sent) == 2
        assert sent[0]["scopeId"] == "scope-1"
        assert sent[1]["scopeId"] == "scope-1"

    @patch("urllib.request.urlopen")
    def test_bulk_delete(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"ok": True})

        client = AccessControlClient(BASE_URL, API_KEY)
        client.permissions.bulk_delete("scope-1", ["perm-1", "perm-2"])

        req = mock_urlopen.call_args[0][0]
        assert req.method == "DELETE"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/permission/bulk"
        sent = json.loads(req.data)
        assert sent == {"ids": ["perm-1", "perm-2"]}


class TestRolesResource:
    @patch("urllib.request.urlopen")
    def test_list(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [
                {"id": "role-1", "name": "admin", "scopeId": "scope-1", "permissionIds": ["perm-1"]},
                {"id": "role-2", "name": "viewer", "scopeId": "scope-1", "permissionIds": []},
            ],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.roles.list(scope_id="scope-1")

        assert len(result.items) == 2
        assert isinstance(result.items[0], RoleItem)
        assert result.items[0].id == "role-1"
        assert result.items[0].name == "admin"
        assert result.items[1].id == "role-2"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert "scope-1/role" in req.full_url

    @patch("urllib.request.urlopen")
    def test_list_with_pagination(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [{"id": "role-1", "name": "admin", "scopeId": "scope-1", "permissionIds": []}],
            "nextToken": "next-page",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.roles.list(scope_id="scope-1", limit="5", next_token="next")

        assert result.next_token == "next-page"
        req = mock_urlopen.call_args[0][0]
        assert "limit=5" in req.full_url
        assert "nextToken=next" in req.full_url

    @patch("urllib.request.urlopen")
    def test_get_by_id(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "role-1", "name": "admin", "scopeId": "scope-1",
            "permissionIds": ["perm-1", "perm-2"], "description": "Admin role",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.roles.get_by_id("scope-1", "role-1")

        assert isinstance(result, RoleItem)
        assert result.id == "role-1"
        assert result.name == "admin"
        assert result.permission_ids == ["perm-1", "perm-2"]

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/role/role-1"

    @patch("urllib.request.urlopen")
    def test_create(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "role-new", "name": "editor", "scopeId": "scope-1",
            "permissionIds": ["perm-1"],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.roles.create("scope-1", {"id": "role-new", "name": "editor", "permissionIds": ["perm-1"]})

        assert isinstance(result, RoleItem)
        assert result.id == "role-new"
        assert result.name == "editor"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/role"
        sent = json.loads(req.data)
        assert sent["scopeId"] == "scope-1"

    @patch("urllib.request.urlopen")
    def test_update(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "role-1", "name": "admin-updated", "scopeId": "scope-1",
            "permissionIds": ["perm-1", "perm-3"],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.roles.update("scope-1", "role-1", {"name": "admin-updated", "permissionIds": ["perm-1", "perm-3"]})

        assert isinstance(result, RoleItem)
        assert result.name == "admin-updated"
        assert result.permission_ids == ["perm-1", "perm-3"]

        req = mock_urlopen.call_args[0][0]
        assert req.method == "PATCH"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/role/role-1"

    @patch("urllib.request.urlopen")
    def test_delete(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.roles.delete("scope-1", "role-1")

        assert result is None
        req = mock_urlopen.call_args[0][0]
        assert req.method == "DELETE"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/role/role-1"

    @patch("urllib.request.urlopen")
    def test_clone(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "role-cloned", "name": "admin (copy)", "scopeId": "scope-1",
            "permissionIds": ["perm-1", "perm-2"],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.roles.clone("scope-1", "role-1", {"name": "admin (copy)"})

        assert isinstance(result, RoleItem)
        assert result.id == "role-cloned"
        assert result.name == "admin (copy)"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/role/role-1/clone"
        sent = json.loads(req.data)
        assert sent == {"name": "admin (copy)"}


class TestApiKeysResource:
    @patch("urllib.request.urlopen")
    def test_list(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [
                {"keyId": "key-1", "type": "application", "maskedKey": "sk_live_***abc", "createdAt": "2025-01-01", "subjectId": "sub-1", "name": "API Key 1"},
                {"keyId": "key-2", "type": "management", "maskedKey": "sk_live_***def", "createdAt": "2025-02-01", "subjectId": "sub-2", "name": "API Key 2"},
            ],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.api_keys.list(scope_id="scope-1")

        assert len(result) == 2
        assert isinstance(result[0], ApiKeyItem)
        assert result[0].key_id == "key-1"
        assert result[0].type == "application"
        assert result[1].key_id == "key-2"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/api-key"

    @patch("urllib.request.urlopen")
    def test_list_empty(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"items": []})

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.api_keys.list(scope_id="scope-1")

        assert result == []

    @patch("urllib.request.urlopen")
    def test_get_by_id(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "keyId": "key-1", "type": "application", "maskedKey": "sk_live_***abc",
            "createdAt": "2025-01-01T00:00:00Z", "subjectId": "sub-1", "name": "My Key",
            "expiresAt": "2026-01-01", "lastUsedAt": "2025-06-01",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.api_keys.get_by_id("scope-1", "key-1")

        assert isinstance(result, ApiKeyItem)
        assert result.key_id == "key-1"
        assert result.name == "My Key"
        assert result.expires_at == "2026-01-01"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/api-key/key-1"

    @patch("urllib.request.urlopen")
    def test_create(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "keyId": "key-new", "type": "application", "maskedKey": "sk_live_***xyz",
            "createdAt": "2025-01-01", "subjectId": "sub-1", "name": "New Key",
            "key": "sk_live_full_key_here",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.api_keys.create("scope-1", {"name": "New Key", "type": "application"})

        assert isinstance(result, ApiKeyCreatedItem)
        assert result.key_id == "key-new"
        assert result.key == "sk_live_full_key_here"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/api-key"

    @patch("urllib.request.urlopen")
    def test_delete(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.api_keys.delete("scope-1", "key-1")

        assert result is None
        req = mock_urlopen.call_args[0][0]
        assert req.method == "DELETE"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/api-key/key-1"

    @patch("urllib.request.urlopen")
    def test_rotate(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "keyId": "key-1", "maskedKey": "sk_live_***new", "key": "sk_live_rotated_key",
            "rotationRef": "rot-ref-123",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.api_keys.rotate("scope-1", "key-1")

        assert result["keyId"] == "key-1"
        assert result["key"] == "sk_live_rotated_key"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/api-key/key-1/rotate"


class TestWebhooksResource:
    @patch("urllib.request.urlopen")
    def test_list(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [
                {"id": "wh-1", "scopeId": "scope-1", "url": "https://example.com/hook", "events": ["permission.created"], "active": True, "createdAt": "2025-01-01"},
                {"id": "wh-2", "scopeId": "scope-1", "url": "https://example.com/hook2", "events": ["role.updated"], "active": False, "createdAt": "2025-02-01"},
            ],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.webhooks.list(scope_id="scope-1")

        assert len(result.items) == 2
        assert isinstance(result.items[0], WebhookEndpointItem)
        assert result.items[0].id == "wh-1"
        assert result.items[0].active is True
        assert result.items[1].id == "wh-2"
        assert result.items[1].active is False

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert "scope-1/webhooks" in req.full_url

    @patch("urllib.request.urlopen")
    def test_list_with_pagination(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [{"id": "wh-1", "scopeId": "scope-1", "url": "https://ex.com/h", "events": [], "active": True, "createdAt": ""}],
            "nextToken": "next-token",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.webhooks.list(scope_id="scope-1", limit="10", next_token="t1")

        assert result.next_token == "next-token"
        req = mock_urlopen.call_args[0][0]
        assert "limit=10" in req.full_url
        assert "nextToken=t1" in req.full_url

    @patch("urllib.request.urlopen")
    def test_get_by_id(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "wh-1", "scopeId": "scope-1", "url": "https://example.com/hook",
            "events": ["permission.created", "role.updated"], "active": True,
            "createdAt": "2025-01-01", "updatedAt": "2025-06-01",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.webhooks.get_by_id("scope-1", "wh-1")

        assert isinstance(result, WebhookEndpointItem)
        assert result.id == "wh-1"
        assert result.url == "https://example.com/hook"
        assert result.events == ["permission.created", "role.updated"]

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/webhooks/wh-1"

    @patch("urllib.request.urlopen")
    def test_create(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "wh-new", "scopeId": "scope-1", "url": "https://example.com/hook",
            "events": ["permission.created"], "active": True, "createdAt": "2025-01-01",
            "secret": "whsec_secret_key",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.webhooks.create("scope-1", {
            "url": "https://example.com/hook", "events": ["permission.created"],
        })

        assert isinstance(result, WebhookEndpointCreatedItem)
        assert result.id == "wh-new"
        assert result.secret == "whsec_secret_key"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/webhooks"

    @patch("urllib.request.urlopen")
    def test_update(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "wh-1", "scopeId": "scope-1", "url": "https://example.com/new-url",
            "events": ["permission.created", "role.created"], "active": False,
            "createdAt": "2025-01-01",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.webhooks.update("scope-1", "wh-1", {"url": "https://example.com/new-url", "active": False})

        assert isinstance(result, WebhookEndpointItem)
        assert result.url == "https://example.com/new-url"
        assert result.active is False

        req = mock_urlopen.call_args[0][0]
        assert req.method == "PATCH"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/webhooks/wh-1"

    @patch("urllib.request.urlopen")
    def test_delete(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.webhooks.delete("scope-1", "wh-1")

        assert result is None
        req = mock_urlopen.call_args[0][0]
        assert req.method == "DELETE"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/webhooks/wh-1"

    @patch("urllib.request.urlopen")
    def test_test_endpoint(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "success": True, "statusCode": 200, "responseBody": "OK",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.webhooks.test("scope-1", "wh-1")

        assert result["success"] is True
        assert result["statusCode"] == 200

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/webhooks/wh-1/test"


class TestAccessPoliciesResource:
    @patch("urllib.request.urlopen")
    def test_list_by_scope(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [
                {"id": "ap-1", "subjectId": "sub-1", "scopeId": "scope-1", "roleIds": ["role-1"], "permissionIds": []},
                {"id": "ap-2", "subjectId": "sub-2", "scopeId": "scope-1", "roleIds": [], "permissionIds": ["perm-1"]},
            ],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access_policies.list_by_scope(scope_id="scope-1")

        assert len(result) == 2
        assert isinstance(result[0], AccessPolicyItem)
        assert result[0].id == "ap-1"
        assert result[0].subject_id == "sub-1"
        assert result[0].role_ids == ["role-1"]
        assert result[1].id == "ap-2"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/access-policy"

    @patch("urllib.request.urlopen")
    def test_list_by_scope_empty(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"items": []})

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access_policies.list_by_scope(scope_id="scope-1")

        assert result == []

    @patch("urllib.request.urlopen")
    def test_list_by_subject(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [
                {"id": "ap-1", "subjectId": "sub-1", "scopeId": "scope-1", "roleIds": ["role-1"], "permissionIds": []},
                {"id": "ap-3", "subjectId": "sub-1", "scopeId": "scope-2", "roleIds": ["role-2"], "permissionIds": []},
            ],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access_policies.list_by_subject(subject_id="sub-1")

        assert len(result) == 2
        assert isinstance(result[0], AccessPolicyItem)
        assert result[0].subject_id == "sub-1"
        assert result[0].scope_id == "scope-1"
        assert result[1].scope_id == "scope-2"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.full_url == BASE_URL + "/v1/access-policy/subject/sub-1"

    @patch("urllib.request.urlopen")
    def test_create(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "ap-new", "subjectId": "sub-1", "scopeId": "scope-1",
            "roleIds": ["role-1"], "permissionIds": ["perm-1"],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access_policies.create("scope-1", {
            "subjectId": "sub-1", "roleIds": ["role-1"], "permissionIds": ["perm-1"],
        })

        assert isinstance(result, AccessPolicyItem)
        assert result.id == "ap-new"
        assert result.subject_id == "sub-1"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/access-policy"
        sent = json.loads(req.data)
        assert sent["scopeId"] == "scope-1"

    @patch("urllib.request.urlopen")
    def test_update(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "ap-1", "subjectId": "sub-1", "scopeId": "scope-1",
            "roleIds": ["role-1", "role-2"], "permissionIds": [],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access_policies.update("scope-1", "ap-1", {"roleIds": ["role-1", "role-2"]})

        assert isinstance(result, AccessPolicyItem)
        assert result.role_ids == ["role-1", "role-2"]

        req = mock_urlopen.call_args[0][0]
        assert req.method == "PATCH"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/access-policy/ap-1"

    @patch("urllib.request.urlopen")
    def test_delete(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.access_policies.delete("scope-1", "ap-1")

        assert result is None
        req = mock_urlopen.call_args[0][0]
        assert req.method == "DELETE"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/access-policy/ap-1"


class TestTuplesResource:
    @patch("urllib.request.urlopen")
    def test_write(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "id": "tuple-1", "subject": "user:alice", "relation": "member", "object": "group:engineering",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        input_data = {"subject": "user:alice", "relation": "member", "object": "group:engineering"}
        result = client.tuples.write(input_data)

        assert result["id"] == "tuple-1"
        assert result["subject"] == "user:alice"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/tuples"
        assert json.loads(req.data) == input_data

    @patch("urllib.request.urlopen")
    def test_list(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [
                {"id": "tuple-1", "subject": "user:alice", "relation": "member", "object": "group:engineering"},
                {"id": "tuple-2", "subject": "user:bob", "relation": "owner", "object": "group:engineering"},
            ],
            "nextToken": "next-token",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.tuples.list(scope_id="scope-1", subject_id="user:alice", limit="10", next_token="t1")

        assert len(result["items"]) == 2
        assert result["items"][0]["id"] == "tuple-1"
        assert result["nextToken"] == "next-token"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert "scopeId=scope-1" in req.full_url
        assert "subjectId=user:alice" in req.full_url
        assert "limit=10" in req.full_url
        assert "nextToken=t1" in req.full_url

    @patch("urllib.request.urlopen")
    def test_list_without_params(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [{"id": "tuple-1", "subject": "user:alice", "relation": "member", "object": "group:engineering"}],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.tuples.list()

        assert len(result["items"]) == 1
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == BASE_URL + "/v1/tuples"

    @patch("urllib.request.urlopen")
    def test_list_by_resource(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [
                {"id": "tuple-1", "subject": "user:alice", "relation": "reader", "object": "docs:paper"},
                {"id": "tuple-2", "subject": "user:bob", "relation": "editor", "object": "docs:paper"},
            ],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.tuples.list_by_resource(resource="docs:paper", limit="5", next_token="tok")

        assert len(result["items"]) == 2
        assert result["items"][0]["object"] == "docs:paper"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert "resource=docs:paper" in req.full_url
        assert "limit=5" in req.full_url
        assert "nextToken=tok" in req.full_url


class TestTeamMembersResource:
    @patch("urllib.request.urlopen")
    def test_list(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "items": [
                {"subjectId": "sub-1", "scopeId": "scope-1", "role": "admin", "addedAt": "2025-01-01"},
                {"subjectId": "sub-2", "scopeId": "scope-1", "role": "viewer", "addedAt": "2025-02-01"},
            ],
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.team_members.list(scope_id="scope-1")

        assert len(result) == 2
        assert isinstance(result[0], TeamMemberItem)
        assert result[0].subject_id == "sub-1"
        assert result[0].role == "admin"
        assert result[1].subject_id == "sub-2"
        assert result[1].role == "viewer"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "GET"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/team-members"

    @patch("urllib.request.urlopen")
    def test_list_empty(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({"items": []})

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.team_members.list(scope_id="scope-1")

        assert result == []

    @patch("urllib.request.urlopen")
    def test_add(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = _make_response({
            "subjectId": "sub-new", "scopeId": "scope-1", "role": "admin", "addedAt": "2025-01-01",
        })

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.team_members.add("scope-1", {"subjectId": "sub-new", "role": "admin"})

        assert isinstance(result, TeamMemberItem)
        assert result.subject_id == "sub-new"
        assert result.role == "admin"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/team-members"

    @patch("urllib.request.urlopen")
    def test_remove(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = AccessControlClient(BASE_URL, API_KEY)
        result = client.team_members.remove("scope-1", "sub-1")

        assert result is None
        req = mock_urlopen.call_args[0][0]
        assert req.method == "DELETE"
        assert req.full_url == BASE_URL + "/v1/scope/scope-1/team-members/sub-1"
