from __future__ import annotations
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Any, Optional, TypeVar, Generic, List

T = TypeVar("T")


class AccessControlApiError(Exception):
    def __init__(self, status_code: int, body: Any, message: str = ""):
        self.status_code = status_code
        self.body = body
        self.message = message
        super().__init__(f"access-control api error {status_code}: {message or body}")


@dataclass
class PaginatedResult(Generic[T]):
    items: List[T]
    next_token: Optional[str] = None

    @staticmethod
    def from_dict(data: dict, item_class):
        return PaginatedResult(
            items=[item_class.from_dict(i) for i in data.get("items", [])],
            next_token=data.get("nextToken"),
        )


class HttpClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        url = self.base_url + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("x-api-key", self.api_key)

        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                body = json.loads(raw)
            except Exception:
                body = raw.decode()
            raise AccessControlApiError(e.code, body, e.reason)

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, body: Any = None) -> Any:
        return self._request("POST", path, body)

    def patch(self, path: str, body: Any = None) -> Any:
        return self._request("PATCH", path, body)

    def put(self, path: str, body: Any = None) -> Any:
        return self._request("PUT", path, body)

    def delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    def get_raw(self, path: str) -> str:
        url = self.base_url + path
        req = urllib.request.Request(url, method="GET")
        req.add_header("x-api-key", self.api_key)
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode()
