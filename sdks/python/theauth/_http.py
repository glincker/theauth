"""Internal HTTP transport layer built on httpx."""

from __future__ import annotations

from typing import Any, Dict, Optional, Type, TypeVar

import httpx

from theauth.errors import (
    AuthenticationError,
    KavachError,
    NetworkError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def _parse_error(response: httpx.Response) -> KavachError:
    """Parse an error response into the appropriate KavachError subclass."""
    retry_after: Optional[int] = None

    try:
        body: Any = response.json()
    except Exception:
        body = {}

    if isinstance(body, dict):
        # Support both { code, message } and { error: { code, message } }
        inner = body.get("error", body)
        if not isinstance(inner, dict):
            inner = body
        code: str = inner.get("code", "API_ERROR")
        message: str = inner.get("message", f"HTTP {response.status_code}")
        details: Dict[str, Any] = inner.get("details", {})
    else:
        code = "API_ERROR"
        message = f"HTTP {response.status_code}"
        details = {}

    status = response.status_code

    if status == 401:
        return AuthenticationError(message, code=code, details=details)
    if status == 403:
        return PermissionError(message, code=code, details=details)
    if status == 404:
        return NotFoundError(message, code=code, details=details)
    if status == 429:
        raw_retry = response.headers.get("Retry-After")
        if raw_retry is not None:
            try:
                retry_after = int(raw_retry)
            except ValueError:
                pass
        return RateLimitError(message, code=code, retry_after=retry_after, details=details)
    if status >= 500:
        return ServerError(message, code=code, status_code=status, details=details)

    return KavachError(message, code=code, status_code=status, details=details)


# ---------------------------------------------------------------------------
# Async transport
# ---------------------------------------------------------------------------


class AsyncTransport:
    """Thin async wrapper around :class:`httpx.AsyncClient`."""

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._extra_headers = headers or {}
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    def _build_headers(self, overrides: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h: Dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._extra_headers,
        }
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        if overrides:
            h.update(overrides)
        return h

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        params: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Perform an authenticated JSON request and return the parsed body.

        Raises the appropriate :class:`~theauth.errors.KavachError` subclass
        on any non-2xx response.
        """
        url = f"{self._base}{path}"
        headers = self._build_headers(extra_headers)

        try:
            response = await self._get_client().request(
                method,
                url,
                headers=headers,
                json=json,
                params=params,
            )
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc

        if response.status_code == 204:
            return None

        if not response.is_success:
            raise _parse_error(response)

        return response.json()

    async def request_raw(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, str]] = None,
    ) -> str:
        """Perform a request and return the raw response text (for CSV exports)."""
        url = f"{self._base}{path}"
        headers = self._build_headers()
        # Remove JSON Accept for raw text endpoints
        headers["Accept"] = "text/plain, application/json"

        try:
            response = await self._get_client().request(
                method,
                url,
                headers=headers,
                params=params,
            )
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc

        if not response.is_success:
            raise _parse_error(response)

        return response.text

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> "AsyncTransport":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


# ---------------------------------------------------------------------------
# Sync transport
# ---------------------------------------------------------------------------


class SyncTransport:
    """Thin sync wrapper around :class:`httpx.Client`."""

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._extra_headers = headers or {}
        self._timeout = timeout
        self._client: Optional[httpx.Client] = None

    def _build_headers(self, overrides: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h: Dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._extra_headers,
        }
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        if overrides:
            h.update(overrides)
        return h

    def _get_client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        params: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Perform an authenticated JSON request and return the parsed body."""
        url = f"{self._base}{path}"
        headers = self._build_headers(extra_headers)

        try:
            response = self._get_client().request(
                method,
                url,
                headers=headers,
                json=json,
                params=params,
            )
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc

        if response.status_code == 204:
            return None

        if not response.is_success:
            raise _parse_error(response)

        return response.json()

    def request_raw(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, str]] = None,
    ) -> str:
        """Perform a request and return the raw response text."""
        url = f"{self._base}{path}"
        headers = self._build_headers()
        headers["Accept"] = "text/plain, application/json"

        try:
            response = self._get_client().request(
                method,
                url,
                headers=headers,
                params=params,
            )
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc

        if not response.is_success:
            raise _parse_error(response)

        return response.text

    def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None and not self._client.is_closed:
            self._client.close()

    def __enter__(self) -> "SyncTransport":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
