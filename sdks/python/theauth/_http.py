"""Internal HTTP transport layer built on httpx."""

from __future__ import annotations

from typing import Any, Dict, Optional, Type, TypeVar

import httpx

from theauth.errors import (
    AuthenticationError,
    NetworkError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
    StepUpRequiredError,
    TheAuthError,
    ValidationError,
)
from theauth.step_up import parse_step_up_challenge

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def _parse_error(response: httpx.Response) -> TheAuthError:
    """Parse an error response into the appropriate TheAuthError subclass."""
    retry_after: Optional[int] = None

    try:
        body: Any = response.json()
    except Exception:
        body = {}

    if isinstance(body, dict) and isinstance(body.get("error"), str):
        # OAuth endpoints (RFC 6749 section 5.2): { error, error_description }
        inner = {
            "code": body["error"],
            "message": body.get("error_description") or f"HTTP {response.status_code}",
        }
        body = {"error": inner}

    if isinstance(body, dict):
        # Support both { code, message } and { error: { code, message } }
        inner = body.get("error", body)
        if not isinstance(inner, dict):
            inner = body
        code: str = inner.get("code", "API_ERROR")
        message: str = inner.get("message", f"HTTP {response.status_code}")
        details: Dict[str, Any] = inner.get("details", {})
        # defineEndpoint validation failures: { error: { code, message, issues } }
        issues: Any = inner.get("issues")
        if issues is None and isinstance(details, dict):
            issues = details.get("issues")
    else:
        code = "API_ERROR"
        message = f"HTTP {response.status_code}"
        details = {}
        issues = None

    status = response.status_code

    if status in (400, 422) and (
        issues is not None or code in ("INVALID_INPUT", "VALIDATION_ERROR")
    ):
        return ValidationError(
            message, code=code, status_code=status, issues=issues, details=details
        )
    if status == 401:
        challenge = parse_step_up_challenge(response.headers.get("WWW-Authenticate"))
        if challenge is not None or code in ("STEP_UP_REQUIRED", "insufficient_user_authentication"):
            return StepUpRequiredError(
                message, code=code, challenge=challenge, details=details
            )
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

    return TheAuthError(message, code=code, status_code=status, details=details)


def unwrap(body: Any) -> Any:
    """Return ``body["data"]`` for the ``{ data }`` envelope the server wraps results in.

    Anything else (a bare list, an object with other keys, an OAuth body) is
    returned as is.
    """
    if isinstance(body, dict) and "data" in body and set(body) <= {"data", "success"}:
        return body["data"]
    return body


def decision_from_error(response: httpx.Response) -> Optional[Dict[str, Any]]:
    """Read an authorize result from a 401 or 403 response, if it carries one.

    The server answers a denied authorize call with 403 (401 for an identity
    failure) and the same ``{ data: result }`` body as an allowed call. A scope
    refusal has ``{ error }`` instead and is not a result.
    """
    if response.status_code not in (401, 403):
        return None
    try:
        inner = unwrap(response.json())
    except Exception:
        return None
    if isinstance(inner, dict) and "allowed" in inner:
        return inner
    return None


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
        auth: Optional[httpx.Auth] = None,
    ) -> None:
        self._auth = auth
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
            self._client = httpx.AsyncClient(timeout=self._timeout, auth=self._auth)
        return self._client

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        params: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        unwrap_data: bool = True,
    ) -> Any:
        """Perform an authenticated JSON request and return the parsed body.

        The ``{ data }`` envelope is removed unless ``unwrap_data`` is false.
        Raises the appropriate :class:`~theauth.errors.TheAuthError` subclass
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

        body = response.json()
        return unwrap(body) if unwrap_data else body

    async def request_decision(
        self,
        path: str,
        *,
        json: Any,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """POST to an authorize endpoint and return the result dict.

        A 401 or 403 that carries a result is a denial, not an error.
        """
        try:
            response = await self._get_client().request(
                "POST",
                f"{self._base}{path}",
                headers=self._build_headers(extra_headers),
                json=json,
            )
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc
        denial = decision_from_error(response)
        if denial is not None:
            return denial
        if not response.is_success:
            raise _parse_error(response)
        result = unwrap(response.json())
        return result  # type: ignore[no-any-return]

    async def request_form(
        self,
        path: str,
        *,
        data: Dict[str, str],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """POST an ``application/x-www-form-urlencoded`` body (OAuth endpoints).

        The JSON response is returned as is, with no ``{ data }`` envelope.
        """
        headers = self._build_headers(extra_headers)
        headers.pop("Content-Type", None)
        try:
            response = await self._get_client().request(
                "POST", f"{self._base}{path}", headers=headers, data=data
            )
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc
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
        auth: Optional[httpx.Auth] = None,
    ) -> None:
        self._auth = auth
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
            self._client = httpx.Client(timeout=self._timeout, auth=self._auth)
        return self._client

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        params: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        unwrap_data: bool = True,
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

        body = response.json()
        return unwrap(body) if unwrap_data else body

    def request_decision(
        self,
        path: str,
        *,
        json: Any,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """POST to an authorize endpoint and return the result dict."""
        try:
            response = self._get_client().request(
                "POST",
                f"{self._base}{path}",
                headers=self._build_headers(extra_headers),
                json=json,
            )
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc
        denial = decision_from_error(response)
        if denial is not None:
            return denial
        if not response.is_success:
            raise _parse_error(response)
        result = unwrap(response.json())
        return result  # type: ignore[no-any-return]

    def request_form(
        self,
        path: str,
        *,
        data: Dict[str, str],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """POST an ``application/x-www-form-urlencoded`` body (OAuth endpoints)."""
        headers = self._build_headers(extra_headers)
        headers.pop("Content-Type", None)
        try:
            response = self._get_client().request(
                "POST", f"{self._base}{path}", headers=headers, data=data
            )
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc
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
