"""Exception hierarchy for the TheAuth Python SDK."""

from __future__ import annotations

from typing import Any, Dict, Optional


class TheAuthError(Exception):
    """Base exception for all TheAuth errors.

    Attributes:
        code: Machine-readable error code (e.g. ``"AGENT_NOT_FOUND"``).
        message: Human-readable description.
        status_code: HTTP status code from the server response, or ``0`` for
            network-level failures.
        details: Optional structured payload from the server.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "KAVACH_ERROR",
        status_code: int = 0,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"code={self.code!r}, "
            f"message={self.message!r}, "
            f"status_code={self.status_code})"
        )


class AuthenticationError(TheAuthError):
    """Raised when the request lacks valid credentials (HTTP 401)."""

    def __init__(
        self,
        message: str = "Authentication required",
        *,
        code: str = "UNAUTHORIZED",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, status_code=401, details=details)


class PermissionError(TheAuthError):
    """Raised when the caller lacks permission for the requested action (HTTP 403)."""

    def __init__(
        self,
        message: str = "Permission denied",
        *,
        code: str = "FORBIDDEN",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, status_code=403, details=details)


class NotFoundError(TheAuthError):
    """Raised when the requested resource does not exist (HTTP 404)."""

    def __init__(
        self,
        message: str = "Resource not found",
        *,
        code: str = "NOT_FOUND",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, status_code=404, details=details)


class RateLimitError(TheAuthError):
    """Raised when the rate limit is exceeded (HTTP 429).

    Attributes:
        retry_after: Suggested wait time in seconds if the server provided
            a ``Retry-After`` header, otherwise ``None``.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        *,
        code: str = "RATE_LIMITED",
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, status_code=429, details=details)
        self.retry_after = retry_after


class ServerError(TheAuthError):
    """Raised for unexpected server-side errors (HTTP 5xx)."""

    def __init__(
        self,
        message: str = "Internal server error",
        *,
        code: str = "SERVER_ERROR",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, status_code=status_code, details=details)


class NetworkError(TheAuthError):
    """Raised when the HTTP request fails at the transport layer."""

    def __init__(
        self,
        message: str = "Network request failed",
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code="NETWORK_ERROR", status_code=0, details=details)


# Deprecated: use TheAuthError instead. Will be removed in a future major version.
KavachError = TheAuthError
