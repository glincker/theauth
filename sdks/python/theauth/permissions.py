"""Permission types and helpers.

This module re-exports the core permission dataclasses and provides
convenience constructors for common patterns.
"""

from __future__ import annotations

from typing import List, Optional

from theauth.types import Permission, PermissionConstraints

__all__ = [
    "Permission",
    "PermissionConstraints",
    "read",
    "write",
    "execute",
    "read_write",
    "full_access",
]


def read(resource: str, constraints: Optional[PermissionConstraints] = None) -> Permission:
    """Shorthand for a read-only permission on a resource.

    Args:
        resource: Resource pattern, e.g. ``"mcp:github:*"``.
        constraints: Optional additional constraints.

    Returns:
        :class:`~theauth.types.Permission` with ``actions=["read"]``.

    Example::

        from theauth.permissions import read
        perm = read("mcp:github:repos")
    """
    return Permission(resource=resource, actions=["read"], constraints=constraints)


def write(resource: str, constraints: Optional[PermissionConstraints] = None) -> Permission:
    """Shorthand for a write-only permission on a resource.

    Args:
        resource: Resource pattern.
        constraints: Optional additional constraints.

    Returns:
        :class:`~theauth.types.Permission` with ``actions=["write"]``.
    """
    return Permission(resource=resource, actions=["write"], constraints=constraints)


def execute(resource: str, constraints: Optional[PermissionConstraints] = None) -> Permission:
    """Shorthand for an execute permission on a resource.

    Args:
        resource: Resource pattern.
        constraints: Optional additional constraints.

    Returns:
        :class:`~theauth.types.Permission` with ``actions=["execute"]``.
    """
    return Permission(resource=resource, actions=["execute"], constraints=constraints)


def read_write(resource: str, constraints: Optional[PermissionConstraints] = None) -> Permission:
    """Shorthand for read + write permission on a resource.

    Args:
        resource: Resource pattern.
        constraints: Optional additional constraints.

    Returns:
        :class:`~theauth.types.Permission` with ``actions=["read", "write"]``.
    """
    return Permission(resource=resource, actions=["read", "write"], constraints=constraints)


def full_access(resource: str, constraints: Optional[PermissionConstraints] = None) -> Permission:
    """Shorthand for full access (read, write, execute, delete) on a resource.

    Args:
        resource: Resource pattern.
        constraints: Optional additional constraints.

    Returns:
        :class:`~theauth.types.Permission` with all standard actions.
    """
    return Permission(
        resource=resource,
        actions=["read", "write", "execute", "delete"],
        constraints=constraints,
    )


def with_approval(base: Permission) -> Permission:
    """Clone a permission and add ``require_approval=True`` to its constraints.

    Args:
        base: The permission to copy.

    Returns:
        A new :class:`~theauth.types.Permission` with approval required.

    Example::

        from theauth.permissions import execute, with_approval
        perm = with_approval(execute("mcp:deploy:production"))
    """
    existing = base.constraints or PermissionConstraints()
    constraints = PermissionConstraints(
        max_calls_per_hour=existing.max_calls_per_hour,
        allowed_arg_patterns=existing.allowed_arg_patterns,
        require_approval=True,
        time_window_start=existing.time_window_start,
        time_window_end=existing.time_window_end,
        ip_allowlist=existing.ip_allowlist,
    )
    return Permission(
        resource=base.resource,
        actions=list(base.actions),
        constraints=constraints,
    )


def rate_limited(base: Permission, max_calls_per_hour: int) -> Permission:
    """Clone a permission and add a rate limit constraint.

    Args:
        base: The permission to copy.
        max_calls_per_hour: Maximum allowed calls per hour.

    Returns:
        A new :class:`~theauth.types.Permission` with rate limiting applied.
    """
    existing = base.constraints or PermissionConstraints()
    constraints = PermissionConstraints(
        max_calls_per_hour=max_calls_per_hour,
        allowed_arg_patterns=existing.allowed_arg_patterns,
        require_approval=existing.require_approval,
        time_window_start=existing.time_window_start,
        time_window_end=existing.time_window_end,
        ip_allowlist=existing.ip_allowlist,
    )
    return Permission(
        resource=base.resource,
        actions=list(base.actions),
        constraints=constraints,
    )


def parse_permissions(raw: List[dict]) -> List[Permission]:  # type: ignore[type-arg]
    """Parse a list of raw permission dicts into typed objects.

    Useful when loading permissions from a config file or database.

    Args:
        raw: List of dicts with ``resource`` and ``actions`` keys.

    Returns:
        List of :class:`~theauth.types.Permission` objects.
    """
    return [Permission.from_dict(p) for p in raw]
