"""Users, sessions and sign-in responses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional



@dataclass
class User:
    """A human user account."""

    id: str
    email: str
    created_at: str
    name: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        return cls(
            id=data["id"],
            email=data["email"],
            created_at=data["createdAt"],
            name=data.get("name"),
        )


@dataclass
class Session:
    """An active session token for a human user."""

    id: str
    user_id: str
    token: str
    expires_at: str
    created_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        return cls(
            id=data["id"],
            user_id=data["userId"],
            token=data["token"],
            expires_at=data["expiresAt"],
            created_at=data["createdAt"],
        )


@dataclass
class AuthResponse:
    """Returned by sign-in and sign-up endpoints."""

    user: User
    session: Session

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthResponse":
        # The API wraps the payload in { success: true, data: { user, session } }
        payload = data.get("data", data)
        return cls(
            user=User.from_dict(payload["user"]),
            session=Session.from_dict(payload["session"]),
        )
