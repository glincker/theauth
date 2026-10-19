"""Step-up authentication helpers (RFC 9470).

A resource that wants a stronger or fresher sign-in answers 401 with
``WWW-Authenticate: Bearer error="insufficient_user_authentication",
acr_values="...", max_age="..."``. :func:`parse_step_up_challenge` reads that
header, :meth:`StepUpChallenge.authorize_params` gives the query parameters for
the new authorization request, and :func:`acr_satisfies` / :func:`auth_is_fresh`
let a client check a token's ``acr`` and ``auth_time`` before it calls.

The class ordering is a theAuth rule (weakest first). RFC 9470 itself treats
``acr`` values as opaque strings, so a value this module does not know never
satisfies a request for another value.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Union

INSUFFICIENT_USER_AUTHENTICATION = "insufficient_user_authentication"

#: ``acr`` classes the server issues, as in ``ACR`` in the TypeScript core.
ACR_NONE = "urn:theauth:acr:none"
ACR_SINGLE_FACTOR = "urn:theauth:acr:single-factor"
ACR_MFA = "urn:theauth:acr:mfa"
ACR_PHISHING_RESISTANT = "urn:theauth:acr:phishing-resistant"

#: Every class, weakest first (the server advertises it as ``acr_values_supported``).
ACR_ORDER: Sequence[str] = (ACR_NONE, ACR_SINGLE_FACTOR, ACR_MFA, ACR_PHISHING_RESISTANT)


@dataclass
class StepUpChallenge:
    """What a resource asked for in an ``insufficient_user_authentication`` challenge."""

    scheme: str
    #: Acceptable ``acr`` values, in the server's order. The user needs any one of them.
    acr_values: List[str] = field(default_factory=list)
    #: Maximum age of the sign-in in seconds, when the resource asked for one.
    max_age: Optional[int] = None
    error_description: Optional[str] = None
    resource_metadata: Optional[str] = None

    def authorize_params(self) -> Dict[str, str]:
        """Query parameters for the authorization request that answers the challenge.

        ``acr_values`` is the space separated list and ``max_age`` is whole seconds
        (RFC 9470 section 4, OpenID Connect Core section 3.1.2.1).
        """
        return step_up_params(self.acr_values, self.max_age)


def step_up_params(
    acr_values: Union[str, Sequence[str], None] = None,
    max_age: Optional[int] = None,
) -> Dict[str, str]:
    """Build ``acr_values`` and ``max_age`` for an authorization request.

    Raises:
        ValueError: ``max_age`` is negative or not a whole number, or an
            ``acr`` value is empty or contains whitespace.
    """
    params: Dict[str, str] = {}
    values: List[str] = (
        [] if acr_values is None else [acr_values] if isinstance(acr_values, str) else list(acr_values)
    )
    if isinstance(acr_values, str):
        values = acr_values.split()
    for value in values:
        if not value or any(ch.isspace() for ch in value):
            raise ValueError(f"invalid acr value {value!r}")
    if values:
        params["acr_values"] = " ".join(values)
    if max_age is not None:
        if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
            raise ValueError("max_age must be a non-negative whole number of seconds")
        params["max_age"] = str(max_age)
    return params


def parse_step_up_challenge(header: Optional[str]) -> Optional[StepUpChallenge]:
    """Read a ``WWW-Authenticate`` value and return the step-up challenge in it.

    Returns ``None`` when no challenge carries ``error="insufficient_user_authentication"``.
    A header with several challenges is searched in order. A malformed
    ``max_age`` is dropped rather than guessed.
    """
    if not header:
        return None
    for scheme, params in _challenges(header):
        if params.get("error") != INSUFFICIENT_USER_AUTHENTICATION:
            continue
        max_age: Optional[int] = None
        raw = params.get("max_age")
        if raw is not None and raw.isascii() and raw.isdigit():
            max_age = int(raw)
        return StepUpChallenge(
            scheme=scheme,
            acr_values=params.get("acr_values", "").split(),
            max_age=max_age,
            error_description=params.get("error_description"),
            resource_metadata=params.get("resource_metadata"),
        )
    return None


def acr_satisfies(have: Optional[str], want: Union[str, Sequence[str]]) -> bool:
    """True when ``have`` is at least as strong as one of the ``want`` classes.

    A missing ``have``, or a class outside :data:`ACR_ORDER`, never satisfies.
    """
    if have not in ACR_ORDER:
        return False
    wanted = [want] if isinstance(want, str) else list(want)
    rank = ACR_ORDER.index(have)
    return any(w in ACR_ORDER and rank >= ACR_ORDER.index(w) for w in wanted)


def auth_is_fresh(
    auth_time: Optional[int],
    max_age: int,
    now: Optional[float] = None,
    skew: int = 0,
) -> bool:
    """True when ``auth_time`` (epoch seconds) is no older than ``max_age`` seconds.

    A missing ``auth_time`` is never fresh. A time in the future beyond ``skew``
    seconds is not fresh either.
    """
    if auth_time is None:
        return False
    current = time.time() if now is None else now
    age = current - auth_time
    return -skew <= age <= max_age


# Header parsing (RFC 9110 section 11.6.1 challenge syntax).

_TOKEN_END = " \t,="


def _challenges(header: str) -> List["tuple[str, Dict[str, str]]"]:
    """Split a header into ``(scheme, params)`` pairs. Names are lower cased."""
    out: List["tuple[str, Dict[str, str]]"] = []
    i, n = 0, len(header)
    current: Optional[Dict[str, str]] = None
    while i < n:
        while i < n and header[i] in " \t,":
            i += 1
        start = i
        while i < n and header[i] not in _TOKEN_END:
            i += 1
        word = header[start:i]
        if not word:
            break
        j = i
        while j < n and header[j] in " \t":
            j += 1
        if j < n and header[j] == "=" and not (j + 1 < n and header[j + 1] == "="):
            # auth-param: name "=" (token / quoted-string)
            j += 1
            while j < n and header[j] in " \t":
                j += 1
            value, i = _read_value(header, j)
            if current is not None:
                current[word.lower()] = value
        else:
            # a new challenge scheme. A token68 after it is read as a stray word and ignored.
            current = {}
            out.append((word, current))
            i = j
    return out


def _read_value(header: str, i: int) -> "tuple[str, int]":
    n = len(header)
    if i < n and header[i] == '"':
        i += 1
        chars: List[str] = []
        while i < n:
            ch = header[i]
            if ch == "\\" and i + 1 < n:
                chars.append(header[i + 1])
                i += 2
                continue
            if ch == '"':
                return "".join(chars), i + 1
            chars.append(ch)
            i += 1
        return "".join(chars), i
    start = i
    while i < n and header[i] not in " \t,":
        i += 1
    return header[start:i], i
