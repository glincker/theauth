"""Shared gate for the framework integrations.

Structural typing only: no framework is imported. The gate mirrors
``createGate`` in ``packages/core/src/integrations/gate.ts`` and fails closed:
a network error, a malformed result or a callback that raises all become a
denial with the code ``guard_error``.
"""

from __future__ import annotations

import dataclasses
import functools
import inspect
import json
from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    Mapping,
    Optional,
    Tuple,
    TypeVar,
    Union,
    cast,
)

from theauth.types import AuthorizeRequest

APPROVAL_REQUIRED = "approval_required"
GUARD_ERROR = "guard_error"

#: Parameter names that carry the framework run context, not tool input.
DEFAULT_CONTEXT_PARAMS: Tuple[str, ...] = ("ctx", "context", "config", "runtime")
_NOT_TOOL_INPUT: FrozenSet[str] = frozenset(("self", "cls") + DEFAULT_CONTEXT_PARAMS)

F = TypeVar("F", bound=Callable[..., Any])
MaybeAwaitable = Union[Any, Awaitable[Any]]


@dataclass(frozen=True)
class ToolDenial:
    """Structured refusal handed back to the model in place of the tool result."""

    tool_name: str
    #: Decision code, or ``guard_error`` when the check itself failed.
    code: str
    reason: str
    #: True when a human could allow the call. The model should ask the user, not retry.
    approval_required: bool = False
    audit_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Same shape as the TypeScript ``ToolDenial`` (camelCase keys)."""
        out: Dict[str, Any] = {
            "ok": False,
            "denied": True,
            "toolName": self.tool_name,
            "code": self.code,
            "reason": self.reason,
            "approvalRequired": self.approval_required,
        }
        if self.audit_id:
            out["auditId"] = self.audit_id
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def to_text(self) -> str:
        """A plain sentence for frameworks whose tools return strings."""
        hint = "Ask the user to approve it." if self.approval_required else "Do not retry."
        return f"Refused ({self.code}): {self.reason}. {hint}"


def is_tool_denial(value: object) -> bool:
    """True for a denial dict as produced by :meth:`ToolDenial.to_dict`."""
    return (
        isinstance(value, dict)
        and value.get("denied") is True
        and value.get("ok") is False
    )


@dataclass(frozen=True)
class ApprovalContext:
    """What ``request_approval`` receives when the decision is ``approval_required``."""

    tool_name: str
    agent_id: str
    action: str
    resource: str
    arguments: Optional[Dict[str, Any]] = None
    audit_id: Optional[str] = None


AuthorizeFn = Callable[[str, AuthorizeRequest], MaybeAwaitable]
AgentIdSource = Union[str, Callable[[Any], Optional[str]]]
RequestApprovalFn = Callable[[ApprovalContext], MaybeAwaitable]
OnDecisionFn = Callable[[str, Optional[ToolDenial]], MaybeAwaitable]
FormatDenial = Callable[[ToolDenial], Any]


def _jsonable(value: Any, depth: int = 0) -> Any:
    """Best effort JSON safe copy, so a rich Python object never breaks the request."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if depth > 8:
        return str(value)
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return _jsonable(dump(), depth + 1)
        except Exception:
            return str(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _jsonable(dataclasses.asdict(value), depth + 1)
    return str(value)


def _field(obj: object, name: str, alt: Optional[str] = None) -> Any:
    if isinstance(obj, Mapping):
        if name in obj:
            return obj[name]
        return obj.get(alt) if alt else None
    value = getattr(obj, name, None)
    if value is None and alt:
        value = getattr(obj, alt, None)
    return value


def _closed(value: object) -> None:
    """Close an un-awaited coroutine so Python does not warn about it."""
    close = getattr(value, "close", None)
    if callable(close):
        close()


class Gate:
    """Runs ``authorize`` before a tool and returns a denial or ``None``.

    Args:
        authorize: ``client.authorize`` (sync or async) or any callable with the
            same ``(agent_id, AuthorizeRequest)`` shape. See :meth:`from_token`
            for agent bearer tokens.
        agent_id: The agent id, or a function from the run context to the id.
        action: Action checked. Default ``execute``.
        resource: ``(tool_name, arguments) -> resource``. Default ``tool:<name>``.
        request_approval: Called on ``approval_required``. Return the id of an
            approved request to retry once with it, or ``None`` to refuse. See
            :func:`theauth.integrations.wait_for_approval`.
        on_decision: Called with ``(tool_name, denial_or_None)`` for logging.
            Errors raised here are ignored.
    """

    def __init__(
        self,
        authorize: AuthorizeFn,
        agent_id: AgentIdSource,
        *,
        action: str = "execute",
        resource: Optional[Callable[[str, Optional[Dict[str, Any]]], str]] = None,
        request_approval: Optional[RequestApprovalFn] = None,
        on_decision: Optional[OnDecisionFn] = None,
        context_params: Tuple[str, ...] = DEFAULT_CONTEXT_PARAMS,
    ) -> None:
        self._authorize = authorize
        self._agent_id = agent_id
        self._action = action
        self._resource = resource
        self._request_approval = request_approval
        self._on_decision = on_decision
        self._context_params = context_params
        self._skip = frozenset(("self", "cls") + tuple(context_params))

    @classmethod
    def from_token(
        cls,
        client: Any,
        agent_token: Union[str, Callable[[], str]],
        **options: Any,
    ) -> "Gate":
        """Build a gate from a client and an agent bearer token (``ta_...``).

        Uses ``POST /authorize/token``. The token may be a function so a rotated
        token is picked up on every call. ``client`` is a ``TheAuthClient`` or
        ``TheAuthSyncClient``.
        """

        def authorize(_agent_id: str, request: AuthorizeRequest) -> MaybeAwaitable:
            token = agent_token() if callable(agent_token) else agent_token
            return client.auth.authorize_by_token(token, request)

        return cls(authorize, "agent-token", **options)

    # decision

    def _prepare(
        self, tool_name: str, args: Any, ctx: Any
    ) -> Union[ToolDenial, Tuple[str, AuthorizeRequest, ApprovalContext]]:
        agent_id = self._agent_id(ctx) if callable(self._agent_id) else self._agent_id
        if not agent_id:
            return ToolDenial(tool_name, GUARD_ERROR, "No agent id for this call")
        record: Optional[Dict[str, Any]] = None
        if isinstance(args, Mapping):
            record = {str(k): _jsonable(v) for k, v in args.items()}
        resource = self._resource(tool_name, record) if self._resource else f"tool:{tool_name}"
        request = AuthorizeRequest(action=self._action, resource=resource, arguments=record)
        info = ApprovalContext(tool_name, agent_id, self._action, resource, record)
        return agent_id, request, info

    def _denial(self, tool_name: str, result: object) -> ToolDenial:
        code = _field(result, "code") or "no_permission"
        audit_id = _field(result, "audit_id", "auditId")
        return ToolDenial(
            tool_name=tool_name,
            code=str(code),
            reason=str(_field(result, "reason") or "Denied by policy"),
            approval_required=code == APPROVAL_REQUIRED,
            audit_id=str(audit_id) if audit_id else None,
        )

    @staticmethod
    def _allowed(result: object) -> bool:
        # Only a literal True allows. A loosely typed result ("false", 1, {}) denies.
        return _field(result, "allowed") is True

    def _guard_error(self, tool_name: str, exc: BaseException) -> ToolDenial:
        return ToolDenial(tool_name, GUARD_ERROR, str(exc) or "Authorization check failed")

    def _decide(self, tool_name: str, args: Any, ctx: Any) -> Optional[ToolDenial]:
        prep = self._prepare(tool_name, args, ctx)
        if isinstance(prep, ToolDenial):
            return prep
        agent_id, request, info = prep
        result = self._authorize(agent_id, request)
        if inspect.isawaitable(result):
            _closed(result)
            return ToolDenial(tool_name, GUARD_ERROR, "Async authorize used in a sync guard")
        if self._allowed(result):
            return None
        if _field(result, "code") == APPROVAL_REQUIRED and self._request_approval:
            approval_id = self._request_approval(
                dataclasses.replace(info, audit_id=_field(result, "audit_id", "auditId"))
            )
            if inspect.isawaitable(approval_id):
                _closed(approval_id)
                return ToolDenial(tool_name, GUARD_ERROR, "Async request_approval in a sync guard")
            if approval_id:
                result = self._authorize(
                    agent_id, dataclasses.replace(request, approval_id=str(approval_id))
                )
                if inspect.isawaitable(result):
                    _closed(result)
                    return ToolDenial(tool_name, GUARD_ERROR, "Async authorize in a sync guard")
                if self._allowed(result):
                    return None
        return self._denial(tool_name, result)

    async def _adecide(self, tool_name: str, args: Any, ctx: Any) -> Optional[ToolDenial]:
        prep = self._prepare(tool_name, args, ctx)
        if isinstance(prep, ToolDenial):
            return prep
        agent_id, request, info = prep
        result = await _maybe_await(self._authorize(agent_id, request))
        if self._allowed(result):
            return None
        if _field(result, "code") == APPROVAL_REQUIRED and self._request_approval:
            approval_id = await _maybe_await(
                self._request_approval(
                    dataclasses.replace(info, audit_id=_field(result, "audit_id", "auditId"))
                )
            )
            if approval_id:
                result = await _maybe_await(
                    self._authorize(
                        agent_id, dataclasses.replace(request, approval_id=str(approval_id))
                    )
                )
                if self._allowed(result):
                    return None
        return self._denial(tool_name, result)

    def check(self, tool_name: str, args: Any = None, ctx: Any = None) -> Optional[ToolDenial]:
        """Sync check. Returns ``None`` when the call may run, else the denial. Never raises."""
        try:
            outcome = self._decide(tool_name, args, ctx)
        except Exception as exc:
            outcome = self._guard_error(tool_name, exc)
        self._notify_sync(tool_name, outcome)
        return outcome

    async def acheck(
        self, tool_name: str, args: Any = None, ctx: Any = None
    ) -> Optional[ToolDenial]:
        """Async check. Same contract as :meth:`check`."""
        try:
            outcome = await self._adecide(tool_name, args, ctx)
        except Exception as exc:
            outcome = self._guard_error(tool_name, exc)
        if self._on_decision:
            try:
                await _maybe_await(self._on_decision(tool_name, outcome))
            except Exception:
                pass  # Logging must not change the outcome.
        return outcome

    def _notify_sync(self, tool_name: str, outcome: Optional[ToolDenial]) -> None:
        if not self._on_decision:
            return
        try:
            _closed(self._on_decision(tool_name, outcome))
        except Exception:
            pass  # Logging must not change the outcome.

    # wrapping

    def tool_input(
        self, fn: Callable[..., Any], args: Tuple[Any, ...], kwargs: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Any]:
        """Map a call to ``(arguments, context)``: named input, minus self and run context."""
        try:
            bound = inspect.signature(fn).bind_partial(*args, **kwargs)
            named: Dict[str, Any] = {}
            for name, value in bound.arguments.items():
                kind = inspect.signature(fn).parameters[name].kind
                if kind is inspect.Parameter.VAR_KEYWORD and isinstance(value, dict):
                    named.update(value)
                else:
                    named[name] = value
        except (TypeError, ValueError):
            named = dict(kwargs)
        ctx = next((named[p] for p in self._context_params if p in named), None)
        return {k: v for k, v in named.items() if k not in self._skip}, ctx

    def wrap(
        self,
        fn: F,
        name: Optional[str] = None,
        *,
        format_denial: Optional[FormatDenial] = None,
    ) -> F:
        """Wrap a sync or async function. A refusal is returned, the function does not run.

        The return value on denial is ``format_denial(denial)``, default the
        denial dict. The signature is preserved, so frameworks that read it
        (LangChain, CrewAI, the OpenAI Agents SDK) keep working.
        """
        tool_name = name or str(getattr(fn, "__name__", "tool"))
        fmt: FormatDenial = format_denial or (lambda d: d.to_dict())

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def awrapper(*args: Any, **kwargs: Any) -> Any:
                arguments, ctx = self.tool_input(fn, args, kwargs)
                refused = await self.acheck(tool_name, arguments, ctx)
                if refused:
                    return fmt(refused)
                return await fn(*args, **kwargs)

            return cast(F, awrapper)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            arguments, ctx = self.tool_input(fn, args, kwargs)
            refused = self.check(tool_name, arguments, ctx)
            if refused:
                return fmt(refused)
            return fn(*args, **kwargs)

        return cast(F, wrapper)

    def tool(
        self, name: Optional[str] = None, *, format_denial: Optional[FormatDenial] = None
    ) -> Callable[[F], F]:
        """Decorator form of :meth:`wrap`: ``@gate.tool("refund")``."""

        def decorate(fn: F) -> F:
            return self.wrap(fn, name, format_denial=format_denial)

        return decorate


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value
