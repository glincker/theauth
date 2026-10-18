"""Wait for a human to decide an approval request, with a timeout.

Use inside ``request_approval``: open the request, then wait for it. Any
outcome other than ``approved`` (denied, expired, timed out) returns ``None``
so the gate refuses the call.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any, Callable, Optional


def _status(state: Any) -> Optional[str]:
    if state is None:
        return None
    status = state.get("status") if isinstance(state, dict) else getattr(state, "status", None)
    return str(status) if status is not None else None


def wait_for_approval(
    approvals: Any,
    approval_id: str,
    *,
    timeout_s: float = 60.0,
    poll_interval_s: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Optional[str]:
    """Poll ``approvals.get(id)`` (``client.approvals`` of the sync client).

    Returns the id once the request is ``approved``, or ``None`` when it is
    denied, expired, missing or ``timeout_s`` passes first.
    """
    deadline = clock() + timeout_s
    while True:
        state = approvals.get(approval_id)
        if inspect.isawaitable(state):
            close = getattr(state, "close", None)
            if callable(close):
                close()
            raise TypeError("Use await_approval with an async client")
        status = _status(state)
        if status == "approved":
            return approval_id
        if status != "pending":
            return None
        remaining = deadline - clock()
        if remaining <= 0:
            return None
        sleep(min(poll_interval_s, remaining))


async def await_approval(
    approvals: Any,
    approval_id: str,
    *,
    timeout_s: float = 60.0,
    poll_interval_s: float = 1.0,
) -> Optional[str]:
    """Async twin of :func:`wait_for_approval` for ``client.approvals`` of the async client."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while True:
        status = _status(await approvals.get(approval_id))
        if status == "approved":
            return approval_id
        if status != "pending":
            return None
        remaining = deadline - loop.time()
        if remaining <= 0:
            return None
        await asyncio.sleep(min(poll_interval_s, remaining))
