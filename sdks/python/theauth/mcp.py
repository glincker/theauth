"""MCP server registry operations."""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import quote

from theauth._http import AsyncTransport, SyncTransport
from theauth.errors import NotFoundError
from theauth.types import McpServer, RegisterMcpServerInput


class AsyncMcpResource:
    """Async MCP server registry (``/mcp/servers``)."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._http = transport

    async def register(self, input: RegisterMcpServerInput) -> McpServer:
        """Register an MCP server.

        Args:
            input: Name, endpoint, tool names and optional rate limit.

        Returns:
            The registered :class:`~theauth.types.McpServer`.
        """
        data = await self._http.request("POST", "/mcp/servers", json=input.to_dict())
        return McpServer.from_dict(data)

    async def list(self) -> List[McpServer]:
        """List registered MCP servers."""
        data = await self._http.request("GET", "/mcp/servers")
        return [McpServer.from_dict(s) for s in data]

    async def get(self, server_id: str) -> Optional[McpServer]:
        """Get an MCP server by ID. Returns ``None`` if not found."""
        try:
            data = await self._http.request("GET", f"/mcp/servers/{quote(server_id, safe='')}")
        except NotFoundError:
            return None
        return McpServer.from_dict(data)


class SyncMcpResource:
    """Sync MCP server registry (``/mcp/servers``)."""

    def __init__(self, transport: SyncTransport) -> None:
        self._http = transport

    def register(self, input: RegisterMcpServerInput) -> McpServer:
        """Register an MCP server."""
        data = self._http.request("POST", "/mcp/servers", json=input.to_dict())
        return McpServer.from_dict(data)

    def list(self) -> List[McpServer]:
        """List registered MCP servers."""
        data = self._http.request("GET", "/mcp/servers")
        return [McpServer.from_dict(s) for s in data]

    def get(self, server_id: str) -> Optional[McpServer]:
        """Get an MCP server by ID. Returns ``None`` if not found."""
        try:
            data = self._http.request("GET", f"/mcp/servers/{quote(server_id, safe='')}")
        except NotFoundError:
            return None
        return McpServer.from_dict(data)
