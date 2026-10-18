"""MCP server registry operations."""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import quote

from theauth._http import AsyncTransport, SyncTransport
from theauth.errors import NotFoundError
from theauth.introspection import IntrospectInput, IntrospectionResponse
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

    async def introspect(self, input: IntrospectInput) -> IntrospectionResponse:
        """Ask the server whether a token is live and what it carries (RFC 7662).

        The caller authenticates as an OAuth client (``client_id`` and
        ``client_secret``, sent as HTTP Basic). The endpoint answers 404 unless
        the server enables introspection.

        Returns:
            :class:`~theauth.introspection.IntrospectionResponse` with the agent
            id and the delegation binding when the token carries them.
        """
        data = await self._http.request_form(
            "/mcp/introspect", data=input.form(), extra_headers=input.headers()
        )
        return IntrospectionResponse.from_dict(data)


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

    def introspect(self, input: IntrospectInput) -> IntrospectionResponse:
        """Ask the server whether a token is live and what it carries (RFC 7662)."""
        data = self._http.request_form(
            "/mcp/introspect", data=input.form(), extra_headers=input.headers()
        )
        return IntrospectionResponse.from_dict(data)
