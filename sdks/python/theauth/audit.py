"""Audit log query and export operations."""

from __future__ import annotations

from typing import List, Optional

from theauth._http import AsyncTransport, SyncTransport
from theauth.types import AuditEntry, AuditFilters, ExportOptions, PaginatedAuditLogs


class AsyncAuditResource:
    """Async audit log access."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._http = transport

    async def query(
        self,
        filters: Optional[AuditFilters] = None,
    ) -> List[AuditEntry]:
        """Query the audit log.

        Args:
            filters: Optional query filters. Use ``limit`` and ``offset`` for
                pagination.

        Returns:
            List of :class:`~theauth.types.AuditEntry` objects, newest first.
        """
        params = filters.to_params() if filters else None
        data = await self._http.request("GET", "/audit", params=params)

        # The API may return either a plain list or a paginated wrapper
        if isinstance(data, list):
            return [AuditEntry.from_dict(e) for e in data]

        return PaginatedAuditLogs.from_dict(data).entries

    async def query_paginated(
        self,
        filters: Optional[AuditFilters] = None,
    ) -> PaginatedAuditLogs:
        """Query the audit log and return the full paginated response.

        Args:
            filters: Optional query filters.

        Returns:
            :class:`~theauth.types.PaginatedAuditLogs` with ``entries`` and
            optional ``total`` count.
        """
        params = filters.to_params() if filters else None
        data = await self._http.request("GET", "/audit", params=params)

        if isinstance(data, list):
            return PaginatedAuditLogs(entries=[AuditEntry.from_dict(e) for e in data])

        return PaginatedAuditLogs.from_dict(data)

    async def export(self, options: Optional[ExportOptions] = None) -> str:
        """Export the audit log as JSON or CSV.

        Args:
            options: Format and date range. Defaults to JSON format.

        Returns:
            Raw export string (JSON text or CSV text depending on format).
        """
        opts = options or ExportOptions()
        params = opts.to_params()
        return await self._http.request_raw("GET", "/audit/export", params=params)


class SyncAuditResource:
    """Sync audit log access."""

    def __init__(self, transport: SyncTransport) -> None:
        self._http = transport

    def query(
        self,
        filters: Optional[AuditFilters] = None,
    ) -> List[AuditEntry]:
        """Query the audit log."""
        params = filters.to_params() if filters else None
        data = self._http.request("GET", "/audit", params=params)

        if isinstance(data, list):
            return [AuditEntry.from_dict(e) for e in data]

        return PaginatedAuditLogs.from_dict(data).entries

    def query_paginated(
        self,
        filters: Optional[AuditFilters] = None,
    ) -> PaginatedAuditLogs:
        """Query the audit log and return the full paginated response."""
        params = filters.to_params() if filters else None
        data = self._http.request("GET", "/audit", params=params)

        if isinstance(data, list):
            return PaginatedAuditLogs(entries=[AuditEntry.from_dict(e) for e in data])

        return PaginatedAuditLogs.from_dict(data)

    def export(self, options: Optional[ExportOptions] = None) -> str:
        """Export the audit log as JSON or CSV."""
        opts = options or ExportOptions()
        params = opts.to_params()
        return self._http.request_raw("GET", "/audit/export", params=params)
