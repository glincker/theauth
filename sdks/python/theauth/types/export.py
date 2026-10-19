"""Audit export options."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Literal, Optional



ExportFormat = Literal["json", "csv"]


@dataclass
class ExportOptions:
    """Options for exporting audit logs."""

    format: ExportFormat = "json"
    since: Optional[str] = None
    until: Optional[str] = None

    def to_params(self) -> Dict[str, str]:
        params: Dict[str, str] = {"format": self.format}
        if self.since is not None:
            params["since"] = self.since
        if self.until is not None:
            params["until"] = self.until
        return params
