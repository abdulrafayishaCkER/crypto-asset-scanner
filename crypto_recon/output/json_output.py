"""JSON report output."""

from __future__ import annotations

import json

from crypto_recon.models.report import Report
from crypto_recon.utils.logger import get_logger

logger = get_logger(__name__)


class JSONOutput:
    """Serialise a :class:`Report` to JSON."""

    def write(self, report: Report, filepath: str) -> None:
        """Write the report as JSON to *filepath*.

        Args:
            report: Report to serialise.
            filepath: Destination file path.
        """
        content = self.to_string(report)
        try:
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(content)
            logger.info("JSON report saved to %s", filepath)
        except OSError as exc:
            logger.error("Failed to write JSON report to %s: %s", filepath, exc)

    def to_string(self, report: Report) -> str:
        """Serialise *report* to an indented JSON string.

        Args:
            report: Report to serialise.

        Returns:
            JSON string.
        """
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
