"""Stable machine-readable report and evidence types."""

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

CVE = "CVE-2026-111497"
ADVISORY = "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
REFERENCES = (ADVISORY, "https://www.cve.org/CVERecord?id=CVE-2026-111497")


class Status(StrEnum):
    NOT_VULNERABLE = "NOT_VULNERABLE"
    VULNERABLE = "VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


EXIT_CODES = {
    Status.NOT_VULNERABLE: 0,
    Status.VULNERABLE: 1,
    Status.INCONCLUSIVE: 2,
    Status.ERROR: 3,
}


@dataclass(frozen=True)
class Identity:
    sha256: str
    version: str
    filename: str
    scope: str
    reference: str
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Report:
    target: str
    status: Status
    scope: str
    evidence_summary: str
    verification_method: str
    confidence: str
    observations: dict[str, Any]
    limitations: tuple[str, ...]
    references: tuple[str, ...] = REFERENCES
    cve: str = CVE
    schema_version: int = 1
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
