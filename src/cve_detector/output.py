"""JSON and escaped console output; exclusive report-file creation."""

import json
from pathlib import Path

from .exceptions import DetectionError
from .models import Report


def render(result: Report, output_format: str = "console", quiet: bool = False) -> str:
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=True) + "\n"
    if quiet:
        return result.status.value + "\n"
    lines = [
        f"{result.cve}: {result.status.value} | scope={result.scope}",
        "Target: " + json.dumps(result.target, ensure_ascii=True),
        result.evidence_summary,
        f"Method: {result.verification_method}",
        "Confidence: " + result.confidence,
        "Observations: " + json.dumps(result.observations, ensure_ascii=True),
        "UTC: " + result.timestamp,
    ]
    lines.extend("Limitation: " + x for x in result.limitations)
    lines.extend("Reference: " + x for x in result.references)
    return "\n".join(lines) + "\n"


def write_report(path: Path, text: str) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
    except OSError:
        raise DetectionError(
            "Cannot create report; choose a new filename in a writable directory."
        ) from None
