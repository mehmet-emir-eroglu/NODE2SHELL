"""Evidence evaluation; exact identity precedes every definitive conclusion."""

import hashlib
import logging
from dataclasses import asdict
from typing import Any

from .evidence import normalize_release, parse_manifest, release_status
from .exceptions import DetectionError
from .models import REFERENCES, Identity, Report, Status
from .network import fetch_manifest
from .verification import fingerprint, load_catalog, local_path

LOG = logging.getLogger(__name__)
LIMITATIONS = (
    "Status applies to the identified file's code, not a running process or exposed application.",
    "Application reachability of attacker-controlled Brotli decompression is not tested.",
    "Only CVE-2026-111497 in official Node.js artifacts is assessed.",
    "Custom builds, backports, unknown files and unsupported release lines remain unverified.",
    "Checksums trust the bundled catalog or verified HTTPS; OpenPGP is not validated.",
)


def error_report(message: str) -> Report:
    return Report(
        "[unvalidated or unavailable]",
        Status.ERROR,
        "unknown",
        message,
        "assessment_failed",
        "No vulnerability conclusion.",
        {},
        ("Operational failure establishes neither vulnerability nor safety.",),
    )


def evaluate(target: str, matches: tuple[Identity, ...], observations: dict[str, Any]) -> Report:
    if not matches:
        return Report(
            target,
            Status.INCONCLUSIVE,
            "local_file",
            "No exact supported official Node.js identity was established.",
            "sha256_identity",
            "Insufficient identity evidence.",
            observations,
            LIMITATIONS,
        )
    decisions = {(release_status(item.version), item.scope, item.version) for item in matches}
    if len(decisions) != 1:
        return Report(
            target,
            Status.INCONCLUSIVE,
            "local_file",
            "Conflicting catalog identities prevent a reliable conclusion.",
            "sha256_identity",
            "Conflicting evidence.",
            observations,
            LIMITATIONS,
        )
    status, scope, version = next(iter(decisions))
    observations.update({"release": version, "identities": [asdict(x) for x in matches]})
    summary = (
        "Exact official Node.js artifact contains the affected Brotli decoder. "
        "Application exploitability has not been established."
        if status == Status.VULNERABLE
        else "Exact official Node.js artifact belongs to a release fixed for CVE-2026-111497."
    )
    references = tuple(dict.fromkeys((*REFERENCES, *(x.reference for x in matches))))
    return Report(
        target,
        status,
        scope,
        summary,
        "sha256_identity",
        "High for artifact code identity and vendor patch status; deployment unverified.",
        observations,
        LIMITATIONS,
        references,
    )


def detect(target: str, release: str | None = None, timeout: float = 5, retries: int = 0) -> Report:
    try:
        version = normalize_release(release) if release is not None else None
        path = local_path(target)
        LOG.info("Hashing local artifact without executing it.")
        digest = fingerprint(path)
        observations: dict[str, Any] = {
            "sha256": digest.sha256,
            "size_bytes": digest.size_bytes,
            "catalog_reviewed_on": "2026-11-01",
            "metadata_source": "bundled",
        }
        matches = tuple(x for x in load_catalog() if x.sha256 == digest.sha256)
        if version is not None:
            observations["requested_release"] = version
            if matches and any(x.version != version for x in matches):
                return Report(
                    str(path),
                    Status.INCONCLUSIVE,
                    "local_file",
                    "Requested release conflicts with the known file identity.",
                    "sha256_identity",
                    "Conflicting evidence.",
                    observations,
                    LIMITATIONS,
                )
            if not matches:
                LOG.info("Looking up public checksums on nodejs.org for release %s.", version)
                payload = fetch_manifest(version, timeout, retries)
                observations.update(
                    {
                        "metadata_source": "nodejs.org_https",
                        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
                matches = tuple(
                    x for x in parse_manifest(payload, version) if x.sha256 == digest.sha256
                )
        return evaluate(str(path), matches, observations)
    except DetectionError as exc:
        return error_report(str(exc))
