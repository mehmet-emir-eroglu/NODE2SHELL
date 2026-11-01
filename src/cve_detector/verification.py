"""Bounded local-file hashing and reviewed catalog loading; no execution or extraction."""

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from .evidence import BUNDLED_RELEASES, parse_manifest
from .exceptions import DetectionError
from .models import Identity

MAX_FILE_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class Fingerprint:
    path: str
    sha256: str
    size_bytes: int


def stat_signature(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def local_path(value: str) -> Path:
    if not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise DetectionError(
            "Target must be a nonempty local file path without control characters."
        )
    if "://" in value or value.startswith(("//", "\\\\")):
        raise DetectionError(
            "Supply a local Node.js binary or package; URLs and UNC shares are unsupported."
        )
    try:
        path = Path(value).expanduser().resolve(strict=True)
        if not path.is_file():
            raise DetectionError("Target must be a regular file, not a directory or device.")
        return path
    except (OSError, ValueError, RuntimeError):
        raise DetectionError(
            "Cannot resolve the local target; check its path and permissions."
        ) from None


def fingerprint(path: Path) -> Fingerprint:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        with os.fdopen(os.open(path, flags), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
                raise DetectionError("Target must be a regular file no larger than 512 MiB.")
            digest, count = hashlib.sha256(), 0
            while chunk := stream.read(1024 * 1024):
                count += len(chunk)
                if count > MAX_FILE_BYTES:
                    raise DetectionError("Target exceeded the 512 MiB read limit.")
                digest.update(chunk)
            after = os.fstat(stream.fileno())
            current = path.stat()
            if stat_signature(before) != stat_signature(after) or stat_signature(
                after
            ) != stat_signature(current):
                raise DetectionError(
                    "Target changed during assessment; retry using an immutable copy."
                )
            if count != before.st_size:
                raise DetectionError("Target could not be read completely.")
            return Fingerprint(str(path), digest.hexdigest(), count)
    except OSError:
        raise DetectionError("Cannot read target; check file access and permissions.") from None


def load_catalog() -> tuple[Identity, ...]:
    try:
        data = files("cve_detector").joinpath("data")
        index = json.loads(data.joinpath("catalog.json").read_text("utf-8"))
        if index["schema_version"] != 1 or index["reviewed_on"] != "2026-11-01":
            raise ValueError
        records: list[Identity] = []
        for version in BUNDLED_RELEASES:
            manifest = data.joinpath(f"v{version}-SHASUMS256.txt").read_bytes()
            if hashlib.sha256(manifest).hexdigest() != index["manifest_sha256"][version]:
                raise ValueError
            records.extend(parse_manifest(manifest, version))
        binaries = index["derived_binaries"]
        if len(binaries) != len(BUNDLED_RELEASES):
            raise ValueError
        seen: set[str] = set()
        for entry in binaries:
            version = entry["version"]
            if version not in BUNDLED_RELEASES or version in seen:
                raise ValueError
            seen.add(version)
            name = f"node-v{version}-linux-x64.tar.xz"
            member = f"node-v{version}-linux-x64/bin/node"
            if entry["archive"] != name or entry["member"] != member:
                raise ValueError
            source = next(r for r in records if r.version == version and r.filename == name)
            if entry["archive_sha256"] != source.sha256 or not re.fullmatch(
                r"[a-f0-9]{64}", entry["sha256"]
            ):
                raise ValueError
            records.append(
                Identity(
                    entry["sha256"],
                    version,
                    member,
                    "runtime_binary",
                    source.reference,
                    {"archive": name, "archive_sha256": source.sha256, "member": member},
                )
            )
        return tuple(records)
    except (OSError, KeyError, ValueError, TypeError, StopIteration):
        raise DetectionError(
            "Bundled catalog failed validation; reinstall from a trusted source."
        ) from None
