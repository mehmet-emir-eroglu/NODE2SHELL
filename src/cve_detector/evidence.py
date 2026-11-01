"""CVE-specific release rules and strict official checksum parsing."""

import re

from .exceptions import DetectionError
from .models import Identity, Status

FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
BUNDLED_RELEASES = ("22.23.3", "22.23.4", "24.22.0", "24.22.1", "26.12.0", "26.12.1")
MAX_MANIFEST_BYTES = 65536


def normalize_release(value: str) -> str:
    if not re.fullmatch(
        r"v?(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})", value
    ):
        raise DetectionError("Release must be an exact stable version, such as 24.22.1.")
    version = value.removeprefix("v")
    if int(version.split(".")[0]) not in FIXED:
        raise DetectionError("Only Node.js release lines 22, 24 and 26 are supported.")
    return version


def release_status(version: str) -> Status:
    """Call only AFTER full-file identity is established; never on a banner."""
    parts = tuple(int(x) for x in normalize_release(version).split("."))
    return Status.NOT_VULNERABLE if parts >= FIXED[parts[0]] else Status.VULNERABLE


def manifest_url(version: str) -> str:
    return f"https://nodejs.org/dist/v{normalize_release(version)}/SHASUMS256.txt"


def artifact_scope(filename: str, version: str) -> str | None:
    prefix = f"node-v{version}"
    if re.fullmatch(r"win-(?:x64|arm64|x86)/node\.exe", filename):
        return "runtime_binary"
    if filename in (prefix + ".tar.gz", prefix + ".tar.xz"):
        return "source_archive"
    if filename == prefix + ".pkg" or re.fullmatch(
        re.escape(prefix) + r"-(?:x64|arm64|x86)\.msi", filename
    ):
        return "installer"
    if re.fullmatch(
        re.escape(prefix) + r"-(?:aix|darwin|linux|win)-[a-z0-9-]+\.(?:tar\.gz|tar\.xz|zip|7z)",
        filename,
    ):
        return "runtime_archive"
    return None


def parse_manifest(data: bytes, version: str) -> tuple[Identity, ...]:
    version = normalize_release(version)
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise DetectionError("Official checksum response is empty or too large.")
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise DetectionError("Official checksum response is not ASCII text.") from None
    found: list[Identity] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})[ \t]+([A-Za-z0-9_./-]+)", line)
        if not match:
            raise DetectionError("Official checksum response contains a malformed line.")
        digest, filename = match.groups()
        if filename in seen or ".." in filename or filename.startswith("/"):
            raise DetectionError("Official checksum response contains duplicate or unsafe names.")
        if not (
            filename.startswith(f"node-v{version}.")
            or filename.startswith(f"node-v{version}-")
            or re.fullmatch(
                r"win-(?:x64|arm64|x86)/(?:node\.exe|node\.lib|node_pdb\.(?:zip|7z))", filename
            )
        ):
            raise DetectionError("Official checksum response does not match the requested release.")
        seen.add(filename)
        scope = artifact_scope(filename, version)
        if scope is not None:
            found.append(Identity(digest, version, filename, scope, manifest_url(version)))
    if not found:
        raise DetectionError("Official checksum response contains no supported Node.js artifacts.")
    return tuple(found)
