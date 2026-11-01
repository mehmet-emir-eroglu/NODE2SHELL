import pytest

from cve_detector.evidence import (
    artifact_scope,
    manifest_url,
    normalize_release,
    parse_manifest,
    release_status,
)
from cve_detector.exceptions import DetectionError
from cve_detector.models import Status


@pytest.mark.parametrize(
    "version,expected",
    [
        ("22.0.0", Status.VULNERABLE),
        ("22.23.3", Status.VULNERABLE),
        ("22.23.4", Status.NOT_VULNERABLE),
        ("22.24.0", Status.NOT_VULNERABLE),
        ("24.22.0", Status.VULNERABLE),
        ("24.22.1", Status.NOT_VULNERABLE),
        ("26.12.0", Status.VULNERABLE),
        ("26.12.1", Status.NOT_VULNERABLE),
        ("26.13.0", Status.NOT_VULNERABLE),
    ],
)
def test_vendor_branch_boundaries(version, expected):
    assert release_status(version) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "20.19.0",
        "27.0.0",
        "24",
        "v24.22.1-rc.1",
        "24.22.1+custom",
        "024.22.1",
        "../24.22.1",
        "https://example.com",
        "24.22.1?x",
        "24.22.1\n",
    ],
)
def test_release_validation(value):
    with pytest.raises(DetectionError):
        normalize_release(value)


def test_canonical_url():
    assert normalize_release("v24.22.1") == "24.22.1"
    assert manifest_url("v24.22.1") == "https://nodejs.org/dist/v24.22.1/SHASUMS256.txt"


@pytest.mark.parametrize(
    "filename,scope",
    [
        ("win-x64/node.exe", "runtime_binary"),
        ("win-arm64/node.exe", "runtime_binary"),
        ("node-v24.22.1-linux-x64.tar.xz", "runtime_archive"),
        ("node-v24.22.1-win-arm64.zip", "runtime_archive"),
        ("node-v24.22.1.tar.gz", "source_archive"),
        ("node-v24.22.1-x64.msi", "installer"),
        ("node-v24.22.1.pkg", "installer"),
        ("node-v24.22.1-headers.tar.gz", None),
        ("win-x64/node.lib", None),
        ("win-x64/node_pdb.zip", None),
    ],
)
def test_artifact_scope(filename, scope):
    assert artifact_scope(filename, "24.22.1") == scope


def test_manifest_parsing_excludes_nonruntime_headers():
    data = (
        f"{'a' * 64}  win-x64/node.exe\r\n{'b' * 64}  node-v24.22.1-headers.tar.gz\r\n"
    ).encode()
    result = parse_manifest(data, "24.22.1")
    assert len(result) == 1
    assert result[0].scope == "runtime_binary"


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"a" * 65537,
        b"\xff",
        b"<html>blocked</html>",
        b"bad  node.exe",
        f"{'a' * 64}  ../node.exe\n".encode(),
        f"{'a' * 64}  node-v24.22.0.tar.gz\n".encode(),
        f"{'a' * 64}  /win-x64/node.exe\n".encode(),
        (f"{'a' * 64}  win-x64/node.exe\n" * 2).encode(),
        f"{'a' * 64}  node-v24.22.1-headers.tar.gz\n".encode(),
    ],
)
def test_malformed_manifests(payload):
    with pytest.raises(DetectionError):
        parse_manifest(payload, "24.22.1")
