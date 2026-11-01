import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cve_detector.evidence import BUNDLED_RELEASES
from cve_detector.exceptions import DetectionError
from cve_detector.verification import MAX_FILE_BYTES, fingerprint, load_catalog, local_path


def test_catalog_provenance_and_coverage():
    records = load_catalog()
    assert {x.version for x in records} == set(BUNDLED_RELEASES)
    for version in BUNDLED_RELEASES:
        derived = [x for x in records if x.version == version and x.provenance]
        assert len(derived) == 1
        binary = derived[0]
        assert binary.scope == "runtime_binary"
        assert binary.filename.endswith("/bin/node")
        assert any(
            x.sha256 == binary.provenance["archive_sha256"]
            and x.filename == binary.provenance["archive"]
            for x in records
        )
        assert any(x.filename == "win-x64/node.exe" and x.version == version for x in records)
    assert not any("headers" in x.filename or "node_pdb" in x.filename for x in records)


def test_real_hash_streaming(tmp_path):
    path = tmp_path / "node"
    content = b"x" * (1024 * 1024 + 17)
    path.write_bytes(content)
    result = fingerprint(local_path(str(path)))
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.size_bytes == len(content)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://example.com/secret",
        "ftp://example.com",
        "//server/share",
        "\\\\server\\share",
        "abc\x00def",
        "bad\nname",
        "a" * 4097,
    ],
)
def test_invalid_paths(value):
    with pytest.raises(DetectionError):
        local_path(value)


def test_missing_and_directory(tmp_path):
    for path in (tmp_path, tmp_path / "missing"):
        with pytest.raises(DetectionError):
            local_path(str(path))


def test_read_failure(tmp_path):
    with pytest.raises(DetectionError, match="Cannot read"):
        fingerprint(tmp_path / "missing")


def test_oversize_rejected_without_reading(tmp_path):
    path = tmp_path / "large"
    with path.open("wb") as stream:
        stream.truncate(MAX_FILE_BYTES + 1)
    with pytest.raises(DetectionError, match="512 MiB"):
        fingerprint(path)


def test_changing_file(tmp_path):
    path = tmp_path / "changing"
    path.write_bytes(b"abc")
    before = path.stat()
    after = SimpleNamespace(
        st_dev=before.st_dev, st_ino=before.st_ino, st_size=4, st_mtime_ns=before.st_mtime_ns
    )
    with patch("cve_detector.verification.os.fstat", side_effect=[before, after]):
        with pytest.raises(DetectionError, match="changed"):
            fingerprint(path)


@pytest.mark.parametrize("mutation", ["checksum", "derived", "duplicate", "schema"])
def test_catalog_corruption_fails_closed(tmp_path, mutation):
    source = Path(__file__).parents[1] / "src/cve_detector/data"
    for original in source.iterdir():
        (tmp_path / original.name).write_bytes(original.read_bytes())
    catalog = json.loads((tmp_path / "catalog.json").read_text())
    if mutation == "checksum":
        (tmp_path / "v24.22.1-SHASUMS256.txt").write_text("corrupted")
    elif mutation == "derived":
        catalog["derived_binaries"][0]["archive_sha256"] = "0" * 64
    elif mutation == "duplicate":
        catalog["derived_binaries"][1] = catalog["derived_binaries"][0]
    else:
        catalog["schema_version"] = 2
    (tmp_path / "catalog.json").write_text(json.dumps(catalog))
    with patch("cve_detector.verification.files") as resource:
        resource.return_value.joinpath.return_value = tmp_path
        with pytest.raises(DetectionError):
            load_catalog()
