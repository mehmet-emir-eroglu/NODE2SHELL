"""Test the maintainer's trust boundary without downloading or running Node.js."""

import hashlib
import importlib.util
import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_detector.evidence import BUNDLED_RELEASES


def builder_module():
    path = Path(__file__).parents[1] / "tools/derive_catalog.py"
    spec = importlib.util.spec_from_file_location("derive_catalog", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verified_archive_member_derivation(tmp_path):
    module = builder_module()
    data = b"Synthetic Node binary for a deterministic derivation test"
    for version in BUNDLED_RELEASES:
        name = f"node-v{version}-linux-x64.tar.xz"
        with tarfile.open(tmp_path / name, "w:xz") as archive:
            member = tarfile.TarInfo(f"node-v{version}-linux-x64/bin/node")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        digest = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        (tmp_path / f"v{version}-SHASUMS256.txt").write_text(f"{digest}  {name}\n")
    result = module.derive(tmp_path, tmp_path)
    assert len(result["derived_binaries"]) == 6
    assert all(x["sha256"] == hashlib.sha256(data).hexdigest() for x in result["derived_binaries"])


def test_mismatched_archive_not_parsed(tmp_path):
    module = builder_module()
    version = BUNDLED_RELEASES[0]
    name = f"node-v{version}-linux-x64.tar.xz"
    (tmp_path / name).write_bytes(b"untrusted archive")
    (tmp_path / f"v{version}-SHASUMS256.txt").write_text(f"{'a' * 64}  {name}\n")
    with patch.object(module.tarfile, "open") as parser:
        with pytest.raises(ValueError, match="mismatch"):
            module.derive(tmp_path, tmp_path)
        parser.assert_not_called()
