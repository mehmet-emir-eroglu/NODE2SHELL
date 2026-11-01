import hashlib
from dataclasses import replace
from unittest.mock import patch

import pytest

from cve_detector.detector import detect, evaluate
from cve_detector.models import Identity, Status
from cve_detector.verification import Fingerprint, load_catalog


@pytest.mark.parametrize("identity", load_catalog())
def test_every_bundled_identity(identity, tmp_path):
    path = tmp_path / "renamed-file"
    path.write_bytes(b"synthetic file; digest explicitly mocked")
    mock_digest = Fingerprint(str(path), identity.sha256, path.stat().st_size)
    with patch("cve_detector.detector.fingerprint", return_value=mock_digest):
        with patch("cve_detector.detector.fetch_manifest") as network:
            result = detect(str(path))
            network.assert_not_called()
    fixed = {"22.23.4", "24.22.1", "26.12.1"}
    assert result.status == (
        Status.NOT_VULNERABLE if identity.version in fixed else Status.VULNERABLE
    )
    assert result.scope == identity.scope
    assert result.observations["release"] == identity.version
    assert result.cve == "CVE-2026-111497"


@pytest.mark.parametrize("filename", ["node-v24.22.1.tar.xz", "node.exe", "node-backport-fixed"])
def test_claimed_fixed_filename_or_version_never_suffices(filename, tmp_path):
    path = tmp_path / filename
    path.write_bytes(b"Node.js v24.22.1 Brotli/1.2.1 patched=true")
    with patch("cve_detector.detector.fetch_manifest") as network:
        assert detect(str(path)).status == Status.INCONCLUSIVE
        network.assert_not_called()


def test_real_hash_with_synthetic_catalog_and_tamper(tmp_path):
    path = tmp_path / "node"
    payload = b"Synthetic fixture, not a Node.js runtime"
    path.write_bytes(payload)
    identity = Identity(
        hashlib.sha256(payload).hexdigest(),
        "24.22.0",
        "win-x64/node.exe",
        "runtime_binary",
        "https://nodejs.org/dist/v24.22.0/SHASUMS256.txt",
    )
    with patch("cve_detector.detector.load_catalog", return_value=(identity,)):
        assert detect(str(path)).status == Status.VULNERABLE
        path.write_bytes(payload + b"backported patch")
        assert detect(str(path)).status == Status.INCONCLUSIVE


def test_conflicting_catalog_evidence():
    record = load_catalog()[0]
    contrary = replace(record, version="26.12.1" if record.version != "26.12.1" else "24.22.0")
    assert evaluate("fixture", (record, contrary), {}).status == Status.INCONCLUSIVE


def test_release_hint_cannot_override_known_affected_identity(tmp_path):
    path = tmp_path / "node"
    path.write_bytes(b"fixture")
    record = next(x for x in load_catalog() if x.version == "24.22.0")
    with patch(
        "cve_detector.detector.fingerprint", return_value=Fingerprint(str(path), record.sha256, 7)
    ):
        with patch("cve_detector.detector.fetch_manifest") as network:
            result = detect(str(path), release="24.22.1")
            network.assert_not_called()
    assert result.status == Status.INCONCLUSIVE


def test_opt_in_manifest_requires_real_digest_match(tmp_path):
    path = tmp_path / "fixture"
    path.write_bytes(b"unit-test fixture")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    fixture_manifest = f"{digest}  win-x64/node.exe\n".encode()
    with patch("cve_detector.detector.fetch_manifest", return_value=fixture_manifest) as network:
        result = detect(str(path), release="24.23.0")
        network.assert_called_once_with("24.23.0", 5, 0)
    assert result.status == Status.NOT_VULNERABLE
    assert result.observations["metadata_source"] == "nodejs.org_https"


def test_wrong_online_digest_is_inconclusive(tmp_path):
    path = tmp_path / "fixture"
    path.write_bytes(b"unit-test fixture")
    with patch(
        "cve_detector.detector.fetch_manifest",
        return_value=f"{'a' * 64}  win-x64/node.exe\n".encode(),
    ):
        assert detect(str(path), release="24.23.0").status == Status.INCONCLUSIVE


def test_transport_failure_is_error(tmp_path):
    from cve_detector.exceptions import DetectionError

    path = tmp_path / "fixture"
    path.write_bytes(b"fixture")
    with patch("cve_detector.detector.fetch_manifest", side_effect=DetectionError("Lookup failed")):
        assert detect(str(path), release="24.23.0").status == Status.ERROR


def test_url_never_contacted_or_echoed():
    with patch("cve_detector.detector.fetch_manifest") as network:
        result = detect("https://user:secret@example.com/")
        network.assert_not_called()
    assert result.status == Status.ERROR
    assert "secret" not in str(result.to_dict())
