"""Maintainer tool: derive Linux x64 binary identities from verified official archives.

Requires locally downloaded SHASUMS256.txt and matching archives. Does not download,
execute, or extract files to disk. Run after installing this project or setting PYTHONPATH.
"""

import argparse
import hashlib
import json
import tarfile
from pathlib import Path

from cve_detector.evidence import BUNDLED_RELEASES, parse_manifest


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def derive(metadata_dir, archive_dir):
    result = {
        "schema_version": 1,
        "reviewed_on": "2026-11-01",
        "manifest_sha256": {},
        "derived_binaries": [],
    }
    for version in BUNDLED_RELEASES:
        filename = f"v{version}-SHASUMS256.txt"
        raw = (metadata_dir / filename).read_bytes()
        identities = parse_manifest(raw, version)
        archive_name = f"node-v{version}-linux-x64.tar.xz"
        expected = next(x.sha256 for x in identities if x.filename == archive_name)
        archive_path = archive_dir / archive_name
        actual = sha256(archive_path)
        if actual != expected:
            raise ValueError(f"Archive SHA-256 mismatch: {archive_name}")
        member_name = f"node-v{version}-linux-x64/bin/node"
        with tarfile.open(archive_path, mode="r:xz") as archive:
            member = archive.getmember(member_name)
            if not member.isfile() or not 0 < member.size <= 256 * 1024 * 1024:
                raise ValueError("Expected bounded regular binary member")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Expected readable binary member")
            with stream:
                binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        result["manifest_sha256"][version] = hashlib.sha256(raw).hexdigest()
        result["derived_binaries"].append(
            {
                "version": version,
                "archive": archive_name,
                "archive_sha256": actual,
                "member": member_name,
                "sha256": binary_hash,
                "size_bytes": member.size,
            }
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata-dir", type=Path, required=True)
    parser.add_argument("--archive-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = derive(args.metadata_dir, args.archive_dir)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {len(result['derived_binaries'])} archives and derived their binary hashes.")


if __name__ == "__main__":
    main()
