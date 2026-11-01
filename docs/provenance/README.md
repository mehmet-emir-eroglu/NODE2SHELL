# Provenance and catalog reproduction

Retrieved 2026-11-01 through verified HTTPS. The runtime package includes the
original Node.js checksum manifests for 22.23.3, 22.23.4, 24.22.0, 24.22.1, 26.12.0
and 26.12.1 under `src/cve_detector/data/`.

Source URL pattern: `https://nodejs.org/dist/vVERSION/SHASUMS256.txt`.
Each corresponding official Linux x64 archive was downloaded from that same
release directory and matched to its manifest digest before its `bin/node`
member was read. No downloaded binary was executed. Archives are not distributed
in this repository.

The generated `catalog.json` records each raw manifest's SHA-256, each verified
archive's SHA-256, its exact member path, member size and member SHA-256. The
detector verifies the provenance relationships and pinned manifest digests when
loading the catalog. This is a reproducibility aid, not an independent signature.

To reproduce, install the project in a development environment, obtain the six
official manifests and matching `node-vVERSION-linux-x64.tar.xz` files, and run:

```sh
python tools/derive_catalog.py --metadata-dir local-manifests --archive-dir local-archives --output reproduced-catalog.json
```

The directory names above are operator-supplied local paths. Compare the generated
JSON with the bundled catalog before proposing a catalog change. The helper
requires matching hashes, a regular member at the exact expected path, and a
bounded member size. It performs no download, execution or extraction to disk.

The adjacent CVE snapshot came from:
https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/111xxx/CVE-2026-111497.json

For future catalog updates, review current vendor advisories and branch scope,
update BUNDLED_RELEASES/review date intentionally, regenerate using official
artifacts, and run provenance, branch-boundary and classification regressions.
