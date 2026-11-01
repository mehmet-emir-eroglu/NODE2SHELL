# Node2Shell detector — CVE-2026-111497

Read-only Python assessment of **official Node.js binaries and distribution files**
for the Brotli decoder vulnerability called Node2Shell, HTTP2Shell or Broccoli2Shell.
Python 3.11+; no third-party runtime dependencies.

## Overview

The detector hashes a user-selected local file and verifies its exact identity
against official Node.js release checksums or reviewed binary fingerprints.
Only then does it apply the vendor's affected/fixed release boundaries.

**VULNERABLE means the identified file contains affected code. It does not mean an
application was exploited or that a remotely reachable decompression route exists.**
NOT_VULNERABLE applies only to this CVE in the identified artifact. A package on
disk does not establish which runtime is serving requests or loaded into memory.

The tool never runs Node.js, decompresses supplied Brotli streams, uploads a
payload, scans ports, or contacts an application endpoint. HTTP URLs are not valid
targets. Without `--release`, assessment is offline. With `--release`, unmatched
files can be compared with public checksums fetched from **nodejs.org only**.
The target's bytes and digest are never sent to that service.

## CVE information

| Item | Value |
| --- | --- |
| CVE | CVE-2026-111497 |
| Underlying component | Google's Brotli C decoder, bundled in Node.js |
| Weakness | Out-of-bounds write; CWE-787 and CWE-252 |
| CNA severity | Critical, CVSS 4.0 9.2 |
| Node.js severity | High in its security release advisory |
| Affected upstream Brotli ranges | 1.0.3–1.0.9, 1.1.0, 1.2.0 |
| Fixed upstream Brotli releases | 1.0.10, 1.1.1, 1.2.1 |
| First fixed supported Node.js releases | 22.23.4, 24.22.1, 26.12.1 |

The two severity labels come from different authorities and are retained rather
than silently equated. This project assesses Node.js release lines 22, 24 and 26;
it does not assess every product embedding Brotli.

## Technical background

The decoder mishandles an invalid block switch, allowing malformed compressed
input to corrupt memory. An application must pass attacker-controlled Brotli data
to the affected decoder for the described attack path to be reachable. Relevant
Node.js APIs are in `node:zlib`. Compression support or an HTTP `br` header alone
does not establish this condition. See the [technical analysis](docs/technical-analysis.md)
for the root cause, patch, CVSS vector, source discrepancies and references.

## Detection methodology

1. Resolve and validate a regular local file, then hash its complete bytes using
   SHA-256, with a 512 MiB file-size limit and bounded read buffers.
2. Match against the bundled official manifests and derived Linux binary hashes.
3. If unresolved and `--release` is supplied, fetch that exact stable release's
   checksum manifest over verified HTTPS from nodejs.org and compare locally.
4. A proven official file identity is classified using its release's branch-specific
   patch boundary. Without identity, the result remains inconclusive.
5. Report scope, provenance, observations, conclusion, limitations and UTC time.

The catalog's six manifests have pinned digests. Linux binary fingerprints were
derived by hashing `bin/node` inside archives whose entire SHA-256 first matched
the official manifest. The maintainer helper never writes archive members to disk.
Runtime assessment never opens a target as an archive. See
[methodology](docs/detection-methodology.md) and [provenance](docs/provenance/README.md).

## Coverage

The bundled snapshot, reviewed **2026-11-01**, contains **174 identities** across:

| Branch | Last affected release included | First fixed release included |
| --- | --- | --- |
| 22 | 22.23.3 | 22.23.4 |
| 24 | 24.22.0 | 24.22.1 |
| 26 | 26.12.0 | 26.12.1 |

There are 20 runtime binaries (14 official Windows executable entries and six
derived Linux x64 binaries), 122 runtime archives, 20 installers, and 12 source
archives. Header-only packages, import libraries and debug-symbol archives are
excluded. Available architectures vary by release; the bundled manifest files
are the definitive inventory.

`--release` extends checksum matching to other official stable releases in the
same three branches. It does not add fingerprints for binaries extracted from
additional Linux/macOS archives. For those releases, assess the unmodified official
archive or installer instead. Later major branches, EOL branches, distribution
packages and custom builds are not inferred to be safe.

## Detection accuracy

| Result | Required evidence |
| --- | --- |
| VULNERABLE | Exact identity of an official artifact from a supported branch below its fixed boundary |
| NOT_VULNERABLE | Exact identity of an official artifact at or above its branch's fixed boundary |
| INCONCLUSIVE | Unknown/modified artifact, conflicting identities, or a conflicting requested release |
| ERROR | Invalid target, unsupported release argument, file failure, corrupt catalog, network failure, or output failure |

A version supplied with `--release` is a lookup hint, not evidence. Renaming a
file, embedding a version string, or claiming a backport cannot change the result.
Patched distribution builds with older versions generally remain inconclusive
because their hashes differ from upstream. A file can be affected even if its
application never decompresses untrusted data; this is explicitly a code-presence
assessment. A fixed binary on disk does not establish that running processes have
restarted. SHA-256 identity and the metadata source are trusted assumptions;
OpenPGP signatures are not verified by this implementation.

## Features

* Default offline verification; optional bounded public-metadata lookup.
* Full-file hashing, strict manifest parsing, provenance and conflict handling.
* Four evidence-based statuses, JSON/console output, stable exit codes.
* No runtime dependency on Node.js or Brotli and no target execution.
* HTTPS verification, no redirects, no inherited proxies, bounded retries.
* Exclusive report creation to prevent overwriting targets or existing reports.

## Requirements and installation

Use Python 3.11 or later. Install each detector project in its own virtual
environment because this project's import package is named `cve_detector`.

Windows, from the repository directory:

```cmd
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install .
```

Linux/macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

## Usage

Check an installed Windows executable without running it:

```cmd
python -m cve_detector --target "C:\Program Files\nodejs\node.exe"
```

Check a Linux executable or a locally acquired release package:

```sh
node2shell-detector --target /usr/local/bin/node --format json
node2shell-detector --target ./node-v24.22.1-linux-x64.tar.xz --output assessment.json --format json
```

Permit an official checksum lookup for a release outside the bundled snapshot:

```sh
node2shell-detector --target ./node-v26.13.0-linux-x64.tar.xz --release 26.13.0 --timeout 5 --retries 0 --format json
```

Examples assume those files already exist. The detector does not download runtime
packages. The same bytes produce the same identity regardless of the local name.
Symlinks to regular local files are resolved; special files and UNC paths are rejected.

## Command-line arguments

| Argument | Meaning/default |
| --- | --- |
| --target | Required local binary, package, installer or source archive |
| --release | Optional exact version in branch 22, 24 or 26; permits official lookup if unmatched |
| --timeout | Metadata socket timeout, 0.1–30 seconds; default 5 |
| --retries | Additional metadata connection attempts, 0–2; default 0 |
| --format | console (default) or json |
| --output | New UTF-8 report file; fails if it already exists |
| --verbose | Progress on stderr |
| --quiet | Console status only; JSON remains complete |
| --version / --help | Version or usage; exit 0 |

`--release` accepts `24.22.1` or `v24.22.1`, not ranges, prereleases, build suffixes
or URLs. If it conflicts with a bundled match, the result is inconclusive without
contacting the network. Metadata error responses are not retried. No auth, proxy,
TLS-bypass or active-exploit options exist.

## Example output

Abridged illustrations, not claims of application exploitation:

```text
CVE-2026-111497: VULNERABLE | scope=runtime_binary
Exact official Node.js artifact contains the affected Brotli decoder.
Application exploitability has not been established.

CVE-2026-111497: NOT_VULNERABLE | scope=runtime_archive
Exact official Node.js artifact belongs to a release fixed for CVE-2026-111497.

CVE-2026-111497: INCONCLUSIVE | scope=local_file
No exact supported official Node.js identity was established.

CVE-2026-111497: ERROR | scope=unknown
Cannot resolve the local target; check its path and permissions.
```

## JSON output schema

| Field | Meaning |
| --- | --- |
| schema_version | Integer 1 |
| cve | CVE-2026-111497 |
| target | Resolved local path; omitted/replaced for failed assessments |
| status | One of the four documented strings |
| scope | runtime_binary, runtime_archive, installer, source_archive, local_file, or unknown |
| evidence_summary | Conclusion and its qualifications |
| verification_method | sha256_identity or assessment_failed |
| confidence | Qualitative confidence in the evidence and scope |
| observations | SHA-256, size, metadata source/date, optional lookup version/manifest digest and matched identities |
| limitations | List of evidence and deployment caveats |
| references | Vendor advisory, CVE record and applicable checksum URLs |
| timestamp | ISO 8601 UTC timestamp |

Identity entries include release, official filename, SHA-256, scope, checksum URL
and (for derived Linux binaries) archive/member provenance. Reports include local
paths; review before sharing. Console strings are escaped to prevent terminal
control injection. No target content or arbitrary server error text is printed.

## Exit codes

0 = NOT_VULNERABLE; 1 = VULNERABLE; 2 = INCONCLUSIVE; 3 = ERROR.
Help/version exit 0; invalid arguments and interruption exit 3. Automation must
handle 2 and 3 explicitly. If a new output file cannot be written, stdout reports
ERROR and exit is 3; discard any partial new file left by a failed write.

## Testing and quality checks

```sh
python -m pip install -e ".[dev]"
python -m pip install --upgrade pip
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m build
python -m pip_audit --strict --cache-dir .audit-cache
```

Unit tests use synthetic files, checksum snapshots and mocked network responses;
they do not contact public targets. Tests that substitute catalog digests label
the fixtures explicitly. Separate real-artifact checks and final tool versions
are recorded in [validation](docs/validation.md). The maintainers' catalog builder
also has tests ensuring unverified archive bytes are never parsed.

## CI/CD integration

Included workflows test Windows/Linux on Python 3.11–3.14, run lint/format/type
checks, build packages, and audit development dependencies with read-only GitHub
permissions. Hosted CI results must be checked after publication. A file finding
must retain its scope when imported into inventory or deployment systems.

## Limitations and security considerations

Use only files you are authorized to inspect. Default assessment performs no
network operation, execution, archive parsing, or modification of the target.
Optional lookup retrieves at most 64 KiB from a fixed HTTPS origin and refuses
redirects or compressed metadata. It does not decompress Brotli data itself.

Socket timeouts are not a global wall-clock deadline: DNS or slow metadata delivery
may take longer. Local filesystem stalls can also block. The file-size ceiling,
read buffers and retry count are bounded. Use immutable copies when local writers
may change files; consistency checks do not defeat a malicious concurrent writer.

Catalog and HTTPS trust are not independent signature verification. The detector
does not prove application reachability, loaded-process state, container-wide
coverage, or overall system safety. Brotli in Python, .NET, Bun, browsers, distro
libraries and other products needs separate vendor-specific assessment. See
[limitations](docs/limitations.md).

## References

* [Node.js security release advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
* [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-111497)
* [Upstream decoder patch](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)
* [Node.js 24.22.1 release](https://nodejs.org/en/blog/release/v24.22.1/)
* [Checksum manifest example](https://nodejs.org/dist/v24.22.1/SHASUMS256.txt)

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). New definitive
checks need trustworthy code identity or patch evidence and regression tests.
Keep unknown/backported builds inconclusive until stronger evidence is available.

## License

MIT; see [LICENSE](LICENSE). Upstream checksum/CVE metadata retains its provenance.
Node.js binaries and source archives are not redistributed with this project.
