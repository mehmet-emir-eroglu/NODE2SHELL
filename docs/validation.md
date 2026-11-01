# Validation record

Executed on Windows, Python **3.12.14**, on **2026-11-01**.

| Check | Actual outcome |
| --- | --- |
| Deterministic pytest suite | **294 passed**, 3.14 seconds |
| Ruff lint | Passed |
| Ruff formatting | Passed; 17 Python files |
| Strict mypy | Passed; 10 source files |
| Source distribution and wheel build | Passed |
| Clean-environment wheel installation | Passed with no third-party runtime dependencies |
| Installed module version and console command | Passed |
| Installed package's complete catalog | Loaded all 174 identities |
| Official artifacts, offline | Ten real files classified as expected |
| Real Windows executable CLI exit codes | Affected = 1, fixed = 0 |
| Optional official metadata lookup | Passed for Node.js 26.13.0 Linux x64 archive |
| Dependency audit | 41 development packages; no known vulnerabilities reported |

Tools: pytest 9.2.0, Ruff 0.17.3, mypy 1.20.2, build 1.6.1,
setuptools 84.2.1, pip-audit 2.10.1, pip 26.2.2. The audit used a local cache,
strict mode and a five-second network timeout. It is a point-in-time advisory
database check, not a guarantee that no vulnerabilities exist. The detector
itself has no third-party runtime dependencies.

## Real-file checks

All downloads came from `https://nodejs.org/dist/`. Files were hashed or read as
data; **no downloaded Node.js executable was run**. Linux binary test files came
from archives whose entire hashes were first matched to official manifests.

| Artifact | Expected and observed result |
| --- | --- |
| node-v22.23.3-linux-x64.tar.xz | VULNERABLE |
| node-v22.23.4-linux-x64.tar.xz | NOT_VULNERABLE |
| node-v24.22.0-linux-x64.tar.xz | VULNERABLE |
| node-v24.22.1-linux-x64.tar.xz | NOT_VULNERABLE |
| node-v26.12.0-linux-x64.tar.xz | VULNERABLE |
| node-v26.12.1-linux-x64.tar.xz | NOT_VULNERABLE |
| Node.js 24.22.0 Windows x64 node.exe | VULNERABLE |
| Node.js 24.22.1 Windows x64 node.exe | NOT_VULNERABLE |
| Node.js 24.22.0 Linux x64 bin/node | VULNERABLE |
| Node.js 24.22.1 Linux x64 bin/node | NOT_VULNERABLE |

Selected independently retrieved file identities:

* Windows x64 24.22.0: `ba93f9a70bd86fce3ebbb39ec758501458453467aa92a34a0a3602d1e3fc2b9c`
* Windows x64 24.22.1: `d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5`
* Linux x64 binary 24.22.0: `67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c`
* Linux x64 binary 24.22.1: `e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb`

The separate optional-lookup check used `node-v26.13.0-linux-x64.tar.xz`, absent
from the bundled snapshot. With `--release 26.13.0`, the tool retrieved the official
manifest and returned NOT_VULNERABLE with runtime_archive scope. Artifact SHA-256:
`d28a96af6c38596f6d9d97c0ee531c13d238d757742387d1928de822d959e997`.
Fetched manifest SHA-256:
`9b0d4aa4d20a4f1afaf2cdcf99175ad90d1856d24c7d31dc46f72369b73e2d35`.

These are code-identity findings, not exploit tests or deployment confirmations.

## Automated coverage

All 174 catalog identities; independent branch boundaries; metadata parsing and
integrity; derived-hash provenance; refusal to parse unverified archives; actual
file hashing and tampering; oversized, missing and changing files; misleading
filenames/version text; backport-like modifications; conflicting evidence; all
four statuses; JSON schema; exit codes; exclusive output creation; interruption;
and sanitized failures are covered.

Network tests mock DNS, refusal, timeout, TLS, malformed HTTP, redirects, HTTP
error statuses, bounded response reads, compression rejection and retries.
They assert fixed-origin requests, certificate validation, no inherited proxy,
and no transfer of target data. Synthetic digest fixtures are explicitly marked
and not presented as genuine Node.js binaries.

## Packaging environment and remaining checks

Builds used a workspace-local TEMP/TMP directory because this machine's default
temporary directory contains braces that interfere with setuptools substitution.
No detector behavior was changed for this environment.

Hosted GitHub CI has not executed. Linux/macOS execution and local Python versions
other than 3.12.14 were not tested; the configured matrix covers Windows/Linux
and Python 3.11–3.14 after publication. OpenPGP verification, custom-build analysis,
process/deployment binding and application exploitability testing are not implemented.
The repository has not been published automatically.
