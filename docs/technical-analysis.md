# Technical analysis — CVE-2026-111497

Research date: 2026-11-01. Scope: the Node.js distribution of Google's Brotli decoder.

## Root cause and prerequisites

An invalid block switch is mishandled as a need for additional input. Continuing
decoding can overrun an internal buffer and corrupt process memory. An attacker
must be able to supply compressed data to a decoder used by the application.
Node.js exposes Brotli decompression through `node:zlib`; the application determines
whether that route is remotely reachable. Authentication is not inherently required.
Consequences may include denial of service, disclosure or code execution.

[Node.js advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).

The upstream patch introduces a permanent invalid-block-switch error and propagates
decoder errors instead of continuing the unsafe path. It changes `c/dec/decode.c`
and the public decoder error definitions. This project does not reproduce the
malformed-input trigger or infer correctness from one error message.

[Patch 0ed4268a4401abcb4472096340477cf4af7d1a2b](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b).

## Affected and fixed versions

The CNA's structured Brotli ranges are 1.0.3 <= version < 1.0.10,
1.1.0 <= version < 1.1.1, and 1.2.0 <= version < 1.2.1.
First fixed Node.js releases are 22.23.4, 24.22.1 and 26.12.1.
For these three branches the detector applies the boundary only after matching
the entire artifact to official release identity. EOL/other majors and custom
or downstream builds do not inherit this rule.

## Severity and reference discrepancies

The Google CNA assigns CVSS 4.0 9.2 (Critical), vector
`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.
Weaknesses are CWE-787 and CWE-252. Node.js labels the issue High; this is a
vendor-specific rating, not a different fixed-version boundary.

The CVE description's broad phrase spanning 1.0.3 through 1.2.0 includes numbers
that are fixed maintenance releases. Use its explicit structured ranges, which
exclude the fixed 1.0.10 and 1.1.1 backports.

The retrieved record also has `datePublic` 2026-02-27 while its publication metadata
and vendor security release concern October. This project records the discrepancy
and uses the vendor's October 21 release announcement for patch timing; it does
not infer a February public exploit or disclosure from that field.

[CNA record snapshot](provenance/CVE-2026-111497.json), retrieved from the
[CVE Program repository](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/111xxx/CVE-2026-111497.json).

## Why this detection method

HTTP compression support does not prove decompression of untrusted input. Version
strings can be masked, forged or unchanged by backports. A behavioral memory-safety
probe can crash a process. Exact official artifact identity plus vendor patch
information supports a narrowly scoped code-status conclusion without exercising
the flaw. Runtime reachability and deployment binding remain separate work.
