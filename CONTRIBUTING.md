# Contributing

Create a dedicated Python 3.11+ virtual environment, install `.[dev]`, and run the
README's tests, lint, formatting, strict type checking and build commands.

New classifications require evidence of exact code or authoritative patch identity.
Do not convert banners, filenames, version arguments, user assertions or HTTP status
codes into definitive findings. Unknown builds and backports stay inconclusive.
Preserve the distinction between file code status and application exploitability.

Catalog changes must include official provenance, branch-boundary review, complete
file identities and regression tests. Follow docs/provenance/README.md to reproduce
derived hashes. Keep network tests deterministic; no public application targets.
No memory-corruption triggers, exploit payloads or target execution belong in this tool.

Do not commit target reports, credentials, downloaded runtime files, environments,
caches or logs. Report security defects through the process in SECURITY.md.
