# Detection methodology

## Trust chain

For directly published artifacts:

`target bytes -> SHA-256 -> official manifest entry -> Node.js release -> CVE boundary`

For bundled Linux x64 binary fingerprints:

`official archive checksum -> verified archive -> exact bin/node member -> binary SHA-256`

The second chain is computed by a maintainer at catalog-generation time, never by
parsing a user's target. Its archive digest and member name are retained in reports.
Default metadata is bundled; optional lookup uses the same manifest parser against
the fixed nodejs.org HTTPS origin. No user-supplied catalog or patch-status boolean
can override classification.

## Decision process

1. Validate the path and requested release before network access. Reject URLs,
   UNC paths, directories, devices, prereleases and unsupported major branches.
2. Hash the entire regular file in bounded chunks, enforcing 512 MiB and checking
   file identity, size and modification time for changes during the read.
3. Validate bundled manifest digests and derived-binary provenance relationships.
4. Look up all identities matching the observed digest. Conflicting release/scope
   identities yield INCONCLUSIVE. A supplied conflicting release also yields
   INCONCLUSIVE rather than overriding observed identity.
5. If no match exists and --release is supplied, retrieve that release's manifest.
   A transport/format failure yields ERROR. A valid manifest without a match yields
   INCONCLUSIVE. A match establishes release identity, not just a version hint.
6. Compare the identified release against the fixed boundary for its major branch.
   Emit the result with scope, provenance and limitations.

## Network constraints

Only public checksum metadata is requested. Request URL construction accepts only
normalized stable release numbers from branches 22/24/26. Proxy inheritance,
redirects, authentication and cookies are absent. TLS certificates and hostnames
are verified. A single response is bounded to 64 KiB; compressed responses are
rejected and never decoded. There are at most three attempts, with short backoff;
HTTP error statuses and TLS failures are not retried. The timeout is per socket
operation, not a total deadline. No arbitrary target URL is contacted.

## Evidence boundary

Classification applies to the exact bytes read. It neither identifies a running
process nor proves that an application's inputs reach Brotli. Different bytes,
even under an official filename or plausible version label, remain unverified.
No numeric confidence score is assigned. A trustworthy checksum origin/catalog
and the SHA-256 identity assumption are explicit parts of the method.
