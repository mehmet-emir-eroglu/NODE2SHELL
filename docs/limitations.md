# Limitations and unresolved deployment evidence

* This is file-code verification, not remote exploitation detection. No URL target,
  port scanning, Brotli payload, crash test or arbitrary command execution exists.
* Runtime binary identity proves which official code file was read, not whether
  that file is loaded into a running worker. Replacing a file without restarting
  a process may leave old code in memory.
* Installers/archives/source files may never have been deployed. Their findings
  must not be relabeled as application or host findings.
* The default snapshot contains six releases and derived Linux x64 binaries only.
  Additional supported-branch releases require --release and an exact match to
  an official top-level distribution file. Arbitrary extracted Linux/macOS
  binaries cannot be identified through that online manifest alone.
* Distribution builds, repacks, custom patches, EOL majors and other Brotli
  ecosystems remain outside definitive coverage. Unknown does not mean safe.
* Trusted HTTPS and bundled checksums are the trust anchors. OpenPGP signature
  verification, independent build reproducibility and compromised publisher
  detection are not implemented.
* File reads have a size ceiling, not an elapsed-time deadline. DNS and slow
  response delivery can exceed socket timeout expectations. Retry counts and
  response sizes are bounded.
* File-consistency checks catch ordinary changes, not every hostile local race.
  Prefer immutable copies. Symlinks resolve to regular files; network-mounted
  filesystems cannot always be distinguished from local storage by path syntax.
* Output includes the local absolute filename. Reports and hostnames should not
  be treated as automatically scrubbed of all operator-chosen sensitive text.
  Target contents, metadata response bodies and exception internals are omitted.
* A partial new report may remain after a write failure. Exit 3 means discard it.
* An official fixed release is treated as fixed for this CVE in that branch.
  Future regressions or changed vendor advisories require renewed review. This
  says nothing about other vulnerabilities in that Node.js release.
