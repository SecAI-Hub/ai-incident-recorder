# Security and Production-Readiness Audit

Audit date: 2026-08-02

## Scope

The audit covered event validation and storage, hash-chain integrity, retention, incident metadata, bundle selection/redaction/signing/verification, daemon authentication and HTTP handling, audit persistence, filesystem boundaries, container packaging, dependencies, tests, and GitHub automation. The review was source-based and exercised in Linux containers on a macOS development host; it did not include a deployed Fedora/SELinux endurance test.

## Remediated findings

- **Critical — corrupted evidence was skipped during startup.** Every existing JSONL line is now bounded, strictly decoded, semantically validated, checked for a unique valid ID, and verified as one complete genesis hash chain. Any corruption prevents new recording.
- **Critical — retention could silently send later writes to the replaced inode.** Retention now re-chains retained evidence, writes and syncs a same-directory temporary file, atomically renames and syncs the directory, swaps the append handle, and commits the in-memory view only when replacement occurred.
- **Critical — bundle authenticity trusted an embedded key.** Verification requires an independent public-key file, rejects unsigned bundles, authenticates the embedded key and signing timestamp, and verifies identity, count, event chain, and integrity digest.
- **High — redaction and event selection could produce misleading evidence.** Redacted exports are re-chained into a self-contained bundle, preserve signed source-chain linkage, and honor an incident's explicit `event_ids`. Strict profiles redact incident title/notes/tags plus JSON keys without silently overwriting colliding keys. Missing selected evidence fails packaging. An unknown privacy profile is rejected instead of falling back to weaker defaults.
- **High — incident and evidence paths allowed unsafe behavior.** Data directories and object IDs are constrained, symlinks and non-regular files are rejected, metadata is strictly decoded and identity-checked, and writes are owner-only, atomic, synced, and traversal-safe.
- **High — API input and service authentication were insufficiently bounded.** Startup requires a bounded owner-only token file. Non-health routes use constant-time bearer authentication, strict JSON with unknown/trailing-field rejection, request/header/time limits, query bounds, validated timestamps/IDs, and graceful shutdown.
- **High — caller-owned maps and slices could mutate stored evidence.** Record, query, incident get/list/create/update, and bundle paths now make defensive deep copies where evidence crosses a trust boundary.
- **Medium — batch validation could partially accept malformed requests.** Batch cardinality is bounded and every event is validated before the first durable append; storage errors stop immediately and are reported.
- **High — store and audit failures could be ignored.** Projected writes are checked against the 1 GiB store cap; an append or `fsync` failure poisons later writes. The strict, bounded audit chain is verified in full at startup; audit write/sync failure poisons readiness and blocks protected routes. Mutations and evidence disclosure are preflight-audited, and the 64 MiB audit cap requires controlled rotation.
- **High — audit rollback had no portable local anchor or guarded recovery path.** The CLI now exports the complete operational audit chain in an owner-only Ed25519-signed checkpoint whose payload digest, entry count, head, embedded key identity, and chain are independently verified. Export never overwrites, and recovery requires a separately retained head, verifies that the candidate contains it, and writes only to a new fsynced path.
- **High — hot reload and CLI import could partially apply invalid state.** Data directory, retention/TTL, and daemon changes are restart-only. JSONL imports strictly prevalidate the complete input before writing and return nonzero with explicit rejected counts on storage failure.
- **Supply chain / operations.** The image uses digest-pinned Go 1.26.5 and Alpine 3.23 bases, a stripped static binary, non-root UID, health check, narrow build context, and durable state volume. The runtime copies CA roots from the immutable builder stage instead of installing unpinned packages. CI actions are SHA-pinned and enforce module verification, formatting, bounded race tests, vet, `govulncheck`, current-tree and full-history secret scanning, container builds, CodeQL, and Dependabot updates. Tagged releases produce Linux binaries, a CycloneDX SBOM, Sigstore-signed checksums, and GitHub provenance attestations. A read-only release gate requires a v-prefixed strict SemVer annotated tag that resolves exactly to the workflow commit and is contained in `origin/main`; write and OIDC permissions remain confined to the publishing job.

## Residual risks and deployment requirements

- The event store is a single serialized JSONL chain with a 1 GiB safety cap; it is not an HA database or multi-writer log. Archive under a controlled procedure before the cap and run only one writer per data directory.
- A batch is validation-atomic but not a multi-record storage transaction: if media or `fsync` fails mid-batch, earlier successfully synced events remain. Clients should use returned IDs and reconcile after failures.
- Retention intentionally creates a new chain for retained records. Preserve signed bundles or externally anchored chain heads when long-term proof of the pre-retention chain is required.
- The local checkpoint boundary is provider-neutral, not itself WORM storage or a trusted timestamp. A privileged actor with the signing key and all local state can still replay or replace evidence. The deployment must choose immutable/object-lock storage, retention duration, replication, encryption, checkpoint cadence, and independently controlled key/head custody.
- Checkpoint filesystem hardening is supported for the Fedora/Linux production target and depends on POSIX UID, no-follow, hard-link, and directory-sync semantics; it is not a Windows recovery implementation.
- Redaction is pattern-based and cannot guarantee removal of every sensitive semantic value. Use the strictest named profile, review exports, and add organization-specific data-loss prevention before external sharing.
- Authentication is a single bearer token without tenant isolation, RBAC, or mTLS. Network segmentation, rotation, and an authenticated reverse proxy remain deployment responsibilities.
- Fedora/SELinux file labels, disk-full/crash fault injection, high-volume retention, coordinated event/incident backup restoration, and recovery drills still require production-environment testing.

## Verification performed

- 80 top-level tests via `go test -race -count=1 ./...`, including checkpoint tamper, trust-anchor, canonical-path, decoded-size, unsafe-mode/directory, injected partial-write cleanup/retry, rollback-anchor, no-overwrite, and exact-byte recovery cases
- `go vet ./...`
- `govulncheck ./...` with `golang.org/x/vuln/cmd/govulncheck@v1.3.0` — no reachable vulnerabilities
- `gosec@v2.28.0 -severity medium -confidence medium ./...` — no findings
- Gitleaks 8.30.1 current tree and history — no leaks; one historical synthetic redaction fixture is documented by exact fingerprint in `.gitleaksignore`
- Trivy 0.70.0 filesystem, Dockerfile, and image scan at HIGH/CRITICAL — no findings (database dated 2026-08-02)
- Digest-pinned Docker image build and inspection — non-root UID `65534:65534`
- Actionlint on all workflows — no findings
- Release dependency/permission graph checks, strict SemVer positive/negative fixtures, and synthetic annotated/lightweight/off-main Git ancestry cases — passed
