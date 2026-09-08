# ai-incident-recorder

`ai-incident-recorder` is a local, tamper-evident flight recorder for SecAI_OS events and incident case bundles.

## Security model

- Events are globally hash chained, projected against a 1 GiB cap, fsynced before acknowledgement, and loaded fail closed. Corruption, truncation, duplicate IDs, unsafe files, and broken chain links prevent startup. An append or sync failure poisons the store until restart and recovery.
- Retention rewrites are atomic, directory-synced, re-chained, and reopened before later writes are accepted.
- Incident metadata is written atomically. Store APIs return defensive copies so callers cannot mutate persisted evidence through shared maps or pointers.
- Exported bundles are self-contained, re-chained after redaction, integrity-digested, and optionally Ed25519-signed. Strict packaging redacts incident title, notes, tags, values, and collision-safe JSON keys. Verification rejects unsigned bundles and requires an independent trusted public key.
- Named privacy profiles are exact: requesting an unknown profile fails instead of falling back to a potentially weaker default.
- The daemon refuses to start without an owner-only bearer token of at least 32 characters and a strict, bounded, valid audit chain. All `/v1/*` routes—including evidence packaging—require authentication and endpoint-wide rate limiting. Audit loss makes `/health` return `503` and blocks protected operations.

Redacting on record permanently removes raw evidence. Prefer packaging-time redaction unless data-minimization requirements explicitly require otherwise.

## Development

Go 1.26.8 or newer is required for descriptor-rooted checkpoint filesystem
operations; CI and production images use Go 1.27.1.

```sh
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

Create keys and verify a bundle with a trusted key:

```sh
go run . keygen -priv recorder.key -pub recorder.pub
go run . package -policy policies/default-policy.yaml -id INCIDENT_ID -key recorder.key -output case.json
go run . verify -bundle case.json -pubkey recorder.pub
```

## Signed audit checkpoints and recovery

These checkpoint commands and their filesystem guarantees are Fedora/Linux
production features. They rely on POSIX UID ownership, no-follow opens, hard
links, and directory `fsync`; POSIX macOS is suitable for development testing,
but Windows filesystems are not supported by this recovery boundary.

The recorder can export its operational audit log as a provider-neutral JSON
checkpoint. The owner-only checkpoint contains the complete audit bytes, their
SHA-256 digest, entry count, chain head, signing public-key identity, and an
Ed25519 signature. Export and recovery write and sync a randomized
same-directory temporary file, publish it with an atomic no-replace hard link,
remove the temporary name, sync the parent directory, and reject malformed,
modified, or broken chains. Failed writes are cleaned up before returning, so a
partial final file cannot block a safe retry.

Provision a dedicated checkpoint keypair separately from the case-bundle key,
keep the private key under independent restricted custody, and expose it only
for the stopped-writer procedure. Stop the daemon before an export so the
checkpoint and operational event boundary are unambiguous:

```sh
install -d -m 0700 /var/lib/secure-ai/checkpoints
ai-incident-recorder audit-checkpoint \
  -audit /var/lib/secure-ai/logs/recorder-audit.jsonl \
  -key /run/secure-ai/recorder-checkpoint.key \
  -output /var/lib/secure-ai/checkpoints/recorder-20260802.json

ai-incident-recorder audit-verify \
  -checkpoint /var/lib/secure-ai/checkpoints/recorder-20260802.json \
  -pubkey /etc/secure-ai/recorder-checkpoint.pub \
  -require-head PREVIOUSLY_RETAINED_CHAIN_HEAD
```

Run the exporter as the owner of both input and key. If custody uses a distinct
export identity, stop the daemon and stage an exact owner-only audit copy under
that identity first. Inputs and outputs must live in trusted
root/export-user-owned directories that are not group/world-writable; never
weaken the source or private-key mode.
All checkpoint source, key, checkpoint-output, and recovery-output paths must
be canonical absolute paths.

After verification, copy the checkpoint to the deployment's immutable retention
target and retain its reported chain head separately. Local `O_EXCL` protection
prevents accidental overwrite but is not WORM storage and the signed local clock
is not a trusted timestamp.

Recovery is deliberately offline, requires an independently retained head to be
present in the candidate chain, and refuses to replace a path:

```sh
ai-incident-recorder audit-recover \
  -checkpoint /recovery/recorder-20260802.json \
  -pubkey /etc/secure-ai/recorder-checkpoint.pub \
  -require-head INDEPENDENTLY_RETAINED_CHAIN_HEAD \
  -output /var/lib/secure-ai/logs/recorder-audit.recovered.jsonl
```

Verify the recovered file through normal startup before changing
`AUDIT_LOG_PATH`. This checkpoint covers the operational audit log; back up
`events.jsonl`, incident metadata, and any signed case bundles together under a
stopped-writer procedure. Retention rewrites the evidence chain, so checkpoint
and externally retain its old head before a purge.

## Daemon deployment

Mount an owner-only service-token file at `SERVICE_TOKEN_PATH` (default `/run/secure-ai/service-token`), the signing key referenced by policy, and durable encrypted storage at `/var/lib/secure-ai`. Back up the event store and incident directory together; a hash chain is tamper-evident, not a substitute for access-controlled, append-oriented storage or external timestamping. Stop the daemon before rotating the 64 MiB audit log, create and verify a final signed checkpoint, and preserve its chain head.

Bind to loopback or an authenticated private network. Use a read-only root filesystem, drop all capabilities, set `no-new-privileges`, and configure PID, CPU, memory, and storage quotas. Treat exported bundles as sensitive customer artifacts.

HTTP endpoints are documented by the route names in `main.go`; all non-health requests use `Authorization: Bearer …`.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the detailed findings, validation record, and residual deployment risks.
