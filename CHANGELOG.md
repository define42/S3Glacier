# Changelog

User-visible changes are recorded here. Entries under `Unreleased` describe the
current development branch and do not imply a published version.

## Unreleased

### Added

- Per-archive committed-boundary checkpoints and identity manifests, with lazy
  recovery of interrupted appends before reads or subsequent writes.
- Multiple buckets, each with a TAR-files-per-hour count chosen at creation and
  fixed for the lifetime of the bucket.
- HTTP bucket management, bucket-aware upload/download and browser routes, and
  S3 bucket creation through a signed `x-amz-meta-tar-files-per-hour` header.
- S3 bucket listing and Signature V4 authentication, including presigned URLs,
  signed streaming uploads, and payload checksum verification.
- `make lint` and `make modernize` development commands, with configurable
  golangci-lint path resolution.
- Source and container quickstarts, an environment reference, an HTTP/S3 API
  guide, and an OpenAPI description of JSON bucket management.

### Changed

- Archive coordination uses process-local locks for each full bucket/hour/shard
  path. One lifetime data-root ownership lock refuses a second standalone server;
  no per-archive lock files are created. No older checkpoint format is migrated.
- Upload success follows durable TAR and checkpoint publication. Every accepted
  upload appends an entry, including repeated UUIDs. GET and HEAD return the first
  committed match; later duplicates remain in the TAR and consume storage.
  Retries after a lost response can add duplicates and are not idempotent.
- All buckets, including `data`, store archives under
  `DATA_FOLDER/buckets/{bucket}` and immutable metadata under `DATA_FOLDER/.buckets`.
  `data` uses 256 TAR files per hour. The previous layout is not supported.
- Disk-pressure cleanup selects the oldest archive hours across all buckets and
  preserves bucket definitions.
- The Makefile uses the Docker Compose plugin (`docker compose`).

### Fixed

- Uploads append without rescanning existing entries in the archive.
- Archive cleanup shares the same lock as readers and writers, so deletion and
  recreation cannot bypass synchronization by locking different file inodes.
- Pressure cleanup removes TARs before checkpoints and can reap orphan checkpoints
  without allocating a deletion marker.
- `make test` now runs the Go test suite instead of referring to a missing file.
- `make lint` locates the configured Go binary directory without requiring it on
  the shell's PATH.
