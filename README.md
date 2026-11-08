# S3 Glacier Archive Server

[![Go version](https://img.shields.io/github/go-mod/go-version/define42/S3Glacier)](go.mod)
[![Build](https://github.com/define42/S3Glacier/actions/workflows/ci.yml/badge.svg)](https://github.com/define42/S3Glacier/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

S3Glacier stores timestamped objects in local TAR archives and exposes a subset of
the S3 API, HTTP upload/download routes, and a web interface. Each bucket has an
immutable maximum number of TAR files per hour; disk-pressure cleanup deletes
whole archives, oldest first. This is a local archive server, not an integration
with the AWS S3 Glacier storage service.

## Demo

After starting the server as described below, create a bucket with up to **4 TAR
files per hour**:

```sh
curl --fail-with-body http://localhost:8000/buckets \
  -H 'Authorization: Bearer local-write' \
  -H 'Content-Type: application/json' \
  -d '{"name":"small-files","tar_files_per_hour":4}'
```

The server returns `201 Created` with the bucket's name, fixed count, and creation
time. Archives are created on demand, so an empty hour creates no TAR files.

## Getting started

### Run from source

Install the Go version specified in [go.mod](go.mod), currently **Go 1.27.3**.
The examples use a POSIX shell and curl.

```sh
git clone https://github.com/define42/S3Glacier.git
cd S3Glacier
go build -o /tmp/s3glacier .

export DATA_FOLDER="$(mktemp -d)"
export SERVER_PORT=8000
export DISK_USAGE_ALLOWED=99
export READ_TOKEN=local-read
export WRITE_TOKEN=local-write
export S3_READ_WRITE_USERS='local-access=local-secret'
/tmp/s3glacier
```

This starts the HTTP server on port 8000 with a fresh temporary storage directory.
Open <http://localhost:8000/> for the web interface. Use a persistent
`DATA_FOLDER` and your own credentials for a deployment. Configuration is supplied
through environment variables; the program has no command-line configuration
flags. See the [configuration reference](docs/configuration.md) for every setting,
TLS setup, and logging behavior.

Keep the server running. In a second terminal, run the demo above, then upload and
retrieve an object:

```sh
S3_ENDPOINT=http://localhost:8000
OBJECT_ID=20261107-1200-4000-8000-000000000001
printf 'hello archive\n' > /tmp/glacier-example.txt

curl --fail-with-body -X PUT \
  "$S3_ENDPOINT/buckets/small-files/rawupload/$OBJECT_ID" \
  -H 'Authorization: Bearer local-write' \
  --data-binary @/tmp/glacier-example.txt

curl --fail-with-body \
  "$S3_ENDPOINT/buckets/small-files/get/$OBJECT_ID" \
  -H 'Authorization: Bearer local-read' \
  -o /tmp/glacier-restored.txt
cmp /tmp/glacier-example.txt /tmp/glacier-restored.txt
```

Raw uploads return an HTML result page; downloads return the original bytes.
Use a fresh UUID for each object. Recreating `small-files` returns `409 Conflict`,
so skip creation if it already exists when repeating the example.

### Run with Docker

Build the image from the checkout and keep the archive directory in a volume:

```sh
docker build -t s3glacier:local .
docker volume create s3glacier-data
docker run --rm --name s3glacier \
  -p 127.0.0.1:8000:8000 \
  --mount source=s3glacier-data,target=/files \
  -e DISK_USAGE_ALLOWED=99 \
  -e READ_TOKEN=local-read \
  -e WRITE_TOKEN=local-write \
  -e S3_READ_WRITE_USERS='local-access=local-secret' \
  s3glacier:local
```

The checked-in [Compose file](docker-compose.yml) is a separate local example:
`make all` builds and starts it with host networking, a `/files` bind mount,
`READ_TOKEN=aaaa`, `WRITE_TOKEN=bbbb`, and no S3 users. Adjust that file for your
environment before using it.

The [CI workflow](.github/workflows/ci.yml) runs vet, race tests, and a static build.
Successful pushes to `main` also publish `ghcr.io/define42/s3glacier` with `latest`,
`YYYY.MM.DD` (UTC), and `sha-<commit>` tags. Pull requests build the container
without publishing it.

## Features and specification

### Buckets and fixed archive counts

- `data` is created at startup with **256 TAR files per hour**.
- New buckets require a count from **1 to 65,536**, including non-powers of two.
- A bucket becomes active immediately. Its count cannot be changed, even while
  empty or after restart. Creating the same name again returns `409`.
- Bucket names are 3–63 lowercase letters, digits, or hyphens, with a letter or
  digit at each end. Names reserved for HTTP routes cannot be used; see the
  [API reference](docs/api.md).
- The same UUID can identify different content in different buckets. Uploading
  to a missing bucket fails; uploads never create buckets implicitly.
- Bucket update and delete APIs are unavailable.

List or inspect bucket definitions using the read token:

```sh
curl --fail-with-body http://localhost:8000/buckets \
  -H 'Authorization: Bearer local-read'
curl --fail-with-body http://localhost:8000/buckets/small-files \
  -H 'Authorization: Bearer local-read'
```

### HTTP and S3 access

| Interface | Authentication | Main operations |
| --- | --- | --- |
| HTTP management and browser routes | `READ_TOKEN` or `WRITE_TOKEN` | Create/list/inspect buckets; browse archives; upload/download objects |
| S3 routes | `S3_READ_ONLY_USERS` or `S3_READ_WRITE_USERS` | Create/list/head buckets; get bucket location; PUT/GET/HEAD objects |

HTTP tokens are single strings. Leaving one empty disables that HTTP permission
check. S3 requests always require configured signing credentials, independently
of the HTTP tokens. All credentials are server-wide; bucket separation does not
provide per-user access policies.

S3 supports Signature V4 header authentication, V4 presigned URLs, and V2
Authorization headers. Configure clients with this server's endpoint,
**path-style addressing**, service `s3`, and a signing region such as `us-east-1`.
V4 checks signatures, request times, signed payload hashes, and supported
checksums. Signed streaming uploads and signed/unsigned checksum trailers are
supported. Presigned URL expiry must be 1–604,800 seconds.

#### Supported S3 commands

The server implements this subset of the S3 API:

| S3 operation | HTTP request | Supported behavior |
| --- | --- | --- |
| `ListBuckets` | `GET /` | Lists all configured bucket names and creation dates. Does not list objects. |
| `CreateBucket` | `PUT /{bucket}` | Creates a bucket with the required signed `x-amz-meta-tar-files-per-hour` header. The count is immutable; an existing name returns `409`. |
| `HeadBucket` | `HEAD /{bucket}` | Checks whether the bucket exists and returns its TAR count header. |
| `GetBucketLocation` | `GET /{bucket}?location` | Returns an empty XML `LocationConstraint`; buckets have no assigned region. |
| `PutObject` | `PUT /{bucket}/{key}` | Appends an object and returns its MD5 `ETag`. Repeated UUIDs append additional entries rather than overwriting earlier ones. |
| `GetObject` | `GET /{bucket}/{key}` | Returns the original, decompressed bytes from the first committed matching UUID. |
| `HeadObject` | `HEAD /{bucket}/{key}` | Returns headers for the first committed matching UUID, without an object body. |

All operations require S3 authentication. `CreateBucket` and `PutObject` require
write permission; the other operations require read permission. Object keys must
contain a [supported time UUID](#object-identifiers). `GetObject` serves the full
object; byte-range and conditional requests are not implemented.

S3 bucket creation uses `PUT /{bucket}` with the required signed extension header
`x-amz-meta-tar-files-per-hour`. For the local example credentials:

```sh
curl --fail-with-body --aws-sigv4 'aws:amz:us-east-1:s3' \
  --user 'local-access:local-secret' \
  -X PUT http://localhost:8000/s3-files \
  -H 'x-amz-content-sha256: UNSIGNED-PAYLOAD' \
  -H 'x-amz-meta-tar-files-per-hour: 4'
```

Clients that cannot add this header can create buckets through the HTTP API.

#### Unsupported S3 commands and features

- `ListObjects` and `ListObjectsV2` (listing objects within a bucket).
- `DeleteBucket`, `DeleteObject`, and `DeleteObjects`.
- `CopyObject` and S3 multipart upload operations, including multipart copy.
- Object versioning and bucket/object subresources such as ACLs, policies,
  tagging, and lifecycle configuration.
- V2 presigned URLs, presigned POST policies, and temporary STS credentials.

HTTP multipart form upload is a separate supported route. S3 signed streaming
uploads are also supported, but do not provide the S3 multipart upload API.

See the [API reference](docs/api.md) for routes, curl examples, status codes,
client configuration, and signing details. The
[OpenAPI document](docs/openapi.yaml) describes the JSON bucket management API.

### Object identifiers

An object name must contain a lowercase UUID in one of these formats:

| Format | Archive hour |
| --- | --- |
| UUID v1 | Embedded UUID timestamp, converted to UTC |
| Application timestamped UUID v4, such as `20261107-1200-4000-8000-000000000001` | Date and hour from the `YYYYMMDD-HHMM` prefix, interpreted as UTC |

The timestamped v4 format requires a year from 2000 through 2099. An ordinary
random UUID v4 does not encode the required date. The first matching
UUID in a supplied name is the storage identifier; surrounding filename text does
not make a distinct object. The web interface can generate supported identifiers.
Its timestamped v4 generator uses the process's local time, so use a UTC process
timezone when those generated prefixes must represent UTC hours.

### Storage and retention

```text
DATA_FOLDER/
  .server.lock                 # One lifetime process-ownership lock
  .buckets/
    data.json
    small-files.json
  buckets/data/
    YYYY/MM/DD/HH/0000.tar
    YYYY/MM/DD/HH/0000.commit    # Durable committed boundary for that TAR
    ...                         # Up to 256 archives in an hour
    YYYY/MM/DD/HH/00ff.tar
  buckets/small-files/
    YYYY/MM/DD/HH/0000.tar
    YYYY/MM/DD/HH/0000.commit
    ...                         # Up to 4 archives in an hour
    YYYY/MM/DD/HH/0003.tar
```

A stable SHA-256 hash of the UUID modulo the saved bucket count selects the TAR
file. Readers, writers, recovery, and cleanup share an in-memory read/write lock
for the full bucket/hour/shard path. Different hours use different locks. Run
only **one server process per data root**; a lifetime `.server.lock` refuses a
second server process. This one ownership lock does not coordinate archive
operations, whose locks remain entirely in memory. Object payloads may be
compressed inside their TAR entries; the HTTP and S3 download handlers restore
the original bytes.

Object and raw TAR downloads hold their archive lock while streaming. Response
writes have a 30-second deadline, refreshed for each chunk, so stalled clients
eventually release that lock. This applies to HTTP and HTTPS and starts when the
response is written, leaving upload buffering unchanged. Downloads that keep
making progress can run longer than 30 seconds. HTML archive listings release
the lock after collecting their metadata, before sending the page.

Each TAR has a matching `.commit` checkpoint and an internal identity manifest
as its first entry.
For a new archive, uploads first persist the newly created directory chain.
They then write the complete entry and TAR footer, sync and close the TAR, write
and sync a temporary checkpoint, atomically publish it, and sync its directory.
Success is acknowledged only after all those steps succeed. Startup also confirms
the bucket-definition directory is durable before exposing loaded buckets.
Reads also confirm
the checkpoint's directory entry is durable, including after a process restart.
After an interrupted append, recovery
restores the last committed boundary and TAR footer under the exclusive lock;
readers do not expose the incomplete tail. A storage failure makes that archive
unavailable for reads and appends until the problem is fixed and the process
restarts, or cleanup durably removes the archive and its checkpoint. Restarting
alone is insufficient after an actual I/O or sync failure: repair the underlying
storage and verify or recover its durable filesystem state before restarting.
Existing TARs without this checkpoint/manifest format are rejected rather than
automatically adopted; no format migration is provided.

The configured count limits TAR files, not all filesystem entries: four TARs in
an hour also have four checkpoint files, plus short-lived files during checkpoint
publication. Browser listings hide checkpoints and the internal manifest; raw
TAR downloads retain the manifest.

Persist and back up **all of `DATA_FOLDER`**, including `.buckets` metadata and
the `.commit` files. Stop writes while taking a filesystem copy, or use a
filesystem snapshot that keeps each TAR and checkpoint consistent.
Use a local filesystem with working file/directory sync, atomic rename, and
power-safe overwrite semantics. This crash-consistency protocol does not provide
replication or protection against arbitrary storage corruption.
Do not externally mutate the managed archive tree or access it through aliases.
Do not edit bucket definitions: changing a count changes where objects resolve.
Invalid metadata prevents startup. Every bucket, including `data`, uses the
layout above; the old storage layout is not supported.

Cleanup checks filesystem usage every 10 seconds and removes whole archives in
oldest-hour order across all buckets until usage is at or below
`DISK_USAGE_ALLOWED`. Busy archives are skipped, and bucket metadata is retained.
Cleanup unlinks and syncs the TAR before removing its checkpoint; it does not
need to allocate a deletion marker when the disk is full. Orphan checkpoints are
reaped without recreating missing TAR files, including when there is no disk
pressure. The same cleanup walk collects abandoned checkpoint temporary files
and removes them under their archive's exclusive lock, skipping busy archives.
Appends and recovery validate the committed checkpoint without scanning sibling
files for temporary checkpoints; unpublished temporary files wait for cleanup.
There are no per-bucket quotas or guaranteed retention periods. The threshold
measures the filesystem containing `DATA_FOLDER`, not just this application's
files. [Extended retention](docs/configuration.md#extended-retention) is an
optional UUID convention, not a retention guarantee.

### Current limits and operations

- Upload handlers buffer a complete object in memory, including decoded V4
  streaming uploads. Account for payload and compression buffers when choosing
  object sizes and concurrency.
- Every accepted upload appends a new entry, including repeated UUIDs with the
  same or different bytes. An existing entry is never overwritten: GET and HEAD
  return the first committed match. Later duplicates consume storage and appear
  in TAR browsing and raw TAR downloads. Use a fresh UUID for each new object;
  retries after a timeout or lost response may append duplicates and are not
  idempotent.
- Reads scan the selected TAR sequentially; there is no separate object index.
- `/metrics` exposes Prometheus counters and gauges without authentication. The
  web landing page and static assets are also public; UUID helpers require the
  read token when one is configured.
- Startup prints configuration values, including credentials. Restrict access to
  process logs; see [configuration](docs/configuration.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build, test, lint, and documentation
checks. User-visible changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## Contributors

Thanks to the [project contributors](https://github.com/define42/S3Glacier/graphs/contributors).

## License

Licensed under the [Apache License 2.0](LICENSE).
