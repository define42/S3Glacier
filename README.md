# S3 Glacier Archive Server 
S3 Glacier is essentially a storage database with high write performance and cohesive delete performance.  
  
It's design is simple (~2000 line of code) and data is simply saved into Tar archives, identified by timestamp in the UUID. 

- UUID version 1(RFC 4122) include timestamp in the UUID and is supported without any changes. 
- UUID version 4 is supported by adding a human readable timestamp(`YYYYMMDD-HHMM`) in the first two sections. 

Timestamps locate objects within an hourly folder tree (`YYYY/MM/DD/HH`).
Each bucket has a fixed maximum number of TAR archives per hour, selected when
that bucket is created. For example, a small bucket can use **4 TAR files per
hour**, while a busier bucket can use 256 or more. Archives are created on demand;
an empty hour does not create any files. Each TAR file has its own read/write lock.

The default `data` bucket uses **256 TAR files per hour** and the same storage
layout and UUID-to-archive mapping as every other bucket.

An object with Time-UUID `20211218-1036-40f1-b34f-02d7517a01d3` in `data` is stored
under `DATA_FOLDER/buckets/data/2021/12/18/10/`. A stable hash of its UUID selects
the TAR file within that hour.

Pros
- Optimized for all blob sizes (1 byte to 8GB)
- Unlimited numbers of blobs
- High write performance
- Predictable archive count: each bucket has its own fixed maximum TAR files per hour
- High delete performance, for aging-out(deletion) of old data
- Automatic age-off oldest data when storage limit is reached
- Multiple buckets with S3 Signature Version 4 and Version 2 support
- Build in prometheus support.
- Build in ACME support.
- Support object/blob compression.
- Support UUID version 4 with human readable timestamp(`YYYYMMDD-HHMM`) in the first two sections.
- Support UUID version 1 according to RFC 4122
- Built-in web-GUI with support for uploading/downloading and browsing files on disk
- Support HTTP Raw-Upload and HTTP-Multipart with multiple files

Cons
- Not possible to delete or overwrite single blob, it must age-off. (Data is frozen within the glacier)
- Only accept Time-UUID as identifiers.

Ongoing work
- Blob encryption
- Blob metadata
- Swift storage
- Multiple variants of same file

## Buckets and TAR files per hour

Create a bucket in the web interface, or use the HTTP API:

```sh
curl -X POST http://localhost:8000/buckets \
  -H "Authorization: Bearer $WRITE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"small-files","tar_files_per_hour":4}'
```

Creation returns HTTP `201`. The count is required and must be an integer from
**1 to 65,536**; it does not have to be a power of two. Bucket names must contain
3–63 lowercase letters, digits or hyphens and start and end with a letter or
digit. Names used by server endpoints (such as `files`, `buckets`, and `upload`)
are reserved.

A bucket becomes active as soon as it is created. **Its TAR count cannot be
changed**, even while empty or after restarting the server. Recreating the same
name returns `409 Conflict`; update and delete operations are unsupported. To use
a different count, create a new bucket. The built-in `data` bucket is always 256.

```sh
# List buckets and their fixed counts.
curl http://localhost:8000/buckets -H "Authorization: Bearer $READ_TOKEN"

# Inspect a bucket.
curl http://localhost:8000/buckets/small-files -H "Authorization: Bearer $READ_TOKEN"

# Upload and retrieve an object in the selected bucket.
OBJECT_ID=20261107-1200-4000-8000-000000000001
curl -X PUT "http://localhost:8000/buckets/small-files/rawupload/$OBJECT_ID" \
  -H "Authorization: Bearer $WRITE_TOKEN" --data-binary @example.bin
curl "http://localhost:8000/buckets/small-files/get/$OBJECT_ID" \
  -H "Authorization: Bearer $READ_TOKEN" -o restored.bin
```

HTTP management, raw upload, multipart upload and browser routes use the existing
`READ_TOKEN` / `WRITE_TOKEN` settings. Omit the Authorization header if the
corresponding token is not configured. S3 routes use the configured
`S3_READ_ONLY_USERS` / `S3_READ_WRITE_USERS` credentials independently. Credentials
remain server-wide: buckets isolate object names and storage, not user permissions.

The same UUID can hold different contents in different buckets. Uploads to an
unknown bucket return `404`; uploading does not implicitly create buckets.

The `/upload`, `/rawupload/{id}`, `/get/{id}` and token-bearing raw/get routes
use `data` by default. Select another bucket with `?bucket=small-files`, a
multipart `bucket` form field, or the explicit `/buckets/{bucket}/...` routes.
Browse `/buckets/small-files/files/`, or choose the bucket in the web interface.

S3 clients use `/{bucket}/{object-id}`. To create a bucket through S3, send a
signed `PUT /small-files` with the signed header
`x-amz-meta-tar-files-per-hour: 4`. This extension is required at creation;
clients that cannot add it should create the bucket through the HTTP API first.
S3 supports listing buckets (`GET /`), bucket existence (`HEAD /{bucket}`),
bucket location (`GET /{bucket}?location`), and object PUT/GET/HEAD. Object listing,
object deletion and S3 multipart upload remain unsupported and return explicit
errors.

### S3 Signature Version 4

S3 requests support AWS Signature Version 4 (`AWS4-HMAC-SHA256`) using an
Authorization header or presigned GET/PUT URLs. Signature Version 2 Authorization
headers remain supported. Both versions use the same access key and secret pairs
configured in `S3_READ_ONLY_USERS` / `S3_READ_WRITE_USERS`; read-only credentials
cannot upload objects or create buckets.

Configure clients with this server's endpoint, **path-style bucket addressing**,
the `s3` service, and a signing region such as `us-east-1`. The server accepts any
valid nonempty region in the credential scope; it does not provision regional
storage. Object keys must still contain a supported time UUID.

For example, with curl's
[`--aws-sigv4` option](https://curl.se/docs/manpage.html#--aws-sigv4), set
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to a configured read/write pair:

```sh
S3_ENDPOINT=http://localhost:8000
OBJECT_ID=20261107-1200-4000-8000-000000000001

# The fixed archive count must be supplied and signed at bucket creation.
curl --aws-sigv4 'aws:amz:us-east-1:s3' \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
  -X PUT "$S3_ENDPOINT/signed-files" \
  -H 'x-amz-content-sha256: UNSIGNED-PAYLOAD' \
  -H 'x-amz-meta-tar-files-per-hour: 4'

# Upload the object with a signed SHA-256 payload hash.
PAYLOAD_HASH=$(sha256sum example.bin | cut -d ' ' -f 1)
curl --aws-sigv4 'aws:amz:us-east-1:s3' \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
  -H "x-amz-content-sha256: $PAYLOAD_HASH" \
  --upload-file example.bin "$S3_ENDPOINT/signed-files/$OBJECT_ID"

curl --aws-sigv4 'aws:amz:us-east-1:s3' \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
  -H 'x-amz-content-sha256: UNSIGNED-PAYLOAD' \
  "$S3_ENDPOINT/signed-files/$OBJECT_ID" -o restored.bin
```

V4 validates signed payload hashes and also supports `UNSIGNED-PAYLOAD` requests.
It accepts signed `aws-chunked` uploads, including signed and unsigned checksum
trailers for CRC32, CRC32C, CRC64NVME, SHA-1, and SHA-256. Chunk framing is verified
and removed before object storage. These are single PUT uploads; S3 multipart
upload is a separate, unsupported API.

Generate presigned URLs with an S3 SDK using V4, this server's endpoint,
path-style addressing, and the configured static credentials. Use `get_object`
for downloads or `put_object` for uploads to an existing bucket, with an expiry
from **1 to 604,800 seconds**. The URL's method, host, path, query parameters, and
any signed headers must match the request sent to the server. Presigned POST
forms and temporary STS session credentials are unsupported.

The signing formats follow the AWS documentation for
[V4 header authentication](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html),
[presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html),
and [streaming uploads](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html).

### Storage and retention

Storage layout:

```text
DATA_FOLDER/
  .buckets/                         # Persistent, immutable bucket definitions
  buckets/data/
    YYYY/MM/DD/HH/0000.tar          # Up to 256 archives for this bucket/hour
    ...
    YYYY/MM/DD/HH/00ff.tar
  buckets/small-files/
    YYYY/MM/DD/HH/0000.tar          # Up to 4 archives for this bucket/hour
    YYYY/MM/DD/HH/0001.tar
    YYYY/MM/DD/HH/0002.tar
    YYYY/MM/DD/HH/0003.tar
```

All buckets use a stable hash of the UUID modulo the saved count. Definitions
and objects both live under `DATA_FOLDER`, so persist and back up that entire
directory. Do not edit or remove `.buckets` definitions: they determine where
objects can be found. An invalid definition prevents startup. Every bucket,
including `data`, stores its archives under `DATA_FOLDER/buckets/{name}/`.

Disk-pressure cleanup applies the existing shared `DISK_USAGE_ALLOWED` threshold
and removes the oldest archives across **all** buckets by hour, regardless of
bucket name. It preserves bucket definitions, so an emptied bucket keeps its
original count. There are no per-bucket capacity quotas or retention policies.

## Development checks

Use the Go version specified in `go.mod`. Linting requires a Go 1.27-compatible
golangci-lint v2 build (validated with v2.15.0).
`make lint` finds the binary in `go env GOBIN`, falling back to the first
`GOPATH` entry's `bin` directory. Override it with
`make lint GOLANGCI_LINT=/path/to/golangci-lint` when needed.

```sh
make test       # Run the Go test suite.
make lint       # Run vet and modernization checks from .golangci.yml.
make modernize  # Apply the Go toolchain's suggested code updates.
```

## Build and container images

GitHub Actions runs tests with race detection, vets the code, and builds the binary
and Docker image for pull requests to `main` and pushes to `main`. The Go version
is read from `go.mod`.

After successful checks on `main`, the workflow publishes
`ghcr.io/define42/s3glacier` with `latest`, `YYYY.MM.DD` (UTC), and `sha-<commit>`
tags. Pull requests build the image without publishing it. Publishing uses the
repository's automatic `GITHUB_TOKEN` with `packages: write`; no Docker Hub
credentials are required.

```sh
docker pull ghcr.io/define42/s3glacier:latest
```

## Example RawUpload
```
POST /rawupload/[[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}]
```

## Example Download/Get
```
GET /get/[[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}]
```

## Example Multipart Upload with multiple files
```
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=---------------------------273754160213256655563977755994

-----------------------------273754160213256655563977755994
Content-Disposition: form-data; name="file"; filename="20221102-1326-4897-aeed-aaaaaaaaaaaa"
Content-Type: application/octet-stream

test

-----------------------------273754160213256655563977755994
Content-Disposition: form-data; name="file"; filename="20221102-1326-4897-aeed-bbbbbbbbbbbb"
Content-Type: application/octet-stream

test

-----------------------------273754160213256655563977755994
Content-Disposition: form-data; name="file"; filename="20221102-1326-4897-aeed-cccccccccccc"
Content-Type: application/octet-stream

test

-----------------------------273754160213256655563977755994--
```
