# HTTP and S3 API

The server exposes a token-authenticated HTTP API and a path-style S3 subset. Both use the same buckets and objects. See [configuration](configuration.md) for server settings and [the README](../README.md) for setup. The [OpenAPI document](openapi.yaml) covers only the JSON bucket management endpoints.

## Authentication

| API | Read access | Write access |
| --- | --- | --- |
| HTTP management, uploads, downloads, UUID helpers, archive browser | `READ_TOKEN` | `WRITE_TOKEN` |
| S3 | Accounts in `S3_READ_ONLY_USERS` or `S3_READ_WRITE_USERS` | Accounts in `S3_READ_WRITE_USERS` |

HTTP tokens and S3 access keys are independent. S3 requests do not need HTTP API tokens. Configured S3 accounts apply to all buckets; there are no per-bucket account permissions.

For HTTP requests, send `Authorization: Bearer <token>`. Existing alternatives are the `token` query parameter, the token segment in `/get/{token}/{id}` or `/rawupload/{token}/{id}`, and the `token` field of a multipart upload. Precedence is bearer header, path token, query token, then parsed form token. Tokens are single literal strings. An empty `READ_TOKEN` or `WRITE_TOKEN` disables that HTTP permission check; S3 authentication is still required. Query and form tokens can appear in generated browser links.

The unsigned home page, static assets, and `/metrics` are accessible without these tokens. S3 signing never authorizes the JSON management endpoints.

## Buckets and object IDs

The server creates `data` with 256 TAR files per hour. A new bucket requires a name and an explicit `tar_files_per_hour` integer from 1 through 65,536; non-power-of-two counts such as 7 are supported. The count is fixed for that bucket's lifetime. Recreating an existing bucket returns `409`, even if the requested count is unchanged. Buckets cannot be renamed, reconfigured, or deleted through either API.

Names contain 3–63 lowercase letters, digits, or hyphens, with a letter or digit at each end. Reserved names are `api`, `buckets`, `files`, `get`, `metrics`, `rawupload`, `redirect`, `static`, `upload`, and `uuid`.

Object IDs must contain a lowercase timestamped version 4 UUID such as `20261107-1200-4000-8000-000000000001`. Use `/uuid` to generate one. The UUID is extracted from a filename or ID containing it; downloads address that extracted UUID. S3 object keys are a single path segment, rather than arbitrary S3 key hierarchies.

Use a fresh UUID for each different object. Every accepted upload appends an entry, including repeated UUIDs with identical or different bytes. Existing entries are never overwritten: HTTP and S3 GET/HEAD return the first committed match for the extracted UUID in that bucket. Later duplicates consume storage and appear in TAR browsing and raw TAR downloads. Object uploads do not reject duplicates with `409` and are not idempotent. Single-object deletion is unavailable; automatic cleanup removes whole archive files. See [storage and retention](../README.md#storage-and-retention) for the on-disk layout and retention behavior.

## JSON bucket management

Successful responses use `application/json`. A bucket has this shape; filesystem paths are omitted:

```json
{
  "name": "logs",
  "tar_files_per_hour": 4,
  "created_at": "2026-11-07T12:00:00Z"
}
```

| Method and path | Permission | Result |
| --- | --- | --- |
| `GET /buckets` | Read | `200`, array of buckets sorted by name. |
| `POST /buckets` | Write | `201`, created bucket and `Location: /buckets/{name}`. |
| `GET /buckets/{bucket}` | Read | `200`, bucket configuration. |
| `HEAD /buckets/{bucket}` | Read | `200` if the bucket exists, with no response body. |

Creation accepts exactly one JSON object containing `name` and `tar_files_per_hour`. Unknown fields are rejected. The body limit is 16 KiB; malformed or oversized bodies return `400`. A missing count becomes zero and is rejected. Unsupported methods return `405` with an `Allow` header. There are no update or delete operations.

The following examples use `curl` and `jq` with the README quickstart credentials. Match the tokens to your server's configuration if you changed them:

```sh
BASE=http://localhost:8000
READ_TOKEN=local-read
WRITE_TOKEN=local-write

curl --fail-with-body -H "Authorization: Bearer $WRITE_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"name":"logs","tar_files_per_hour":4}' "$BASE/buckets"

curl --fail-with-body -H "Authorization: Bearer $READ_TOKEN" "$BASE/buckets"
curl --fail-with-body -H "Authorization: Bearer $READ_TOKEN" "$BASE/buckets/logs"
```

## HTTP object operations

These operations use existing buckets. An upload does not create its bucket.

| Method and path | Permission | Result |
| --- | --- | --- |
| `POST` or `PUT /buckets/{bucket}/rawupload/{id}` | Write | Stores the raw request body; `200` HTML with object links. |
| `POST /buckets/{bucket}/upload` | Write | Accepts multipart files named `file`; `200` HTML with object links. |
| `GET /buckets/{bucket}/get/{id}` | Read | Returns the object bytes and detected content type. |
| `HEAD /buckets/{bucket}/get/{id}` | Read | Checks the actual object and returns headers without its body. |

Unscoped `/rawupload/{id}`, `/upload`, and `/get/{id}` use `data`, or a selected bucket from `?bucket=logs`. Multipart uploads also accept a `bucket` form field. A bucket in the path takes precedence over query and form selection. The token-in-path raw and download routes follow the same selection rules.

Raw upload and download:

```sh
object_id=$(curl --fail-with-body -sS \
  -H "Authorization: Bearer $READ_TOKEN" "$BASE/uuid?bucket=logs" | jq -r .Uuid)

printf 'archive example\n' | curl --fail-with-body \
  -H "Authorization: Bearer $WRITE_TOKEN" --data-binary @- \
  "$BASE/buckets/logs/rawupload/$object_id"

curl --fail-with-body -H "Authorization: Bearer $READ_TOKEN" \
  "$BASE/buckets/logs/get/$object_id" --output downloaded.txt

curl --fail-with-body --head -H "Authorization: Bearer $READ_TOKEN" \
  "$BASE/buckets/logs/get/$object_id"
```

For multipart uploads, filenames normally supply the IDs. Set a nonempty `newuuid` query parameter to generate a new ID for each file instead:

```sh
printf 'archive example\n' > report.txt
printf '{"event":"example"}\n' > events.json

curl --fail-with-body -H "Authorization: Bearer $WRITE_TOKEN" \
  -F 'file=@report.txt' -F 'file=@events.json' \
  "$BASE/buckets/logs/upload?newuuid=1"
```

A `read_token` multipart field is used only to construct the resulting download links. It does not grant upload permission. Multiple files are saved sequentially; if a later file fails, earlier uploads remain saved.

Uploads are buffered before archive writes. The multipart parser's 32 MiB in-memory threshold is not an overall request-size limit. There is no resumable upload API.

Success is acknowledged only after the TAR contents and committed-boundary checkpoint are synced. An interrupted append is rolled back to that boundary before the archive is read or written again. A timeout or lost response can leave the client uncertain whether a write committed. Retrying always appends another entry if accepted, even with the same UUID and bytes, so the archive may contain duplicates. `newuuid` uploads generate fresh IDs for every request; neither mode provides idempotent retries.

Downloads decompress stored objects automatically. `Content-Length` describes the decoded object when no parser is requested. `?parse=avro` converts Avro object-container data to JSON; it is an application extension, not an S3 operation. Range requests and conditional GET handling are not implemented.

## UUID helpers and archive browsing

| Method and path | Permission | Result |
| --- | --- | --- |
| `GET /uuid` | Read | A timestamped version 4 UUID and its resolved archive. |
| `GET /redirect?file={id}` | Read | `303` redirect to a bucket-scoped object download. |
| `GET` or `HEAD /buckets/{bucket}/files/{path}` | Read | HTML directory or TAR contents view; `?download=1` downloads a TAR file. |
| `GET /buckets/{bucket}/files` | None on the redirect itself | `307` redirect to the trailing-slash browser path, where read authorization applies. |
| `GET` or `HEAD /files/{path}` | Read | The same browser for `data`, or `?bucket={name}`. |

UUID helpers and redirects accept `?bucket={name}`. UUID responses use the field names `Uuid`, `ContainerFile`, `Bucket`, and `TarFilesPerHour`. `ContainerFile` is a server filesystem path, not a download URL.

Browser paths are dated directories such as `2026/11/07/12/` or a TAR filename within an hour. TAR pages show committed user-object entries and offer a raw archive link. Checkpoint files and the internal archive manifest are hidden from these listings. Add `?download=1` to an existing TAR path to receive an `application/x-tar` attachment, including the manifest, under the same read authorization and archive lock. Configuration directories and symlink paths are excluded. A busy archive can return `503` with `Retry-After: 1`. Archives in an unsupported or unrecoverable checkpoint format fail rather than exposing uncommitted bytes.

HTML TAR listings release the archive lock after collecting their rows and before
rendering the response. Object and raw TAR downloads retain the lock while
streaming. Response writes have a 30-second deadline refreshed as chunks are
sent, so a stalled client eventually releases the shard. This is a per-write
limit, not a maximum duration for a progressing download, and does not limit the
time spent buffering an upload before its response starts.

```sh
curl --fail-with-body -H "Authorization: Bearer $READ_TOKEN" \
  "$BASE/buckets/logs/files/"
```

## S3 operations

Use path-style URLs, static access keys from the S3 settings, and a signing region such as `us-east-1`. The server does not assign buckets a region and accepts a nonempty region in an otherwise valid S3 credential scope.

| Method and path | Permission | Result |
| --- | --- | --- |
| Signed `GET /` | Read | `200` XML `ListAllMyBucketsResult`, including bucket names and creation dates. Unsigned `GET /` serves the browser UI. |
| `PUT /{bucket}` or `PUT /{bucket}/` | Write | `200`, creates the bucket. Requires `X-Amz-Meta-Tar-Files-Per-Hour`. |
| `HEAD /{bucket}` | Read | `200` for an existing bucket; response includes its TAR count header. |
| `GET /{bucket}?location` | Read | `200`, empty XML `LocationConstraint` and TAR count header. |
| `PUT /{bucket}/{id}` | Write | `200`, appends an object entry and returns a quoted MD5 `ETag` for the uploaded bytes. |
| `GET /{bucket}/{id}` | Read | `200`, decoded bytes from the first committed match. |
| `HEAD /{bucket}/{id}` | Read | `200` and headers from the first committed match, with no body. |

The creation header must appear exactly once with an integer count and must be included in the signature. The same header is returned by successful bucket creation, inspection, and location lookup. Existing buckets return `409 BucketAlreadyOwnedByYou`; a new count never changes their layout. Supplying the count only as a query parameter or standard S3 `CreateBucketConfiguration` XML does not replace this header requirement. Generic SDK bucket creation therefore needs a way to add and sign this custom header; creating a bucket through the JSON API is another option.

For a `curl` build with `--aws-sigv4`, the signing inputs are:

```sh
S3_ACCESS_KEY=local-access
S3_SECRET_KEY=local-secret

curl --fail-with-body --aws-sigv4 'aws:amz:us-east-1:s3' \
  --user "$S3_ACCESS_KEY:$S3_SECRET_KEY" --request PUT \
  -H 'X-Amz-Meta-Tar-Files-Per-Hour: 4' "$BASE/s3-logs"

curl --fail-with-body --aws-sigv4 'aws:amz:us-east-1:s3' \
  --user "$S3_ACCESS_KEY:$S3_SECRET_KEY" --request PUT \
  --data-binary @report.txt "$BASE/s3-logs/$object_id"

curl --fail-with-body --aws-sigv4 'aws:amz:us-east-1:s3' \
  --user "$S3_ACCESS_KEY:$S3_SECRET_KEY" \
  "$BASE/s3-logs/$object_id" --output downloaded-s3.txt

curl --fail-with-body --aws-sigv4 'aws:amz:us-east-1:s3' \
  --user "$S3_ACCESS_KEY:$S3_SECRET_KEY" "$BASE/"
```

Bucket listing is supported; object listing is not. `GET /{bucket}` and ListObjects/ListObjectsV2 requests return `501`. S3 multipart operations (`uploads`, `uploadId`, `partNumber`), object versioning, ACLs, and other subresources are unsupported. Unsupported methods, including `DELETE`, return `405`; unsupported query subresources return `501`. The signed SDK `x-id` annotation is accepted but does not choose the operation.

### Signature modes and integrity

| Authentication | Supported behavior |
| --- | --- |
| Signature V2 | `Authorization: AWS <access-key>:<signature>` headers using configured static keys. |
| Signature V4 headers | `AWS4-HMAC-SHA256`, service `s3`, matching credential/date scope, and a timestamp within 15 minutes of server time. |
| Signature V4 presigned URLs | Query authentication with expiry from 1 to 604,800 seconds; expired requests and dates over 15 minutes in the future are rejected. |

Header and query authentication cannot be combined. Duplicate authentication fields are rejected. Session/STS tokens are not supported. V2 presigned URLs and S3 POST policies are not server authentication modes, even though the package retains V2 client signing helpers. V2 does not provide the V4 timestamp and payload-verification checks.

V4 requires signed `host` and all supplied `x-amz-*` headers except `x-amz-content-sha256`, whose value is already bound as the canonical payload hash. A supplied `Content-MD5` header must also be signed. Do not change the host, path, query, or signed headers after signing.

Supported V4 payload modes are:

- A lowercase hexadecimal SHA-256 digest: the decoded body must match.
- `UNSIGNED-PAYLOAD`: no SHA-256 body digest is required by the signature.
- `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: signed `aws-chunked` chunks.
- `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`: signed chunks and signed checksum trailers.
- `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: unsigned chunk framing with verified checksum trailers.

An absent payload hash defaults to `UNSIGNED-PAYLOAD`, including standalone MinIO signer requests. V4 presigned requests can supply `X-Amz-Content-Sha256` in the signed query; if also supplied as a header, the values must match. GET and HEAD do not accept bodies. Streaming modes require `Content-Encoding: aws-chunked` and `X-Amz-Decoded-Content-Length`; trailer modes also declare their checksum fields with `X-Amz-Trailer`.

V4 validates supplied CRC32, CRC32C, CRC64NVME, SHA-1, and SHA-256 checksums in `x-amz-checksum-*` headers, signed query parameters, or supported trailers. Checksum values are base64 encoded. Header/query conflicts, duplicate checksum values, unknown checksum fields, mismatches, and malformed framing are rejected before archive writes. Recognized SDK checksum annotation parameters are accepted after verification. Object PUT also validates a supplied `Content-MD5` header. Checksum validation does not imply that the server implements S3 checksum metadata retrieval or returns checksum headers on downloads.

## Errors

The HTTP management and application endpoints return plain-text errors, even when successful responses are JSON or HTML. Common statuses are `400` for invalid input, `403` for a missing or incorrect configured token, `404` for a missing bucket/object, `409` for an existing bucket, `405` for an unsupported method, `503` for a busy or quarantined archive, and `500` for other storage or recovery failures.

S3 failures use `application/xml` with `Code`, `Message`, and `Resource`, for example:

```xml
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The bucket does not exist.</Message>
  <Resource>/missing/object-id</Resource>
</Error>
```

Common S3 codes include `AccessDenied`, `InvalidAccessKeyId`, `SignatureDoesNotMatch`, `RequestTimeTooSkewed`, `InvalidToken`, `InvalidArgument`, `InvalidBucketName`, `NoSuchBucket`, `NoSuchKey`, `BucketAlreadyOwnedByYou`, `BadDigest`, `SlowDown`, `ServiceUnavailable`, and `NotImplemented`. Recreating an existing bucket returns `409 BucketAlreadyOwnedByYou`; repeated object UUIDs append another entry. HEAD responses do not carry error bodies; use their status code. Neither API returns a JSON error envelope.
