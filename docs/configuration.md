# Configuration

The server reads process environment variables. It does not load configuration
files or implement command-line flags. Defaults apply only when a variable is
**unset**: setting a variable to an empty string overrides its default. Values
are not trimmed or expanded by the application. For example, quote a path in the
shell rather than placing literal quote characters in its value.

Most settings are loaded when the router is initialized. `DISK_USAGE_ALLOWED` is
read earlier, during package initialization. Set the environment before starting
the process and restart the server to apply changes; there is no reload endpoint.

Startup prints the current settings, including HTTP tokens and S3 secret keys,
to standard output. Treat these logs as sensitive and restrict access to them.

## Environment variables

| Variable | Default when unset | Meaning and empty-value behavior |
| --- | --- | --- |
| `DATA_FOLDER` | `/files` | Root for persisted bucket definitions, TAR archives, and their `.commit` checkpoints. It must be writable and owned by one serving process; missing directories are created. An empty value causes startup to fail. Relative paths are resolved against the process's working directory. |
| `SERVER_PORT` | `8000` | Plain HTTP listen port on all interfaces. Used when ACME mode is inactive. An empty value does not restore `8000`: the application passes the bind address `:` to the HTTP server. Use an explicit port. |
| `DISK_USAGE_ALLOWED` | `75` | Maximum target usage percentage for the filesystem containing `DATA_FOLDER`, shared by all buckets. Accepts a finite number from `5` through `99`, inclusive. Empty, unparseable, or out-of-range values use `75`. |
| `EXTEND_LIFE_SUPPORT` | `false` | Only the exact string `true` enables UUIDv4 month-offset interpretation. Empty and all other strings leave it disabled. See [extended retention](#extended-retention). |
| `READ_TOKEN` | empty | One literal token protecting HTTP reads, bucket listing/inspection, UUID helpers, archive browsing, and redirects. Empty disables that HTTP token check. It is not a list. |
| `WRITE_TOKEN` | empty | One literal token protecting HTTP bucket creation and object uploads. Empty disables that HTTP token check. It is not a list. |
| `S3_READ_ONLY_USERS` | empty | Semicolon-separated `access-key=secret-key` pairs with S3 read access to all buckets. Empty configures no accounts from this list. |
| `S3_READ_WRITE_USERS` | empty | Semicolon-separated `access-key=secret-key` pairs with S3 read and write access to all buckets. Empty configures no accounts from this list. |
| `SERVER_DOMAIN` | empty | The single hostname for ACME certificate management. ACME mode requires both this and `ACME_SERVER` to be nonempty. Empty selects plain HTTP even if an ACME server is configured. |
| `ACME_SERVER` | empty | ACME directory URL used for certificate issuance. ACME mode requires both this and `SERVER_DOMAIN` to be nonempty. Empty selects plain HTTP even if a domain is configured. |

Invalid settings are not uniformly rejected at startup. The settings registry
keeps raw strings; consumers interpret them. In particular, the displayed disk
threshold can differ from the effective `75` fallback after an invalid value.
The application does not support environment variables for per-bucket quotas,
minimum retention, maximum object size, or a listen-host override.

For a locally built binary, use a data directory owned by the current user:

```sh
DATA_FOLDER="$PWD/data" \
SERVER_PORT=8000 \
DISK_USAGE_ALLOWED=75 \
READ_TOKEN='replace-with-read-token' \
WRITE_TOKEN='replace-with-write-token' \
S3_READ_ONLY_USERS='reader=replace-with-reader-secret' \
S3_READ_WRITE_USERS='writer=replace-with-writer-secret' \
./s3glacier
```

The HTTP tokens and S3 credentials in this example are separate credentials;
replace the placeholder values before use.

## HTTP tokens and S3 credentials

HTTP management, raw upload, multipart upload, browser helpers, and object
retrieval use `READ_TOKEN` or `WRITE_TOKEN` according to the operation. Each is a
single, exact string. A semicolon inside either token is a literal character,
despite the startup table's short token description.

For token-protected HTTP API calls, prefer:

```sh
curl http://localhost:8000/buckets \
  -H "Authorization: Bearer $READ_TOKEN"
```

The HTTP credential lookup order is:

1. `Authorization: Bearer <token>`.
2. A token in a route that defines a token path parameter.
3. A nonempty `token` query parameter.
4. A `token` form field after the handler has parsed the form.

A higher-priority credential is not replaced just because it is incorrect. The
browser interface submits the write token for uploads and a separate read token
for the resulting download links. Tokens in links can appear in browser history
and access logs.

S3 requests use their configured static access-key/secret-key pairs independently
of HTTP tokens. S3 always requires authentication, including when both HTTP tokens
are empty. Signature Version 4 headers and presigned GET/PUT/HEAD URLs are
supported; Signature Version 2 supports Authorization headers. Temporary session
credentials are unsupported. See the [API reference](api.md) for protocol details.

S3 credential entries are separated with `;`, for example:

```sh
S3_READ_ONLY_USERS='reader-one=secret-one;reader-two=secret-two'
S3_READ_WRITE_USERS='writer-one=secret-three'
```

Surrounding whitespace is trimmed from each complete entry. Entries without an
`=` or with an empty key or secret are ignored. Avoid duplicate access keys:
write accounts load first and read-only accounts load afterward, so a matching
read-only entry replaces that key's secret and write permission. All credentials
are server-wide; buckets do not provide separate user permissions.

The unsigned browser home page, embedded static assets, and `/metrics` endpoint
are not protected by these token settings. Archive browsing is protected by the
read token when one is configured.

## Storage and cleanup

Persist the entire `DATA_FOLDER`, including hidden files:

```text
DATA_FOLDER/
  .server.lock                      # Held for the standalone process lifetime
  .buckets/                         # Immutable definitions and configuration lock
  buckets/data/YYYY/MM/DD/HH/0000.tar
  buckets/data/YYYY/MM/DD/HH/0000.commit
  buckets/example/YYYY/MM/DD/HH/0000.tar
  buckets/example/YYYY/MM/DD/HH/0000.commit
```

Every bucket, including `data`, uses this layout. Definitions record each
bucket's fixed TAR files per hour; editing or removing them can prevent startup
or make object paths inconsistent. Archive files are created on demand. Each TAR
contains an internal identity manifest and has a matching `.commit` file recording
its durable committed boundary. The fixed count applies to TAR files; checkpoints
add one persistent file per TAR, plus transient checkpoint-publication files.
Back up the definitions, archive tree, and checkpoints as a consistent snapshot,
or stop writes before copying them.

Only one server process may serve a `DATA_FOLDER`; the standalone server holds
one lifetime `.server.lock` and refuses a second process using that root. This
ownership guard is separate from archive synchronization and does not add lock
files to each archive. The archive lock registry is
in memory and keyed by the full bucket/hour/shard path; different hours do not
share a lock, and other processes do not participate in these locks. Idle lock
entries are released after their holders and waiters finish. Existing TARs without
the checkpoint/manifest format are rejected; there is no automatic adoption or
migration of older archives.

Object and raw TAR responses keep their archive read lock while streaming.
HTTP and HTTPS response writes have a 30-second deadline, refreshed before each
chunk of at most 32 KiB and before flushing. The deadline starts with response
output, so receiving and buffering an upload does not consume its write window.
There is no fixed maximum download duration: successive writes refresh the
deadline. A blocked write times out and releases the archive lock when the
handler returns. HTML archive listings release the lock before rendering their
already collected metadata.

Before creating a new archive, the server creates and syncs its directory chain,
including the parents needed to persist newly created directories. Before an
upload is acknowledged, the server writes the entry and TAR footer, syncs and
closes the TAR, writes and syncs a new checkpoint, atomically publishes it, and
syncs its directory. Startup confirms the bucket-definition directory is durable
before exposing loaded buckets, including after interrupted publication. Reads confirm
directory durability before exposing existing state, including after a process
restart. Recovery runs under the exclusive archive lock and restores the committed
boundary and footer before serving the archive. If a storage write or sync fails, that archive is
quarantined for reads and appends. Restarting alone is insufficient after an
actual I/O or sync failure: repair the storage and verify or recover its durable
filesystem state before restarting the server. Pressure cleanup may still
durably remove a quarantined archive and its
checkpoint, allowing a later write to create a fresh generation.

Every accepted upload appends an entry, including repeated UUIDs. Existing entries
are never overwritten; GET and HEAD return the first committed match. Later
duplicates consume storage and remain visible in TAR browsing and raw exports.
Retrying after a lost response may create duplicates; uploads are not idempotent.

The supported storage target is a local filesystem that honors file and directory
sync, atomic rename, and power-safe overwrite semantics. Checkpoints establish
crash-consistent visibility, not replication or protection against arbitrary media
corruption. Network-shared data roots and multiple serving processes are unsupported.
External mutation of the managed archive tree and access through aliases are unsupported.

`DISK_USAGE_ALLOWED` measures **the whole filesystem** containing `DATA_FOLDER`,
not just this server's archive bytes. Cleanup runs once at startup and then about
every ten seconds. When usage exceeds the threshold, it removes eligible TAR
archives by resolved folder hour across all buckets and rechecks usage before
each deletion. Archives with busy locks are skipped. Deletion syncs removal of
the TAR before removing its checkpoint, without allocating a deletion marker.
Orphan checkpoints do not count toward the data-window metric and are reaped
without recreating their missing TARs. The same tree walk collects interrupted
checkpoint temporary files and batches their removal per archive under its
exclusive lock, syncing the directory after removal. Busy archives wait for a
later pass. Appends and recovery do not rescan the hour directory for temporary
files; committed checkpoints remain the recovery authority. This metadata
cleanup also runs below the disk-pressure threshold. Bucket
definitions remain in place, so an
emptied bucket retains its original configuration.

This is pressure-based eviction with no guaranteed minimum retention period.
Unrelated data on the same filesystem can trigger eviction, and the cleanup loop
can remove a recently uploaded object whose UUID resolves to an old hour. Disk
measurement or traversal errors stop that cleanup pass; they do not establish a
storage guarantee. No per-bucket capacity quota is enforced.

### Extended retention

`EXTEND_LIFE_SUPPORT=true` changes the folder date for flagged UUIDv4 identifiers.
It does not affect UUIDv1. The last two hexadecimal characters of the second UUID
group are interpreted as one byte: its high bit (`0x80`) enables an offset, and
the remaining seven bits specify **0–127 calendar months** added to the date.
The hour is preserved. Month-end dates follow Go's `time.AddDate` normalization,
so a date can roll into the following month.

For example, `20261107-1081-40f1-b34f-02d7517a01d3` uses hour `10` and offset byte
`0x81`. With the flag enabled, its folder is `2026/12/07/10`; with the flag
disabled, its folder is `2026/11/07/10`. The built-in UUID generator uses ordinary
decimal minutes `00`–`59` and does not set the extension bit.

Keep this setting consistent for writes and subsequent reads. Changing it can
change where an existing flagged UUID is looked up. A future folder date changes
cleanup ordering; it does not prevent eviction when the filesystem is full.

## ACME HTTPS mode

The stock executable enables ACME only when both `SERVER_DOMAIN` and
`ACME_SERVER` are nonempty. It obtains a certificate for that one domain, listens
on **TCP 80 and 443**, serves challenges and redirects on port 80, and serves the
application on port 443. `SERVER_PORT` is unused in this mode. The hostname must
resolve to the service and the ACME server must be able to complete its supported
challenge; there is no environment setting for alternative challenge ports.

ACME uses paths outside `DATA_FOLDER`:

| Path | Purpose |
| --- | --- |
| `/data/acme/` | Writable certificate/account state. Persist this directory between restarts. |
| `/data/ca/` | Optional additional certificate PEM bundles trusted when contacting the ACME server. An unreadable directory is ignored; every entry in a readable directory must parse as a certificate bundle. |
| `/etc/ssl/certs/ca-certificates.crt` | Required system CA bundle, included in the container image. Failure to load it terminates startup in ACME mode. |

Invalid extra CA files cause a panic during startup. Each decoded PEM block must
have type `CERTIFICATE` and contain a valid X.509 certificate. This directory is
for CA trust when contacting the issuer, rather than a place to provide the
server's private key. The ACME library manages issued certificates in
`/data/acme/`.

## Container Compose example

The checked-in [`docker-compose.yml`](../docker-compose.yml) uses host networking,
bind-mounts `/files/` to `/files/`, and sets these overrides:

```yaml
DISK_USAGE_ALLOWED: 99
READ_TOKEN: aaaa
WRITE_TOKEN: bbbb
```

Those are example credentials and a `99` percent disk threshold, not the defaults
in the binary. Replace them for your deployment. The file does not configure S3
accounts, ACME, or ACME persistence volumes. It uses the default plain HTTP port
`8000` through host networking.

## Metrics

The service exposes Prometheus metrics at `/metrics`:

| Metric | Meaning |
| --- | --- |
| `rawupload_processed_total` | Upload attempts admitted by HTTP/S3 handlers; multipart requests count per file. |
| `rawupload_processed_total_done` | Durably committed upload entries, including repeated UUIDs. |
| `disk_free` | Free bytes on the filesystem containing `DATA_FOLDER`. |
| `disk_used_percent` | Used percentage on that filesystem. |
| `tar_files_open` | Active archive append calls, including lock waits and recovery; excludes readers and compression. |
| `current_data_window_in_hours` | Age of the oldest retained archive folder across buckets; zero for no archives or future-only timestamps. |

Filesystem capacity gauges update about once per second. The retained-window
gauge updates with cleanup passes. A disk-stat failure leaves the capacity gauges
at their last recorded values. Both upload counters include repeated UUIDs;
in-flight attempts need not yet have matching completions. A successful archive
write counter is not a guarantee of replication or a checksum audit of all
previously stored objects.

Implementation references: [`config/settings.go`](../config/settings.go),
[`main.go`](../main.go), [`acme.go`](../acme.go),
[`autoclean/autoclean.go`](../autoclean/autoclean.go), and
[`prometheus/prometheus.go`](../prometheus/prometheus.go).
