// Package shared resolves timestamped UUIDv4 IDs into bucket archives and
// provides object IO shared by the HTTP and S3 handlers. Storage functions expect
// callers to authorize access; the token helpers apply only to the HTTP and
// browser APIs.
//
// Objects are appended to hourly TAR files. Shard selection hashes the UUID
// bytes with SHA-256 and reduces the first eight digest bytes, interpreted as a
// big-endian integer, modulo the bucket's immutable archive count.
package shared
