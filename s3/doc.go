// Package s3 provides the archive server's path-style S3 API and request
// authentication. Register BucketHandler, ObjectHandler, and ListBuckets behind
// S3Security; callers must supply the bucket and id mux variables used by each
// resource handler.
//
// The API supports bucket creation with an immutable TAR shard count, bucket
// listing and location lookup, object PUT, GET, and HEAD, and ListObjectsV2.
// V2 listings support literal canonical-UUID prefixes, delimiters, pagination,
// URL encoding and optional owner fields. ListObjects V1, object deletion,
// replacement, multipart S3 uploads, and POST-policy uploads are not
// implemented. Raw HTTP multipart uploads are a separate application API.
//
// PUT persists x-amz-meta-* user metadata and the supported Content-Type,
// Content-Disposition, Content-Encoding, Content-Language, Cache-Control and
// Expires fields. GET and HEAD return the first committed entry's metadata.
// User metadata has a 2 KiB budget; representation fields have a separate
// 2 KiB budget. Verified V4 query metadata is accepted, with conflicting header
// values rejected. Authentication, cookies and framing headers are not stored.
//
// Listings expose original object sizes and the UUID-date LastModified used by
// HEAD, together with persisted ETags when available. Owner fields
// use the server identity "s3glacier", not per-user ownership. Continuation
// tokens bind the bucket incarnation and filter to the authenticated secret;
// they survive a restart with unchanged credentials, data root and settings.
// Pages observe committed archives without a bucket-wide snapshot. Concurrent
// uploads and retention can change subsequent pages.
//
// Authentication accepts Signature V2 authorization headers and Signature V4
// authorization headers or presigned URLs. V4 verifies payload hashes, supported
// aws-chunked signatures, and supported checksum trailers before storage writes.
// Credentials are configured globally through AddS3User, AddS3UserWrite, and
// AddS3UserReadOnly, independently of the application's HTTP read and write tokens.
//
// PreSignV2 and PostPresignSignatureV2 are retained client-side signing helpers;
// they do not imply server support for V2 presigned URLs or POST policies.
package s3
