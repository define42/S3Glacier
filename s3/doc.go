// Package s3 provides the archive server's path-style S3 API and request
// authentication. Register BucketHandler, ObjectHandler, and ListBuckets behind
// S3Security; callers must supply the bucket and id mux variables used by each
// resource handler.
//
// The API supports bucket creation with an immutable TAR shard count, bucket
// listing and location lookup, and object PUT, GET, and HEAD. Object listing,
// deletion, replacement, multipart S3 uploads, and POST-policy uploads are not
// implemented. Raw HTTP multipart uploads are a separate application API.
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
