// Package main implements the S3 Glacier Archive Server executable.
//
// The executable reads its settings from environment variables, serves the
// embedded browser interface and HTTP/S3 APIs, and runs disk-pressure cleanup
// and filesystem metrics collection. Bucket definitions and TAR archives are
// persisted beneath DATA_FOLDER; TLS certificate state uses a separate path.
//
// NewServer constructs the router without starting listeners or background
// jobs. The main function starts those jobs and chooses plain HTTP or ACME TLS
// according to SERVER_DOMAIN and ACME_SERVER. Configuration details are in
// docs/configuration.md; the executable does not implement command-line flags.
package main
