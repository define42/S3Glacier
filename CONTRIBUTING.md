# Contributing to S3Glacier

S3Glacier is a Go application with embedded web assets. Its tests use temporary
storage and local HTTP test servers; an external S3 service is not required.

## Prerequisites and setup

- Use the Go version in [go.mod](go.mod), currently Go 1.27.3.
- Install GNU Make for the convenience targets and curl for HTTP examples.
- Race tests need a supported platform and a C compiler for Go's race runtime.
- Docker with the Compose plugin is needed only for container development.

```sh
git clone https://github.com/define42/S3Glacier.git
cd S3Glacier
go mod download
go build -o /tmp/s3glacier .
```

Use the [README quickstart](README.md#getting-started) to run the binary with a
writable storage directory. Tests bind loopback ports, so their environment must
permit local sockets.

Install a Go 1.27-compatible golangci-lint v2 build. The following version has
been validated with this project:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```

`make lint` resolves `go env GOBIN`, or the first `GOPATH` entry's `bin` directory
when `GOBIN` is empty. For another installation location:

```sh
make lint GOLANGCI_LINT=/path/to/golangci-lint
```

## Development checks

```sh
make test
make lint
go test -race -shuffle=on -count=1 -timeout=5m ./...
CGO_ENABLED=0 go build -o /tmp/s3glacier .
```

[.golangci.yml](.golangci.yml) enables `govet` and `modernize`. The
[CI workflow](.github/workflows/ci.yml) verifies modules, runs vet and race tests,
and builds a static binary. Container publication is restricted to successful
pushes to `main`.

`make modernize` applies `go fix ./...` to the working tree. Review its diff and
run the checks afterward. To inspect suggestions without editing files, run
`go fix -diff ./...`; it exits nonzero when changes are proposed. `make goadd`
runs `go mod tidy`. Include `go.mod` and `go.sum` when dependency changes need them.

## Code and documentation changes

Format changed Go files with `gofmt`. Keep changes focused and include tests for
new behavior or bug fixes. HTTP/S3 tests should exercise permissions and rejected
requests as well as successful operations. Signature changes should retain AWS
published vectors and client interoperability coverage.

Bucket definitions and archive placement are storage contracts. A bucket's count
is fixed at creation, including the `data` bucket. Explain any proposed storage
format change and its effect on existing data in the pull request.

Update the relevant documentation with behavior changes:

- [README.md](README.md): first-run examples, features, and limitations.
- [docs/configuration.md](docs/configuration.md): environment defaults and effects.
- [docs/api.md](docs/api.md): HTTP and S3 routes, authentication, responses.
- [docs/openapi.yaml](docs/openapi.yaml): JSON bucket management operations only.
- [CHANGELOG.md](CHANGELOG.md): user-visible changes under `Unreleased`.
- Go package and exported declaration comments: constraints and caller contracts.

The OpenAPI document is maintained by hand; compare it with `buckets.go` when
changing management handlers. Verify examples against a server using temporary
storage and example credentials. Do not include real credentials or captured
startup configuration logs in an issue or pull request.

Preview package documentation locally:

```sh
go doc glacier/bucket
go doc glacier/s3
go doc glacier/shared.GetBucketContainerFile
```

## Pull requests

Describe the problem, resulting behavior, and checks performed. Include concrete
request/response examples when changing an API. Note changes to storage layout,
authentication, configuration defaults, or unsupported operations. Do not include
local archive data, generated binaries, or secrets in the diff.
