.PHONY: all test goadd lint modernize

GO_BIN_DIR = $(or $(shell go env GOBIN),$(firstword $(subst :, ,$(shell go env GOPATH)))/bin)
GOLANGCI_LINT ?= $(GO_BIN_DIR)/golangci-lint

all:
	docker compose build
	docker compose up

test:
	go test -tags=integration ./...

lint:
	"$(GOLANGCI_LINT)" run ./...

modernize:
	go fix ./...

goadd:
	go mod tidy

