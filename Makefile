BINARY_NAME := kubectl-rbac-map
MODULE      := github.com/hrishis/kubectl-rbacmap
GO          := go
GOFLAGS     :=
LDFLAGS     :=

.PHONY: build clean fmt vet tidy install uninstall

## build: compile the binary
build: fmt vet
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

## clean: remove build artifacts
clean:
	rm -f $(BINARY_NAME)

## fmt: format Go source files
fmt:
	$(GO) fmt ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## tidy: tidy and verify module dependencies
tidy:
	$(GO) mod tidy

## install: install the binary to $GOPATH/bin (makes it available as kubectl plugin)
install: build
	cp $(BINARY_NAME) $(shell $(GO) env GOPATH)/bin/$(BINARY_NAME)

## uninstall: remove the binary from $GOPATH/bin
uninstall:
	rm -f $(shell $(GO) env GOPATH)/bin/$(BINARY_NAME)

## help: display this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
