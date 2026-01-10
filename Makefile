.PHONY: build test vet lint clean run

GO ?= go

build:
	$(GO) build -o transfer.ng .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run --out-format=github-actions --config .golangci.yml

clean:
	rm -f transfer.ng

run:
	$(GO) run main.go --provider=local --listener :8080 --temp-path=/tmp/ --basedir=/tmp/

all: vet test build
