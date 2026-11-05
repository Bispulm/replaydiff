.PHONY: build test race lint vuln secrets check proto

build:
	go build -o bin/ ./cmd/...

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

secrets:
	gitleaks git --no-banner --redact .

check: lint race vuln secrets

.PHONY: demo gate-demo
demo:
	./scripts/demo.sh

gate-demo:
	./scripts/gate-demo.sh

# Regenerates the fixture's descriptor set. Needs protoc.
proto:
	protoc --proto_path=internal/fixture/proto --include_imports \
		--descriptor_set_out=internal/fixture/proto/orders.binpb orders.proto

# Builds the container image with both binaries. IMAGE and VERSION can be overridden.
IMAGE ?= replaydiff:dev
VERSION ?= dev
.PHONY: image
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .
