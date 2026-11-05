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

# Capture and replay through the Helm chart on a kind cluster named replaydiff-dev. Needs
# Docker, kind, kubectl and helm. KEEP=1 keeps the cluster for the next run.
.PHONY: kind-test
kind-test:
	REPLAYDIFF_KIND=1 REPLAYDIFF_KIND_KEEP=$(KEEP) go test -count=1 -timeout 30m -v ./test/kind/

# Go benchmarks of proxying, redaction, encoding and comparison, with allocations.
.PHONY: bench
bench:
	go test -run '^$$' -bench . -benchmem -count 5 ./internal/...

# Measures capture and replay against the targets in docs/benchmarks.md. Takes about ten
# minutes and loads the machine, so run it with nothing else heavy going on.
.PHONY: bench-harness
bench-harness: build
	bin/replaydiff-bench --capture bin/replaydiff --out .bench

# The local stack in compose.yaml. See docs/deployment.md#compose.
.PHONY: compose-up compose-down
compose-up:
	docker compose up --build --detach
compose-down:
	docker compose down --volumes
