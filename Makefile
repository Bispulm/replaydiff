.PHONY: build test race lint vuln secrets check

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
