## ═══════════════════════════════════════════════════════════
## KitSentinel — Makefile
## ═══════════════════════════════════════════════════════════

BINARY      := kitsentinel
VERSION     := 1.0.0
BUILD_DIR   := ./build
MAIN        := ./cmd/kitsentinel/main.go
MODULE      := github.com/kitsentinel/cli

LDFLAGS     := -ldflags "-X main.AppVersion=$(VERSION) -s -w"
GOFLAGS     := CGO_ENABLED=1

.PHONY: all build install run clean test lint deps tidy help

## ── Build ─────────────────────────────────────────────────
all: deps build

build:
	@echo "  Building $(BINARY) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@$(GOFLAGS) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(MAIN)
	@echo "  ✓ Binary: $(BUILD_DIR)/$(BINARY)"

build-linux:
	@GOOS=linux GOARCH=amd64 $(GOFLAGS) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(MAIN)

build-mac:
	@GOOS=darwin GOARCH=arm64 $(GOFLAGS) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 $(MAIN)

build-windows:
	@GOOS=windows GOARCH=amd64 $(GOFLAGS) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(MAIN)

build-all: build-linux build-mac build-windows

## ── Install ───────────────────────────────────────────────
install: build
	@echo "  Installing to /usr/local/bin/$(BINARY)..."
	@sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "  ✓ Installed. Run: $(BINARY) init"

## ── Run ───────────────────────────────────────────────────
run:
	@go run $(MAIN)

tui:
	@go run $(MAIN) tui

status:
	@go run $(MAIN) status

inventory:
	@go run $(MAIN) inventory --target $(TARGET)

## ── Dependencies ──────────────────────────────────────────
deps:
	@echo "  Installing Go dependencies..."
	@go mod download
	@echo "  ✓ Dependencies installed"

tidy:
	@go mod tidy

vendor:
	@go mod vendor

## ── Test ──────────────────────────────────────────────────
test:
	@echo "  Running tests..."
	@CGO_ENABLED=1 go test ./... -v -race -timeout 120s

test-short:
	@CGO_ENABLED=1 go test ./... -short

cover:
	@CGO_ENABLED=1 go test ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "  Coverage report: coverage.html"

## ── Lint ──────────────────────────────────────────────────
lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@golangci-lint run ./...

fmt:
	@go fmt ./...
	@gofmt -s -w .

vet:
	@go vet ./...

## ── Python ────────────────────────────────────────────────
python-test:
	@echo "  Testing Python engines..."
	@python3 -c "import json, sqlite3, argparse, uuid, math; print('  ✓ Python dependencies OK')"

python-risk:
	@python3 python/risk_engine/risk_engine.py $(DB) --format text

python-analytics:
	@python3 python/analytics/trend_analytics.py $(DB) --days 7 --format text

python-recs:
	@python3 python/recommendation/recommendation_engine.py $(DB) --format text

## ── Clean ─────────────────────────────────────────────────
clean:
	@rm -rf $(BUILD_DIR) coverage.out coverage.html
	@echo "  ✓ Cleaned"

## ── Help ──────────────────────────────────────────────────
help:
	@echo ""
	@echo "  KitSentinel Makefile"
	@echo "  ─────────────────────────────────────────────"
	@echo "  make build          Build binary to ./build/"
	@echo "  make install        Build and install to /usr/local/bin"
	@echo "  make run            Run without building"
	@echo "  make tui            Launch TUI"
	@echo "  make inventory      Scan target (TARGET=example.com)"
	@echo "  make test           Run all tests"
	@echo "  make cover          Generate coverage report"
	@echo "  make lint           Run linter"
	@echo "  make build-all      Build for Linux, macOS, Windows"
	@echo "  make clean          Remove build artifacts"
	@echo ""
