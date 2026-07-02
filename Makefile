# =============================================================================
# apisix-acme-go Makefile
# =============================================================================

# 项目信息
BINARY_NAME := apisix-acme-go
MODULE      := github.com/as7446/apisix-acme-go
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME  := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_USER  := $(shell whoami)
BUILD_HOST   = $(shell hostname -s 2>/dev/null || hostname)

# 编译输出
OUTPUT_DIR    := bin
DIST_DIR     := dist

# 镜像
IMAGE_NAME   ?= $(BINARY_NAME)
IMAGE_REGISTRY ?= docker.io
IMAGE_TAG    ?= latest
IMAGE_FULL   := $(IMAGE_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

# 多平台
PLATFORMS    := linux/amd64,linux/arm64

# Go 参数
GO_CMD       := go
GOOS         ?= $(shell $(GO_CMD) env GOOS)
GOARCH       ?= $(shell $(GO_CMD) env GOARCH)
CGO_ENABLED  := 0

# ldflags
LDFLAGS      := -s -w \
	-X $(MODULE)/internal/infra/config.Version=$(VERSION) \
	-X $(MODULE)/internal/infra/config.BuildTime=$(BUILD_TIME) \
	-X $(MODULE)/internal/infra/config.BuildUser=$(BUILD_USER) \
	-X $(MODULE)/internal/infra/config.BuildHost=$(BUILD_HOST)

# 编译目标
CERTMANAGER_BIN := $(OUTPUT_DIR)/certmanager

.PHONY: all build build-all build-certmanager \
	clean install docker-build docker-buildx docker-buildx-push \
	fmt vet lint test test-cover mod-tidy mod-download help dist dist-all \
	version help web-install web-dev web-build

# -----------------------------------------------------------------------------
# Default
# -----------------------------------------------------------------------------
all: mod-download build-all

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------
build: build-certmanager

build-all: build-certmanager

build-certmanager: $(CERTMANAGER_BIN)

$(CERTMANAGER_BIN):
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO_CMD) build -ldflags "$(LDFLAGS)" \
		-o $@ ./cmd/certmanager

web-install:
	cd web && npm install

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build

# 交叉编译 amd64
build-amd64:
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 $(GO_CMD) build -ldflags "$(LDFLAGS)" \
		-o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/certmanager

# 交叉编译 arm64
build-arm64:
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 $(GO_CMD) build -ldflags "$(LDFLAGS)" \
		-o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/certmanager

# -----------------------------------------------------------------------------
# Go 模块
# -----------------------------------------------------------------------------
mod-download:
	$(GO_CMD) mod download

mod-tidy:
	$(GO_CMD) mod tidy
	$(GO_CMD) mod verify

# -----------------------------------------------------------------------------
# 代码质量
# -----------------------------------------------------------------------------
fmt:
	@echo "=== fmt ==="
	$(GO_CMD) fmt ./...
	gofmt -s -w .

vet:
	@echo "=== vet ==="
	$(GO_CMD) vet -all ./...

lint: vet
	@echo "=== lint (staticcheck) ==="
	@which staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skip"

# -----------------------------------------------------------------------------
# Test
# -----------------------------------------------------------------------------
test:
	$(GO_CMD) test -v -race -coverprofile=coverage.out ./...

test-cover: test
	$(GO_CMD) tool cover -html=coverage.out -o coverage.html

# -----------------------------------------------------------------------------
# Clean
# -----------------------------------------------------------------------------
clean:
	rm -rf $(OUTPUT_DIR) $(DIST_DIR) coverage.out coverage.html

dist-clean:
	rm -rf $(DIST_DIR)

# -----------------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------------
install: build-all
	@mkdir -p /usr/local/bin
	cp $(CERTMANAGER_BIN) /usr/local/bin/$(BINARY_NAME)

# -----------------------------------------------------------------------------
# Docker
# -----------------------------------------------------------------------------
docker-build:
	docker build $(DOCKER_BUILD_ARGS) -t $(IMAGE_FULL) .

docker-buildx:
	docker buildx build \
		--platform $(PLATFORMS) \
		--progress=plain \
		-t $(IMAGE_FULL) \
		--load \
		.

docker-buildx-push:
	docker buildx build \
		--platform $(PLATFORMS) \
		--progress=plain \
		-t $(IMAGE_FULL) \
		--push \
		.

# -----------------------------------------------------------------------------
# Dist (goreleaser)
# -----------------------------------------------------------------------------
dist: mod-tidy
	goreleaser build --snapshot --rm-dist --output $(DIST_DIR)

dist-all: mod-tidy
	goreleaser release --snapshot --rm-dist --output $(DIST_DIR)

# -----------------------------------------------------------------------------
# Version
# -----------------------------------------------------------------------------
version:
	@echo "Version:    $(VERSION)"
	@echo "BuildTime:  $(BUILD_TIME)"
	@echo "BuildUser:  $(BUILD_USER)"
	@echo "BuildHost:  $(BUILD_HOST)"
	@echo "GoVersion:  $(shell $(GO_CMD) version)"
	@echo "GOOS:       $(GOOS)"
	@echo "GOARCH:     $(GOARCH)"

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
