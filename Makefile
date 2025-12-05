BINARY ?= apisix-acme-go
OUTPUT_DIR ?= bin
MAIN_PKG ?= .
IMAGE ?= apisix-acme-go:latest
PLATFORMS ?= linux/amd64,linux/arm64
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

.PHONY: build build-amd64 build-arm64 clean docker-build docker-build-amd64 docker-build-arm64 docker-build-multi

build:
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(OUTPUT_DIR)/$(BINARY)-$(GOOS)-$(GOARCH) $(MAIN_PKG)

build-amd64:
	$(MAKE) build GOOS=linux GOARCH=amd64 CGO_ENABLED=0

build-arm64:
	$(MAKE) build GOOS=linux GOARCH=arm64 CGO_ENABLED=0

clean:
	rm -rf $(OUTPUT_DIR)

docker-build:
	docker build -t $(IMAGE) .

docker-build-amd64:
	docker buildx build --platform linux/amd64 -t $(IMAGE)-amd64 --build-arg TARGETOS=linux --build-arg TARGETARCH=amd64 --load .

docker-build-arm64:
	docker buildx build --platform linux/arm64 -t $(IMAGE)-arm64 --build-arg TARGETOS=linux --build-arg TARGETARCH=arm64 --load .

docker-build-multi:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE) --push .

