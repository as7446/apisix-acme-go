ARG GO_VERSION=1.24

FROM golang:${GO_VERSION} AS builder
WORKDIR /src

ARG USE_CN_MIRROR
RUN if [ "$USE_CN_MIRROR" = "true" ]; then \
      go env -w GOPROXY=https://goproxy.cn,direct && \
      echo "Using goproxy.cn"; \
    fi

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

ENV CGO_ENABLED=0

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -ldflags "-s -w -X github.com/as7446/apisix-acme-go/internal/infra/config.Version=${VERSION}" \
    -o /out/certmanager \
    ./cmd/certmanager

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -ldflags "-s -w" \
    -o /out/migrate-storm \
    ./cmd/migrate-storm


FROM registry.cn-shanghai.aliyuncs.com/sh-cloud/debian:13.5
WORKDIR /app

ENV TZ=UTC

# 主程序
COPY --from=builder /out/certmanager /usr/local/bin/certmanager

# migrate 工具
COPY --from=builder /out/migrate-storm /app/migrate-storm

# 配置文件
COPY config.controller.example.yml /app/config.controller.example.yml
COPY config.agent.example.yml /app/config.agent.example.yml

RUN chmod +x /app/migrate-storm /usr/local/bin/certmanager

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/certmanager"]