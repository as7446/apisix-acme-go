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


FROM debian:13.5
WORKDIR /app

ENV TZ=UTC

COPY --from=builder /out/certmanager /usr/local/bin/certmanager
COPY config.controller.example.yml /app/config.controller.example.yml
COPY config.agent.example.yml /app/config.agent.example.yml

RUN sed -i 's|http://deb.debian.org|https://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's|http://security.debian.org|https://mirrors.tuna.tsinghua.edu.cn/debian-security|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/certmanager"]