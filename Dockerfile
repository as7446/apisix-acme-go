# syntax=docker/dockerfile:1.6

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
ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/apisix-acme-go .

FROM debian:12
WORKDIR /app

ARG USE_CN_MIRROR=true
RUN if [ "$USE_CN_MIRROR" = "true" ]; then \
 echo "Using CN mirror: aliyun"; \
 sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources && \
 sed -i 's|security.debian.org|mirrors.aliyun.com/debian-security|g' /etc/apt/sources.list.d/debian.sources ; \
fi \
&& apt-get update \
&& apt-get install -y --no-install-recommends ca-certificates tzdata curl \
&& rm -rf /var/lib/apt/lists/* \

COPY --from=builder /out/apisix-acme-go /usr/local/bin/apisix-acme-go
COPY config.example.yml /app/config.example.yml

ENV TZ=UTC

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/apisix-acme-go"]

