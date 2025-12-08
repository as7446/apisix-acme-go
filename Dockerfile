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

COPY --from=builder /out/apisix-acme-go /usr/local/bin/apisix-acme-go
COPY config.example.yml /app/config.example.yml

ENV TZ=UTC

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/apisix-acme-go"]

