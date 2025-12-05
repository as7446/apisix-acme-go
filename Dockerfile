# syntax=docker/dockerfile:1.6

ARG GO_VERSION=1.22

FROM golang:${GO_VERSION} AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/apisix-acme-go .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=builder /out/apisix-acme-go /usr/local/bin/apisix-acme-go
COPY config.example.yml /app/config.example.yml

ENV TZ=UTC

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/apisix-acme-go"]

