# syntax=docker/dockerfile:1.7
FROM golang:1.27-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates upx
COPY . .
RUN go mod tidy && go mod download
# Run all root-module tests and the focused tests for the locally patched dependency.
RUN set -eux; \
    (cd third_party/nftables && go test ./expr); \
    go test ./...; \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /tmp/gonetfilter ./cmd/gonetfilter; \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /tmp/iptables ./cmd/iptables; \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /tmp/nft ./cmd/nft
RUN set -eux; \
    mkdir -p /out; \
    for spec in 'amd64:' 'arm64:' 'armv5:5' 'armv7:7'; do \
      name="${spec%%:*}"; arm="${spec#*:}"; \
      case "$name" in amd64) arch=amd64;; arm64) arch=arm64;; *) arch=arm;; esac; \
      if [ -n "$arm" ]; then \
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOARM="$arm" go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "/out/gonetfilter-$name" ./cmd/gonetfilter; \
      else \
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "/out/gonetfilter-$name" ./cmd/gonetfilter; \
      fi; \
      upx --best --lzma "/out/gonetfilter-$name"; \
      upx -t "/out/gonetfilter-$name"; \
    done; \
    chmod 755 /out/gonetfilter-*
FROM scratch AS export
COPY --from=build /out/ /
