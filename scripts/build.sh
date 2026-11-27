#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="${OUT_DIR:-$ROOT/dist}"
MODE="${1:-all}"
ARCHSET="${2:-all}"
VERSION="${VERSION:-}"

case "$MODE" in
    unified|separate|all) ;;
    *) echo "Usage: $0 [unified|separate|all] [all|amd64|arm64|armv5|armv7]" >&2; exit 2 ;;
esac

build() {
    name=$1 arch=$2 arm=$3 dest=$4
    echo "==> building $name ($arch${arm:+, GOARM=$arm})"
    mkdir -p "$(dirname "$dest")"
    ldflags="-s -w -buildid="
    if [ "$name" = gonetfilter ] && [ -n "$VERSION" ]; then
        ldflags="$ldflags -X main.version=$VERSION"
    fi
    if [ -n "$arm" ]; then
        (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOARM="$arm" \
            go build -trimpath -buildvcs=false -ldflags="$ldflags" -o "$dest" "./cmd/$name")
    else
        (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            go build -trimpath -buildvcs=false -ldflags="$ldflags" -o "$dest" "./cmd/$name")
    fi
}

build_arch() {
    label=$1 arch=$2 arm=$3
    if [ "$MODE" = unified ] || [ "$MODE" = all ]; then
        dir="$OUT/$label/unified"
        build gonetfilter "$arch" "$arm" "$dir/gonetfilter"
        ln -sf gonetfilter "$dir/iptables"
        ln -sf gonetfilter "$dir/iptables-legacy"
        ln -sf gonetfilter "$dir/ip6tables"
        ln -sf gonetfilter "$dir/ip6tables-legacy"
        ln -sf gonetfilter "$dir/nft"
    fi
    if [ "$MODE" = separate ] || [ "$MODE" = all ]; then
        dir="$OUT/$label/separate"
        build iptables "$arch" "$arm" "$dir/iptables"
        build ip6tables "$arch" "$arm" "$dir/ip6tables"
        build nft "$arch" "$arm" "$dir/nft"
    fi
}

case "$ARCHSET" in
    all)
        build_arch amd64 amd64 ""
        build_arch arm64 arm64 ""
        build_arch armv5 arm 5
        build_arch armv7 arm 7
        ;;
    amd64) build_arch amd64 amd64 "" ;;
    arm64) build_arch arm64 arm64 "" ;;
    armv5) build_arch armv5 arm 5 ;;
    armv7) build_arch armv7 arm 7 ;;
    *) echo "Unknown architecture set: $ARCHSET" >&2; exit 2 ;;
esac

echo "Build outputs: $OUT"
