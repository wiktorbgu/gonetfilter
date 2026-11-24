# GoNetFilter

**Compact Go frontends for Linux Netfilter: `iptables-legacy` and native `nftables`.**

GoNetFilter targets MikroTik RouterOS containers and other constrained Linux/router environments where the kernel provides the required Netfilter APIs, but installing the full userspace firewall packages is undesirable.

The project builds standalone CLI entry points and a combined BusyBox-style `gonetfilter` binary. Both backends communicate with the kernel directly; neither launches the system `iptables` or `nft` executable as a child process.

> **Project status:** GoNetFilter implements a focused subset of command forms for its target workloads. It is not a complete drop-in replacement for upstream `iptables(8)` or `nft(8)`. Test on the exact target kernel before deploying firewall changes.

## Features

### `iptables` — IPv4 iptables-legacy

The `iptables` frontend uses the legacy x_tables socket ABI (`getsockopt` / `setsockopt`), not `iptables-nft`.

Supported append forms include:

```sh
iptables -t nat -A PREROUTING -i "$ETH_IFACE" -p tcp -j REDIRECT --to-port "$REDIRECT_PORT"
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -t mangle -A PREROUTING -i "$ETH_IFACE" -p udp -j MARK --set-mark "$UDP_TUN_MARK"
iptables -t mangle -A PREROUTING -p udp --dport 443 -j DROP
```

Inspection commands include:

```sh
iptables -t nat -L
iptables -t nat -L -n -v
iptables -t nat -S
iptables -t mangle -L
iptables -t mangle -S
iptables --version
```

Scope is IPv4, the `nat` and `mangle` tables, the forms listed above, and exact interface names (no `+` wildcard). The legacy listing/decoder is intentionally partial; it is not a universal decoder for arbitrary match and target extensions.

The legacy backend reads the current table, inserts a rule, adjusts offsets and submits a full table replacement. This read/modify/replace model can race with other writers. Do not modify the same legacy table concurrently from multiple processes.

### `nft` — native nftables over Netlink

The `nft` frontend uses `NETLINK_NETFILTER` through `github.com/google/nftables`. The implemented subset covers the command forms and expressions used by the project's target workloads, including:

- `ip`, `ip6` and `inet` families;
- tables and base chains with supported types, hooks, priorities and policies;
- `meta l4proto`, `meta mark`, `meta oiftype` and `iifname`;
- IPv4 destination matches and CIDR exclusions;
- `masquerade`, `redirect` and IPv4/IPv6 `tproxy`;
- `socket transparent`, FIB address-type lookups;
- TCP MPTCP option matching and basic verdicts;
- named kernel sets for supported protocol and FIB lookups.

Example commands:

```sh
nft add table ip nat
nft add chain ip nat prerouting '{ type nat hook prerouting priority dstnat; }'
nft add rule ip nat prerouting meta l4proto tcp redirect to :4080

nft add table ip mangle
nft add chain ip mangle prerouting '{ type filter hook prerouting priority mangle; }'
nft add rule ip mangle prerouting iifname eth0 meta l4proto udp meta mark set 110
nft add rule ip mangle prerouting udp dport 443 drop

nft list ruleset
nft --help
```

`nft list ruleset` is an inspection-oriented renderer for the supported expression subset, not a complete implementation of upstream nft syntax or formatting. Unknown expression types must not be assumed to have been interpreted correctly.

#### Tested ruleset readback

The output of GoNetFilter was compared against the system `nft list ruleset` on an Alpine container for a ruleset containing NAT masquerade with IPv4 CIDR exclusions, `meta oiftype ether`, `socket transparent`, packet marks, FIB address types, an MPTCP option match, and IPv4/IPv6 TPROXY. The output matched for that test ruleset.

This is a focused result for the tested ruleset and kernel, not a claim of full nftables compatibility across all expressions or kernel versions.

### Unified binary

The combined executable dispatches by `argv[0]` when invoked through symlinks, or by an explicit subcommand:

```sh
gonetfilter iptables -t nat -L
gonetfilter nft list ruleset
```

Install the combined executable and aliases:

```sh
install -m 0755 gonetfilter /usr/sbin/gonetfilter
ln -sf gonetfilter /usr/sbin/iptables
ln -sf gonetfilter /usr/sbin/iptables-legacy
ln -sf gonetfilter /usr/sbin/nft
```

Running `nft` without arguments or with `--help` displays the compact `tiny-nft` help and its supported command subset.

## Build

### Local build

Requirements: Go 1.23+. The first build requires access to the Go module proxy to download external dependencies.

```sh
go test ./...
(cd third_party/nftables && go test ./expr)
./scripts/build.sh all all
```

Build modes:

```sh
./scripts/build.sh unified armv7    # combined binary and symlink aliases
./scripts/build.sh separate armv7   # standalone iptables and nft binaries
./scripts/build.sh all armv7        # both build styles
```

By default, `./scripts/build.sh all all` builds amd64, arm64, ARMv5 and ARMv7 targets. Outputs are written to `dist/`.

### Docker / BuildKit

A Go installation on the host is not required. The Dockerfile uses Go 1.23 Alpine, runs tests, builds the combined binary for four architectures, compresses each binary with UPX `--best --lzma`, and verifies it with `upx -t`.

```sh
docker buildx build --no-cache --output type=local,dest=./dist .
```

Exported files:

```text
dist/
├── gonetfilter-amd64
├── gonetfilter-arm64
├── gonetfilter-armv5
└── gonetfilter-armv7
```

The Docker build environment needs access to the Go module proxy when downloading external dependencies.

### Manual single-binary build

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o gonetfilter ./cmd/gonetfilter
```

## nftables dependency and local patch

The project uses `github.com/google/nftables` version `v0.3.0`. A small local patch is required so the upstream expression decoder restores `socket` and `tproxy` expressions when reading rules from the kernel. The patched module source is kept under `third_party/nftables`, and the root `go.mod` uses a local `replace` directive to select that copy.

This keeps the patch reviewable and reproducible without depending on a separate fork. The nested module retains its own `go.mod`, `go.sum` and upstream `LICENSE`. The origin and exact patch contents are documented in [`third_party/nftables/PATCHES.md`](third_party/nftables/PATCHES.md).

When updating the dependency, rebase the patch, run the decoder tests, run the root module tests and cross-builds, then repeat the runtime comparison against the system `nft` utility.

## Runtime requirements

- Firewall changes normally require `CAP_NET_ADMIN` in the network namespace being managed.
- The kernel must provide the relevant backend, tables, targets and expressions.
- A userspace binary does not provide missing kernel modules or enable unavailable kernel features.
- RouterOS/container networking and capabilities are controlled by the host configuration.
- Test changes in a disposable container or maintenance window before using them on a production router.

For the legacy backend, the kernel must expose the IPv4 x_tables API and required table/extension modules (for example `ip_tables`, `iptable_nat`, `iptable_mangle`, `xt_REDIRECT`, `xt_MASQUERADE`, `xt_mark` and `xt_tcpudp`). For nftables, the kernel must provide native nftables Netlink support and the expressions used by the ruleset.

## Project layout

```text
cmd/
├── gonetfilter/     # combined BusyBox-style dispatcher
├── iptables/        # standalone iptables-legacy entry point
└── nft/             # standalone tiny-nft entry point
internal/
├── iptables/        # legacy x_tables backend and tests
└── nft/             # nftables Netlink frontend, builder, readback and tests
third_party/
└── nftables/        # locally patched google/nftables v0.3.0 module
scripts/             # cross-build script
Dockerfile           # Docker/BuildKit multi-architecture build and UPX compression
docs/                # architecture and device-testing guidance
```

## Development principles

1. Keep the legacy x_tables and native nftables backends independent.
2. Add regression tests for each supported command form and decoded expression.
3. Do not invoke external firewall binaries from GoNetFilter.
4. Validate binary size, architecture, endianness and ABI on target devices.
5. Do not hide or silently rewrite expressions that are not understood.
6. Compare nft readback with the system `nft` utility and validate values decoded from kernel Netlink, not only rendered text.

## Device testing

See [`docs/TESTING.md`](docs/TESTING.md) for the target-device checklist. At minimum, compare both readers against the same kernel ruleset:

```sh
nft list ruleset
./nft list ruleset
```

Record both outputs, the kernel version, architecture, exact rule-creation commands and exit status. For rule changes, verify the kernel state and packet-level behavior; a successful CLI return alone does not prove the rule works as intended.
