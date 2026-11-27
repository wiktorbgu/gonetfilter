# GoNetFilter

[English](README.md) | [Русский](README.ru.md)

**Compact Go frontends for Linux Netfilter: `iptables-legacy`, `ip6tables-legacy` and native `nftables`.**

GoNetFilter targets MikroTik RouterOS containers and other constrained Linux/router environments where the kernel provides the required Netfilter APIs, but installing full userspace firewall packages is undesirable.

On RouterOS, the available firewall tools depend on the device architecture: RouterOS on 64-bit ARM64 and AMD64 provides `nft` and `iptables`, while ARM32 devices (ARMv7 and ARMv5) use the legacy `iptables` interface. GoNetFilter implements compact `iptables-legacy` / `ip6tables-legacy` frontends for those legacy environments, alongside its native `nft` frontend.

It is useful alongside network and VPN software such as **Mihomo, Xray, sing-box, WireGuard/AmneziaWG and other network tools**, when they need basic firewall rules without bringing in a full firewall userspace. On ARMv5, Alpine Linux is not available, and a Debian userspace can be disproportionately large; on other supported architectures, the operating system and its firewall packages still take storage. This matters on routers with limited internal storage and no practical way to attach external storage over USB. GoNetFilter provides standalone frontends instead of requiring those packages. The project compresses its binaries because these utilities are typically invoked briefly to configure firewall rules, not kept running as a long-lived service; reducing their storage footprint is therefore useful. GoNetFilter still relies on the host kernel for the Netfilter APIs, tables, targets and expressions it uses; it does not replace kernel support or configure these applications automatically.

The project builds standalone CLI entry points and a combined BusyBox-style `gonetfilter` binary. Both backends communicate with the kernel directly; neither launches the system `iptables` or `nft` executable as a child process.

> **Project status:** GoNetFilter implements a focused subset of command forms for its target workloads. It is not a complete drop-in replacement for upstream `iptables(8)` or `nft(8)`. Test on the exact target kernel before deploying firewall changes.

## Features

### `iptables` — IPv4 iptables-legacy

The `iptables` frontend uses the legacy x_tables socket ABI (`getsockopt` / `setsockopt`), not `iptables-nft`.

The current compact command subset includes user-chain creation, appending and positional insertion of rules in built-in and user chains (`-I CHAIN [RULENUM]`, defaulting to position 1), standard chain jumps/verdicts, and the rule forms used by the Mihomo redirect setup:

```sh
iptables -t nat -N mihomo-output
iptables -t nat -I OUTPUT -j mihomo-output
iptables -t nat -A OUTPUT -p tcp -j mihomo-output
iptables -t nat -A mihomo-output -o "$TUN_IFACE" -p tcp -j REDIRECT --to-ports 33643

iptables -t nat -N mihomo-prerouting
iptables -t nat -A PREROUTING -j mihomo-prerouting
iptables -t nat -A mihomo-prerouting -p udp -m udp --dport 53 -j DNAT --to 198.19.0.2
iptables -t nat -A mihomo-prerouting -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -A mihomo-prerouting -p tcp -j REDIRECT --to-ports 33643

iptables -t filter -N mihomo-input
iptables -t filter -A INPUT -i "$TUN_IFACE" -j mihomo-input
iptables -t filter -A mihomo-input -i "$TUN_IFACE" -j ACCEPT
```

Supported table families are IPv4 `filter`, `nat`, `mangle` and `raw` (the `raw` table exposes its kernel-supported `PREROUTING` and `OUTPUT` hooks). Listing defaults to the `filter` table when `-t` is omitted and accepts `-L`, `-S`, `-v`, `-n` and `--line-numbers`. The implemented operation subset includes `-N`, `-A`, `-I`, `-L`, `-S`, `REDIRECT`, IPv4 `DNAT` (`--to` and `--to-destination`), `MASQUERADE`, `MARK`, `ACCEPT`, `RETURN`, `DROP`, jumps to user chains, UDP destination-port matching, `addrtype --dst-type LOCAL`, and exact `-i`/`-o` interface names. The IPv6 frontend is a separate legacy x_tables backend with its own ABI and dispatcher entry. The listing/decoder remains intentionally partial and is not a universal decoder for arbitrary match and target extensions.

The legacy backend reads the current table, inserts or appends rules at the requested chain position, adjusts hook/underflow and jump offsets, and submits a full table replacement. This read/modify/replace model can race with other writers. Do not modify the same legacy table concurrently from multiple processes.

### `ip6tables` — IPv6 iptables-legacy

The IPv6 frontend uses the separate `AF_INET6` / `SOL_IPV6` x_tables ABI and its own `ip6t_entry` layout; it does not alias IPv6 commands to the IPv4 backend. It implements the same focused rule-management path for the Mihomo IPv6 rules: `filter`, `nat`, `mangle` and `raw` table listing, user chains, append/insert, chain jumps, UDP destination-port matches, `REDIRECT`, IPv6 `DNAT`, `ACCEPT`, `RETURN`, and `addrtype --dst-type LOCAL`. It is not a complete ip6tables replacement. Validate against the target kernel before deployment.

Example IPv6 NAT rule forms:

```sh
ip6tables -t nat -A mihomo-prerouting -p udp -m udp --dport 53 -j DNAT --to-destination fdfe:dcba:9876::2
ip6tables -t nat -A mihomo-output -o "$TUN_IFACE" -p tcp -j REDIRECT --to-ports 40707
```

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
ln -sf gonetfilter /usr/sbin/ip6tables
ln -sf gonetfilter /usr/sbin/ip6tables-legacy
ln -sf gonetfilter /usr/sbin/nft
```

Running `nft` without arguments displays a two-line summary; `nft --help` shows the supported command subset and examples.

## Build

### Local build

Requirements: Go 1.27 (or the version specified by the project toolchain). The first build requires access to the Go module proxy to download external dependencies. The unified `gonetfilter` binary displays its build version; if not set, it displays `dev`.

```sh
go test ./...
(cd third_party/nftables && go test ./expr)
./scripts/build.sh all all
VERSION=1.2.3 ./scripts/build.sh unified armv7
```

Build modes:

```sh
./scripts/build.sh unified armv7    # combined binary and symlink aliases
./scripts/build.sh separate armv7   # standalone iptables and nft binaries
./scripts/build.sh all armv7        # both build styles
```

By default, `./scripts/build.sh all all` builds amd64, arm64, ARMv5 and ARMv7 targets. Outputs are written to `dist/`. Set `VERSION` to choose the version string embedded in the unified binary; omit it to use `dev`. The version is shown by running `gonetfilter` with no arguments. The standalone `iptables`, `ip6tables` and `nft` frontends do not display a project version. For a tagged release, create the Git tag separately (for example, `git tag v1.2.3`) and build with `VERSION=1.2.3`; setting `VERSION` does not create or push a tag. The standalone `iptables`, `ip6tables` and `nft` frontends do not display a project version.

### Docker / BuildKit

A Go installation on the host is not required. The Dockerfile uses Go 1.27 Alpine, runs tests, builds the combined binary for four architectures, compresses each binary with UPX `--best --lzma`, and verifies it with `upx -t`. The build argument `VERSION` sets the version shown by the main `gonetfilter` command (default: `dev`).

```sh
docker buildx build --no-cache --build-arg VERSION=1.2.3 --output type=local,dest=./dist .
```

Exported files:

```text
dist/
├── gonetfilter-amd64
├── gonetfilter-arm64
├── gonetfilter-armv5
└── gonetfilter-armv7
```

The Docker build environment needs access to the Go module proxy when downloading external dependencies. `VERSION` is embedded in the unified `gonetfilter` banner; it does not alter the standalone frontend banners.

### Manual single-binary build

Set `VERSION` to choose the version string embedded in the unified binary; it defaults to `dev`.

```sh
VERSION=1.2.3
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o gonetfilter ./cmd/gonetfilter
```

## nftables dependency and local patch

The project uses `github.com/google/nftables` version `v0.3.0`. A small local patch is required so the upstream expression decoder restores `socket` and `tproxy` expressions when reading rules from the kernel. The patched module source is kept under `third_party/nftables`, and the root `go.mod` uses a local `replace` directive to select that copy.

This keeps the patch reviewable and reproducible without depending on a separate fork. The nested module retains its own `go.mod`, `go.sum` and upstream `LICENSE`. The origin and exact patch contents are documented in [`third_party/nftables/PATCHES.md`](third_party/nftables/PATCHES.md) ([Русский](third_party/nftables/PATCHES.ru.md)).

When updating the dependency, rebase the patch, run the decoder tests, run the root module tests and cross-builds, then repeat the runtime comparison against the system `nft` utility.

## Runtime requirements

GoNetFilter does not grant itself firewall permissions or change RouterOS container access settings. It can only use the Netfilter interfaces and permissions made available by the host. The kernel must provide the relevant backend, tables, targets and expressions; a userspace binary cannot supply missing kernel modules or enable unavailable kernel features. Check the access mode and firewall support documented for the target RouterOS/device, and test changes before applying them to a production router.

For the legacy backend, the kernel must expose the relevant x_tables API and required table/extension support. For nftables, the kernel must provide native nftables Netlink support and the expressions used by the ruleset.

## Project layout

```text
cmd/
├── gonetfilter/     # combined BusyBox-style dispatcher
├── iptables/        # standalone IPv4 iptables-legacy entry point
├── ip6tables/       # standalone IPv6 ip6tables-legacy entry point
└── nft/             # standalone nft frontend entry point
internal/
├── iptables/        # IPv4 legacy x_tables backend and tests
├── ip6tables/       # IPv6 legacy x_tables backend and tests
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
7. Compare IPv4/IPv6 legacy readback with the system `iptables` / `ip6tables` utilities where available; validate values decoded from the kernel x_tables ABI, not only rendered text.

## Device testing

See [`docs/TESTING.md`](docs/TESTING.md) ([Русский](docs/TESTING.ru.md)) for the target-device checklist. At minimum, compare both nft readers against the same kernel ruleset:

```sh
nft list ruleset
./nft list ruleset
```

Record both outputs, the kernel version, architecture, exact rule-creation commands and exit status. For legacy `iptables`/`ip6tables`, compare each implemented table against the matching system legacy utility where available. For rule changes, verify the kernel state and packet-level behavior; a successful CLI return alone does not prove the rule works as intended.
