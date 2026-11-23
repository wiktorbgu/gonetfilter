# GoNetFilter

**Small, self-contained Go firewall utilities for Linux router containers.**

GoNetFilter builds two independent command-line programs from one repository:

- **`iptables`** — a compact implementation of the **IPv4 iptables-legacy** socket ABI (`getsockopt` / `setsockopt`). It does not use iptables-nft.
- **`nft`** — a compact nftables CLI subset using Netlink through [`google/nftables`](https://github.com/google/nftables).

The primary target is **MikroTik RouterOS containers** and other constrained router/container environments where the relevant Netfilter backend is provided by the host kernel, but installing the full userspace firewall packages would be wasteful.

Instead of shipping Alpine/Ubuntu/Debian's full `iptables`/`nftables` userspace stack and its supporting libraries, the container can include only the GoNetFilter executable it needs. Both programs are built with `CGO_ENABLED=0`; they do not shell out to `/sbin/iptables`, `/usr/sbin/iptables`, or `/usr/sbin/nft`.

> **Important:** GoNetFilter is an intentionally small, evolving implementation of the command forms needed by its target workloads. It is not currently a drop-in replacement for the complete upstream `iptables` or `nft` command-line interfaces.

## Design

```text
                    GoNetFilter repository
                 ┌──────────────────────────┐
                 │       shared Go module   │
                 └────────────┬─────────────┘
                              │
                  ┌───────────┴───────────┐
                  │                       │
           cmd/iptables               cmd/nft
                  │                       │
          IPv4 xtables legacy       nftables Netlink
          getsockopt/setsockopt     NETLINK_NETFILTER
                  │                       │
                  └───────────┬───────────┘
                              │
                       Linux kernel
                         Netfilter
```

The two backends remain separate on purpose. `iptables` means **legacy x_tables**, while `nft` means **native nftables**. There is no iptables-nft translation layer because the intended devices expose one backend or the other, and the project does not need to emulate the iptables-nft compatibility mode.

## Current command coverage

### `iptables` — legacy IPv4

The initial implementation supports this narrow set:

```sh
iptables -t nat -A PREROUTING -i "$ETH_IFACE" -p tcp -j REDIRECT --to-port "$REDIRECT_PORT"
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -t mangle -A PREROUTING -i "$ETH_IFACE" -p udp -j MARK --set-mark "$UDP_TUN_MARK"
iptables -t mangle -A PREROUTING -p udp --dport 443 -j DROP
```

Inspection commands currently include:

```sh
iptables -t nat -L
iptables -t nat -L -n -v
iptables -t nat -S
iptables -t mangle -L
iptables -t mangle -S
iptables --version
```

Limits: IPv4 only; `nat` and `mangle` tables; the four append rule forms above; exact interface names (no `+` wildcard). The listing/decoder is deliberately partial and should not be treated as a universal decoder for arbitrary extension matches and targets.

The legacy backend reads the current table, inserts the new entry before the built-in chain policy, updates offsets and submits a full table replacement. The replacement header's flexible entry payload is explicitly aligned to 8 bytes; this is essential on 32-bit ARM, where the pointer-containing header's raw Go size can be 92 bytes while the kernel expects the entry array at offset 96. This is the classic legacy table read/modify/replace model. Concurrent writers (including another iptables process) can race and overwrite each other's changes. Avoid simultaneous firewall writers while using this prototype.

### `nft` — native nftables

Current commands include:

```sh
nft add table ip nat
nft add chain ip nat prerouting '{ type nat hook prerouting priority dstnat; }'
nft add rule ip nat prerouting meta l4proto tcp redirect to :4080

nft add table ip mangle
nft add chain ip mangle prerouting '{ type filter hook prerouting priority mangle; }'
nft add rule ip mangle prerouting iifname eth0 meta l4proto udp meta mark set 110
nft add rule ip mangle prerouting udp dport 443 drop

nft list ruleset
```

Current scope is IPv4 (`ip`) and a limited set of chain types, hooks, priorities, and expressions. `list ruleset` is an inspection-oriented renderer, not a complete syntax-compatible implementation of upstream `nft`.

## Build

Requirements: Go 1.23+ and network access on the first build to download the Go module dependencies.

```sh
go test ./...
./scripts/build.sh
```

Output:

```text
dist/
├── amd64/
│   ├── iptables
│   └── nft
├── arm64/
│   ├── iptables
│   └── nft
└── armv5/
    └── iptables
```

The legacy `iptables` implementation has a 32-bit ARMv5 build target in the supplied build script. The nftables binary is currently built for amd64 and arm64; add further targets only after verifying the Go dependency and target kernel support.

To build a single binary manually:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags='-s -w -buildid=' -o nft ./cmd/nft

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags='-s -w -buildid=' -o iptables ./cmd/iptables
```

## Runtime requirements

- The process must have the required network-administration capability, normally `CAP_NET_ADMIN`, in the network namespace where rules should be changed.
- The host kernel must have the relevant Netfilter backend, tables, matches, targets, and expressions enabled or loadable.
- A small userspace binary does **not** provide missing kernel modules or kernel features.
- RouterOS container networking and capabilities are controlled by the host/router configuration. Verify that the container is permitted to administer the intended network namespace.
- Test changes in a disposable container or maintenance window before using them on a production router.

### Kernel/backend prerequisites

For `iptables-legacy`, the kernel must expose the IPv4 x_tables legacy API and the requested table/target modules. The original prototype specifically documents `ip_tables`, `iptable_nat`, `iptable_mangle`, `xt_REDIRECT`, `xt_MASQUERADE`, `xt_mark`, and `xt_tcpudp`.

For `nft`, the kernel must provide nftables Netlink support and the requested expressions (for example `redir`, `masq`, `meta`, `payload`, and `cmp`).

## Project layout

```text
cmd/
├── iptables/     # IPv4 iptables-legacy CLI and ABI tests
└── nft/          # native nftables Netlink CLI
docs/             # design notes and test guidance
scripts/          # reproducible cross-build scripts
```

## Development principles

1. Keep the two kernel backends independent: legacy x_tables is not nftables.
2. Preserve the currently working command forms as regression tests before expanding parsing or ABI support.
3. Prefer small, pure-Go dependencies and avoid invoking external firewall binaries.
4. Validate binary size, architecture, endianness, and ABI against each target router/kernel.
5. Treat unknown rule expressions and extension layouts conservatively; never silently rewrite rules that cannot be understood.

## Status and next work

This repository is the first consolidation of the supplied working prototypes. The next engineering steps should be driven by real device tests:

- add parser/unit tests for every supported CLI form and invalid argument combinations;
- add fixture-based tests for legacy table parsing, offset adjustment, jump targets, and counter mapping;
- test nftables rule construction and listing against rulesets created by the reference `nft` utility;
- improve error messages and output compatibility without claiming full upstream CLI parity;
- measure the actual stripped binaries for each architecture and keep size regressions visible;
- verify behavior on the exact MikroTik RouterOS kernel builds and both backend configurations.

See [docs/TESTING.md](docs/TESTING.md) for the target-device test checklist.


## Unified BusyBox-style binary

The unified executable dispatches by `argv[0]` when invoked through symlinks,
or by explicit subcommand:

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

Build modes:

```sh
./scripts/build.sh unified armv7    # dist/armv7/unified/gonetfilter + symlinks
./scripts/build.sh separate armv7   # dist/armv7/separate/iptables and nft
./scripts/build.sh all armv7        # both build styles
```

The default `all all` builds unified and separate variants for amd64, arm64,
ARMv5 and ARMv7. The unified executable contains both frontends; actual kernel
support still depends on the target kernel.
