# Architecture

[English](ARCHITECTURE.md) | [Русский](ARCHITECTURE.ru.md)

- `internal/iptables`: compact IPv4 iptables-legacy implementation using
  `AF_INET` x_tables ABI calls.
- `internal/ip6tables`: separate IPv6 ip6tables-legacy implementation using
  `AF_INET6` / `SOL_IPV6` and the IPv6-specific `ip6t_entry` ABI.
- `internal/nft`: compact nftables implementation using `NETLINK_NETFILTER`
  through `github.com/google/nftables`.
- `cmd/iptables`, `cmd/ip6tables` and `cmd/nft`: thin standalone command entry points.
- `cmd/gonetfilter`: BusyBox-style combined dispatcher.
- `third_party/nftables`: local replacement for
  `github.com/google/nftables v0.3.0`, carrying the decoder patch documented
  in `third_party/nftables/PATCHES.md`.

The combined binary dispatches by executable name (`argv[0]`): `iptables`,
`iptables-legacy`, `ip6tables`, `ip6tables-legacy`, `nft`, or `nftables`. Invoked as `gonetfilter`, it accepts an explicit `iptables`, `ip6tables` or `nft` subcommand.

The combined binary shares one Go runtime. Symlinks do not duplicate the
executable on disk. The combined binary contains both frontend implementations
and is not necessarily smaller than either standalone binary individually;
compare it against the sum of both standalone binaries.

No frontend invokes system `iptables` or `nft` executables.

## nftables readback path

`internal/nft` reads tables, chains, sets, set elements and rules from the
kernel through Netlink. Supported named-set lookups are resolved for protocol
and FIB sets; IPv4 interval-set elements are reconstructed as canonical CIDR
ranges for the supported NAT exclusion form. Rule formatting handles the
supported `meta`, `fib`, `socket`, `tproxy`, TCP option, NAT and verdict
expressions.

The local `google/nftables` patch is required because v0.3.0 did not register
`socket` and `tproxy` in its expression-name decoder. Without the registration,
those expressions can be dropped while decoding rules received from the
kernel. See `third_party/nftables/PATCHES.md` for exact changes.
