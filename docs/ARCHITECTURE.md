# Architecture

- `internal/iptables`: compact IPv4 iptables-legacy implementation using
  `getsockopt`/`setsockopt` and the Linux x_tables ABI.
- `internal/nft`: compact nftables implementation using `NETLINK_NETFILTER`
  through `github.com/google/nftables`.
- `cmd/iptables` and `cmd/nft`: thin standalone command entry points.
- `cmd/gonetfilter`: BusyBox-style combined dispatcher.

The combined binary dispatches by executable name (`argv[0]`): `iptables`,
`iptables-legacy`, `nft`, or `nftables`. Invoked as `gonetfilter`, it accepts
an explicit `iptables` or `nft` subcommand.

The combined binary shares one Go runtime. Symlinks do not duplicate the
executable on disk. The combined binary contains both frontend implementations
and is not necessarily smaller than either standalone binary individually;
compare it against the sum of both standalone binaries.

No frontend invokes system `iptables` or `nft` executables.
