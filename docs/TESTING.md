# Device test checklist

This is a checklist for validating GoNetFilter on MikroTik RouterOS containers and other Linux router containers. The kernel and container configuration are part of the test environment; successful compilation alone does not prove runtime compatibility.

## Before testing

Record:

- Router model and RouterOS version
- Container image/base and userspace architecture
- `uname -a` and kernel version/build
- CPU architecture (`amd64`, `arm64`, or 32-bit ARM/EABI)
- Active backend available inside the container: legacy x_tables or nftables
- Whether the container has `CAP_NET_ADMIN` and operates in the intended network namespace

Do not assume that a userspace architecture or kernel version implies a particular Netfilter feature set.

## Legacy iptables test

Use only on a test router/container or during a safe maintenance window. Confirm that the legacy tables and extensions required by the test rules are available.

```sh
./iptables --version
./iptables -t nat -L -n -v
./iptables -t mangle -L -n -v

./iptables -t nat -A PREROUTING -i br-lan -p tcp -j REDIRECT --to-port 4080
./iptables -t nat -A POSTROUTING -j MASQUERADE
./iptables -t mangle -A PREROUTING -i br-lan -p udp -j MARK --set-mark 110
./iptables -t mangle -A PREROUTING -p udp --dport 443 -j DROP

./iptables -t nat -S
./iptables -t mangle -S
```

Replace `br-lan` and the ports/mark with the intended test values. The normal system iptables command may be used as an independent inspection oracle if present; GoNetFilter itself does not invoke it.

Important: legacy table updates use a read/modify/replace operation. Do not run multiple writers concurrently while testing. Verify that existing rules and counters remain correct after each insertion.

## nftables test

Use only where the kernel exposes native nftables. Create a dedicated test table so the test does not alter unrelated rules.

```sh
./nft add table ip gonetfilter_test
./nft add chain ip gonetfilter_test prerouting '{ type nat hook prerouting priority dstnat; }'
./nft add rule ip gonetfilter_test prerouting meta l4proto tcp redirect to :4080
./nft list ruleset
```

The current CLI supports only a limited set of expressions and chain configurations. Compare its output and the kernel-installed rules with the system `nft` command if available.

Clean up test tables using the reference system tool or a dedicated cleanup implementation once delete operations are implemented; the current GoNetFilter nft CLI does not yet implement table deletion.

## Cross-architecture validation

For 32-bit ARM, pay particular attention to `IPT_SO_SET_REPLACE`: the entry blob in `struct ipt_replace` starts at an 8-byte-aligned offset even when the pointer-sized Go header is only 92 bytes. The implementation aligns this offset to 96 bytes. Run the ABI layout tests and verify rule insertion on the actual ARMv5/ARMv7 kernel.

For every target binary:

```sh
file ./iptables
file ./nft
```

Then run `--version` / `--help` on the target device. Check binary sizes with `ls -lh` and record them alongside the build commit.

## Report results

For each command, record:

- exact command line and exit status;
- stdout/stderr;
- before/after ruleset inspection;
- whether pre-existing rules were preserved;
- packet-level behavior, not just successful command return;
- binary architecture and file size.

Do not report a feature as supported on a router family until it has passed runtime testing on the relevant kernel build.

## nftables readback comparison (tested ruleset)

For the current supported transparent-proxy readback path, compare the output
of the reference `nft` binary with GoNetFilter against the same kernel ruleset:

```sh
nft list ruleset
./nft list ruleset
```

The regression set used during development covers:

- `ip nat` postrouting with `meta oiftype ether`, IPv4 destination exclusions
  (`127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`, and
  `255.255.255.255`) and `masquerade`;
- an `inet` divert chain with `meta l4proto tcp`, `socket transparent 1`,
  `meta mark set 0x00000123` and `accept`;
- an `inet` prerouting chain with FIB address types (`local`, `broadcast`,
  `multicast`), TCP MPTCP option match, grouped TCP/UDP protocol lookup, and
  IPv4/IPv6 TPROXY destinations.

For this exact test ruleset, GoNetFilter's rendered output was compared with
and matched the reference nft output on the tested Alpine container/kernel.
This is a focused compatibility result, not a claim that every nftables
expression, set datatype, kernel release or nft CLI syntax is supported.

When repeating the test, capture both outputs and verify at least:

- `meta oiftype ether` (not an unknown value or raw compare);
- the four IPv4 exclusions, with the host address rendered without `/32`;
- mark `0x00000123` without byte swapping;
- FIB labels in canonical order;
- `socket transparent 1`;
- TPROXY family, address, port and verdict for both IPv4 and IPv6.
