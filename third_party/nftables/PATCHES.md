[English](PATCHES.md) | [Русский](PATCHES.ru.md)

# Local patches

This directory is based on **github.com/google/nftables v0.3.0**.
The upstream module source and its license are retained here. The root
`go.mod` uses a local `replace` directive so builds use this maintained copy
instead of downloading an unpatched copy of the same module.

## GoNetFilter changes

Only the following upstream files are modified:

- `expr/expr.go`: register the existing `Socket` and `TProxy` expression
  implementations in `exprFromName`, allowing the Netlink decoder to restore
  these expressions when reading rules from the kernel.
- `expr/tproxy.go`: decode `NFTA_TPROXY_FAMILY` using the 32-bit Netlink
  attribute representation before narrowing it to the expression's byte-sized
  family field.

A focused regression test is added in `expr/expr_name_test.go` to ensure the
expression names resolve to the expected expression types.

No upstream expression encoder implementation is intentionally changed by
this patch. The rest of the module is retained so the local replacement remains
a self-contained Go module with the original package layout and license.

## Updating

When rebasing onto a newer upstream release:

1. Replace this directory with the exact upstream source release.
2. Reapply the changes listed above (review Netlink attribute widths against
   the relevant kernel UAPI definitions).
3. Run `go test ./expr` from this directory.
4. Run the root module tests and cross-builds.
5. Compare `nft list ruleset` from the reference nft utility and GoNetFilter on
   the target kernel, including `socket`, IPv4/IPv6 `tproxy`, and their register
   values.
