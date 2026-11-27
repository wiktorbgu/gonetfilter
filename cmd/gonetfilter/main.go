//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gonetfilter/gonetfilter/internal/ip6tables"
	"github.com/gonetfilter/gonetfilter/internal/iptables"
	"github.com/gonetfilter/gonetfilter/internal/nft"
)

// version is the default release version; build-time -ldflags may override it.
var version = "0.1.0"

func main() { os.Exit(dispatch(os.Args[0], os.Args[1:])) }

func dispatch(argv0 string, args []string) int {
	switch filepath.Base(argv0) {
	case "iptables", "iptables-legacy":
		return iptables.Main(args)
	case "ip6tables", "ip6tables-legacy":
		return ip6tables.Main(args)
	case "nft", "nftables":
		return nft.Main(args)
	case "gonetfilter":
		if len(args) == 0 {
			usage()
			return 2
		}
		switch args[0] {
		case "iptables", "iptables-legacy":
			return iptables.Main(args[1:])
		case "ip6tables", "ip6tables-legacy":
			return ip6tables.Main(args[1:])
		case "nft", "nftables":
			return nft.Main(args[1:])
		case "help", "--help", "-h":
			usage()
			return 0
		default:
			fmt.Fprintf(os.Stderr, "gonetfilter: unknown frontend %q\n", args[0])
			usage()
			return 2
		}
	default:
		fmt.Fprintf(os.Stderr, "gonetfilter: unknown invocation name %q\n", filepath.Base(argv0))
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "GoNetFilter %s - compact Netfilter frontends\n", version)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  gonetfilter iptables [arguments]")
	fmt.Fprintln(os.Stderr, "  gonetfilter ip6tables [arguments]")
	fmt.Fprintln(os.Stderr, "  gonetfilter nft [arguments]")
}
