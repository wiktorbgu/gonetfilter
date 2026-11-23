//go:build linux

package main

import (
	"os"

	"github.com/gonetfilter/gonetfilter/internal/iptables"
)

func main() { os.Exit(iptables.Main(os.Args[1:])) }
