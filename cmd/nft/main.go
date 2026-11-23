//go:build linux

package main

import (
	"os"

	"github.com/gonetfilter/gonetfilter/internal/nft"
)

func main() { os.Exit(nft.Main(os.Args[1:])) }
