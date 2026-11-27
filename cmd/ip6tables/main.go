//go:build linux

package main

import (
	"github.com/gonetfilter/gonetfilter/internal/ip6tables"
	"os"
)

func main() { os.Exit(ip6tables.Main(os.Args[1:])) }
