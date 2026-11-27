//go:build linux

package ip6tables

import (
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"
)

func TestIPv6LegacyABISizes(t *testing.T) {
	if got := unsafe.Sizeof(ip6tIP{}); got != 136 {
		t.Fatalf("ip6t_ip6 size=%d want=136", got)
	}
	if got := unsafe.Sizeof(ip6tEntry{}); got != 168 {
		t.Fatalf("ip6t_entry size=%d want=168", got)
	}
	if got := unsafe.Offsetof(ip6tEntry{}.Counters); got != 152 {
		t.Fatalf("ip6t_entry counters offset=%d want=152", got)
	}
	if got := unsafe.Sizeof(ip6tGetInfo{}); got != 84 {
		t.Fatalf("ip6t_getinfo size=%d want=84", got)
	}
	if got := unsafe.Sizeof(ip6tGetEntries{}); got != 40 {
		t.Fatalf("ip6t_get_entries size=%d want=40", got)
	}
	if got := align(int(unsafe.Sizeof(ip6tReplace{}))); got != 96 {
		t.Fatalf("ip6t_replace aligned size=%d want=96", got)
	}
}

func TestIPv6NATRangeABI(t *testing.T) {
	if got := unsafe.Sizeof(natRange{}); got != 40 {
		t.Fatalf("nf_nat_range size=%d want=40", got)
	}
	if got := unsafe.Offsetof(natRange{}.MinIP); got != 4 {
		t.Fatalf("nf_nat_range min_addr offset=%d want=4", got)
	}
	if got := unsafe.Offsetof(natRange{}.MaxIP); got != 20 {
		t.Fatalf("nf_nat_range max_addr offset=%d want=20", got)
	}
	if got := unsafe.Offsetof(natRange{}.MinProto); got != 36 {
		t.Fatalf("nf_nat_range min_proto offset=%d want=36", got)
	}
	if got := unsafe.Offsetof(natRange{}.MaxProto); got != 38 {
		t.Fatalf("nf_nat_range max_proto offset=%d want=38", got)
	}
}

func TestIPv6RedirectTargetUsesDirectRange(t *testing.T) {
	rule, err := makeRuleFor("tcp", "", "Meta", "REDIRECT", 42139, 0, 0, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	entry := (*ip6tEntry)(unsafe.Pointer(&rule[0]))
	target := (*xtEntryTarget)(unsafe.Pointer(&rule[int(entry.TargetOffset)]))
	if got, want := target.Size, uint16(align(int(unsafe.Sizeof(xtEntryTarget{}))+int(unsafe.Sizeof(natRange{})))); got != want {
		t.Fatalf("REDIRECT target size=%d want=%d", got, want)
	}
	data := rule[int(entry.TargetOffset)+int(unsafe.Sizeof(xtEntryTarget{})):]
	if got := binary.BigEndian.Uint16(data[36:38]); got != 42139 {
		t.Fatalf("REDIRECT min port=%d want=42139", got)
	}
	if got := binary.BigEndian.Uint16(data[38:40]); got != 42139 {
		t.Fatalf("REDIRECT max port=%d want=42139", got)
	}
}

func TestBuildIPv6DNATRule(t *testing.T) {
	rule, err := makeRuleFor("udp", "", "", "DNAT", 0, 0, 53, 0, "", "fdfe:dcba:9876::2")
	if err != nil {
		t.Fatal(err)
	}
	entry := (*ip6tEntry)(unsafe.Pointer(&rule[0]))
	if entry.IP.Proto != ipProtoUDP || entry.IP.Flags&1 == 0 {
		t.Fatalf("IPv6 UDP protocol not encoded: proto=%d flags=%#x", entry.IP.Proto, entry.IP.Flags)
	}
	items, err := decodeTable(rule)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("decoded %d entries, want 1", len(items))
	}
	got := decodeRule(items[0])
	if !strings.Contains(got, "--dport 53") || !strings.Contains(got, "--to-destination fdfe:dcba:9876::2") {
		t.Fatalf("unexpected decoded IPv6 DNAT: %q", got)
	}
}

func TestBuildIPv6RedirectRule(t *testing.T) {
	rule, err := makeRuleFor("tcp", "", "Meta", "REDIRECT", 40707, 0, 0, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	items, err := decodeTable(rule)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeRule(items[0])
	if !strings.Contains(got, "-p tcp") || !strings.Contains(got, "-o Meta") || !strings.Contains(got, "--to-ports 40707") {
		t.Fatalf("unexpected decoded IPv6 REDIRECT: %q", got)
	}
}

func TestIPv6MarkTargetUsesRevision2(t *testing.T) {
	rule, err := makeRule("udp", "", "MARK", 0, 110, 0)
	if err != nil {
		t.Fatal(err)
	}
	entry := (*ip6tEntry)(unsafe.Pointer(&rule[0]))
	target := (*xtEntryTarget)(unsafe.Pointer(&rule[int(entry.TargetOffset)]))
	if target.Revision != 2 {
		t.Fatalf("MARK target revision=%d want=2", target.Revision)
	}
}
