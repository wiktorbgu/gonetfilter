//go:build linux

package main

import (
	"strings"
	"testing"
	"unsafe"
)

func TestLegacyABISizes(t *testing.T) {
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"ipt_entry", unsafe.Sizeof(iptEntry{}), 112},
		{"ipt_getinfo", unsafe.Sizeof(iptGetInfo{}), 84},
		{"ipt_get_entries", unsafe.Sizeof(iptGetEntries{}), 40},
		{"ipt_replace_header_aligned", uintptr(align(int(unsafe.Sizeof(iptReplace{})))), 96},
		{"xt_entry_target", unsafe.Sizeof(xtEntryTarget{}), 32},
		{"xt_entry_match", unsafe.Sizeof(xtEntryMatch{}), 32},
		{"nat_range", unsafe.Sizeof(natRange{}), 16},
		{"nat_multi_range", unsafe.Sizeof(natMultiRange{}), 20},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s size=%d want=%d", c.name, c.got, c.want)
		}
	}
}

func TestIPTReplaceFlexibleArrayAlignment(t *testing.T) {
	if got := unsafe.Offsetof(iptReplace{}.Counters); got != 88 {
		t.Fatalf("ipt_replace counters offset=%d want=88", got)
	}
	got := align(int(unsafe.Sizeof(iptReplace{})))
	if got != 96 {
		t.Fatalf("ipt_replace entries payload offset=%d want=96", got)
	}
	if got < int(unsafe.Sizeof(iptReplace{})) {
		t.Fatalf("aligned header %d is smaller than struct size %d", got, unsafe.Sizeof(iptReplace{}))
	}
}

func TestRuleLayouts(t *testing.T) {
	cases := []struct {
		target, proto, iface string
		port, mark, dport    int
	}{
		{"REDIRECT", "tcp", "br-lan", 4080, 0, 0},
		{"MASQUERADE", "", "", 0, 0, 0},
		{"MARK", "udp", "br-lan", 0, 110, 0},
		{"DROP", "udp", "", 0, 0, 443},
	}
	for _, c := range cases {
		r, err := makeRule(c.proto, c.iface, c.target, c.port, c.mark, c.dport)
		if err != nil {
			t.Fatal(err)
		}
		e := (*iptEntry)(unsafe.Pointer(&r[0]))
		if int(e.NextOffset) != len(r) {
			t.Fatalf("%s next_offset=%d len=%d", c.target, e.NextOffset, len(r))
		}
		if int(e.TargetOffset) >= len(r) {
			t.Fatalf("%s invalid target offset", c.target)
		}
	}
}

func TestHookEntryAtInsertPointStaysAtInsertedRule(t *testing.T) {
	info := iptGetInfo{}
	info.HookEntry[0] = 504
	info.Underflow[0] = 504
	shiftHookOffsets(&info, 504, 168)
	if info.HookEntry[0] != 504 {
		t.Fatalf("HookEntry moved past inserted rule: got %d want 504", info.HookEntry[0])
	}
	if info.Underflow[0] != 504 {
		t.Fatalf("shiftHookOffsets must not modify Underflow")
	}
	info.HookEntry[1] = 672
	shiftHookOffsets(&info, 504, 168)
	if info.HookEntry[1] != 840 {
		t.Fatalf("later HookEntry not shifted: got %d want 840", info.HookEntry[1])
	}
}

func TestStandardDropTargetIsNotAutomaticallyPolicy(t *testing.T) {
	rule, err := makeRule("udp", "", "DROP", 0, 0, 443)
	if err != nil {
		t.Fatal(err)
	}
	items, err := decodeTable(rule)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("decoded %d entries, want 1", len(items))
	}
	if items[0].isPolicy {
		t.Fatal("ordinary DROP rule incorrectly classified as chain policy")
	}
	if got := decodeRule(items[0]); !strings.Contains(got, "-j DROP") {
		t.Fatalf("DROP rule not decoded: %q", got)
	}
}
