//go:build linux

package iptables

import (
	"encoding/binary"
	"net"
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
		target := (*xtEntryTarget)(unsafe.Pointer(&r[int(e.TargetOffset)]))
		if c.target == "MARK" && target.Revision != 2 {
			t.Fatalf("MARK target revision=%d want=2", target.Revision)
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

func TestParseMihomoCommandSubset(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want command
	}{
		{
			name: "create nat user chain",
			args: []string{"-t", "nat", "-N", "mihomo-output"},
			want: command{table: "nat", operation: "new-chain", chain: "mihomo-output"},
		},
		{
			name: "insert at head of built-in output chain",
			args: []string{"-t", "nat", "-I", "OUTPUT", "-j", "mihomo-output"},
			want: command{table: "nat", operation: "insert", chain: "OUTPUT", target: "mihomo-output", position: 1},
		},
		{
			name: "insert at explicit position",
			args: []string{"-t", "nat", "-I", "OUTPUT", "3", "-p", "tcp", "-j", "mihomo-output"},
			want: command{table: "nat", operation: "insert", chain: "OUTPUT", position: 3, proto: "tcp", target: "mihomo-output"},
		},
		{
			name: "jump from built-in output to user chain",
			args: []string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "mihomo-output"},
			want: command{table: "nat", operation: "append", chain: "OUTPUT", proto: "tcp", target: "mihomo-output"},
		},
		{
			name: "udp dns dnat",
			args: []string{"-t", "nat", "-A", "mihomo-prerouting", "-p", "udp", "-m", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "198.19.0.2"},
			want: command{table: "nat", operation: "append", chain: "mihomo-prerouting", proto: "udp", target: "DNAT", dstIP: "198.19.0.2", dport: 53},
		},
		{
			name: "udp dns dnat short to alias used by mihomo",
			args: []string{"-t", "nat", "-A", "mihomo-prerouting", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", "198.19.0.2"},
			want: command{table: "nat", operation: "append", chain: "mihomo-prerouting", proto: "udp", target: "DNAT", dstIP: "198.19.0.2", dport: 53},
		},
		{
			name: "local destination return",
			args: []string{"-t", "nat", "-A", "mihomo-prerouting", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"},
			want: command{table: "nat", operation: "append", chain: "mihomo-prerouting", target: "RETURN", dstType: "LOCAL"},
		},
		{
			name: "output interface redirect",
			args: []string{"-t", "nat", "-A", "mihomo-output", "-o", "Meta", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "33643"},
			want: command{table: "nat", operation: "append", chain: "mihomo-output", outIface: "Meta", proto: "tcp", target: "REDIRECT", port: 33643},
		},
		{
			name: "filter accept",
			args: []string{"-t", "filter", "-A", "mihomo-input", "-i", "Meta", "-j", "ACCEPT"},
			want: command{table: "filter", operation: "append", chain: "mihomo-input", inIface: "Meta", target: "ACCEPT"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCommand(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("parseCommand() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestRuleInsertionOffsetBuiltInChain(t *testing.T) {
	info := iptGetInfo{}
	h := nfOutput
	info.ValidHooks = 1 << h
	info.HookEntry[h] = 100
	info.Underflow[h] = 260
	items := []decodedEntry{
		{offset: 100},
		{offset: 180},
		{offset: 260, isPolicy: true},
	}
	cases := []struct {
		position int
		want     int
	}{
		{1, 100}, // default -I: first rule
		{2, 180},
		{3, 260}, // one past the last rule: before policy
		{0, 260}, // append: before policy
	}
	for _, tc := range cases {
		got, err := ruleInsertionOffset(info, items, "nat", "OUTPUT", tc.position)
		if err != nil {
			t.Fatalf("position %d: %v", tc.position, err)
		}
		if got != tc.want {
			t.Errorf("position %d offset=%d want=%d", tc.position, got, tc.want)
		}
	}
	if _, err := ruleInsertionOffset(info, items, "nat", "OUTPUT", 4); err == nil {
		t.Fatal("out-of-range position was accepted")
	}
}

func TestRuleInsertionOffsetUserChain(t *testing.T) {
	ret := makeReturnEntry()
	retEntry := (*iptEntry)(unsafe.Pointer(&ret[0]))
	retTarget := (*xtEntryTarget)(unsafe.Pointer(&ret[int(retEntry.TargetOffset)]))
	retData := ret[int(retEntry.TargetOffset)+int(unsafe.Sizeof(xtEntryTarget{})):]
	items := []decodedEntry{
		{offset: 0, isMarker: true, chain: "mihomo-output"},
		{offset: 64},
		{offset: 128},
		{offset: 192, target: retTarget, targetData: retData},
	}
	info := iptGetInfo{}
	cases := []struct {
		position int
		want     int
	}{
		{1, 64},
		{2, 128},
		{3, 192}, // insertion after the last rule, before RETURN
		{0, 192}, // append
	}
	for _, tc := range cases {
		got, err := ruleInsertionOffset(info, items, "nat", "mihomo-output", tc.position)
		if err != nil {
			t.Fatalf("position %d: %v", tc.position, err)
		}
		if got != tc.want {
			t.Errorf("position %d offset=%d want=%d", tc.position, got, tc.want)
		}
	}
	if _, err := ruleInsertionOffset(info, items, "nat", "mihomo-output", 4); err == nil {
		t.Fatal("out-of-range position was accepted")
	}
}

func TestUserChainMarkerAndReturnLayout(t *testing.T) {
	marker, err := makeChainMarker("mihomo-output")
	if err != nil {
		t.Fatal(err)
	}
	ret := makeReturnEntry()
	blob := append(append([]byte{}, marker...), ret...)
	items, err := decodeTable(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("decoded %d entries, want 2", len(items))
	}
	if !items[0].isMarker || items[0].chain != "mihomo-output" {
		t.Fatalf("marker = %#v", items[0])
	}
	if cString(items[1].target.Name[:]) != "" || int32(binary.LittleEndian.Uint32(items[1].targetData[:4])) != -5 {
		t.Fatal("user chain does not end in standard RETURN")
	}
}

func TestMakeMihomoRuleLayouts(t *testing.T) {
	jump, err := makeRuleFor("tcp", "", "Meta", "CHAIN", 0, 0, 0, 224, "", "")
	if err != nil {
		t.Fatal(err)
	}
	je := (*iptEntry)(unsafe.Pointer(&jump[0]))
	if cString(je.IP.Outiface[:]) != "Meta" || je.IP.OutifaceMask[0] != 0xff {
		t.Fatal("output interface match was not encoded")
	}
	jt := (*xtEntryTarget)(unsafe.Pointer(&jump[int(je.TargetOffset)]))
	if cString(jt.Name[:]) != "" || binary.LittleEndian.Uint32(jump[int(je.TargetOffset)+int(unsafe.Sizeof(xtEntryTarget{})):]) != 224 {
		t.Fatal("user-chain jump target was not encoded")
	}

	dnat, err := makeRuleFor("udp", "", "", "DNAT", 0, 0, 53, 0, "", "198.19.0.2")
	if err != nil {
		t.Fatal(err)
	}
	de := (*iptEntry)(unsafe.Pointer(&dnat[0]))
	if de.IP.Proto != ipProtoUDP {
		t.Fatalf("DNAT protocol = %d, want UDP", de.IP.Proto)
	}
	if len(dnat[unsafe.Sizeof(iptEntry{}):int(de.TargetOffset)]) == 0 {
		t.Fatal("UDP destination-port match is missing")
	}
	dt := (*xtEntryTarget)(unsafe.Pointer(&dnat[int(de.TargetOffset)]))
	if cString(dt.Name[:]) != "DNAT" {
		t.Fatalf("DNAT target name = %q", cString(dt.Name[:]))
	}
	n := (*natMultiRange)(unsafe.Pointer(&dnat[int(de.TargetOffset)+int(unsafe.Sizeof(xtEntryTarget{}))]))
	ip := make([]byte, 4)
	binary.NativeEndian.PutUint32(ip, n.Range.MinIP)
	if got := net.IP(ip).String(); got != "198.19.0.2" {
		t.Fatalf("DNAT address = %s", got)
	}

	local, err := makeRuleFor("", "", "", "RETURN", 0, 0, 0, 0, "LOCAL", "")
	if err != nil {
		t.Fatal(err)
	}
	le := (*iptEntry)(unsafe.Pointer(&local[0]))
	m := (*xtEntryMatch)(unsafe.Pointer(&local[unsafe.Sizeof(iptEntry{})]))
	if cString(m.Name[:]) != "addrtype" || m.Revision != 1 {
		t.Fatalf("addrtype match = %q revision %d", cString(m.Name[:]), m.Revision)
	}
	a := (*xtAddrTypeInfoV1)(unsafe.Pointer(&local[unsafe.Sizeof(iptEntry{})+unsafe.Sizeof(xtEntryMatch{})]))
	if a.Dest != 0x0004 {
		t.Fatalf("addrtype destination = %d, want XT_ADDRTYPE_LOCAL (RTN_LOCAL=2, bit 2)", a.Dest)
	}
	_ = le
}

func TestParseRawTable(t *testing.T) {
	c, err := parseCommand([]string{"-t", "raw", "-A", "PREROUTING", "-j", "RETURN"})
	if err != nil {
		t.Fatal(err)
	}
	if c.table != "raw" || c.chain != "PREROUTING" {
		t.Fatalf("raw command parsed incorrectly: %#v", c)
	}
	if _, ok := tableHook("raw", "PREROUTING"); !ok {
		t.Fatal("raw PREROUTING hook not recognized")
	}
	if _, ok := tableHook("raw", "OUTPUT"); !ok {
		t.Fatal("raw OUTPUT hook not recognized")
	}
	if _, ok := tableHook("raw", "INPUT"); ok {
		t.Fatal("raw INPUT must not be a built-in hook")
	}
}

func TestDecodeUDPPortUsesNetworkByteOrder(t *testing.T) {
	entry := &iptEntry{}
	entry.IP.Proto = ipProtoUDP
	matches := make([]byte, align(int(unsafe.Sizeof(xtEntryMatch{}))+int(unsafe.Sizeof(xtUDP{}))))
	m := (*xtEntryMatch)(unsafe.Pointer(&matches[0]))
	m.Size = uint16(len(matches))
	cstr(m.Name[:], "udp")
	payload := matches[int(unsafe.Sizeof(xtEntryMatch{})):]
	// Match the ARM32 kernel dump: destination port 53 is stored as 35 00.
	payload[4], payload[5] = 0x35, 0x00
	payload[6], payload[7] = 0x35, 0x00
	got := decodeRule(decodedEntry{entry: entry, matches: matches})
	if !strings.Contains(got, "--dport 53") {
		t.Fatalf("decoded UDP rule = %q, want destination port 53", got)
	}
}

func TestDecodeAddrTypeLocalReturn(t *testing.T) {
	entry := &iptEntry{}
	target := &xtEntryTarget{}
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, ^uint32(4)) // standard RETURN verdict (-5)
	matches := make([]byte, align(int(unsafe.Sizeof(xtEntryMatch{}))+int(unsafe.Sizeof(xtAddrTypeInfoV1{}))))
	m := (*xtEntryMatch)(unsafe.Pointer(&matches[0]))
	m.Size = uint16(len(matches))
	m.Revision = 1
	cstr(m.Name[:], "addrtype")
	a := (*xtAddrTypeInfoV1)(unsafe.Pointer(&matches[unsafe.Sizeof(xtEntryMatch{})]))
	a.Dest = 0x0004 // XT_ADDRTYPE_LOCAL (RTN_LOCAL=2, bit 2)
	got := decodeRule(decodedEntry{entry: entry, target: target, targetData: data, matches: matches})
	want := "-m addrtype --dst-type LOCAL -j RETURN"
	if !strings.Contains(got, want) {
		t.Fatalf("decoded addrtype rule = %q, want to contain %q", got, want)
	}
}

func TestDecodeDNATCompactKernelPayload(t *testing.T) {
	entry := &iptEntry{}
	target := &xtEntryTarget{}
	cstr(target.Name[:], "DNAT")
	// Captured 32-bit legacy kernel payload: rangesize followed by the
	// network-order IPv4 address 198.19.0.2.
	data := []byte{
		0x01, 0x00, 0x00, 0x00,
		0xc6, 0x13, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	got := decodeRule(decodedEntry{entry: entry, target: target, targetData: data})
	if !strings.Contains(got, "--to-destination 198.19.0.2") {
		t.Fatalf("decoded DNAT rule = %q, want destination 198.19.0.2", got)
	}
}
