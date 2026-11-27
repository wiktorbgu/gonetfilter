//go:build linux

package nft

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestFamilySupportsIPAndINET(t *testing.T) {
	cases := map[string]nftables.TableFamily{
		"ip":   nftables.TableFamilyIPv4,
		"ip6":  nftables.TableFamilyIPv6,
		"inet": nftables.TableFamilyINet,
	}
	for name, want := range cases {
		got, err := family(name)
		if err != nil || got != want {
			t.Fatalf("family(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
	if _, err := family("bridge"); err == nil {
		t.Fatal("family(bridge) unexpectedly succeeded")
	}
}

func TestPriorityLabelUsesNamedBaseAndArithmeticOffset(t *testing.T) {
	cases := []struct {
		name string
		got  nftables.ChainPriority
		want string
	}{
		{name: "exact mangle", got: *nftables.ChainPriorityMangle, want: "mangle"},
		{name: "below mangle", got: *nftables.ChainPriorityMangle - 5, want: "mangle - 5"},
		{name: "above mangle", got: *nftables.ChainPriorityMangle + 5, want: "mangle + 5"},
		{name: "below filter", got: *nftables.ChainPriorityFilter - 10, want: "filter - 10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := priorityLabel(tc.got); got != tc.want {
				t.Fatalf("priorityLabel(%d) = %q, want %q", tc.got, got, tc.want)
			}
		})
	}
}

func TestSplitMultilineChainCommand(t *testing.T) {
	got := splitCommand("add chain inet tproxy_ci divert {\n type filter hook prerouting priority mangle - 5;\n policy accept;\n}")
	want := []string{"add", "chain", "inet", "tproxy_ci", "divert", "{", "type", "filter", "hook", "prerouting", "priority", "mangle", "-", "5", ";", "policy", "accept", ";", "}"}
	if len(got) != len(want) {
		t.Fatalf("splitCommand returned %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token %d = %q, want %q (all: %#v)", i, got[i], want[i], got)
		}
	}
}

func TestBuildTPROXYRulesIPv4AndIPv6(t *testing.T) {
	cases := []struct {
		name       string
		family     nftables.TableFamily
		cmd        []string
		wantFamily byte
	}{
		{"ipv4", nftables.TableFamilyINet, []string{"iifname", `"eth0"`, "meta", "l4proto", "{", "tcp,", "udp", "}", "meta", "mark", "set", "0x123", "tproxy", "ip", "to", "127.0.0.1:15123", "accept"}, unix.NFPROTO_IPV4},
		{"ipv6", nftables.TableFamilyINet, []string{"iifname", `"eth0"`, "meta", "l4proto", "{", "tcp,", "udp", "}", "meta", "mark", "set", "0x123", "tproxy", "ip6", "to", "[::1]:15123", "accept"}, unix.NFPROTO_IPV6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules, sets, err := buildRules(tc.family, tc.cmd)
			if err != nil {
				t.Fatal(err)
			}
			if len(rules) != 1 {
				t.Fatalf("got %d rules, want one grouped TCP+UDP rule", len(rules))
			}
			if len(sets) != 1 || len(sets[0].elements) != 2 || sets[0].keyType != nftables.TypeInetProto {
				t.Fatalf("unexpected protocol set: %#v", sets)
			}
			for _, rule := range rules {
				found := false
				lookupFound := false
				for _, e := range rule {
					if _, ok := e.(*expr.Lookup); ok {
						lookupFound = true
					}
					if tp, ok := e.(*expr.TProxy); ok {
						found = true
						if tp.Family != tc.wantFamily {
							t.Errorf("TProxy family = %d, want %d", tp.Family, tc.wantFamily)
						}
						if tp.RegAddr != 1 || tp.RegPort != 2 {
							t.Errorf("TProxy registers = addr:%d port:%d, want addr:1 port:2", tp.RegAddr, tp.RegPort)
						}
					}
				}
				if !found {
					t.Error("rule has no TProxy expression")
				}
				if !lookupFound {
					t.Error("rule has no kernel set lookup for l4proto")
				}
			}
		})
	}
}

func TestBuildSocketTransparentRule(t *testing.T) {
	cmd := []string{"meta", "l4proto", "tcp", "socket", "transparent", "1", "meta", "mark", "set", "0x123", "accept"}
	rules, _, err := buildRules(nftables.TableFamilyINet, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	found := false
	for _, e := range rules[0] {
		if _, ok := e.(*expr.Socket); ok {
			found = true
		}
	}
	if !found {
		t.Fatal("socket expression missing")
	}
}

func TestBuildFibLocalExclusions(t *testing.T) {
	cmd := []string{"fib", "daddr", "type", "{", "local,", "broadcast,", "multicast", "}", "return"}
	rules, sets, err := buildRules(nftables.TableFamilyINet, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want one grouped FIB rule", len(rules))
	}
	if len(sets) != 1 || len(sets[0].elements) != 3 || sets[0].keyType != nftables.TypeFIBAddr {
		t.Fatalf("unexpected FIB set: %#v", sets)
	}
}

func TestBuildIPv4DestinationFallback(t *testing.T) {
	cmd := []string{"ip", "daddr", "{", "0.0.0.0/8,", "127.0.0.0/8,", "192.0.2.10", "}", "return"}
	rules, _, err := buildRules(nftables.TableFamilyINet, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("got %d destination rules, want 3", len(rules))
	}
	for _, rule := range rules {
		found := false
		for _, e := range rule {
			if _, ok := e.(*expr.Payload); ok {
				found = true
			}
		}
		if !found {
			t.Error("destination rule has no IPv4 payload match")
		}
	}
}

func TestAssignNamedSetNamesRemapsLookup(t *testing.T) {
	lookup := &expr.Lookup{SourceRegister: 1, SetID: 1}
	rules := [][]expr.Any{{lookup}}
	sets := []setSpec{{id: 1, keyType: nftables.TypeInetProto}}
	if err := assignNamedSetNames(rules, sets); err != nil {
		t.Fatal(err)
	}
	if sets[0].name == "" || !strings.HasPrefix(sets[0].name, "gn_") {
		t.Fatalf("unexpected kernel set name %q", sets[0].name)
	}
	if lookup.SetName != sets[0].name || lookup.SetID != 0 {
		t.Fatalf("lookup references name=%q id=%d, set name=%q", lookup.SetName, lookup.SetID, sets[0].name)
	}
}

func TestFormatKernelSetKeys(t *testing.T) {
	proto, ok := formatSetKey(nftables.TypeInetProto, []byte{unix.IPPROTO_TCP})
	if !ok || proto != "tcp" {
		t.Fatalf("TCP set key = %q, %v", proto, ok)
	}
	fib, ok := formatSetKey(nftables.TypeFIBAddr, binary.NativeEndian.AppendUint32(nil, 5))
	if !ok || fib != "multicast" {
		t.Fatalf("FIB set key = %q, %v", fib, ok)
	}
}

func TestFormatRuleResolvesNamedSetLookups(t *testing.T) {
	labels := map[string]string{
		"gn_proto": "{ tcp, udp }",
		"gn_fib":   "{ local, broadcast, multicast }",
	}
	protoRule := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: "gn_proto"},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
	got := formatRuleWithSets(protoRule, labels)
	if !strings.Contains(got, "meta l4proto { tcp, udp }") || !strings.Contains(got, "accept") {
		t.Fatalf("protocol rule formatted as %q", got)
	}
	fibRule := []expr.Any{
		&expr.Fib{Register: 1, ResultADDRTYPE: true, FlagDADDR: true},
		&expr.Lookup{SourceRegister: 1, SetName: "gn_fib"},
		&expr.Verdict{Kind: expr.VerdictReturn},
	}
	got = formatRuleWithSets(fibRule, labels)
	if !strings.Contains(got, "fib daddr type { local, broadcast, multicast }") || !strings.Contains(got, "return") {
		t.Fatalf("FIB rule formatted as %q", got)
	}
}

func TestBuildMasqueradePreservesIPv4DestinationExclusions(t *testing.T) {
	cmd := []string{
		"meta", "oiftype", "ether", "ip", "daddr", "!=", "{",
		"127.0.0.0/8,", "169.254.0.0/16,", "224.0.0.0/4,", "255.255.255.255", "}", "masquerade",
	}
	rules, sets, err := buildRules(nftables.TableFamilyIPv4, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 0 {
		t.Fatalf("unexpected sets: %#v", sets)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want one", len(rules))
	}
	neq := 0
	masq := false
	for _, item := range rules[0] {
		if cmp, ok := item.(*expr.Cmp); ok && cmp.Op == expr.CmpOpNeq {
			neq++
		}
		if _, ok := item.(*expr.Masq); ok {
			masq = true
		}
	}
	if neq != 4 || !masq {
		t.Fatalf("got %d exclusion comparisons and masquerade=%v; want 4 and true", neq, masq)
	}
	got := formatRule(rules[0])
	for _, prefix := range []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"} {
		if !strings.Contains(got, prefix) {
			t.Errorf("formatted rule %q does not contain %q", got, prefix)
		}
	}
	if !strings.Contains(got, "masquerade") {
		t.Errorf("formatted rule %q does not contain masquerade", got)
	}
}

func TestParseIPv4PrefixSetWithAttachedClosingBrace(t *testing.T) {
	got, err := parseIPv4PrefixSet([]string{
		"{", "127.0.0.0/8,", "169.254.0.0/16,", "224.0.0.0/4,",
		"255.255.255.255}", "masquerade",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"}
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if canonicalIPv4Prefix(got[i]) != want[i] {
			t.Errorf("prefix %d = %q, want %q", i, canonicalIPv4Prefix(got[i]), want[i])
		}
	}
}

func TestFormatSocketTransparentRule(t *testing.T) {
	cmd := []string{"meta", "l4proto", "tcp", "socket", "transparent", "1", "meta", "mark", "set", "0x123", "accept"}
	rules, _, err := buildRules(nftables.TableFamilyINet, cmd)
	if err != nil {
		t.Fatal(err)
	}
	got := formatRule(rules[0])
	if !strings.Contains(got, "socket transparent 1") {
		t.Fatalf("formatted rule %q does not contain socket transparent", got)
	}
}

func TestFormatTPROXYIPv4AndIPv6(t *testing.T) {
	cases := []struct {
		name   string
		family byte
		addr   []byte
		want   string
	}{
		{"ipv4", unix.NFPROTO_IPV4, []byte{127, 0, 0, 1}, "tproxy ip to 127.0.0.1:15123"},
		{"ipv6", unix.NFPROTO_IPV6, net.ParseIP("::1").To16(), "tproxy ip6 to [::1]:15123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			es := []expr.Any{
				&expr.Immediate{Register: 1, Data: binary.NativeEndian.AppendUint32(nil, 0x123)},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
				&expr.Immediate{Register: 1, Data: tc.addr},
				&expr.Immediate{Register: 2, Data: []byte{0x3b, 0x13}},
				&expr.TProxy{Family: tc.family, RegAddr: 1, RegPort: 2},
				&expr.Verdict{Kind: expr.VerdictAccept},
			}
			got := formatRule(es)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("formatted rule %q does not contain %q", got, tc.want)
			}
			if strings.Contains(got, "immediate") {
				t.Fatalf("formatted rule contains leaked immediate operands: %q", got)
			}
		})
	}
}

func TestFormatNativeEndianKernelScalars(t *testing.T) {
	oif := formatRule([]expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFTYPE},
		&expr.Cmp{Op: expr.CmpOpEq, Data: binary.NativeEndian.AppendUint16(nil, uint16(unix.ARPHRD_ETHER))},
	})
	if oif != "meta oiftype ether" {
		t.Fatalf("oiftype formatted as %q", oif)
	}
	mark := formatRule([]expr.Any{
		&expr.Immediate{Register: 1, Data: binary.NativeEndian.AppendUint32(nil, 0x123)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
	})
	if mark != "meta mark set 0x00000123" {
		t.Fatalf("mark formatted as %q", mark)
	}
	fib := formatRule([]expr.Any{
		&expr.Fib{FlagDADDR: true, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpEq, Data: binary.NativeEndian.AppendUint32(nil, 2)},
		&expr.Verdict{Kind: expr.VerdictReturn},
	})
	if !strings.Contains(fib, "local") {
		t.Fatalf("FIB formatted as %q", fib)
	}
}

func TestFormatIPv4IntervalSet(t *testing.T) {
	elements := []nftables.SetElement{
		{Key: net.ParseIP("127.0.0.0").To4()},
		{Key: net.ParseIP("128.0.0.0").To4(), IntervalEnd: true},
		{Key: net.ParseIP("169.254.0.0").To4()},
		{Key: net.ParseIP("169.255.0.0").To4(), IntervalEnd: true},
		{Key: net.ParseIP("224.0.0.0").To4()},
		{Key: net.ParseIP("240.0.0.0").To4(), IntervalEnd: true},
		{Key: net.ParseIP("255.255.255.255").To4()},
	}
	got := formatIPv4SetElements(elements, true)
	want := []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("interval set = %#v, want %#v", got, want)
	}
}

func TestFormatIPv4PayloadInvertedLookup(t *testing.T) {
	rule := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFTYPE},
		&expr.Cmp{Op: expr.CmpOpEq, Data: binary.NativeEndian.AppendUint16(nil, uint16(unix.ARPHRD_ETHER))},
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
		&expr.Lookup{SourceRegister: 1, SetName: "__set0", Invert: true},
		&expr.Masq{},
	}
	got := formatRuleWithSets(rule, map[string]string{"__set0": "{ 127.0.0.0/8, 169.254.0.0/16 }"})
	want := "meta oiftype ether ip daddr != { 127.0.0.0/8, 169.254.0.0/16 } masquerade"
	if got != want {
		t.Fatalf("formatted NAT rule = %q, want %q", got, want)
	}
}
