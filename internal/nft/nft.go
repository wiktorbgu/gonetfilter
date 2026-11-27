// tiny-nft: intentionally small nft(8) compatibility shim for this project's
// entrypoint. It programs Linux nftables through Netlink; it never execs nft.
package nft

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Main executes the compact nftables CLI and returns its process exit code.
func Main(args []string) int {
	if len(args) == 1 {
		// The entrypoint passes multiline chain declarations as one quoted
		// argument. Split that argument while preserving quoted interface names.
		args = splitCommand(args[0])
	}
	if len(args) < 1 {
		printBanner(os.Stdout)
		return 0
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(os.Stdout)
		return 0
	}
	var err error
	switch args[0] {
	case "add":
		if len(args) < 2 {
			err = errors.New("incomplete add command")
		} else {
			switch args[1] {
			case "table":
				err = addTable(args[2:])
			case "chain":
				err = addChain(args[2:])
			case "rule":
				err = addRule(args[2:])
			default:
				err = fmt.Errorf("unsupported add operation %q", args[1])
			}
		}
	case "list":
		if len(args) != 2 || args[1] != "ruleset" {
			err = errors.New("usage: nft list ruleset")
		} else {
			err = listRuleset()
		}
	default:
		err = fmt.Errorf("unsupported command %q", args[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "nft:", err)
		return 1
	}
	return 0
}

// printBanner keeps the no-argument output compact, like the iptables frontends.
func printBanner(w *os.File) {
	fmt.Fprintln(w, "nft: compact nftables subset")
	fmt.Fprintln(w, "Supported: add table/chain/rule, list ruleset ... OR nft list ruleset")
}

// printUsage documents the supported subset and practical command examples.
func printUsage(w *os.File) {
	fmt.Fprintln(w, "nft: compact nftables subset for GoNetFilter")
	fmt.Fprintln(w, "This is a limited frontend, not a full nft(8) replacement.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Supported commands:")
	fmt.Fprintln(w, "  nft add table FAMILY TABLE")
	fmt.Fprintln(w, "  nft add chain FAMILY TABLE CHAIN '{ type TYPE hook HOOK priority PRIORITY; policy POLICY; }'")
	fmt.Fprintln(w, "  nft add rule FAMILY TABLE CHAIN EXPRESSION...")
	fmt.Fprintln(w, "  nft list ruleset")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  nft list ruleset")
	fmt.Fprintln(w, "  nft add table inet filter")
	fmt.Fprintln(w, "  nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'")
	fmt.Fprintln(w, "  nft add rule inet filter input counter accept")
}

// listRuleset reads the current ruleset from the kernel using Netlink.
// Expressions are printed with their decoded Go type and fields. This is an
// inspection/debug view, not a full nft(8)-compatible pretty-printer.
func listRuleset() error {
	c, err := conn()
	if err != nil {
		return err
	}
	tables, err := c.ListTables()
	if err != nil {
		return fmt.Errorf("netlink receive while listing tables: %w", err)
	}
	chains, err := c.ListChains()
	if err != nil {
		return fmt.Errorf("netlink receive while listing chains: %w", err)
	}

	chainsByTable := make(map[string][]*nftables.Chain)
	for _, ch := range chains {
		if ch.Table == nil {
			continue
		}
		key := fmt.Sprintf("%d/%s", ch.Table.Family, ch.Table.Name)
		chainsByTable[key] = append(chainsByTable[key], ch)
	}

	if len(tables) == 0 {
		fmt.Println("# no nftables tables found")
		return nil
	}

	for _, table := range tables {
		setLabels, err := loadSetLabels(c, table)
		if err != nil {
			return fmt.Errorf("list sets in %s/%s: %w", familyLabel(table.Family), table.Name, err)
		}
		fmt.Printf("table %s %s {\n", familyLabel(table.Family), table.Name)
		key := fmt.Sprintf("%d/%s", table.Family, table.Name)
		for _, ch := range chainsByTable[key] {
			fmt.Printf("\tchain %s {\n", ch.Name)
			if ch.Type != "" {
				fmt.Printf("\t\ttype %s", ch.Type)
				if ch.Hooknum != nil {
					fmt.Printf(" hook %s", hookLabel(*ch.Hooknum))
				}
				if ch.Priority != nil {
					fmt.Printf(" priority %s", priorityLabel(*ch.Priority))
				}
				fmt.Print(";")
				if ch.Policy != nil {
					fmt.Printf(" policy %s;", policyLabel(*ch.Policy))
				}
				fmt.Println()
			}

			rules, err := c.GetRules(table, ch)
			if err != nil {
				return fmt.Errorf("list rules in %s/%s/%s: %w", familyLabel(table.Family), table.Name, ch.Name, err)
			}
			for _, rule := range rules {
				fmt.Printf("\t\t%s\n", formatRuleWithSets(rule.Exprs, setLabels))
			}
			fmt.Println("\t}")
		}
		fmt.Println("}")
	}
	return nil
}

// loadSetLabels retrieves named-set elements from the kernel and prepares
// compact nft-style labels keyed by the set name referenced by expr.Lookup.
func loadSetLabels(c *nftables.Conn, table *nftables.Table) (map[string]string, error) {
	labels := make(map[string]string)
	sets, err := c.GetSets(table)
	if err != nil {
		return nil, err
	}
	for _, set := range sets {
		elements, err := c.GetSetElements(set)
		if err != nil {
			return nil, fmt.Errorf("read set %q: %w", set.Name, err)
		}
		values := make([]string, 0, len(elements))
		if set.KeyType == nftables.TypeIPAddr {
			values = formatIPv4SetElements(elements, set.Interval)
		} else {
			for _, element := range elements {
				value, ok := formatSetKey(set.KeyType, element.Key)
				if ok {
					values = append(values, value)
				}
			}
		}
		if len(values) != 0 {
			// Kernel set element iteration order is not guaranteed. Keep the
			// textual output stable and close to nft(8)'s canonical order.
			sortSetValues(set.KeyType, values)
			labels[set.Name] = "{ " + strings.Join(values, ", ") + " }"
		}
	}
	return labels, nil
}

// formatIPv4SetElements reconstructs IPv4 values from kernel set elements.
// Interval sets are returned as alternating inclusive-start and exclusive-end
// markers. The resulting ranges are rendered as the minimal CIDR list.
func formatIPv4SetElements(elements []nftables.SetElement, interval bool) []string {
	ordered := append([]nftables.SetElement(nil), elements...)
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i].Key, ordered[j].Key) < 0 })
	var values []string
	var pending []byte
	for _, element := range ordered {
		if len(element.Key) != 4 {
			continue
		}
		if !interval {
			var raw [4]byte
			copy(raw[:], element.Key)
			values = append(values, netip.AddrFrom4(raw).String())
			continue
		}
		if element.IntervalEnd {
			if len(pending) == 4 {
				values = append(values, ipv4RangePrefixes(pending, element.Key)...)
				pending = nil
			}
			continue
		}
		if len(element.KeyEnd) == 4 {
			values = append(values, ipv4RangePrefixes(element.Key, element.KeyEnd)...)
			continue
		}
		if len(pending) == 4 {
			var raw [4]byte
			copy(raw[:], pending)
			values = append(values, canonicalIPv4Prefix(netip.PrefixFrom(netip.AddrFrom4(raw), 32)))
		}
		pending = append(pending[:0], element.Key...)
	}
	if len(pending) == 4 {
		var raw [4]byte
		copy(raw[:], pending)
		values = append(values, canonicalIPv4Prefix(netip.PrefixFrom(netip.AddrFrom4(raw), 32)))
	}
	return values
}

// canonicalIPv4Prefix matches nft(8) display: host addresses are printed
// without an explicit /32 suffix, while shorter network prefixes retain it.
func canonicalIPv4Prefix(prefix netip.Prefix) string {
	if prefix.Bits() == 32 {
		return prefix.Addr().String()
	}
	return prefix.String()
}

// ipv4RangePrefixes converts [start, endExclusive) into its minimal CIDR cover.
func ipv4RangePrefixes(startBytes, endBytes []byte) []string {
	if len(startBytes) != 4 || len(endBytes) != 4 {
		return nil
	}
	start := uint64(binary.BigEndian.Uint32(startBytes))
	end := uint64(binary.BigEndian.Uint32(endBytes))
	if end <= start {
		if end == 0 && start == 0xffffffff {
			var raw [4]byte
			binary.BigEndian.PutUint32(raw[:], uint32(start))
			return []string{canonicalIPv4Prefix(netip.PrefixFrom(netip.AddrFrom4(raw), 32))}
		}
		return nil
	}
	var out []string
	for start < end {
		align := 32
		if start != 0 {
			align = bits.TrailingZeros32(uint32(start))
		}
		remaining := end - start
		maxPower := bits.Len64(remaining) - 1
		if align > maxPower {
			align = maxPower
		}
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], uint32(start))
		out = append(out, canonicalIPv4Prefix(netip.PrefixFrom(netip.AddrFrom4(raw), 32-align)))
		start += uint64(1) << uint(align)
	}
	return out
}

func sortSetValues(keyType nftables.SetDatatype, values []string) {
	switch keyType {
	case nftables.TypeFIBAddr:
		rank := map[string]int{"local": 0, "broadcast": 1, "multicast": 2}
		sort.SliceStable(values, func(i, j int) bool {
			ri, iok := rank[values[i]]
			rj, jok := rank[values[j]]
			if iok && jok {
				return ri < rj
			}
			if iok != jok {
				return iok
			}
			return values[i] < values[j]
		})
	case nftables.TypeInetProto:
		rank := map[string]int{"tcp": 0, "udp": 1}
		sort.SliceStable(values, func(i, j int) bool {
			ri, iok := rank[values[i]]
			rj, jok := rank[values[j]]
			if iok && jok {
				return ri < rj
			}
			if iok != jok {
				return iok
			}
			return values[i] < values[j]
		})
	}
}

func formatSetKey(keyType nftables.SetDatatype, key []byte) (string, bool) {
	switch keyType {
	case nftables.TypeInetProto:
		if len(key) != 1 {
			return "", false
		}
		switch key[0] {
		case unix.IPPROTO_TCP:
			return "tcp", true
		case unix.IPPROTO_UDP:
			return "udp", true
		default:
			return strconv.Itoa(int(key[0])), true
		}
	case nftables.TypeFIBAddr:
		if len(key) < 4 {
			return "", false
		}
		v := binary.NativeEndian.Uint32(key[:4])
		if name, ok := map[uint32]string{2: "local", 3: "broadcast", 5: "multicast"}[v]; ok {
			return name, true
		}
		return strconv.FormatUint(uint64(v), 10), true
	default:
		return "", false
	}
}

// formatRule is retained for tests and callers that do not have a set cache.
func formatRule(es []expr.Any) string { return formatRuleWithSets(es, nil) }

// formatRuleWithSets renders the expression sequence and resolves Lookup
// references against the set elements fetched from the kernel.
func formatRuleWithSets(es []expr.Any, setLabels map[string]string) string {
	var parts []string
	for i := 0; i < len(es); i++ {
		switch e := es[i].(type) {
		case *expr.Meta:
			switch e.Key {
			case expr.MetaKeyIIFNAME:
				if i+1 < len(es) {
					if c, ok := es[i+1].(*expr.Cmp); ok {
						parts = append(parts, "iifname "+strconv.Quote(trimNUL(string(c.Data))))
						i++
						continue
					}
				}
				parts = append(parts, "meta iifname")
			case expr.MetaKeyL4PROTO:
				if i+1 < len(es) {
					if lookup, ok := es[i+1].(*expr.Lookup); ok {
						if label, found := setLabels[lookup.SetName]; found {
							parts = append(parts, "meta l4proto "+label)
						} else {
							parts = append(parts, "meta l4proto <set "+lookup.SetName+">")
						}
						i++
						continue
					}
				}
				// "udp dport" already implies UDP. The kernel expression
				// sequence is Meta(l4proto), Cmp(udp), Payload(dport), Cmp(port).
				if i+3 < len(es) {
					if c, ok := es[i+1].(*expr.Cmp); ok && len(c.Data) > 0 && c.Data[0] == unix.IPPROTO_UDP {
						if p, ok := es[i+2].(*expr.Payload); ok &&
							p.Base == expr.PayloadBaseTransportHeader && p.Offset == 2 && p.Len == 2 {
							if _, ok := es[i+3].(*expr.Cmp); ok {
								i++ // also consume the UDP protocol comparison
								continue
							}
						}
					}
				}
				proto := "?"
				if i+1 < len(es) {
					if c, ok := es[i+1].(*expr.Cmp); ok && len(c.Data) > 0 {
						switch c.Data[0] {
						case unix.IPPROTO_TCP:
							proto = "tcp"
						case unix.IPPROTO_UDP:
							proto = "udp"
						default:
							proto = strconv.Itoa(int(c.Data[0]))
						}
						i++
					}
				}
				parts = append(parts, "meta l4proto "+proto)
			case expr.MetaKeyOIFTYPE:
				kind := "?"
				if i+1 < len(es) {
					if c, ok := es[i+1].(*expr.Cmp); ok {
						// NFT_META_OIFTYPE is a 16-bit hardware type, unlike
						// mark/FIB values which are 32-bit scalars.
						if len(c.Data) >= 2 && binary.NativeEndian.Uint16(c.Data[:2]) == uint16(unix.ARPHRD_ETHER) {
							kind = "ether"
						}
						i++
					}
				}
				parts = append(parts, "meta oiftype "+kind)
			case expr.MetaKeyMARK:
				if e.SourceRegister && i > 0 {
					if imm, ok := es[i-1].(*expr.Immediate); ok && len(imm.Data) >= 4 {
						parts = append(parts, fmt.Sprintf("meta mark set 0x%08x", binary.NativeEndian.Uint32(imm.Data[:4])))
						continue
					}
				}
				parts = append(parts, "meta mark")
			default:
				parts = append(parts, fmt.Sprintf("meta key-%d", e.Key))
			}
		case *expr.Payload:
			if e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 16 && e.Len == 4 && i+1 < len(es) {
				if lookup, ok := es[i+1].(*expr.Lookup); ok {
					if label, found := setLabels[lookup.SetName]; found {
						operator := "in"
						if lookup.Invert {
							operator = "!="
						}
						parts = append(parts, "ip daddr "+operator+" "+label)
						i++
						continue
					}
				}
			}
			if e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 16 && e.Len == 4 {
				var exclusions []string
				j := i
				for j+2 < len(es) {
					payload, okPayload := es[j].(*expr.Payload)
					maskExpr, okMask := es[j+1].(*expr.Bitwise)
					cmp, okCmp := es[j+2].(*expr.Cmp)
					if !okPayload || payload.Base != expr.PayloadBaseNetworkHeader || payload.Offset != 16 || payload.Len != 4 || !okMask || !okCmp || cmp.Op != expr.CmpOpNeq || len(cmp.Data) != 4 || len(maskExpr.Mask) != 4 {
						break
					}
					bits, valid := maskPrefixBits(maskExpr.Mask)
					if !valid {
						break
					}
					var raw [4]byte
					copy(raw[:], cmp.Data)
					prefix := netip.PrefixFrom(netip.AddrFrom4(raw), bits).Masked()
					if bits == 32 {
						exclusions = append(exclusions, prefix.Addr().String())
					} else {
						exclusions = append(exclusions, prefix.String())
					}
					j += 3
				}
				if len(exclusions) != 0 {
					parts = append(parts, "ip daddr != { "+strings.Join(exclusions, ", ")+" }")
					i = j - 1
					continue
				}
			}
			if e.Base == expr.PayloadBaseTransportHeader && e.Offset == 2 && e.Len == 2 && i+1 < len(es) {
				if c, ok := es[i+1].(*expr.Cmp); ok && len(c.Data) >= 2 {
					parts = append(parts, fmt.Sprintf("udp dport %d", binary.BigEndian.Uint16(c.Data[:2])))
					i++
					continue
				}
			}
			parts = append(parts, "payload")
		case *expr.Fib:
			if e.FlagDADDR && e.ResultADDRTYPE {
				if i+1 < len(es) {
					if lookup, ok := es[i+1].(*expr.Lookup); ok {
						if label, found := setLabels[lookup.SetName]; found {
							parts = append(parts, "fib daddr type "+label)
						} else {
							parts = append(parts, "fib daddr type <set "+lookup.SetName+">")
						}
						i++
						continue
					}
				}
				if i+2 < len(es) {
					if c, ok := es[i+1].(*expr.Cmp); ok && len(c.Data) >= 4 {
						typ := binary.NativeEndian.Uint32(c.Data[:4])
						name := map[uint32]string{2: "local", 3: "broadcast", 5: "multicast"}[typ]
						if name == "" {
							name = strconv.FormatUint(uint64(typ), 10)
						}
						parts = append(parts, "fib daddr type == "+name)
						i++
						continue
					}
				}
				parts = append(parts, "fib daddr type")
			} else {
				parts = append(parts, "fib")
			}
		case *expr.Exthdr:
			if e.Op == expr.ExthdrOpTcpopt && e.Type == 30 {
				parts = append(parts, "tcp option mptcp exists")
				if i+1 < len(es) {
					if _, ok := es[i+1].(*expr.Cmp); ok {
						i++
					}
				}
			} else {
				parts = append(parts, fmt.Sprintf("exthdr type-%d", e.Type))
			}
		case *expr.Socket:
			if e.Key == expr.SocketKeyTransparent {
				parts = append(parts, "socket transparent 1")
				if i+1 < len(es) {
					if _, ok := es[i+1].(*expr.Cmp); ok {
						i++
					}
				}
			} else {
				parts = append(parts, "socket")
			}
		case *expr.TProxy:
			addr, port := "?", "?"
			if i >= 2 {
				if a, ok := es[i-2].(*expr.Immediate); ok {
					ip := net.IP(a.Data)
					if e.Family == unix.NFPROTO_IPV4 {
						addr = ip.To4().String()
					} else {
						addr = "[" + ip.String() + "]"
					}
				}
				if p, ok := es[i-1].(*expr.Immediate); ok && len(p.Data) >= 2 {
					port = strconv.Itoa(int(binary.BigEndian.Uint16(p.Data[:2])))
				}
			}
			fam := "ip"
			if e.Family == unix.NFPROTO_IPV6 {
				fam = "ip6"
			}
			parts = append(parts, fmt.Sprintf("tproxy %s to %s:%s", fam, addr, port))
		case *expr.Immediate:
			// The address and port immediates immediately preceding a TPROXY
			// expression are its operands, not standalone nft statements.
			if i+1 < len(es) {
				if _, ok := es[i+1].(*expr.Immediate); ok && i+2 < len(es) {
					if _, isTProxy := es[i+2].(*expr.TProxy); isTProxy {
						continue
					}
				}
				if _, isTProxy := es[i+1].(*expr.TProxy); isTProxy {
					continue
				}
				switch next := es[i+1].(type) {
				case *expr.Redir:
					if len(e.Data) >= 2 {
						parts = append(parts, fmt.Sprintf("redirect to :%d", binary.BigEndian.Uint16(e.Data[:2])))
						i++
						continue
					}
				case *expr.Meta:
					if next.Key == expr.MetaKeyMARK && next.SourceRegister && len(e.Data) >= 4 {
						parts = append(parts, fmt.Sprintf("meta mark set 0x%08x", binary.NativeEndian.Uint32(e.Data[:4])))
						i++
						continue
					}
				}
			}
			parts = append(parts, "immediate")
		case *expr.Redir:
			parts = append(parts, "redirect")
		case *expr.Masq:
			parts = append(parts, "masquerade")
		case *expr.Verdict:
			switch e.Kind {
			case expr.VerdictAccept:
				parts = append(parts, "accept")
			case expr.VerdictDrop:
				parts = append(parts, "drop")
			case expr.VerdictReturn:
				parts = append(parts, "return")
			case expr.VerdictContinue:
				parts = append(parts, "continue")
			case expr.VerdictBreak:
				parts = append(parts, "break")
			default:
				parts = append(parts, fmt.Sprintf("verdict-%d", e.Kind))
			}
		case *expr.Lookup:
			if label, found := setLabels[e.SetName]; found {
				parts = append(parts, label)
			} else {
				parts = append(parts, "<set "+e.SetName+">")
			}
		case *expr.Cmp:
			parts = append(parts, "compare")
		default:
			parts = append(parts, fmt.Sprintf("<%T>", es[i]))
		}
	}
	if len(parts) == 0 {
		return "# empty rule"
	}
	return strings.Join(parts, " ")
}

func maskPrefixBits(mask []byte) (int, bool) {
	bits := 0
	zeroSeen := false
	for _, b := range mask {
		for bit := 7; bit >= 0; bit-- {
			set := b&(1<<uint(bit)) != 0
			if set && zeroSeen {
				return 0, false
			}
			if set {
				bits++
			} else {
				zeroSeen = true
			}
		}
	}
	return bits, true
}

func trimNUL(s string) string {
	return strings.TrimRight(s, "\x00")
}

func familyLabel(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyNetdev:
		return "netdev"
	case nftables.TableFamilyBridge:
		return "bridge"
	default:
		return fmt.Sprintf("family-%d", f)
	}
}

func hookLabel(h nftables.ChainHook) string {
	switch h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	default:
		return fmt.Sprintf("hook-%d", h)
	}
}

func priorityLabel(p nftables.ChainPriority) string {
	// Use the priority names exported by nftables instead of duplicating their
	// numeric values here. nft accepts arithmetic offsets from these base
	// priorities (for example, "mangle - 5").
	bases := []struct {
		priority *nftables.ChainPriority
		name     string
	}{
		{nftables.ChainPriorityRaw, "raw"},
		{nftables.ChainPriorityMangle, "mangle"},
		{nftables.ChainPriorityNATDest, "dstnat"},
		{nftables.ChainPriorityFilter, "filter"},
		{nftables.ChainPrioritySecurity, "security"},
		{nftables.ChainPriorityNATSource, "srcnat"},
	}

	bestName := ""
	bestDelta := int64(0)
	bestDistance := int64(^uint64(0) >> 1)
	value := int64(p)
	for _, base := range bases {
		if base.priority == nil {
			continue
		}
		delta := value - int64(*base.priority)
		distance := delta
		if distance < 0 {
			distance = -distance
		}
		if distance < bestDistance {
			bestName = base.name
			bestDelta = delta
			bestDistance = distance
		}
	}

	if bestName == "" {
		return strconv.Itoa(int(p))
	}
	if bestDelta == 0 {
		return bestName
	}
	if bestDelta < 0 {
		return fmt.Sprintf("%s - %d", bestName, -bestDelta)
	}
	return fmt.Sprintf("%s + %d", bestName, bestDelta)
}

func policyLabel(p nftables.ChainPolicy) string {
	if p == nftables.ChainPolicyDrop {
		return "drop"
	}
	if p == nftables.ChainPolicyAccept {
		return "accept"
	}
	return fmt.Sprintf("policy-%d", p)
}

func family(s string) (nftables.TableFamily, error) {
	switch s {
	case "ip":
		return nftables.TableFamilyIPv4, nil
	case "ip6":
		return nftables.TableFamilyIPv6, nil
	case "inet":
		return nftables.TableFamilyINet, nil
	default:
		return 0, fmt.Errorf("unsupported family %q (supported: ip, ip6, inet)", s)
	}
}
func conn() (*nftables.Conn, error) { return nftables.New() }
func addTable(a []string) error {
	if len(a) != 2 {
		return errors.New("usage: add table ip NAME")
	}
	f, err := family(a[0])
	if err != nil {
		return err
	}
	c, err := conn()
	if err != nil {
		return err
	}
	c.AddTable(&nftables.Table{Family: f, Name: a[1]})
	return c.Flush()
}
func addChain(a []string) error {
	if len(a) < 3 {
		return errors.New("usage: add chain FAMILY TABLE CHAIN { type TYPE hook HOOK priority PRIORITY ; policy POLICY ; }")
	}
	f, err := family(a[0])
	if err != nil {
		return err
	}
	tableName, chainName := a[1], a[2]
	var typ, hook, prio, policy string
	for i := 3; i < len(a); i++ {
		switch strings.Trim(a[i], "{};") {
		case "type":
			if i+1 < len(a) {
				typ = a[i+1]
				i++
			}
		case "hook":
			if i+1 < len(a) {
				hook = a[i+1]
				i++
			}
		case "priority":
			if i+1 < len(a) {
				prio = a[i+1]
				i++
			}
			// nft accepts arithmetic priority notation, e.g. "mangle - 5".
			if i+2 < len(a) && a[i+1] == "-" {
				prio += " - " + a[i+2]
				i += 2
			}
		case "policy":
			if i+1 < len(a) {
				policy = a[i+1]
				i++
			}
		}
	}
	if typ == "" || hook == "" || prio == "" {
		return errors.New("chain requires type, hook and priority")
	}
	var ct nftables.ChainType
	switch typ {
	case "nat":
		ct = nftables.ChainTypeNAT
	case "filter":
		ct = nftables.ChainTypeFilter
	default:
		return fmt.Errorf("unsupported chain type %q", typ)
	}
	var hn *nftables.ChainHook
	switch hook {
	case "prerouting":
		hn = nftables.ChainHookPrerouting
	case "input":
		hn = nftables.ChainHookInput
	case "forward":
		hn = nftables.ChainHookForward
	case "output":
		hn = nftables.ChainHookOutput
	case "postrouting":
		hn = nftables.ChainHookPostrouting
	default:
		return fmt.Errorf("unsupported hook %q", hook)
	}
	var pn *nftables.ChainPriority
	switch strings.TrimSpace(prio) {
	case "dstnat":
		pn = nftables.ChainPriorityNATDest
	case "srcnat":
		pn = nftables.ChainPriorityNATSource
	case "mangle":
		pn = nftables.ChainPriorityMangle
	default:
		v := strings.TrimSpace(prio)
		if strings.Contains(v, " ") {
			fields := strings.Fields(v)
			if len(fields) != 3 || fields[1] != "-" {
				return fmt.Errorf("unsupported priority %q", prio)
			}
			base := map[string]int{"mangle": int(*nftables.ChainPriorityMangle), "filter": int(*nftables.ChainPriorityFilter), "dstnat": int(*nftables.ChainPriorityNATDest), "srcnat": int(*nftables.ChainPriorityNATSource)}
			b, ok := base[fields[0]]
			if !ok {
				return fmt.Errorf("unsupported priority %q", prio)
			}
			n, e := strconv.Atoi(fields[2])
			if e != nil {
				return fmt.Errorf("unsupported priority %q", prio)
			}
			pn = nftables.ChainPriorityRef(nftables.ChainPriority(b - n))
		} else {
			n, e := strconv.Atoi(v)
			if e != nil {
				return fmt.Errorf("unsupported priority %q", prio)
			}
			pn = nftables.ChainPriorityRef(nftables.ChainPriority(n))
		}
	}
	var pol *nftables.ChainPolicy
	if policy != "" {
		var v nftables.ChainPolicy
		switch policy {
		case "accept":
			v = nftables.ChainPolicyAccept
		case "drop":
			v = nftables.ChainPolicyDrop
		default:
			return fmt.Errorf("unsupported chain policy %q", policy)
		}
		pol = &v
	}
	c, err := conn()
	if err != nil {
		return err
	}
	t := &nftables.Table{Family: f, Name: tableName}
	c.AddChain(&nftables.Chain{Name: chainName, Table: t, Type: ct, Hooknum: hn, Priority: pn, Policy: pol})
	return c.Flush()
}

func addRule(a []string) error {
	if len(a) < 5 {
		return errors.New("incomplete add rule command")
	}
	f, err := family(a[0])
	if err != nil {
		return err
	}
	tableName, chainName := a[1], a[2]
	t := &nftables.Table{Family: f, Name: tableName}
	ch := &nftables.Chain{Name: chainName, Table: t}
	words := normalizeRuleTokens(a[3:])
	rules, sets, err := buildRules(f, words)
	if err != nil {
		return err
	}
	if err := assignNamedSetNames(rules, sets); err != nil {
		return fmt.Errorf("allocate nft set names: %w", err)
	}

	// Named sets are committed before the rules that reference them. This
	// avoids binding anonymous sets and their lookups in the same batch, which
	// was rejected with EBUSY by the target kernel. The set itself is still a
	// real kernel nftables set; only its lifetime differs from an anonymous set.
	if len(sets) != 0 {
		setConn, err := conn()
		if err != nil {
			return err
		}
		for _, spec := range sets {
			set := &nftables.Set{Table: t, Name: spec.name, Constant: true, KeyType: spec.keyType, KeyByteOrder: binaryutil.BigEndian}
			if err := setConn.AddSet(set, spec.elements); err != nil {
				return fmt.Errorf("queue nft set name=%s key-type=%v elements=%d: %w", spec.name, spec.keyType, len(spec.elements), err)
			}
		}
		if err := setConn.Flush(); err != nil {
			return fmt.Errorf("netlink create nft sets %s/%s: %w", familyLabel(f), tableName, err)
		}
	}

	ruleConn, err := conn()
	if err != nil {
		return err
	}
	for _, es := range rules {
		ruleConn.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: es})
	}
	if err := ruleConn.Flush(); err != nil {
		return fmt.Errorf("netlink add rule %s/%s/%s: %w", familyLabel(f), tableName, chainName, err)
	}
	return nil
}

type setSpec struct {
	id       uint32 // temporary parser-local reference, replaced by name before sending
	name     string
	keyType  nftables.SetDatatype
	elements []nftables.SetElement
}

// assignNamedSetNames assigns unique persistent kernel set names and rewrites
// Lookup expressions to reference those names instead of transaction-local IDs.
func assignNamedSetNames(rules [][]expr.Any, sets []setSpec) error {
	remap := make(map[uint32]string, len(sets))
	for i := range sets {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return err
		}
		sets[i].name = "gn_" + hex.EncodeToString(raw[:])
		remap[sets[i].id] = sets[i].name
	}
	for _, rule := range rules {
		for _, item := range rule {
			lookup, ok := item.(*expr.Lookup)
			if !ok {
				continue
			}
			if name, exists := remap[lookup.SetID]; exists {
				lookup.SetID = 0
				lookup.SetName = name
			}
		}
	}
	return nil
}

// buildRules compiles the deliberately small nft syntax subset. Multi-value
// matches use named kernel sets, so each source rule remains one kernel rule.
func buildRules(f nftables.TableFamily, a []string) ([][]expr.Any, []setSpec, error) {
	joined := strings.Join(a, " ")
	base, err := appendIIFName(nil, a)
	if err != nil {
		return nil, nil, err
	}
	// Existing compatibility forms.
	if strings.Contains(joined, "redirect to :") {
		port, e := parsePort(a)
		if e != nil {
			return nil, nil, e
		}
		return [][]expr.Any{append(append([]expr.Any{}, base...), &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}}, &expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))}, &expr.Redir{RegisterProtoMin: 1})}, nil, nil
	}
	if strings.Contains(joined, "meta oiftype ether") && strings.Contains(joined, "masquerade") {
		es := append(append([]expr.Any{}, base...),
			&expr.Meta{Key: expr.MetaKeyOIFTYPE, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(unix.ARPHRD_ETHER))},
		)
		// Preserve the destination exclusions in the kernel rule. These are
		// expressed as masked comparisons (one per CIDR), which is equivalent
		// to an inverted interval-set lookup and avoids lossy host-only sets.
		if hasSequence(a, "ip", "daddr") {
			prefixes, parseErr := parseIPv4PrefixSet(a)
			if parseErr != nil {
				return nil, nil, parseErr
			}
			for _, prefix := range prefixes {
				addr := prefix.Masked().Addr().As4()
				mask := ipv4Mask(prefix.Bits())
				es = append(es,
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
					&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
					&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: addr[:]},
				)
			}
		}
		es = append(es, &expr.Masq{})
		return [][]expr.Any{es}, nil, nil
	}
	if strings.Contains(joined, "meta l4proto udp") && strings.Contains(joined, "meta mark set") {
		mark, e := numberAfter(a, "set")
		if e != nil {
			return nil, nil, e
		}
		es := append(append([]expr.Any{}, base...), &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}}, &expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(mark))}, &expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true})
		return [][]expr.Any{es}, nil, nil
	}
	if strings.Contains(joined, "udp dport 443") && strings.HasSuffix(strings.TrimSpace(joined), "drop") {
		es := append(append([]expr.Any{}, base...), &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 443)}, &expr.Verdict{Kind: expr.VerdictDrop})
		return [][]expr.Any{es}, nil, nil
	}
	// `fib daddr type { local, broadcast, multicast } return`.
	if hasSequence(a, "fib", "daddr", "type") && contains(a, "return") {
		// Linux RTN_LOCAL=2, RTN_BROADCAST=3, RTN_MULTICAST=5.
		set := setSpec{id: 1, keyType: nftables.TypeFIBAddr, elements: []nftables.SetElement{
			{Key: binaryutil.NativeEndian.PutUint32(2)},
			{Key: binaryutil.NativeEndian.PutUint32(3)},
			{Key: binaryutil.NativeEndian.PutUint32(5)},
		}}
		es := append([]expr.Any{}, base...)
		es = append(es, &expr.Fib{Register: 1, ResultADDRTYPE: true, FlagDADDR: true}, &expr.Lookup{SourceRegister: 1, SetID: set.id}, &expr.Verdict{Kind: expr.VerdictReturn})
		return [][]expr.Any{es}, []setSpec{set}, nil
	}
	// Older kernels may reject `fib daddr type`; the entrypoint then falls
	// back to an IPv4 destination-address set followed by `return`.
	if hasSequence(a, "ip", "daddr") && contains(a, "return") {
		var out [][]expr.Any
		collect := false
		for _, token := range a {
			if token == "{" {
				collect = true
				continue
			}
			if token == "}" {
				collect = false
				continue
			}
			if !collect {
				continue
			}
			for _, item := range strings.Split(strings.Trim(token, ",{};"), ",") {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				prefix, e := netip.ParsePrefix(item)
				if e != nil {
					addr, addrErr := netip.ParseAddr(item)
					if addrErr != nil {
						return nil, nil, fmt.Errorf("invalid IPv4 destination %q", item)
					}
					if !addr.Is4() {
						return nil, nil, fmt.Errorf("fallback destination %q is not IPv4", item)
					}
					prefix = netip.PrefixFrom(addr, 32)
				}
				if !prefix.Addr().Is4() {
					return nil, nil, fmt.Errorf("fallback destination %q is not IPv4", item)
				}
				addr := prefix.Masked().Addr().As4()
				mask := make([]byte, 4)
				bits := prefix.Bits()
				for j := 0; j < 4; j++ {
					remaining := bits - j*8
					if remaining >= 8 {
						mask[j] = 0xff
					} else if remaining > 0 {
						mask[j] = byte(0xff << (8 - remaining))
					}
				}
				es := append([]expr.Any{}, base...)
				es = append(es, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4})
				if bits < 32 {
					es = append(es, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}})
				}
				es = append(es, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr[:]}, &expr.Verdict{Kind: expr.VerdictReturn})
				out = append(out, es)
			}
		}
		if len(out) == 0 {
			return nil, nil, errors.New("IPv4 daddr set is empty")
		}
		return out, nil, nil
	}
	// MPTCP TCP option kind 30. The PRESENT flag makes the exthdr expression
	// return a boolean indicating whether that TCP option is present.
	if hasSequence(a, "tcp", "option", "mptcp", "exists") && contains(a, "drop") {
		es := append(append([]expr.Any{}, base...), &expr.Exthdr{DestRegister: 1, Type: 30, Offset: 0, Len: 1, Flags: 1, Op: expr.ExthdrOpTcpopt}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, &expr.Verdict{Kind: expr.VerdictDrop})
		return [][]expr.Any{es}, nil, nil
	}
	// TPROXY rule: `meta l4proto { tcp, udp } meta mark set MARK tproxy
	// ip|ip6 to ADDRESS:PORT accept`. Expand protocol set to TCP and UDP.
	if contains(a, "tproxy") {
		mark, e := numberAfter(a, "set")
		if e != nil {
			return nil, nil, e
		}
		protoIdx := indexOf(a, "l4proto")
		if protoIdx < 0 {
			return nil, nil, errors.New("tproxy rule requires meta l4proto")
		}
		var protos []byte
		for _, v := range a[protoIdx+1:] {
			v = strings.Trim(v, "{},;")
			if v == "tcp" {
				protos = append(protos, unix.IPPROTO_TCP)
			}
			if v == "udp" {
				protos = append(protos, unix.IPPROTO_UDP)
			}
			if v == "tproxy" {
				break
			}
		}
		if len(protos) == 0 {
			return nil, nil, errors.New("tproxy rule requires tcp and/or udp")
		}
		kindIdx := indexOf(a, "tproxy")
		if kindIdx < 0 || kindIdx+3 >= len(a) {
			return nil, nil, errors.New("incomplete tproxy target")
		}
		familyWord := a[kindIdx+1]
		if familyWord != "ip" && familyWord != "ip6" {
			return nil, nil, fmt.Errorf("unsupported tproxy address family %q", familyWord)
		}
		addrPort := strings.Trim(a[kindIdx+3], `";`)
		addr, portText, e := net.SplitHostPort(addrPort)
		if e != nil {
			return nil, nil, fmt.Errorf("tproxy target must be ADDRESS:PORT: %w", e)
		}
		port, e := strconv.Atoi(strings.Trim(portText, "[]"))
		if e != nil || port < 1 || port > 65535 {
			return nil, nil, fmt.Errorf("invalid tproxy port %q", portText)
		}
		ip := netParseIP(addr)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid tproxy address %q", addr)
		}
		var ipBytes []byte
		nfproto := byte(unix.NFPROTO_IPV4)
		if familyWord == "ip" {
			ipBytes = net.IP(ip).To4()
			if ipBytes == nil {
				return nil, nil, fmt.Errorf("%q is not an IPv4 address", addr)
			}
		} else {
			nfproto = byte(unix.NFPROTO_IPV6)
			ipBytes = net.IP(ip).To16()
			if ipBytes == nil || net.IP(ip).To4() != nil {
				return nil, nil, fmt.Errorf("%q is not an IPv6 address", addr)
			}
		}
		set := setSpec{id: 1, keyType: nftables.TypeInetProto}
		for _, proto := range protos {
			set.elements = append(set.elements, nftables.SetElement{Key: []byte{proto}})
		}
		es := append([]expr.Any{}, base...)
		es = append(es, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Lookup{SourceRegister: 1, SetID: set.id}, &expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(mark))}, &expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true})
		// NFT_REG_1 and NFT_REG_2 are adjacent legacy 16-byte slots.
		addrReg, portReg := uint32(1), uint32(2)
		es = append(es, &expr.Immediate{Register: addrReg, Data: ipBytes}, &expr.Immediate{Register: portReg, Data: binaryutil.BigEndian.PutUint16(uint16(port))}, &expr.TProxy{Family: nfproto, RegAddr: addrReg, RegPort: portReg}, &expr.Verdict{Kind: expr.VerdictAccept})
		return [][]expr.Any{es}, []setSpec{set}, nil
	}
	// socket transparent 1 + mark + accept (divert chain).
	if hasSequence(a, "socket", "transparent", "1") && contains(a, "accept") {
		mark, e := numberAfter(a, "set")
		if e != nil {
			return nil, nil, e
		}
		es := append(append([]expr.Any{}, base...), &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}}, &expr.Socket{Key: expr.SocketKeyTransparent, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(1)}, &expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(mark))}, &expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true}, &expr.Verdict{Kind: expr.VerdictAccept})
		return [][]expr.Any{es}, nil, nil
	}
	if contains(a, "return") {
		return [][]expr.Any{append(append([]expr.Any{}, base...), &expr.Verdict{Kind: expr.VerdictReturn})}, nil, nil
	}
	if contains(a, "accept") {
		return [][]expr.Any{append(append([]expr.Any{}, base...), &expr.Verdict{Kind: expr.VerdictAccept})}, nil, nil
	}
	if contains(a, "drop") {
		return [][]expr.Any{append(append([]expr.Any{}, base...), &expr.Verdict{Kind: expr.VerdictDrop})}, nil, nil
	}
	return nil, nil, fmt.Errorf("unsupported rule expression: %s", joined)
}

func parseIPv4PrefixSet(tokens []string) ([]netip.Prefix, error) {
	inside := false
	var prefixes []netip.Prefix
	var item strings.Builder
	flushItem := func() error {
		value := strings.TrimSpace(strings.Trim(item.String(), ",;"))
		item.Reset()
		if value == "" {
			return nil
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			addr, addrErr := netip.ParseAddr(value)
			if addrErr != nil || !addr.Is4() {
				return fmt.Errorf("invalid IPv4 destination exclusion %q", value)
			}
			prefix = netip.PrefixFrom(addr, 32)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("destination exclusion %q is not IPv4", value)
		}
		prefixes = append(prefixes, prefix.Masked())
		return nil
	}

	// Keep the current set member across argv tokens: a closing brace may be
	// its own token, so the final address must not be discarded at the token
	// boundary (e.g. "255.255.255.255", "}", "masquerade").
	for _, token := range tokens {
		for _, r := range token {
			switch r {
			case '{':
				if inside {
					return nil, errors.New("unexpected nested IPv4 destination exclusion set")
				}
				inside = true
			case '}':
				if inside {
					if err := flushItem(); err != nil {
						return nil, err
					}
					inside = false
				}
			case ',', ';':
				if inside {
					if err := flushItem(); err != nil {
						return nil, err
					}
				}
			default:
				if inside {
					item.WriteRune(r)
				}
			}
		}
	}
	if inside {
		return nil, errors.New("unterminated IPv4 destination exclusion set")
	}
	if len(prefixes) == 0 {
		return nil, errors.New("IPv4 destination exclusion set is empty")
	}
	return prefixes, nil
}

func ipv4Mask(bits int) []byte {
	mask := make([]byte, 4)
	for i := range mask {
		remaining := bits - i*8
		if remaining >= 8 {
			mask[i] = 0xff
		} else if remaining > 0 {
			mask[i] = byte(0xff << (8 - remaining))
		}
	}
	return mask
}

func contains(a []string, s string) bool {
	for _, v := range a {
		if strings.Trim(v, "{},;") == s {
			return true
		}
	}
	return false
}
func indexOf(a []string, s string) int {
	for i, v := range a {
		if strings.Trim(v, "{},;") == s {
			return i
		}
	}
	return -1
}
func hasSequence(a []string, seq ...string) bool {
	for i := 0; i+len(seq) <= len(a); i++ {
		ok := true
		for j, v := range seq {
			if strings.Trim(a[i+j], "{},;") != v {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
func netParseIP(s string) []byte { return net.ParseIP(strings.Trim(s, "[]")) }

// splitCommand handles the quoted multiline command form used for chain setup.
func splitCommand(s string) []string {
	var out []string
	var b strings.Builder
	quote := rune(0)
	for _, r := range s {
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if unicode.IsSpace(r) {
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
			continue
		}
		if r == ';' {
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
			out = append(out, ";")
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}
func normalizeRuleTokens(a []string) []string {
	var out []string
	for _, v := range a {
		if v == "\\" {
			continue
		}
		if strings.ContainsAny(v, "\n\t") {
			out = append(out, splitCommand(v)...)
		} else {
			out = append(out, v)
		}
	}
	return out
}

func ifname(s string) []byte { b := make([]byte, 16); copy(b, []byte(s)); return b }
func numberAfter(a []string, key string) (int, error) {
	for i := 0; i+1 < len(a); i++ {
		if a[i] == key {
			n64, e := strconv.ParseInt(strings.Trim(a[i+1], ":"), 0, 32)
			n := int(n64)
			if e != nil {
				return 0, e
			}
			return n, nil
		}
	}
	return 0, fmt.Errorf("missing numeric value after %s", key)
}
func parsePort(a []string) (int, error) {
	for i := 0; i+1 < len(a); i++ {
		if a[i] == "to" {
			n, err := strconv.Atoi(strings.TrimPrefix(strings.Trim(a[i+1], `"`), ":"))
			if err != nil {
				return 0, fmt.Errorf("invalid redirect port: %w", err)
			}
			if n < 1 || n > 65535 {
				return 0, fmt.Errorf("invalid redirect port %d", n)
			}
			return n, nil
		}
	}
	return 0, errors.New("redirect rule requires 'to :PORT'")
}

// appendIIFName adds an ingress-interface equality match only when the
// command contains `iifname NAME`. With no iifname, the rule matches all
// ingress interfaces, which is useful in single-interface containers.
func appendIIFName(es []expr.Any, a []string) ([]expr.Any, error) {
	for i := 0; i+1 < len(a); i++ {
		if a[i] != "iifname" {
			continue
		}
		name := strings.Trim(a[i+1], `"`)
		if name == "" || len([]byte(name)) > 15 {
			return nil, fmt.Errorf("invalid interface name %q (must be 1-15 bytes)", name)
		}
		es = append(es,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
		)
		return es, nil
	}
	return es, nil
}
