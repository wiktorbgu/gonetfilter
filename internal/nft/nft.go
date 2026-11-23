// tiny-nft: intentionally small nft(8) compatibility shim for this project's
// entrypoint. It programs Linux nftables through Netlink; it never execs nft.
package nft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Main executes the compact nftables CLI and returns its process exit code.
func Main(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "nft: usage: nft add table|chain|rule ... OR nft list ruleset")
		return 1
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
		return fmt.Errorf("list tables: %w", err)
	}
	chains, err := c.ListChains()
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
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
				fmt.Printf("\t\t%s\n", formatRule(rule.Exprs))
			}
			fmt.Println("\t}")
		}
		fmt.Println("}")
	}
	return nil
}

// formatRule renders the expression sequences emitted by addRule in nft syntax.
// Unknown expressions remain visible as diagnostics rather than being hidden.
func formatRule(es []expr.Any) string {
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
					if c, ok := es[i+1].(*expr.Cmp); ok && len(c.Data) >= 4 {
						if binary.BigEndian.Uint32(c.Data[:4]) == uint32(unix.ARPHRD_ETHER) {
							kind = "ether"
						}
						i++
					}
				}
				parts = append(parts, "meta oiftype "+kind)
			case expr.MetaKeyMARK:
				if e.SourceRegister && i > 0 {
					if imm, ok := es[i-1].(*expr.Immediate); ok && len(imm.Data) >= 4 {
						parts = append(parts, fmt.Sprintf("meta mark set %d", binary.BigEndian.Uint32(imm.Data[:4])))
						continue
					}
				}
				parts = append(parts, "meta mark")
			default:
				parts = append(parts, fmt.Sprintf("meta key-%d", e.Key))
			}
		case *expr.Payload:
			if e.Base == expr.PayloadBaseTransportHeader && e.Offset == 2 && e.Len == 2 && i+1 < len(es) {
				if c, ok := es[i+1].(*expr.Cmp); ok && len(c.Data) >= 2 {
					parts = append(parts, fmt.Sprintf("udp dport %d", binary.BigEndian.Uint16(c.Data[:2])))
					i++
					continue
				}
			}
			parts = append(parts, "payload")
		case *expr.Immediate:
			if i+1 < len(es) {
				switch next := es[i+1].(type) {
				case *expr.Redir:
					if len(e.Data) >= 2 {
						parts = append(parts, fmt.Sprintf("redirect to :%d", binary.BigEndian.Uint16(e.Data[:2])))
						i++
						continue
					}
				case *expr.Meta:
					if next.Key == expr.MetaKeyMARK && next.SourceRegister && len(e.Data) >= 4 {
						parts = append(parts, fmt.Sprintf("meta mark set %d", binary.BigEndian.Uint32(e.Data[:4])))
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
			if e.Kind == expr.VerdictDrop {
				parts = append(parts, "drop")
			} else {
				parts = append(parts, fmt.Sprintf("verdict-%d", e.Kind))
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
	switch {
	case p == *nftables.ChainPriorityNATDest:
		return "dstnat"
	case p == *nftables.ChainPriorityNATSource:
		return "srcnat"
	case p == *nftables.ChainPriorityMangle:
		return "mangle"
	default:
		return strconv.Itoa(int(p))
	}
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
	if s == "ip" {
		return nftables.TableFamilyIPv4, nil
	}
	return 0, fmt.Errorf("only IPv4 family 'ip' is supported, got %q", s)
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
	if len(a) < 4 {
		return errors.New("usage: add chain ip TABLE CHAIN { type TYPE hook HOOK priority PRIORITY ; }")
	}
	f, err := family(a[0])
	if err != nil {
		return err
	}
	tableName, chainName := a[1], a[2]
	var typ, hook, prio string
	for i := 3; i < len(a); i++ {
		switch a[i] {
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
	case "postrouting":
		hn = nftables.ChainHookPostrouting
	default:
		return fmt.Errorf("unsupported hook %q", hook)
	}
	var pn *nftables.ChainPriority
	switch prio {
	case "dstnat":
		pn = nftables.ChainPriorityNATDest
	case "srcnat":
		pn = nftables.ChainPriorityNATSource
	case "mangle":
		pn = nftables.ChainPriorityMangle
	default:
		n, e := strconv.Atoi(prio)
		if e != nil {
			return fmt.Errorf("unsupported priority %q", prio)
		}
		pn = nftables.ChainPriorityRef(nftables.ChainPriority(n))
	}
	c, err := conn()
	if err != nil {
		return err
	}
	t := &nftables.Table{Family: f, Name: tableName}
	c.AddChain(&nftables.Chain{Name: chainName, Table: t, Type: ct, Hooknum: hn, Priority: pn})
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
	c, err := conn()
	if err != nil {
		return err
	}
	var es []expr.Any
	// Exact expression forms used by entrypoint_redirect.sh.
	joined := strings.Join(a[3:], " ")
	switch {
	case strings.Contains(joined, "redirect to :"):
		port, e := parsePort(a[3:])
		if e != nil {
			return e
		}
		es, err = appendIIFName(es, a[3:]) // optional: omit iifname to match any ingress interface.
		if err != nil {
			return err
		}
		es = append(es,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
			&expr.Redir{RegisterProtoMin: 1},
		)
	case strings.Contains(joined, "meta oiftype ether") && strings.Contains(joined, "masquerade"):
		es = append(es,
			&expr.Meta{Key: expr.MetaKeyOIFTYPE, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(unix.ARPHRD_ETHER))},
			&expr.Masq{},
		)
	case strings.Contains(joined, "meta l4proto udp") && strings.Contains(joined, "meta mark set"):
		mark, e := numberAfter(a[3:], "set")
		if e != nil {
			return e
		}
		es, err = appendIIFName(es, a[3:]) // optional ingress-interface restriction
		if err != nil {
			return err
		}
		es = append(es,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(mark))},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
		)
	case strings.Contains(joined, "udp dport 443") && strings.HasSuffix(strings.TrimSpace(joined), "drop"):
		es, err = appendIIFName(es, a[3:]) // optional ingress-interface restriction
		if err != nil {
			return err
		}
		es = append(es,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 443)},
			&expr.Verdict{Kind: expr.VerdictDrop},
		)
	default:
		return fmt.Errorf("unsupported rule expression: %s", joined)
	}
	c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: es})
	return c.Flush()
}
func ifname(s string) []byte { b := make([]byte, 16); copy(b, []byte(s)); return b }
func numberAfter(a []string, key string) (int, error) {
	for i := 0; i+1 < len(a); i++ {
		if a[i] == key {
			n, e := strconv.Atoi(strings.Trim(a[i+1], ":"))
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
