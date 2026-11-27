//go:build linux

package iptables

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	afInet        = 2
	ipProtoRaw    = 255
	solIP         = 0
	iptSoReplace  = 64
	iptSoGetInfo  = 64
	iptSoGetEnts  = 65
	nfPreRouting  = 0
	nfInput       = 1
	nfForward     = 2
	nfOutput      = 3
	nfPostRouting = 4
	ipProtoTCP    = 6
	ipProtoUDP    = 17
	xtAlign       = 8
)

type xtCounters struct{ Pcnt, Bcnt uint64 }

type iptGetInfo struct {
	Name       [32]byte
	ValidHooks uint32
	HookEntry  [5]uint32
	Underflow  [5]uint32
	NumEntries uint32
	Size       uint32
}
type iptGetEntries struct {
	Name [32]byte
	Size uint32
	Pad  uint32 // C ABI tail padding: flexible entrytable is 8-byte aligned
}
type iptReplace struct {
	Name        [32]byte
	ValidHooks  uint32
	NumEntries  uint32
	Size        uint32
	HookEntry   [5]uint32
	Underflow   [5]uint32
	NumCounters uint32
	Counters    uintptr
}
type iptIP struct {
	Src, Dst, SMSK, DMSK      [4]byte
	Iniface, Outiface         [16]byte
	InifaceMask, OutifaceMask [16]byte
	Proto                     uint16
	Flags, Invflags           uint8
}
type iptEntry struct {
	IP           iptIP
	NFCache      uint32
	TargetOffset uint16
	NextOffset   uint16
	ComeFrom     uint32
	Counters     xtCounters
}
type xtEntryTarget struct {
	Size     uint16
	Name     [29]byte
	Revision uint8
}
type xtEntryMatch struct {
	Size     uint16
	Name     [29]byte
	Revision uint8
}
type xtUDP struct {
	Spts     [2]uint16
	Dpts     [2]uint16
	Invflags uint8
	Pad      [3]byte
}
type xtMarkInfo struct{ Mark, Mask uint32 }
type xtAddrTypeInfoV1 struct {
	Source, Dest uint16
	Flags        uint32
}
type natRange struct {
	Flags              uint32
	MinIP, MaxIP       uint32
	MinProto, MaxProto uint16
}
type natMultiRange struct {
	RangeSize uint32
	Range     natRange
}

func align(n int) int           { return (n + xtAlign - 1) &^ (xtAlign - 1) }
func cstr(dst []byte, s string) { copy(dst, s) }
func htons(v uint16) uint16     { return (v<<8)&0xff00 | v>>8 }

func sock() (int, error) {
	fd, err := syscall.Socket(afInet, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, ipProtoRaw)
	if err != nil {
		return -1, err
	}
	return fd, nil
}
func getInfo(fd int, table string) (iptGetInfo, error) {
	var info iptGetInfo
	copy(info.Name[:], table)
	optlen := uint32(unsafe.Sizeof(info))
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), solIP, iptSoGetInfo,
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&optlen)), 0)
	runtime.KeepAlive(&info)
	runtime.KeepAlive(&optlen)
	if e != 0 {
		return info, e
	}
	return info, nil
}
func getEntries(fd int, table string, size uint32) ([]byte, error) {
	buf := make([]byte, int(unsafe.Sizeof(iptGetEntries{}))+int(size))
	h := (*iptGetEntries)(unsafe.Pointer(&buf[0]))
	copy(h.Name[:], table)
	h.Size = size
	sz := uint32(len(buf))
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), solIP, iptSoGetEnts,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)), 0)
	runtime.KeepAlive(buf)
	runtime.KeepAlive(&sz)
	if e != 0 {
		return nil, e
	}
	return buf[int(unsafe.Sizeof(iptGetEntries{})):], nil
}
func setReplace(fd int, table string, info iptGetInfo, blob []byte, oldCounters []xtCounters) error {
	// ipt_replace ends with a flexible array of ipt_entry. ipt_entry is
	// 8-byte aligned (because xt_counters contains u64 values), so the
	// entry payload starts at an 8-byte boundary even on 32-bit ARM where
	// sizeof(iptReplace) itself can be 92 bytes due to the 32-bit pointer.
	// The kernel expects the same aligned offset used by
	// offsetof(struct ipt_replace, entries), not the raw Go struct size.
	hdr := align(int(unsafe.Sizeof(iptReplace{})))
	buf := make([]byte, hdr+len(blob))
	r := (*iptReplace)(unsafe.Pointer(&buf[0]))
	copy(r.Name[:], table)
	r.ValidHooks = info.ValidHooks
	r.NumEntries = info.NumEntries
	r.Size = uint32(len(blob))
	r.HookEntry = info.HookEntry
	r.Underflow = info.Underflow
	r.NumCounters = uint32(len(oldCounters))
	if len(oldCounters) > 0 {
		r.Counters = uintptr(unsafe.Pointer(&oldCounters[0]))
	}
	copy(buf[hdr:], blob)
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), solIP, iptSoReplace,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	runtime.KeepAlive(r)
	runtime.KeepAlive(oldCounters)
	runtime.KeepAlive(blob)
	runtime.KeepAlive(buf)
	if e != 0 {
		return e
	}
	return nil
}

type decodedEntry struct {
	offset     int
	entry      *iptEntry
	target     *xtEntryTarget
	targetData []byte
	matches    []byte
	chain      string
	isMarker   bool
	isPolicy   bool
}

func readTable(table string) (iptGetInfo, []byte, error) {
	fd, err := sock()
	if err != nil {
		return iptGetInfo{}, nil, err
	}
	defer syscall.Close(fd)
	info, err := getInfo(fd, table)
	if err != nil {
		return info, nil, fmt.Errorf("IPT_SO_GET_INFO %s: %w", table, err)
	}
	entries, err := getEntries(fd, table, info.Size)
	if err != nil {
		return info, nil, fmt.Errorf("IPT_SO_GET_ENTRIES %s: %w", table, err)
	}
	return info, entries, nil
}

func decodeTable(blob []byte) ([]decodedEntry, error) {
	out := make([]decodedEntry, 0, 32)
	entrySize := int(unsafe.Sizeof(iptEntry{}))
	for pos := 0; pos < len(blob); {
		if pos+entrySize > len(blob) {
			return nil, fmt.Errorf("truncated entry at byte %d", pos)
		}
		e := (*iptEntry)(unsafe.Pointer(&blob[pos]))
		next, targetOff := int(e.NextOffset), int(e.TargetOffset)
		if next < entrySize || pos+next > len(blob) || targetOff < entrySize || targetOff+int(unsafe.Sizeof(xtEntryTarget{})) > next {
			return nil, fmt.Errorf("invalid entry offsets at byte %d", pos)
		}
		t := (*xtEntryTarget)(unsafe.Pointer(&blob[pos+targetOff]))
		item := decodedEntry{offset: pos, entry: e, target: t, targetData: blob[pos+targetOff+int(unsafe.Sizeof(xtEntryTarget{})) : pos+next]}
		if targetOff > entrySize {
			item.matches = blob[pos+entrySize : pos+targetOff]
		}
		name := cString(t.Name[:])
		if name == "ERROR" {
			item.isMarker = true
			item.chain = cString(item.targetData)
		}
		out = append(out, item)
		pos += next
	}
	return out, nil
}
func cString(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
func ntohs(v uint16) uint16 { return htons(v) }

func decodeRule(item decodedEntry) string { return decodeRuleWithChains(item, nil) }

func decodeRuleWithChains(item decodedEntry, chainNames map[uint32]string) string {
	e := item.entry
	parts := make([]string, 0, 10)
	if e.IP.InifaceMask != ([16]byte{}) {
		if iface := cString(e.IP.Iniface[:]); iface != "" {
			parts = append(parts, "-i", iface)
		}
	}
	if e.IP.OutifaceMask != ([16]byte{}) {
		if iface := cString(e.IP.Outiface[:]); iface != "" {
			parts = append(parts, "-o", iface)
		}
	}
	switch e.IP.Proto {
	case ipProtoTCP:
		parts = append(parts, "-p", "tcp")
	case ipProtoUDP:
		parts = append(parts, "-p", "udp")
	}
	for off := 0; off+int(unsafe.Sizeof(xtEntryMatch{})) <= len(item.matches); {
		m := (*xtEntryMatch)(unsafe.Pointer(&item.matches[off]))
		ms := int(m.Size)
		if ms < int(unsafe.Sizeof(xtEntryMatch{})) || off+ms > len(item.matches) {
			break
		}
		if cString(m.Name[:]) == "udp" && ms >= int(unsafe.Sizeof(xtEntryMatch{}))+int(unsafe.Sizeof(xtUDP{})) {
			// The legacy xtables match payload is exposed in the host ABI's
			// byte order. In the captured ARM32 rules, dport 53 is 35 00;
			// decode it as a native-endian uint16 (not network byte order).
			payload := item.matches[off+int(unsafe.Sizeof(xtEntryMatch{})) : off+int(unsafe.Sizeof(xtEntryMatch{}))+int(unsafe.Sizeof(xtUDP{}))]
			lo := int(binary.NativeEndian.Uint16(payload[4:6]))
			hi := int(binary.NativeEndian.Uint16(payload[6:8]))
			if lo == hi && lo != 0 {
				parts = append(parts, "-m", "udp", "--dport", strconv.Itoa(int(lo)))
			}
		} else if cString(m.Name[:]) == "addrtype" && ms >= int(unsafe.Sizeof(xtEntryMatch{}))+int(unsafe.Sizeof(xtAddrTypeInfoV1{})) {
			a := (*xtAddrTypeInfoV1)(unsafe.Pointer(&item.matches[off+int(unsafe.Sizeof(xtEntryMatch{}))]))
			if a.Dest&0x0004 != 0 {
				parts = append(parts, "-m", "addrtype", "--dst-type", "LOCAL")
			}
		}
		off += ms
	}
	targetName := ""
	if item.target != nil {
		targetName = cString(item.target.Name[:])
	}
	switch targetName {
	case "REDIRECT":
		port := 0
		if len(item.targetData) >= int(unsafe.Sizeof(natMultiRange{})) {
			port = int(ntohs((*natMultiRange)(unsafe.Pointer(&item.targetData[0])).Range.MinProto))
		}
		parts = append(parts, "-j", "REDIRECT")
		if port > 0 {
			parts = append(parts, "--to-ports", strconv.Itoa(port))
		}
	case "MASQUERADE":
		parts = append(parts, "-j", "MASQUERADE")
	case "DNAT":
		parts = append(parts, "-j", "DNAT")
		if len(item.targetData) >= 8 {
			// The IPv4 NAT compat payload is a kernel UAPI structure. Some
			// legacy userspace/kernel combinations expose the compact form
			// (rangesize followed directly by the network-order IPv4 address),
			// while the standard nf_nat_ipv4_range form has flags first.
			// Valid NF_NAT_RANGE flags are confined to the low bits; an
			// impossible flag word therefore identifies the compact form.
			flags := binary.NativeEndian.Uint32(item.targetData[4:8])
			ipOffset := 8
			if flags&^uint32(0x7f) != 0 {
				ipOffset = 4
			}
			if len(item.targetData) >= ipOffset+4 {
				dst := net.IP(item.targetData[ipOffset : ipOffset+4]).String()
				if ipOffset == 8 && flags&2 != 0 && len(item.targetData) >= 18 {
					port := binary.BigEndian.Uint16(item.targetData[16:18])
					if port != 0 {
						dst += ":" + strconv.Itoa(int(port))
					}
				}
				parts = append(parts, "--to-destination", dst)
			}
		}
	case "MARK":
		mark := uint32(0)
		if len(item.targetData) >= 8 {
			mark = (*xtMarkInfo)(unsafe.Pointer(&item.targetData[0])).Mark
		}
		parts = append(parts, "-j", "MARK", "--set-xmark", strconv.FormatUint(uint64(mark), 10)+"/0xffffffff")
	case "":
		v := int32(0)
		if len(item.targetData) >= 4 {
			v = int32(binary.LittleEndian.Uint32(item.targetData[:4]))
		}
		switch v {
		case -1:
			parts = append(parts, "-j", "DROP")
		case -2:
			parts = append(parts, "-j", "ACCEPT")
		case -5:
			parts = append(parts, "-j", "RETURN")
		default:
			if v >= 0 && chainNames != nil && chainNames[uint32(v)] != "" {
				parts = append(parts, "-j", chainNames[uint32(v)])
			} else {
				parts = append(parts, "-j", "RETURN")
			}
		}
	default:
		parts = append(parts, "-j", cString(item.target.Name[:]))
	}
	return strings.Join(parts, " ")
}

func listRules(table string, args []string) error {
	if table != "filter" && table != "nat" && table != "mangle" && table != "raw" {
		return fmt.Errorf("unsupported table %q (supported: filter, nat, mangle, raw)", table)
	}
	info, blob, err := readTable(table)
	if err != nil {
		return err
	}
	items, err := decodeTable(blob)
	if err != nil {
		return err
	}
	policyOffsets := map[uint32]bool{}
	for i, off := range info.Underflow {
		if info.ValidHooks&(1<<i) != 0 {
			policyOffsets[off] = true
		}
	}
	for i := range items {
		if policyOffsets[uint32(items[i].offset)] {
			items[i].isPolicy = true
		}
	}

	chains := map[string][]decodedEntry{}
	hookNames := map[int]string{}
	if table == "raw" {
		hookNames[0] = "PREROUTING"
		hookNames[3] = "OUTPUT"
	} else if table == "nat" {
		hookNames[0] = "PREROUTING"
		hookNames[1] = "INPUT"
		hookNames[3] = "OUTPUT"
		hookNames[4] = "POSTROUTING"
	} else {
		hookNames[0] = "PREROUTING"
		hookNames[1] = "INPUT"
		hookNames[2] = "FORWARD"
		hookNames[3] = "OUTPUT"
		hookNames[4] = "POSTROUTING"
	}
	// The kernel's HookEntry/Underflow offsets are authoritative for built-in chains.
	// Include only the actual rules between the chain header and its policy entry.
	for hook, name := range hookNames {
		if info.ValidHooks&(1<<hook) == 0 {
			continue
		}
		begin, policy := info.HookEntry[hook], info.Underflow[hook]
		if policy < begin || int(policy) >= len(blob) {
			continue
		}
		for _, it := range items {
			off := uint32(it.offset)
			// HookEntry points at the first rule in the built-in chain,
			// not necessarily at a separate chain-marker entry.
			if off < begin || off >= policy {
				continue
			}
			chains[name] = append(chains[name], it)
		}
		// Keep empty built-in chains visible.
		if _, ok := chains[name]; !ok {
			chains[name] = nil
		}
	}
	userChains := map[string]bool{}
	chainOffsets := map[uint32]string{}
	chainReferences := map[string]int{}
	for i, it := range items {
		// The terminal ERROR sentinel is not a user-defined chain.
		if !it.isMarker || it.chain == "" || it.chain == "ERROR" {
			continue
		}
		userChains[it.chain] = true
		chainOffsets[uint32(it.offset)] = it.chain
		// Some legacy jump entries point at the first rule after the chain
		// marker rather than at the marker itself.
		chainOffsets[uint32(it.offset)+uint32(it.entry.NextOffset)] = it.chain
		end := i + 1
		for end < len(items) && !items[end].isMarker {
			end++
		}
		entries := append([]decodedEntry(nil), items[i+1:end]...)
		if len(entries) > 0 {
			last := &entries[len(entries)-1]
			if cString(last.target.Name[:]) == "" && len(last.targetData) >= 4 && int32(binary.LittleEndian.Uint32(last.targetData[:4])) == -5 {
				last.isPolicy = true
			}
		}
		chains[it.chain] = entries
	}
	for _, it := range items {
		if cString(it.target.Name[:]) != "" || len(it.targetData) < 4 {
			continue
		}
		v := int32(binary.LittleEndian.Uint32(it.targetData[:4]))
		if v >= 0 {
			if name := chainOffsets[uint32(v)]; name != "" {
				chainReferences[name]++
			}
		}
	}
	showRules := len(args) > 0 && (args[0] == "-S" || args[0] == "--list-rules")
	chain := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		chain = args[0]
	}
	if showRules && len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		chain = args[1]
	}
	verbose, lineNumbers := false, false
	for _, a := range args {
		if a == "-v" || a == "--verbose" {
			verbose = true
		}
		if a == "--line-numbers" {
			lineNumbers = true
		}
	}
	chainNames := make([]string, 0, len(chains))
	for name := range chains {
		chainNames = append(chainNames, name)
	}
	sort.Strings(chainNames)
	if showRules {
		fmt.Printf("*%s\n", table)
		for _, name := range chainNames {
			entries := chains[name]
			if chain != "" && chain != name {
				continue
			}
			if userChains[name] {
				fmt.Printf("-N %s\n", name)
			}
			for _, it := range entries {
				if it.isPolicy {
					continue
				}
				r := decodeRuleWithChains(it, chainOffsets)
				if r != "" {
					fmt.Printf("-A %s %s\n", name, r)
				}
			}
		}
		fmt.Println("COMMIT")
		return nil
	}
	printed := 0
	for _, name := range chainNames {
		entries := chains[name]
		if chain != "" && chain != name {
			continue
		}
		policy := "ACCEPT"
		for _, it := range entries {
			if it.isPolicy && len(it.targetData) >= 4 {
				v := int32(binary.LittleEndian.Uint32(it.targetData[:4]))
				if v == -1 {
					policy = "DROP"
				}
			}
		}
		if userChains[name] {
			fmt.Printf("Chain %s (%d references)\n", name, chainReferences[name])
		} else {
			fmt.Printf("Chain %s (policy %s)\n", name, policy)
		}
		if verbose && lineNumbers {
			fmt.Println("num   pkts bytes target     prot opt in     out     source               destination")
		} else if verbose {
			fmt.Println(" pkts bytes target     prot opt in     out     source               destination")
		} else if lineNumbers {
			fmt.Println("num  target     prot opt in     out     source               destination")
		} else {
			fmt.Println("target     prot opt in     out     source               destination")
		}
		ruleNo := 0
		for _, it := range entries {
			if it.isPolicy {
				continue
			}
			r := decodeRuleWithChains(it, chainOffsets)
			if r == "" {
				continue
			}
			ruleNo++
			if verbose && lineNumbers {
				fmt.Printf("%3d %5d %5d %s\n", ruleNo, it.entry.Counters.Pcnt, it.entry.Counters.Bcnt, r)
			} else if verbose {
				fmt.Printf("%5d %5d %s\n", it.entry.Counters.Pcnt, it.entry.Counters.Bcnt, r)
			} else if lineNumbers {
				fmt.Printf("%3d %s\n", ruleNo, r)
			} else {
				fmt.Println(r)
			}
		}
		printed++
	}
	if printed == 0 {
		if chain != "" {
			return fmt.Errorf("chain %s not found", chain)
		}
		return fmt.Errorf("no chains decoded in table %s", table)
	}
	return nil
}

func debugDump(table string) error {
	info, blob, err := readTable(table)
	if err != nil {
		return err
	}
	items, err := decodeTable(blob)
	if err != nil {
		return err
	}
	fmt.Printf("TABLE=%s valid_hooks=%#x num_entries=%d size=%d blob=%d\n", table, info.ValidHooks, info.NumEntries, info.Size, len(blob))
	hooks := []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}
	for i, name := range hooks {
		if info.ValidHooks&(1<<i) != 0 {
			fmt.Printf("HOOK %s index=%d hook_entry=%d underflow=%d\n", name, i, info.HookEntry[i], info.Underflow[i])
		}
	}
	for _, it := range items {
		tname := cString(it.target.Name[:])
		verdict := ""
		if tname == "" && len(it.targetData) >= 4 {
			verdict = strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(it.targetData[:4]))), 10)
		}
		fmt.Printf("ENTRY off=%d next=%d target_off=%d target=%q verdict=%s proto=%d iface=%q matches=%d matchhex=%x targethex=%x decoded=%q policy=%v marker=%v chain=%q\n",
			it.offset, it.entry.NextOffset, it.entry.TargetOffset, tname, verdict, it.entry.IP.Proto,
			cString(it.entry.IP.Iniface[:]), len(it.matches), it.matches, it.targetData, decodeRule(it), it.isPolicy, it.isMarker, it.chain)
	}
	return nil
}

type command struct {
	table, operation, chain string
	inIface, outIface       string
	proto, target           string
	dstType, dstIP          string
	port, mark, dport       int
	position                int // 1-based rule number for -I; zero means append
}

func parseCommand(args []string) (command, error) {
	c := command{table: "filter"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func(flag string) (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", flag)
			}
			i++
			return args[i], nil
		}
		switch a {
		case "-t", "--table":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.table = v
		case "-N", "--new-chain":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.operation, c.chain = "new-chain", v
		case "-A", "--append":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.operation, c.chain = "append", v
		case "-I", "--insert":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.operation, c.chain, c.position = "insert", v, 1
			// iptables accepts an optional 1-based rule number immediately
			// after the chain. Without it, insertion is at the head.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				if n, e := strconv.Atoi(args[i+1]); e == nil {
					if n < 1 {
						return c, fmt.Errorf("invalid insertion position %d", n)
					}
					c.position = n
					i++
				}
			}
		case "-i", "--in-interface":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.inIface = v
		case "-o", "--out-interface":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.outIface = v
		case "-p", "--protocol":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.proto = strings.ToLower(v)
			if c.proto == "all" {
				c.proto = ""
			}
		case "-j", "--jump":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.target = v
		case "--to-port", "--to-ports":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			n, e := strconv.Atoi(v)
			if e != nil {
				return c, e
			}
			c.port = n
		case "--set-mark", "--set-xmark":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			v = strings.SplitN(v, "/", 2)[0]
			n, e := strconv.ParseUint(v, 0, 32)
			if e != nil {
				return c, e
			}
			c.mark = int(n)
		case "--dport", "--destination-port":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			n, e := strconv.Atoi(v)
			if e != nil {
				return c, e
			}
			c.dport = n
		case "--dst-type":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.dstType = strings.ToUpper(v)
		case "--to", "--to-destination":
			v, err := next(a)
			if err != nil {
				return c, err
			}
			c.dstIP = v
			c.target = "DNAT"
		case "-m", "--match":
			// Match modules are parsed through their following options. The compact
			// backend currently recognizes udp and addrtype in the rule builder.
			if i+1 >= len(args) {
				return c, fmt.Errorf("missing value for %s", a)
			}
			i++
		default:
			if strings.HasPrefix(a, "-") {
				return c, fmt.Errorf("unsupported argument %q", a)
			}
		}
	}
	if c.table != "filter" && c.table != "nat" && c.table != "mangle" && c.table != "raw" {
		return c, fmt.Errorf("unsupported table %q (supported: filter, nat, mangle, raw)", c.table)
	}
	if c.operation == "" || c.chain == "" {
		return c, errors.New("usage: iptables -t {filter|nat|mangle} -N CHAIN | -A CHAIN ... | -I CHAIN [RULENUM] ...")
	}
	if len(c.inIface) >= 16 || len(c.outIface) >= 16 || strings.ContainsAny(c.inIface+c.outIface, "+") {
		return c, errors.New("invalid interface name (max 15 chars, no wildcard)")
	}
	return c, nil
}

// parseArgs is retained for the original focused rule tests and legacy callers.
func parseArgs(args []string) (table, chain, iface, proto, target string, port, mark, dport int, err error) {
	c, err := parseCommand(args)
	if err != nil {
		return
	}
	if c.operation != "append" {
		err = errors.New("only append rules are accepted by parseArgs")
		return
	}
	return c.table, c.chain, c.inIface, c.proto, c.target, c.port, c.mark, c.dport, nil
}

func makeRule(proto string, iface string, target string, port, mark, dport int) ([]byte, error) {
	return makeRuleFor(proto, iface, "", target, port, mark, dport, 0, "", "")
}

func makeRuleFor(proto, inIface, outIface, target string, port, mark, dport int, jumpOffset uint32, dstType, dstIP string) ([]byte, error) {
	var p uint16
	switch proto {
	case "tcp":
		p = ipProtoTCP
	case "udp":
		p = ipProtoUDP
	case "":
	default:
		return nil, fmt.Errorf("unsupported protocol %q", proto)
	}
	entrySize := int(unsafe.Sizeof(iptEntry{}))
	matches := []byte{}
	if proto == "udp" && dport > 0 {
		m := make([]byte, align(int(unsafe.Sizeof(xtEntryMatch{}))+int(unsafe.Sizeof(xtUDP{}))))
		h := (*xtEntryMatch)(unsafe.Pointer(&m[0]))
		h.Size = uint16(len(m))
		cstr(h.Name[:], "udp")
		u := (*xtUDP)(unsafe.Pointer(&m[unsafe.Sizeof(xtEntryMatch{})]))
		u.Dpts = [2]uint16{htons(uint16(dport)), htons(uint16(dport))}
		matches = append(matches, m...)
	}
	if dstType != "" {
		if dstType != "LOCAL" {
			return nil, fmt.Errorf("unsupported destination address type %q", dstType)
		}
		m := make([]byte, align(int(unsafe.Sizeof(xtEntryMatch{}))+int(unsafe.Sizeof(xtAddrTypeInfoV1{}))))
		h := (*xtEntryMatch)(unsafe.Pointer(&m[0]))
		h.Size = uint16(len(m))
		h.Revision = 1
		cstr(h.Name[:], "addrtype")
		a := (*xtAddrTypeInfoV1)(unsafe.Pointer(&m[unsafe.Sizeof(xtEntryMatch{})]))
		a.Dest = 0x0004 // XT_ADDRTYPE_LOCAL (RTN_LOCAL=2, bit 2)
		matches = append(matches, m...)
	}
	var targetData []byte
	switch target {
	case "REDIRECT", "MASQUERADE":
		n := natMultiRange{RangeSize: 1}
		if target == "REDIRECT" {
			n.Range.Flags = 2
			n.Range.MinProto = htons(uint16(port))
			n.Range.MaxProto = htons(uint16(port))
		}
		targetData = make([]byte, align(int(unsafe.Sizeof(xtEntryTarget{}))+int(unsafe.Sizeof(natMultiRange{}))))
		copy(targetData[int(unsafe.Sizeof(xtEntryTarget{})):], unsafe.Slice((*byte)(unsafe.Pointer(&n)), int(unsafe.Sizeof(n))))
	case "DNAT":
		ip := net.ParseIP(dstIP).To4()
		if ip == nil {
			return nil, fmt.Errorf("DNAT requires an IPv4 --to/--to-destination address, got %q", dstIP)
		}
		n := natMultiRange{RangeSize: 1}
		n.Range.Flags = 1
		n.Range.MinIP = binary.NativeEndian.Uint32(ip)
		n.Range.MaxIP = n.Range.MinIP
		if port > 0 {
			n.Range.Flags |= 2
			n.Range.MinProto = htons(uint16(port))
			n.Range.MaxProto = htons(uint16(port))
		}
		targetData = make([]byte, align(int(unsafe.Sizeof(xtEntryTarget{}))+int(unsafe.Sizeof(natMultiRange{}))))
		copy(targetData[int(unsafe.Sizeof(xtEntryTarget{})):], unsafe.Slice((*byte)(unsafe.Pointer(&n)), int(unsafe.Sizeof(n))))
	case "MARK":
		n := xtMarkInfo{Mark: uint32(mark), Mask: 0xffffffff}
		targetData = make([]byte, align(int(unsafe.Sizeof(xtEntryTarget{}))+int(unsafe.Sizeof(n))))
		copy(targetData[int(unsafe.Sizeof(xtEntryTarget{})):], unsafe.Slice((*byte)(unsafe.Pointer(&n)), int(unsafe.Sizeof(n))))
	case "DROP", "ACCEPT", "RETURN":
		targetData = make([]byte, align(int(unsafe.Sizeof(xtEntryTarget{}))+4))
		verdict := int32(-1) // NF_DROP
		if target == "ACCEPT" {
			verdict = -2
		} else if target == "RETURN" {
			verdict = -5
		}
		binary.LittleEndian.PutUint32(targetData[int(unsafe.Sizeof(xtEntryTarget{})):], uint32(verdict))
	case "CHAIN":
		targetData = make([]byte, align(int(unsafe.Sizeof(xtEntryTarget{}))+4))
		binary.LittleEndian.PutUint32(targetData[int(unsafe.Sizeof(xtEntryTarget{})):], jumpOffset)
	default:
		return nil, fmt.Errorf("unsupported target %s", target)
	}
	t := (*xtEntryTarget)(unsafe.Pointer(&targetData[0]))
	t.Size = uint16(len(targetData))
	if target == "REDIRECT" || target == "MASQUERADE" || target == "MARK" || target == "DNAT" {
		cstr(t.Name[:], target)
	}
	// xt_mark's kernel target uses revision 2 (xt_mark_tginfo2: mark, mask).
	// Revision 0 is rejected by kernels that only register the current target
	// revision, with EPROTOTYPE during IPT_SO_SET_REPLACE.
	if target == "MARK" {
		t.Revision = 2
	}
	total := entrySize + len(matches) + len(targetData)
	out := make([]byte, total)
	e := (*iptEntry)(unsafe.Pointer(&out[0]))
	e.IP.Proto = p
	if inIface != "" {
		copy(e.IP.Iniface[:], inIface)
		for i := 0; i <= len(inIface); i++ {
			e.IP.InifaceMask[i] = 0xff
		}
	}
	if outIface != "" {
		copy(e.IP.Outiface[:], outIface)
		for i := 0; i <= len(outIface); i++ {
			e.IP.OutifaceMask[i] = 0xff
		}
	}
	e.TargetOffset = uint16(entrySize + len(matches))
	e.NextOffset = uint16(total)
	copy(out[entrySize:], matches)
	copy(out[entrySize+len(matches):], targetData)
	return out, nil
}

func makeChainMarker(name string) ([]byte, error) {
	if name == "" || len(name) >= 30 || strings.ContainsAny(name, " /\t\n") {
		return nil, fmt.Errorf("invalid chain name %q", name)
	}
	entrySize := int(unsafe.Sizeof(iptEntry{}))
	targetSize := align(int(unsafe.Sizeof(xtEntryTarget{})) + 30)
	out := make([]byte, entrySize+targetSize)
	e := (*iptEntry)(unsafe.Pointer(&out[0]))
	e.TargetOffset = uint16(entrySize)
	e.NextOffset = uint16(len(out))
	t := (*xtEntryTarget)(unsafe.Pointer(&out[entrySize]))
	t.Size = uint16(targetSize)
	cstr(t.Name[:], "ERROR")
	copy(out[entrySize+int(unsafe.Sizeof(xtEntryTarget{})):], name)
	return out, nil
}

func makeReturnEntry() []byte {
	entrySize := int(unsafe.Sizeof(iptEntry{}))
	targetSize := align(int(unsafe.Sizeof(xtEntryTarget{})) + 4)
	out := make([]byte, entrySize+targetSize)
	e := (*iptEntry)(unsafe.Pointer(&out[0]))
	e.TargetOffset = uint16(entrySize)
	e.NextOffset = uint16(len(out))
	t := (*xtEntryTarget)(unsafe.Pointer(&out[entrySize]))
	t.Size = uint16(targetSize)
	binary.LittleEndian.PutUint32(out[entrySize+int(unsafe.Sizeof(xtEntryTarget{})):], ^uint32(4))
	return out
}

func shiftHookOffsets(info *iptGetInfo, off, delta uint32) {
	for i := range info.HookEntry {
		// HookEntry at the insertion point must remain there: the inserted
		// rule becomes the first rule in that built-in chain.
		if info.HookEntry[i] > off {
			info.HookEntry[i] += delta
		}
	}
}

func tableHook(table, chain string) (int, bool) {
	hooks := map[string]int{"PREROUTING": nfPreRouting, "INPUT": nfInput, "FORWARD": nfForward, "OUTPUT": nfOutput, "POSTROUTING": nfPostRouting}
	h, ok := hooks[chain]
	if table == "nat" && chain == "FORWARD" {
		return 0, false
	}
	if table == "raw" && chain != "PREROUTING" && chain != "OUTPUT" {
		return 0, false
	}
	if table == "filter" && (chain == "PREROUTING" || chain == "POSTROUTING") {
		return 0, false
	}
	return h, ok
}

func collectCounters(blob []byte) ([]xtCounters, error) {
	var out []xtCounters
	for pos := 0; pos < len(blob); {
		if pos+int(unsafe.Sizeof(iptEntry{})) > len(blob) {
			return nil, errors.New("corrupt entry table")
		}
		e := (*iptEntry)(unsafe.Pointer(&blob[pos]))
		n := int(e.NextOffset)
		if n < int(unsafe.Sizeof(iptEntry{})) || pos+n > len(blob) {
			return nil, errors.New("corrupt entry size")
		}
		out = append(out, e.Counters)
		pos += n
	}
	return out, nil
}

func replaceTable(fd int, table string, info iptGetInfo, blob []byte, counters []xtCounters) error {
	info.Size = uint32(len(blob))
	if err := setReplace(fd, table, info, blob, counters); err != nil {
		return fmt.Errorf("IPT_SO_SET_REPLACE %s: %w", table, err)
	}
	check, err := getInfo(fd, table)
	if err != nil {
		return fmt.Errorf("read-back IPT_SO_GET_INFO failed: %w", err)
	}
	if check.NumEntries != info.NumEntries || check.Size != info.Size {
		return fmt.Errorf("kernel table verification mismatch: entries want=%d got=%d size want=%d got=%d", info.NumEntries, check.NumEntries, info.Size, check.Size)
	}
	return nil
}

func findUserChain(items []decodedEntry, name string) (int, int, bool) {
	for i, it := range items {
		if it.isMarker && it.chain == name {
			end := i + 1
			for end < len(items) && !items[end].isMarker {
				end++
			}
			return i, end, true
		}
	}
	return 0, 0, false
}

func createChain(table, chain string) error {
	fd, err := sock()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	info, err := getInfo(fd, table)
	if err != nil {
		return err
	}
	blob, err := getEntries(fd, table, info.Size)
	if err != nil {
		return err
	}
	items, err := decodeTable(blob)
	if err != nil {
		return err
	}
	if _, _, ok := findUserChain(items, chain); ok {
		return fmt.Errorf("chain %s already exists", chain)
	}
	marker, err := makeChainMarker(chain)
	if err != nil {
		return err
	}
	ret := makeReturnEntry()
	counters, err := collectCounters(blob)
	if err != nil {
		return err
	}
	newBlob := append(append(append([]byte{}, blob...), marker...), ret...)
	info.NumEntries += 2
	return replaceTable(fd, table, info, newBlob, counters)
}

func ruleInsertionOffset(info iptGetInfo, items []decodedEntry, table, chain string, position int) (int, error) {
	if position < 0 {
		return 0, fmt.Errorf("invalid insertion position %d", position)
	}
	if h, ok := tableHook(table, chain); ok && info.ValidHooks&(1<<h) != 0 {
		start, end := int(info.HookEntry[h]), int(info.Underflow[h])
		if start < 0 || end < start {
			return 0, errors.New("kernel returned invalid built-in chain offsets")
		}
		if position == 0 { // append: immediately before the policy/underflow entry
			return end, nil
		}
		var rules []int
		for _, item := range items {
			if item.offset < start || item.offset >= end || item.isMarker {
				continue
			}
			rules = append(rules, item.offset)
		}
		if position > len(rules)+1 {
			return 0, fmt.Errorf("insertion position %d is out of range (chain has %d rules)", position, len(rules))
		}
		if position == len(rules)+1 {
			return end, nil
		}
		return rules[position-1], nil
	}

	marker, end, ok := findUserChain(items, chain)
	if !ok {
		return 0, fmt.Errorf("chain %s does not exist in table %s", chain, table)
	}
	if end <= marker+1 {
		return 0, fmt.Errorf("malformed user chain %s", chain)
	}
	terminator := items[end-1]
	if cString(terminator.target.Name[:]) != "" || len(terminator.targetData) < 4 || int32(binary.LittleEndian.Uint32(terminator.targetData[:4])) != -5 {
		return 0, fmt.Errorf("user chain %s has no RETURN terminator", chain)
	}
	rules := items[marker+1 : end-1]
	if position == 0 { // append before the implicit RETURN
		return terminator.offset, nil
	}
	if position > len(rules)+1 {
		return 0, fmt.Errorf("insertion position %d is out of range (chain has %d rules)", position, len(rules))
	}
	if position == len(rules)+1 {
		return terminator.offset, nil
	}
	return rules[position-1].offset, nil
}

func appendRule(table, chain string, hook int, rule []byte) error {
	return insertRuleAt(table, chain, hook, rule, 0)
}

func insertRuleAt(table, chain string, hook int, rule []byte, position int) error {
	fd, err := sock()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	info, err := getInfo(fd, table)
	if err != nil {
		return fmt.Errorf("IPT_SO_GET_INFO %s: %w", table, err)
	}
	entries, err := getEntries(fd, table, info.Size)
	if err != nil {
		return err
	}
	items, err := decodeTable(entries)
	if err != nil {
		return err
	}
	insertAt, err := ruleInsertionOffset(info, items, table, chain, position)
	if err != nil {
		return err
	}
	if insertAt < 0 || insertAt > len(entries) {
		return errors.New("kernel returned invalid insertion offset")
	}
	counters, err := collectCounters(entries)
	if err != nil {
		return err
	}
	newBlob := make([]byte, len(entries)+len(rule))
	copy(newBlob, entries[:insertAt])
	copy(newBlob[insertAt:], rule)
	copy(newBlob[insertAt+len(rule):], entries[insertAt:])
	shiftHookOffsets(&info, uint32(insertAt), uint32(len(rule)))
	for i := range info.Underflow {
		if info.Underflow[i] >= uint32(insertAt) {
			info.Underflow[i] += uint32(len(rule))
		}
	}
	// Standard jump verdicts are absolute byte offsets. Keep their destinations
	// stable when an entry is inserted before a user-chain marker.
	for pos := 0; pos < len(newBlob); {
		e := (*iptEntry)(unsafe.Pointer(&newBlob[pos]))
		n := int(e.NextOffset)
		if n <= 0 || pos+n > len(newBlob) {
			return errors.New("corrupt rebuilt table")
		}
		tpos := pos + int(e.TargetOffset)
		if tpos+int(unsafe.Sizeof(xtEntryTarget{}))+4 <= pos+n {
			t := (*xtEntryTarget)(unsafe.Pointer(&newBlob[tpos]))
			if t.Name[0] == 0 {
				v := int32(binary.LittleEndian.Uint32(newBlob[tpos+int(unsafe.Sizeof(xtEntryTarget{})):]))
				if v >= int32(insertAt) {
					binary.LittleEndian.PutUint32(newBlob[tpos+int(unsafe.Sizeof(xtEntryTarget{})):], uint32(v+int32(len(rule))))
				}
			}
		}
		pos += n
	}
	info.NumEntries++
	return replaceTable(fd, table, info, newBlob, counters)
}

func run(args []string) error {
	c, err := parseCommand(args)
	if err != nil {
		return err
	}
	if c.operation == "new-chain" {
		return createChain(c.table, c.chain)
	}
	if c.operation != "append" && c.operation != "insert" {
		return fmt.Errorf("unsupported operation %s", c.operation)
	}
	if c.target == "" {
		return errors.New("missing -j target")
	}
	targetName := strings.ToUpper(c.target)
	if targetName == "REDIRECT" && c.port <= 0 {
		return errors.New("REDIRECT requires --to-ports")
	}
	if targetName == "MARK" && c.mark < 0 {
		return errors.New("invalid MARK value")
	}
	hook, isBuiltin := tableHook(c.table, c.chain)
	itemsHook := -1
	if isBuiltin {
		itemsHook = hook
	}
	jumpOffset := uint32(0)
	target := targetName
	if target == "DNAT" && c.dstIP == "" {
		return errors.New("DNAT requires --to or --to-destination")
	}
	if target != "REDIRECT" && target != "MASQUERADE" && target != "MARK" && target != "DROP" && target != "ACCEPT" && target != "RETURN" && target != "DNAT" {
		fd, e := sock()
		if e != nil {
			return e
		}
		defer syscall.Close(fd)
		info, e := getInfo(fd, c.table)
		if e != nil {
			return e
		}
		blob, e := getEntries(fd, c.table, info.Size)
		if e != nil {
			return e
		}
		items, e := decodeTable(blob)
		if e != nil {
			return e
		}
		idx, _, ok := findUserChain(items, c.target)
		if !ok {
			return fmt.Errorf("jump target chain %s does not exist", c.target)
		}
		// A user-chain marker is an ERROR target; jump to the first rule after it.
		jumpOffset = uint32(items[idx].offset) + uint32(items[idx].entry.NextOffset)
		target = "CHAIN"
	}
	rule, err := makeRuleFor(c.proto, c.inIface, c.outIface, target, c.port, c.mark, c.dport, jumpOffset, c.dstType, c.dstIP)
	if err != nil {
		return err
	}
	if c.operation == "insert" {
		return insertRuleAt(c.table, c.chain, itemsHook, rule, c.position)
	}
	return appendRule(c.table, c.chain, itemsHook, rule)
}

// Main executes the compact iptables-legacy CLI and returns its process exit code.
func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  iptables [-t TABLE] -L [CHAIN] [OPTIONS]")
	fmt.Println("  iptables [-t TABLE] -S [CHAIN]")
	fmt.Println("  iptables -t TABLE -N CHAIN")
	fmt.Println("  iptables -t TABLE -A CHAIN [RULE]")
	fmt.Println("  iptables -t TABLE -I CHAIN [RULENUM] [RULE]")
	fmt.Println()
	fmt.Println("Tables: filter, nat, mangle, raw")
	fmt.Println("List options: -n (numeric), -v (verbose), --line-numbers")
	fmt.Println("Rule options: -i IN, -o OUT, -p PROTO, -m udp --dport PORT, -j TARGET")
	fmt.Println("Targets: ACCEPT, RETURN, DROP, REDIRECT, DNAT, MASQUERADE, MARK, or user chain")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  iptables -L -n -v")
	fmt.Println("  iptables -t nat -L PREROUTING --line-numbers")
	fmt.Println("  iptables -t nat -N MYCHAIN")
	fmt.Println("  iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports 12345")
	fmt.Println("  iptables -t nat -A PREROUTING -d 198.51.100.10 -j DNAT --to-destination 198.51.100.10")
	fmt.Println()
	fmt.Println("This is a compact legacy subset; unsupported iptables options are not implemented.")
}

func Main(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "iptables: compact IPv4 legacy subset\nSupported: filter/nat/mangle/raw tables, user-chain creation, append/insert rules, chain jumps, ACCEPT/RETURN/DROP, REDIRECT, DNAT, MASQUERADE and MARK")
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" {
		printHelp()
		return 0
	}
	if len(args) > 0 && (args[0] == "-L" || args[0] == "--list" || args[0] == "-S" || args[0] == "--list-rules") {
		if err := listRules("filter", args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "iptables:", err)
			return 1
		}
		return 0
	}
	if len(args) >= 3 && args[0] == "-t" && (args[2] == "-L" || args[2] == "--list" || args[2] == "-S" || args[2] == "--list-rules") {
		if err := listRules(args[1], args[3:]); err != nil {
			fmt.Fprintln(os.Stderr, "iptables:", err)
			return 1
		}
		return 0
	}
	if len(args) == 2 && args[0] == "--debug-dump" {
		if err := debugDump(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "iptables:", err)
			return 1
		}
		return 0
	}
	if args[0] == "--version" || args[0] == "-V" {
		fmt.Println("iptables v1.8-compact (legacy IPv4 subset)")
		return 0
	}
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, "iptables:", err)
		return 1
	}
	return 0
}
