//go:build linux

package iptables

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	r.NumCounters = info.NumEntries - 1
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

func decodeRule(item decodedEntry) string {
	e := item.entry
	parts := make([]string, 0, 10)
	if e.IP.InifaceMask != ([16]byte{}) {
		iface := cString(e.IP.Iniface[:])
		if iface != "" {
			parts = append(parts, "-i", iface)
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
			u := (*xtUDP)(unsafe.Pointer(&item.matches[off+int(unsafe.Sizeof(xtEntryMatch{}))]))
			lo, hi := ntohs(u.Dpts[0]), ntohs(u.Dpts[1])
			if lo == hi && lo != 0 {
				parts = append(parts, "-m", "udp", "--dport", strconv.Itoa(int(lo)))
			}
		}
		off += ms
	}
	switch cString(item.target.Name[:]) {
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
		default:
			parts = append(parts, "-j", "RETURN")
		}
	default:
		parts = append(parts, "-j", cString(item.target.Name[:]))
	}
	return strings.Join(parts, " ")
}

func listRules(table string, args []string) error {
	if table != "nat" && table != "mangle" {
		return fmt.Errorf("unsupported table %q (supported: nat, mangle)", table)
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
	if table == "nat" {
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
	showRules := len(args) > 0 && (args[0] == "-S" || args[0] == "--list-rules")
	chain := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		chain = args[0]
	}
	if showRules && len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		chain = args[1]
	}
	verbose := false
	for _, a := range args {
		if a == "-v" || a == "--verbose" {
			verbose = true
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
			for _, it := range entries {
				if it.isPolicy {
					continue
				}
				r := decodeRule(it)
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
		fmt.Printf("Chain %s (policy %s)\n", name, policy)
		if verbose {
			fmt.Println(" pkts bytes target     prot opt in     out     source               destination")
		} else {
			fmt.Println("target     prot opt in     out     source               destination")
		}
		for _, it := range entries {
			if it.isPolicy {
				continue
			}
			r := decodeRule(it)
			if r == "" {
				continue
			}
			if verbose {
				fmt.Printf("%5d %5d %s\n", it.entry.Counters.Pcnt, it.entry.Counters.Bcnt, r)
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
		fmt.Printf("ENTRY off=%d next=%d target_off=%d target=%q proto=%d iface=%q matches=%d decoded=%q policy=%v marker=%v\n",
			it.offset, it.entry.NextOffset, it.entry.TargetOffset, tname, it.entry.IP.Proto,
			cString(it.entry.IP.Iniface[:]), len(it.matches), decodeRule(it), it.isPolicy, it.isMarker)
	}
	return nil
}

func parseArgs(args []string) (table, chain, iface, proto, target string, port, mark, dport int, err error) {
	if len(args) < 5 || args[0] != "-t" {
		err = errors.New("usage: iptables -t {nat|mangle} -A CHAIN ...")
		return
	}
	table = args[1]
	if table != "nat" && table != "mangle" {
		err = fmt.Errorf("unsupported table %q", table)
		return
	}
	if args[2] != "-A" {
		err = errors.New("only -A is supported")
		return
	}
	chain = args[3]
	for i := 4; i < len(args); i++ {
		switch args[i] {
		case "-i":
			i++
			if i >= len(args) {
				err = errors.New("missing -i interface")
				return
			}
			iface = args[i]
		case "-p":
			i++
			if i >= len(args) {
				err = errors.New("missing protocol")
				return
			}
			proto = args[i]
		case "-j":
			i++
			if i >= len(args) {
				err = errors.New("missing target")
				return
			}
			target = args[i]
		case "--to-port":
			i++
			if i >= len(args) {
				err = errors.New("missing --to-port")
				return
			}
			port, err = strconv.Atoi(args[i])
			if err != nil {
				return
			}
		case "--set-mark":
			i++
			if i >= len(args) {
				err = errors.New("missing --set-mark")
				return
			}
			mark, err = strconv.Atoi(args[i])
			if err != nil {
				return
			}
		case "--dport":
			i++
			if i >= len(args) {
				err = errors.New("missing --dport")
				return
			}
			dport, err = strconv.Atoi(args[i])
			if err != nil {
				return
			}
		default:
			err = fmt.Errorf("unsupported argument %q", args[i])
			return
		}
	}
	if iface != "" && (len(iface) >= 16 || strings.Contains(iface, "+")) {
		err = fmt.Errorf("invalid interface name %q (max 15 chars, no wildcard)", iface)
		return
	}
	if table == "nat" && chain == "PREROUTING" && proto == "tcp" && target == "REDIRECT" && iface != "" && port > 0 && port <= 65535 && mark == 0 && dport == 0 {
		return
	}
	if table == "nat" && chain == "POSTROUTING" && proto == "" && target == "MASQUERADE" && iface == "" && port == 0 && mark == 0 && dport == 0 {
		return
	}
	if table == "mangle" && chain == "PREROUTING" && proto == "udp" && target == "MARK" && iface != "" && mark >= 0 && port == 0 && dport == 0 {
		return
	}
	if table == "mangle" && chain == "PREROUTING" && proto == "udp" && target == "DROP" && iface == "" && dport > 0 && dport <= 65535 && port == 0 && mark == 0 {
		return
	}
	err = errors.New("command is outside the supported subset; expected one of the four entrypoint rules")
	return
}
func makeRule(proto string, iface string, target string, port, mark, dport int) ([]byte, error) {
	var p uint16
	if proto == "tcp" {
		p = ipProtoTCP
	} else if proto == "udp" {
		p = ipProtoUDP
	}
	entrySize := int(unsafe.Sizeof(iptEntry{}))
	matches := []byte{}
	if target == "DROP" {
		m := make([]byte, align(int(unsafe.Sizeof(xtEntryMatch{}))+int(unsafe.Sizeof(xtUDP{}))))
		h := (*xtEntryMatch)(unsafe.Pointer(&m[0]))
		h.Size = uint16(len(m))
		cstr(h.Name[:], "udp")
		u := (*xtUDP)(unsafe.Pointer(&m[unsafe.Sizeof(xtEntryMatch{})]))
		u.Dpts = [2]uint16{htons(uint16(dport)), htons(uint16(dport))}
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
	case "MARK":
		n := xtMarkInfo{Mark: uint32(mark), Mask: 0xffffffff}
		targetData = make([]byte, align(int(unsafe.Sizeof(xtEntryTarget{}))+int(unsafe.Sizeof(n))))
		copy(targetData[int(unsafe.Sizeof(xtEntryTarget{})):], unsafe.Slice((*byte)(unsafe.Pointer(&n)), int(unsafe.Sizeof(n))))
	case "DROP":
		targetData = make([]byte, align(int(unsafe.Sizeof(xtEntryTarget{}))+4))
		binary.LittleEndian.PutUint32(targetData[int(unsafe.Sizeof(xtEntryTarget{})):], ^uint32(0)) // NF_DROP verdict = -1
	default:
		return nil, fmt.Errorf("unsupported target %s", target)
	}
	t := (*xtEntryTarget)(unsafe.Pointer(&targetData[0]))
	t.Size = uint16(len(targetData))
	// DROP/ACCEPT/RETURN are standard verdicts, not extension targets.
	// The standard target's user-space name must be empty; its verdict
	// is carried in the first int32 of targetData.
	if target != "DROP" {
		cstr(t.Name[:], target)
	}
	if target == "MARK" {
		t.Revision = 2
	}
	total := entrySize + len(matches) + len(targetData)
	out := make([]byte, total)
	e := (*iptEntry)(unsafe.Pointer(&out[0]))
	e.IP.Proto = p
	if iface != "" {
		copy(e.IP.Iniface[:], iface)
		for i := 0; i <= len(iface); i++ {
			e.IP.InifaceMask[i] = 0xff
		}
	}
	e.TargetOffset = uint16(entrySize + len(matches))
	e.NextOffset = uint16(total)
	copy(out[entrySize:], matches)
	copy(out[entrySize+len(matches):], targetData)
	return out, nil
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

func appendRule(table, chain string, hook int, rule []byte) error {
	fd, err := sock()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	info, err := getInfo(fd, table)
	if err != nil {
		return fmt.Errorf("IPT_SO_GET_INFO %s: %w", table, err)
	}
	if hook < 0 || hook >= len(info.Underflow) || info.ValidHooks&(1<<hook) == 0 {
		return fmt.Errorf("hook %d is unavailable in table %s", hook, table)
	}
	entries, err := getEntries(fd, table, info.Size)
	if err != nil {
		return fmt.Errorf("IPT_SO_GET_ENTRIES %s: %w", table, err)
	}
	off := int(info.Underflow[hook])
	if off < 0 || off > len(entries) {
		return errors.New("kernel returned invalid underflow offset")
	}
	// Copy the old counter vector in original entry order for the kernel's counter remapping.
	counters := make([]xtCounters, 0, info.NumEntries)
	for pos := 0; pos < len(entries); {
		if pos+int(unsafe.Sizeof(iptEntry{})) > len(entries) {
			return errors.New("corrupt entry table")
		}
		e := (*iptEntry)(unsafe.Pointer(&entries[pos]))
		if e.NextOffset == 0 || pos+int(e.NextOffset) > len(entries) {
			return errors.New("corrupt entry size")
		}
		counters = append(counters, e.Counters)
		pos += int(e.NextOffset)
	}
	if uint32(len(counters)) != info.NumEntries {
		return fmt.Errorf("entry count mismatch: kernel=%d parsed=%d", info.NumEntries, len(counters))
	}
	// Insertion before the built-in chain policy: shift all following offsets and jump destinations.
	newBlob := make([]byte, len(entries)+len(rule))
	copy(newBlob, entries[:off])
	copy(newBlob[off:], rule)
	copy(newBlob[off+len(rule):], entries[off:])
	shiftHookOffsets(&info, uint32(off), uint32(len(rule)))
	for i := range info.Underflow {
		if info.Underflow[i] >= uint32(off) {
			info.Underflow[i] += uint32(len(rule))
		}
	}
	// Every standard jump target is an absolute byte offset into the table.
	for pos := 0; pos < len(newBlob); {
		e := (*iptEntry)(unsafe.Pointer(&newBlob[pos]))
		if e.NextOffset == 0 || pos+int(e.NextOffset) > len(newBlob) {
			return errors.New("corrupt rebuilt table")
		}
		tpos := pos + int(e.TargetOffset)
		if tpos+int(unsafe.Sizeof(xtEntryTarget{})) <= pos+int(e.NextOffset) {
			t := (*xtEntryTarget)(unsafe.Pointer(&newBlob[tpos]))
			if t.Name[0] == 0 && tpos+int(unsafe.Sizeof(xtEntryTarget{}))+4 <= pos+int(e.NextOffset) {
				v := int32(binary.LittleEndian.Uint32(newBlob[tpos+int(unsafe.Sizeof(xtEntryTarget{})):]))
				if v >= int32(off) {
					binary.LittleEndian.PutUint32(newBlob[tpos+int(unsafe.Sizeof(xtEntryTarget{})):], uint32(v+int32(len(rule))))
				}
			}
		}
		pos += int(e.NextOffset)
	}
	info.NumEntries++
	info.Size += uint32(len(rule))
	if err := setReplace(fd, table, info, newBlob, counters); err != nil {
		return fmt.Errorf("IPT_SO_SET_REPLACE %s: %w", table, err)
	}

	// Verify the kernel actually published the replacement before reporting success.
	check, err := getInfo(fd, table)
	if err != nil {
		return fmt.Errorf("rule submitted, but read-back IPT_SO_GET_INFO failed: %w", err)
	}
	if check.NumEntries != info.NumEntries || check.Size != info.Size {
		return fmt.Errorf("kernel accepted IPT_SO_SET_REPLACE but table did not change: entries before=%d after=%d; size before=%d after=%d",
			info.NumEntries-1, check.NumEntries, info.Size-uint32(len(rule)), check.Size)
	}
	// The kernel may normalize rule bytes when storing a replacement (for
	// example, target-specific data and alignment/padding). Do not compare the
	// raw userspace blob byte-for-byte: that can report false errors even when
	// the rule was accepted and is visible in the table. The metadata check
	// above is the reliable confirmation that the table was updated.
	return nil
}

func run(args []string) error {
	table, chain, iface, proto, target, port, mark, dport, err := parseArgs(args)
	if err != nil {
		return err
	}
	if target == "REDIRECT" && iface == "" {
		return errors.New("REDIRECT rule requires -i interface")
	}
	if target == "MARK" && iface == "" {
		return errors.New("MARK rule requires -i interface")
	}
	hook := nfPreRouting
	if chain == "POSTROUTING" {
		hook = nfPostRouting
	}
	rule, err := makeRule(proto, iface, target, port, mark, dport)
	if err != nil {
		return err
	}
	return appendRule(table, chain, hook, rule)
}

// Main executes the compact iptables-legacy CLI and returns its process exit code.
func Main(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(os.Stderr, "iptables: compact IPv4 legacy subset\nSupported: nat PREROUTING REDIRECT, nat POSTROUTING MASQUERADE, mangle PREROUTING MARK, mangle PREROUTING UDP dport DROP")
		if len(args) == 0 {
			return 2
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
