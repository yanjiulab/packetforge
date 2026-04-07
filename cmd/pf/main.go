// pf: Register protocols based on PDL and send packets to the interface based on PSL script
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/yanjiulab/packetforge/pkg/engine"
	"github.com/yanjiulab/packetforge/pkg/packet"
	"github.com/yanjiulab/packetforge/pkg/pdl"
	"github.com/yanjiulab/packetforge/pkg/psl"
)

// isRecvTimeout is true when libpcap returns no packet within the handle read timeout
// (gopacket pcap.NextErrorTimeoutExpired, Error() == "Timeout Expired").
// We match by string so cmd/pf does not import gopacket/pcap (keeps Linux CGO=0 builds working).
func isRecvTimeout(err error) bool {
	return err != nil && err.Error() == "Timeout Expired"
}

// FormatTCPDump converts binary buffer to tcpdump-style string
// Parameters:
//
//	buf: binary data to format
//	startOffset: starting address offset (e.g. 0 for 0x0000:)
//
// Returns:
//
//	tcpdump-style formatted string (each line: offset + hex + ASCII)
func FormatTCPDump(buf []byte, startOffset int) string {
	const bytesPerLine = 16         // tcpdump default: 16 bytes per line
	var dumpBuilder strings.Builder // Build final output string
	offset := startOffset           // Current address offset

	// Iterate buffer by 16-byte chunks
	for i := 0; i < len(buf); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(buf) {
			end = len(buf)
		}
		lineBytes := buf[i:end]

		// 1. Build offset prefix (e.g. 0x0000:)
		offsetStr := fmt.Sprintf("0x%04x:", offset)
		dumpBuilder.WriteString(offsetStr)
		dumpBuilder.WriteString("  ")

		// 2. Build hex part (8 bytes + 2 spaces + 8 bytes)
		hexParts := make([]string, bytesPerLine)
		for j, b := range lineBytes {
			hexParts[j] = fmt.Sprintf("%02x", b)
		}
		// Fill empty slots for alignment (for last line)
		for j := len(lineBytes); j < bytesPerLine; j++ {
			hexParts[j] = "  "
		}
		// Split into two groups (8 bytes each) for readability
		hexStr := strings.Join(hexParts[:8], " ") + "  " + strings.Join(hexParts[8:], " ")
		dumpBuilder.WriteString(hexStr)
		dumpBuilder.WriteString("  ")

		// 3. Build ASCII part (printable chars or '.')
		for _, b := range lineBytes {
			if b >= 32 && b <= 126 { // Printable ASCII range
				dumpBuilder.WriteByte(b)
			} else {
				dumpBuilder.WriteByte('.')
			}
		}

		// 4. Add newline (except for last line)
		if i+bytesPerLine < len(buf) {
			dumpBuilder.WriteString("\n")
		}

		// Update offset for next line
		offset += bytesPerLine
	}

	return dumpBuilder.String()
}

// FormatGoBytesLiteral converts binary buffer to copyable Go []byte literal.
func FormatGoBytesLiteral(buf []byte) string {
	if len(buf) == 0 {
		return "[]byte{}"
	}
	var b strings.Builder
	b.WriteString("[]byte{")
	for i, v := range buf {
		if i%12 == 0 {
			b.WriteString("\n\t")
		} else {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "0x%02x,", v)
	}
	b.WriteString("\n}")
	return b.String()
}

// FormatCBytesLiteral converts binary buffer to copyable C unsigned char array initializer.
func FormatCBytesLiteral(buf []byte) string {
	if len(buf) == 0 {
		return "static const unsigned char pkt[] = { };"
	}
	var b strings.Builder
	b.WriteString("static const unsigned char pkt[] = {")
	for i, v := range buf {
		if i%12 == 0 {
			b.WriteString("\n\t")
		} else {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "0x%02x,", v)
	}
	b.WriteString("\n};")
	return b.String()
}

// FormatCppBytesLiteral converts binary buffer to copyable C++ std::array literal (requires <array>).
func FormatCppBytesLiteral(buf []byte) string {
	if len(buf) == 0 {
		return "static const std::array<unsigned char, 0> pkt{{}};"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "static const std::array<unsigned char, %d> pkt{{", len(buf))
	for i, v := range buf {
		if i%12 == 0 {
			b.WriteString("\n\t")
		} else {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "0x%02x,", v)
	}
	b.WriteString("\n}};")
	return b.String()
}

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
	BuiltBy = "unknown"
)

// String returns a human-friendly version string.
func VersionString() string {
	return fmt.Sprintf(
		"packetforge %s (commit=%s, date=%s, builtBy=%s, go=%s)",
		Version,
		Commit,
		Date,
		BuiltBy,
		runtime.Version(),
	)
}

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "pf",
		Short: "PacketForge protocol registry and packet sender",
		RunE: func(cmd *cobra.Command, args []string) error {
			pslFile := viper.GetString("stream")
			if pslFile == "" {
				return fmt.Errorf("required flag \"stream\" not set")
			}

			recvWaitExplicit := cmd.Flags().Changed("recv-wait") || os.Getenv("PF_RECV_WAIT") != ""
			return run(
				pslFile,
				viper.GetString("proto"),
				viper.GetString("iface"),
				viper.GetBool("dry-run"),
				viper.GetBool("go-literal"),
				viper.GetBool("c-literal"),
				viper.GetBool("cpp-literal"),
				viper.GetBool("builtin-proto"),
				viper.GetBool("recv"),
				viper.GetBool("recv-match-only"),
				viper.GetString("recv-view"),
				viper.GetString("expect-match-mode"),
				viper.GetDuration("recv-wait"),
				viper.GetInt("recv-count"),
				viper.GetString("recv-bpf"),
				recvWaitExplicit,
			)
		},
	}

	rootCmd.Version = VersionString()
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	flags := rootCmd.Flags()
	flags.StringP("proto", "p", "proto", "Protocol definition directory (.pdl files), optional")
	flags.StringP("stream", "s", "", "Packet stream language file (required)")
	flags.StringP("iface", "i", "lo", "Network interface to send packets (e.g. eth0, lo)")
	flags.BoolP("dry-run", "d", false, "Parse and build packets only, do not actually send")
	flags.Bool("go-literal", false, "Print each packet as Go []byte literal and do not send")
	flags.Bool("c-literal", false, "Print each packet as C static const unsigned char[] literal and do not send")
	flags.Bool("cpp-literal", false, "Print each packet as C++ std::array<unsigned char,N> literal and do not send")
	flags.BoolP("recv", "r", false, "Start receiving packets before sending and print received hex dump")
	flags.Bool("recv-match-only", false, "With -r, only print hex dump for packets matched by @expect")
	flags.String("recv-view", "hex", "Receive output view: packetview|hex|both")
	flags.String("expect-match-mode", "exact", "Expect match mode: exact|subset")
	flags.Duration("recv-wait", time.Second, "Wait duration for receiving packets after send completes (e.g. 500ms, 2s)")
	flags.Int("recv-count", 0, "Stop receive when this many packets are captured (0 means unlimited)")
	flags.String("recv-bpf", "", "tcpdump-style BPF filter for recv (e.g. icmp, tcp port 80); Linux uses libpcap when set")
	flags.BoolP("builtin-proto", "b", true, "Load built-in common protocols first (eth/vlan/arp/arp_request/arp_reply/ip/ipv6/icmp/icmp6/ndp_ns/ndp_na/udp/tcp)")
	flags.Int64("seed", 0, "Random seed for built-in random functions (0 means auto)")
	_ = rootCmd.RegisterFlagCompletionFunc("iface", completeIfaceNames)

	_ = viper.BindPFlag("proto", flags.Lookup("proto"))
	_ = viper.BindPFlag("stream", flags.Lookup("stream"))
	_ = viper.BindPFlag("iface", flags.Lookup("iface"))
	_ = viper.BindPFlag("dry-run", flags.Lookup("dry-run"))
	_ = viper.BindPFlag("go-literal", flags.Lookup("go-literal"))
	_ = viper.BindPFlag("c-literal", flags.Lookup("c-literal"))
	_ = viper.BindPFlag("cpp-literal", flags.Lookup("cpp-literal"))
	_ = viper.BindPFlag("recv", flags.Lookup("recv"))
	_ = viper.BindPFlag("recv-match-only", flags.Lookup("recv-match-only"))
	_ = viper.BindPFlag("recv-view", flags.Lookup("recv-view"))
	_ = viper.BindPFlag("expect-match-mode", flags.Lookup("expect-match-mode"))
	_ = viper.BindPFlag("recv-wait", flags.Lookup("recv-wait"))
	_ = viper.BindPFlag("recv-count", flags.Lookup("recv-count"))
	_ = viper.BindPFlag("recv-bpf", flags.Lookup("recv-bpf"))
	_ = viper.BindPFlag("builtin-proto", flags.Lookup("builtin-proto"))
	_ = viper.BindPFlag("seed", flags.Lookup("seed"))
	viper.SetEnvPrefix("PF")
	viper.AutomaticEnv()
	rootCmd.AddCommand(newBuiltinCmd())
	rootCmd.AddCommand(newExplainCmd())
	rootCmd.AddCommand(newFuzzCmd())
	rootCmd.AddCommand(newGenCmd())

	return rootCmd
}

func completeIfaceNames(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	names := make([]string, 0, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Name == "" {
			continue
		}
		names = append(names, ifc.Name)
	}
	sort.Strings(names)
	return names, cobra.ShellCompDirectiveNoFileComp
}

func newBuiltinCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "builtin",
		Short: "Show builtin protocol list",
		Run: func(cmd *cobra.Command, args []string) {
			for _, name := range pdl.BuiltinCommonProtocolNames() {
				fmt.Println(name)
			}
		},
	}
}

type explainLayer struct {
	Proto  string `json:"proto"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	Hex    string `json:"hex"`
}

type explainPacket struct {
	Index  int            `json:"index"`
	Bytes  int            `json:"bytes"`
	Layers []explainLayer `json:"layers"`
}

func newExplainCmd() *cobra.Command {
	var stream, protoDir, format string
	var builtinProto bool
	var seed int64
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Visualize packet layer layout and bytes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if stream == "" {
				return fmt.Errorf("required flag \"stream\" not set")
			}
			reg, err := loadRegistry(protoDir, builtinProto)
			if err != nil {
				return err
			}
			pslData, err := os.ReadFile(stream)
			if err != nil {
				return fmt.Errorf("read PSL: %w", err)
			}
			script, err := psl.NewParser(string(pslData)).ParseScript()
			if err != nil {
				return fmt.Errorf("parse PSL: %w", err)
			}
			packets := collectPackets(script.Stmts)
			if len(packets) == 0 {
				return fmt.Errorf("no packet statements found")
			}

			builder := packet.NewBuilder(reg)
			if seed != 0 {
				builder.SetRandSeed(seed)
			}

			var out []explainPacket
			for i, pkt := range packets {
				raw, err := builder.Build(pkt, &packet.BuildOptions{RepeatIndex: 0})
				if err != nil {
					return fmt.Errorf("build packet #%d: %w", i+1, err)
				}
				sizes, err := builder.LayerSizes(pkt)
				if err != nil {
					return fmt.Errorf("calc packet #%d layer size: %w", i+1, err)
				}
				offset := 0
				layers := make([]explainLayer, 0, len(pkt.Layers))
				for li, l := range pkt.Layers {
					sz := sizes[li]
					seg := raw[offset : offset+sz]
					layers = append(layers, explainLayer{
						Proto:  l.Proto,
						Offset: offset,
						Length: sz,
						Hex:    strings.ToUpper(hex.EncodeToString(seg)),
					})
					offset += sz
				}
				out = append(out, explainPacket{Index: i + 1, Bytes: len(raw), Layers: layers})
			}

			if strings.EqualFold(format, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			for _, p := range out {
				fmt.Printf("Packet #%d (%d bytes)\n", p.Index, p.Bytes)
				for _, l := range p.Layers {
					fmt.Printf("  - %-12s off=%-3d len=%-3d hex=%s\n", l.Proto, l.Offset, l.Length, l.Hex)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&stream, "stream", "s", "", "Packet stream language file (required)")
	cmd.Flags().StringVarP(&protoDir, "proto", "p", "proto", "Protocol definition directory (.pdl files), optional")
	cmd.Flags().BoolVarP(&builtinProto, "builtin-proto", "b", true, "Load built-in common protocols first")
	cmd.Flags().Int64Var(&seed, "seed", 0, "Random seed for built-in random functions (0 means auto)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func loadRegistry(pdlDir string, builtinProto bool) (*pdl.Registry, error) {
	reg := pdl.NewRegistry()
	if builtinProto {
		if err := reg.LoadBuiltinCommonProtocols(); err != nil {
			return nil, fmt.Errorf("load builtin protocols: %w", err)
		}
	}
	if pdlDir != "" {
		if _, err := os.Stat(pdlDir); err == nil {
			if err := reg.LoadPDLDir(pdlDir); err != nil {
				return nil, fmt.Errorf("load PDL dir: %w", err)
			}
		} else if !os.IsNotExist(err) || pdlDir != "proto" {
			return nil, fmt.Errorf("read proto dir %q: %w", pdlDir, err)
		}
	}
	return reg, nil
}

func collectPackets(stmts []psl.Stmt) []*psl.Packet {
	var packets []*psl.Packet
	for _, st := range stmts {
		switch s := st.(type) {
		case *psl.PacketStmt:
			if s.Packet != nil {
				packets = append(packets, s.Packet)
			}
		case *psl.BlockStmt:
			packets = append(packets, collectPackets(s.Stmts)...)
		}
	}
	return packets
}

func collectPacketStmts(stmts []psl.Stmt) []*psl.PacketStmt {
	var out []*psl.PacketStmt
	for _, st := range stmts {
		switch s := st.(type) {
		case *psl.PacketStmt:
			out = append(out, s)
		case *psl.BlockStmt:
			out = append(out, collectPacketStmts(s.Stmts)...)
		}
	}
	return out
}

func newFuzzCmd() *cobra.Command {
	var stream, protoDir, iface string
	var builtinProto, dryRun bool
	var seed int64
	var maxCases int
	cmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Run packet fuzzing rules from PSL",
		RunE: func(cmd *cobra.Command, args []string) error {
			if stream == "" {
				return fmt.Errorf("required flag \"stream\" not set")
			}
			reg, err := loadRegistry(protoDir, builtinProto)
			if err != nil {
				return err
			}
			pslData, err := os.ReadFile(stream)
			if err != nil {
				return fmt.Errorf("read PSL: %w", err)
			}
			parser := psl.NewParserWithOptions(string(pslData), psl.ParserOptions{AllowFuzz: true})
			script, err := parser.ParseScript()
			if err != nil {
				return fmt.Errorf("parse PSL: %w", err)
			}
			builder := packet.NewBuilder(reg)
			if seed != 0 {
				builder.SetRandSeed(seed)
			}
			sendFn := func(data []byte) error {
				if dryRun {
					fmt.Printf("[dry-run] Send %d bytes:\n%s\n", len(data), FormatTCPDump(data, 0))
					return nil
				}
				return nil
			}
			if !dryRun {
				sender, err := packet.NewSender(iface)
				if err != nil {
					return fmt.Errorf("create sender: %w", err)
				}
				defer sender.Close()
				sendFn = sender.Send
			}
			stmts := collectPacketStmts(script.Stmts)
			if len(stmts) == 0 {
				return fmt.Errorf("no packet statements found")
			}
			caseID := 0
			for si, st := range stmts {
				cases := fuzzCasesForStmt(st, reg, maxCases)
				if len(cases) == 0 {
					cases = []map[string]uint64{{}}
				}
				for _, c := range cases {
					caseID++
					pkt := clonePacket(st.Packet)
					for k, v := range c {
						if err := applyFuzzValue(pkt, k, v); err != nil {
							return fmt.Errorf("stmt #%d case #%d apply fuzz: %w", si+1, caseID, err)
						}
					}
					data, err := builder.Build(pkt, &packet.BuildOptions{RepeatIndex: 0})
					if err != nil {
						return fmt.Errorf("stmt #%d case #%d build: %w", si+1, caseID, err)
					}
					fmt.Printf("[fuzz] stmt=%d case=%d vars=%v\n", si+1, caseID, c)
					if err := sendFn(data); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&stream, "stream", "s", "", "Packet stream language file (required)")
	cmd.Flags().StringVarP(&protoDir, "proto", "p", "proto", "Protocol definition directory (.pdl files), optional")
	cmd.Flags().StringVarP(&iface, "iface", "i", "lo", "Network interface to send packets (e.g. eth0, lo)")
	cmd.Flags().BoolVarP(&dryRun, "dry-run", "d", false, "Parse and build packets only, do not actually send")
	cmd.Flags().BoolVarP(&builtinProto, "builtin-proto", "b", true, "Load built-in common protocols first")
	cmd.Flags().Int64Var(&seed, "seed", 0, "Random seed for built-in random functions (0 means auto)")
	cmd.Flags().IntVar(&maxCases, "max-cases", 0, "Maximum fuzz cases per statement (0 means no limit)")
	_ = cmd.RegisterFlagCompletionFunc("iface", completeIfaceNames)
	return cmd
}

func fuzzCasesForStmt(st *psl.PacketStmt, reg *pdl.Registry, maxCases int) []map[string]uint64 {
	if len(st.FuzzRules) == 0 {
		return nil
	}
	valuesByRule := make([][]uint64, 0, len(st.FuzzRules))
	maxLen := 0
	for _, r := range st.FuzzRules {
		ft := lookupFieldType(st.Packet, reg, r.Layer, r.Field)
		vals := fuzzValuesForRule(r, ft)
		valuesByRule = append(valuesByRule, vals)
		if len(vals) > maxLen {
			maxLen = len(vals)
		}
	}
	if st.FuzzCount > 0 {
		maxLen = st.FuzzCount
	}
	if maxCases > 0 && (maxLen == 0 || maxLen > maxCases) {
		maxLen = maxCases
	}
	if maxLen == 0 || len(valuesByRule) == 0 {
		return nil
	}
	out := make([]map[string]uint64, 0, maxLen)
	for i := 0; i < maxLen; i++ {
		caseVals := make(map[string]uint64)
		for ri, r := range st.FuzzRules {
			vals := valuesByRule[ri]
			if len(vals) == 0 {
				continue
			}
			key := r.Layer + "." + r.Field
			caseVals[key] = vals[i%len(vals)]
		}
		out = append(out, caseVals)
	}
	return out
}

func fuzzValuesForRule(r psl.FuzzRule, ft pdl.FieldType) []uint64 {
	switch r.Mode {
	case psl.FuzzPick:
		return append([]uint64(nil), r.Args...)
	case psl.FuzzRange:
		if len(r.Args) < 2 {
			return nil
		}
		min, max := r.Args[0], r.Args[1]
		step := uint64(1)
		if len(r.Args) > 2 && r.Args[2] > 0 {
			step = r.Args[2]
		}
		if max < min {
			min, max = max, min
		}
		var out []uint64
		for x := min; x <= max; x += step {
			out = append(out, x)
			if x+step < x {
				break
			}
		}
		return out
	case psl.FuzzBoundary:
		switch ft {
		case pdl.TypeU8:
			return []uint64{0, 1, 127, 254, 255}
		case pdl.TypeU16:
			return []uint64{0, 1, 255, 256, 1024, 65535}
		case pdl.TypeU32:
			return []uint64{0, 1, 65535, 65536, 2147483647, 4294967295}
		default:
			return []uint64{0, 1, 255, 256, 65535}
		}
	default:
		return nil
	}
}

func lookupFieldType(pkt *psl.Packet, reg *pdl.Registry, layerName, fieldName string) pdl.FieldType {
	for _, l := range pkt.Layers {
		if !strings.EqualFold(l.Proto, layerName) {
			continue
		}
		proto := reg.Get(l.Proto)
		if proto == nil {
			return pdl.TypeU32
		}
		for _, f := range proto.Fields {
			if strings.EqualFold(f.Name, fieldName) {
				return f.Type
			}
		}
	}
	return pdl.TypeU32
}

func clonePacket(pkt *psl.Packet) *psl.Packet {
	out := &psl.Packet{Payload: pkt.Payload}
	out.Layers = make([]*psl.Layer, 0, len(pkt.Layers))
	for _, l := range pkt.Layers {
		nl := &psl.Layer{Proto: l.Proto, KV: make(map[string]psl.Value, len(l.KV))}
		for k, v := range l.KV {
			nl.KV[k] = v
		}
		out.Layers = append(out.Layers, nl)
	}
	return out
}

func applyFuzzValue(pkt *psl.Packet, path string, val uint64) error {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid fuzz path %q", path)
	}
	layerName, fieldName := parts[0], parts[1]
	for _, l := range pkt.Layers {
		if strings.EqualFold(l.Proto, layerName) {
			l.KV[fieldName] = psl.Value{Kind: psl.ValNumber, Num: val}
			return nil
		}
	}
	return fmt.Errorf("layer %q not found", layerName)
}

func run(pslFile, pdlDir, iface string, dryRun bool, goLiteral, cLiteral, cppLiteral bool, builtinProto bool, recv bool, recvMatchOnly bool, recvView string, expectMatchMode string, recvWait time.Duration, recvCount int, recvBpf string, recvWaitExplicit bool) error {
	literalCount := 0
	if goLiteral {
		literalCount++
	}
	if cLiteral {
		literalCount++
	}
	if cppLiteral {
		literalCount++
	}
	if literalCount > 1 {
		return fmt.Errorf("at most one of --go-literal, --c-literal, --cpp-literal may be set")
	}
	effectiveDryRun := dryRun || goLiteral || cLiteral || cppLiteral
	// 1. Load PDL protocols
	reg, err := loadRegistry(pdlDir, builtinProto)
	if err != nil {
		return err
	}

	// 2. Parse PSL script
	pslData, err := os.ReadFile(pslFile)
	if err != nil {
		return fmt.Errorf("read PSL: %w", err)
	}
	parser := psl.NewParser(string(pslData))
	script, err := parser.ParseScript()
	if err != nil {
		return fmt.Errorf("parse PSL: %w", err)
	}

	builder := packet.NewBuilder(reg)
	if seed := viper.GetInt64("seed"); seed != 0 {
		builder.SetRandSeed(seed)
	}

	sendFn := func(data []byte) error {
		switch {
		case goLiteral:
			fmt.Printf("[go-literal] packet bytes (%d):\n%s\n", len(data), FormatGoBytesLiteral(data))
			return nil
		case cLiteral:
			fmt.Printf("[c-literal] packet bytes (%d):\n%s\n", len(data), FormatCBytesLiteral(data))
			return nil
		case cppLiteral:
			fmt.Printf("[cpp-literal] packet bytes (%d):\n%s\n", len(data), FormatCppBytesLiteral(data))
			return nil
		case effectiveDryRun:
			fmt.Printf("[dry-run] Send %d bytes:\n%s\n", len(data), FormatTCPDump(data, 0))
			return nil
		default:
			return nil
		}
	}

	if recvCount < 0 {
		return fmt.Errorf("--recv-count must be >= 0")
	}
	if !strings.EqualFold(recvView, "hex") && !strings.EqualFold(recvView, "packetview") && !strings.EqualFold(recvView, "both") {
		return fmt.Errorf("--recv-view must be one of: packetview, hex, both")
	}
	if !strings.EqualFold(expectMatchMode, "exact") && !strings.EqualFold(expectMatchMode, "subset") {
		return fmt.Errorf("--expect-match-mode must be one of: exact, subset")
	}

	if recv {
		sendFn = func(data []byte) error {
			switch {
			case goLiteral:
				fmt.Printf("[go-literal] packet bytes (%d):\n%s\n", len(data), FormatGoBytesLiteral(data))
				return nil
			case cLiteral:
				fmt.Printf("[c-literal] packet bytes (%d):\n%s\n", len(data), FormatCBytesLiteral(data))
				return nil
			case cppLiteral:
				fmt.Printf("[cpp-literal] packet bytes (%d):\n%s\n", len(data), FormatCppBytesLiteral(data))
				return nil
			default:
				fmt.Printf("[send] %d bytes:\n%s\n", len(data), FormatTCPDump(data, 0))
				if effectiveDryRun {
					return nil
				}
				return nil
			}
		}
	}

	var (
		recvWG         sync.WaitGroup
		recvDone       chan struct{}
		receiver       *packet.Receiver
		recvFrames     chan []byte
		sendPhaseEnded atomic.Bool
		drainOnce      sync.Once
		drainDone      chan struct{}
	)

	if recv && !effectiveDryRun {
		drainDone = make(chan struct{})
		var err error
		receiver, err = packet.NewReceiver(iface, recvBpf)
		if err != nil {
			return fmt.Errorf("create receiver: %w", err)
		}
		recvDone = make(chan struct{})
		recvFrames = make(chan []byte, 1024)
		recvWG.Add(1)
		go func() {
			defer recvWG.Done()
			defer func() {
				drainOnce.Do(func() { close(drainDone) })
			}()
			drainCount := 0
			for {
				data, err := receiver.Recv()
				if err != nil {
					if isRecvTimeout(err) {
						continue
					}
					select {
					case <-recvDone:
						return
					default:
						fmt.Fprintf(os.Stderr, "[recv] error: %v\n", err)
						return
					}
				}
				if !recvMatchOnly {
					printRecvFrame(data, recvView, "recv")
				}
				select {
				case recvFrames <- append([]byte(nil), data...):
				default:
				}
				if !sendPhaseEnded.Load() {
					continue
				}
				drainCount++
				if recvCount > 0 && drainCount >= recvCount {
					return
				}
			}
		}()
	}

	var expectFn engine.ExpectFn
	if !effectiveDryRun {
		expectFn = func(expect *psl.Packet, opts *packet.BuildOptions, timeout time.Duration) error {
			if recvFrames == nil {
				return fmt.Errorf("@expect requires -r/--recv in non-dry-run mode")
			}
			var expectBytes []byte
			if strings.EqualFold(expectMatchMode, "exact") {
				var err error
				expectBytes, err = builder.Build(expect, &packet.BuildOptions{RepeatIndex: opts.RepeatIndex})
				if err != nil {
					return fmt.Errorf("build @expect packet: %w", err)
				}
			}
			fmt.Printf("[expect] waiting up to %s for expected packet (%s mode)\n", timeout, strings.ToLower(expectMatchMode))
			timer := time.NewTimer(timeout)
			defer timer.Stop()
			seen := 0
			for {
				select {
				case <-timer.C:
					return fmt.Errorf("@expect timeout after %s (checked %d received packets)", timeout, seen)
				case got := <-recvFrames:
					seen++
					matched := false
					if strings.EqualFold(expectMatchMode, "subset") {
						var e error
						matched, e = matchExpectSubset(expect, got, reg)
						if e != nil {
							return e
						}
					} else {
						matched = bytes.Equal(got, expectBytes)
					}
					if matched {
						fmt.Printf("[expect] matched after checking %d received packets\n", seen)
						if recvMatchOnly {
							printRecvFrame(got, recvView, "recv-matched")
						}
						return nil
					}
				}
			}
		}
	}

	if !effectiveDryRun {
		sender, err := packet.NewSender(iface)
		if err != nil {
			return fmt.Errorf("create sender: %w", err)
		}
		defer sender.Close()
		sendRaw := sender.Send
		if recv {
			sendFn = func(data []byte) error {
				fmt.Printf("[send] %d bytes:\n%s\n", len(data), FormatTCPDump(data, 0))
				return sendRaw(data)
			}
		} else {
			sendFn = sendRaw
		}
	}

	runErr := engine.Run(script, builder, sendFn, expectFn)
	if recv && !effectiveDryRun {
		sendPhaseEnded.Store(true)
		// recv-count: wait until N drain-phase packets unless user set --recv-wait (then cap by time).
		// Default recv-wait (1s) must not stop recv before N packets — that was the bug.
		if recvCount > 0 {
			if recvWaitExplicit && recvWait > 0 {
				select {
				case <-drainDone:
				case <-time.After(recvWait):
				}
			} else {
				<-drainDone
			}
		} else if recvWait > 0 {
			<-time.After(recvWait)
		}
		close(recvDone)
		_ = receiver.Close()
		recvWG.Wait()
	}
	if runErr != nil {
		return fmt.Errorf("run: %w", runErr)
	}
	return nil
}

func matchExpectSubset(expect *psl.Packet, got []byte, reg *pdl.Registry) (bool, error) {
	if expect == nil {
		return false, nil
	}
	customIdx := -1
	for i, l := range expect.Layers {
		name := strings.ToLower(l.Proto)
		if !isBuiltinLocatorLayer(name) {
			customIdx = i
			break
		}
	}
	if customIdx >= 0 {
		if customIdx == 0 || strings.ToLower(expect.Layers[0].Proto) != "eth" {
			return false, fmt.Errorf("@expect custom layer requires explicit locator chain starting with eth()")
		}
		if customIdx != len(expect.Layers)-1 {
			return false, fmt.Errorf("@expect custom layer must be the last layer in subset mode")
		}
		for i := 0; i < customIdx; i++ {
			if !isBuiltinLocatorLayer(strings.ToLower(expect.Layers[i].Proto)) {
				return false, fmt.Errorf("@expect custom layer requires explicit built-in locator layers before it")
			}
		}
		customLayer := expect.Layers[customIdx]
		proto := reg.Get(customLayer.Proto)
		if proto == nil {
			return false, fmt.Errorf("@expect custom protocol %q not found in registry", customLayer.Proto)
		}
		off := 0
		for i := 0; i < customIdx; i++ {
			next, ok := consumeAndMatchBuiltin(expect.Layers[i], got, off)
			if !ok {
				return false, nil
			}
			off = next
		}
		offAfter := off
		ok, err := decodeAndMatchProtocolSubset(proto, customLayer.KV, got, &offAfter, reg, strings.ToLower(customLayer.Proto)+".")
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		return matchExpectedPayload(expect, got, offAfter), nil
	}

	off := 0
	for _, l := range expect.Layers {
		next, ok := consumeAndMatchBuiltin(l, got, off)
		if !ok {
			return false, nil
		}
		off = next
	}
	return matchExpectedPayload(expect, got, off), nil
}

func isBuiltinLocatorLayer(name string) bool {
	switch strings.ToLower(name) {
	case "eth", "ip", "ipv6", "udp", "tcp":
		return true
	default:
		return false
	}
}

func consumeAndMatchBuiltin(layer *psl.Layer, data []byte, off int) (int, bool) {
	name := strings.ToLower(layer.Proto)
	switch name {
	case "eth":
		if len(data) < off+14 {
			return off, false
		}
		fields := map[string]string{
			"src":  formatMAC(data[off+6 : off+12]),
			"dst":  formatMAC(data[off : off+6]),
			"type": fmt.Sprintf("%d", binary.BigEndian.Uint16(data[off+12:off+14])),
		}
		if !matchLayerKV(layer.KV, fields) {
			return off, false
		}
		return off + 14, true
	case "ip":
		if len(data) < off+20 {
			return off, false
		}
		ver := data[off] >> 4
		if ver != 4 {
			return off, false
		}
		ihl := int(data[off]&0x0f) * 4
		if ihl < 20 || len(data) < off+ihl {
			return off, false
		}
		fields := map[string]string{
			"src":      formatIPv4(data[off+12 : off+16]),
			"dst":      formatIPv4(data[off+16 : off+20]),
			"id":       fmt.Sprintf("%d", binary.BigEndian.Uint16(data[off+4:off+6])),
			"ttl":      fmt.Sprintf("%d", data[off+8]),
			"protocol": fmt.Sprintf("%d", data[off+9]),
		}
		if !matchLayerKV(layer.KV, fields) {
			return off, false
		}
		return off + ihl, true
	case "udp":
		if len(data) < off+8 {
			return off, false
		}
		fields := map[string]string{
			"sport": fmt.Sprintf("%d", binary.BigEndian.Uint16(data[off:off+2])),
			"dport": fmt.Sprintf("%d", binary.BigEndian.Uint16(data[off+2:off+4])),
		}
		if !matchLayerKV(layer.KV, fields) {
			return off, false
		}
		return off + 8, true
	case "tcp":
		if len(data) < off+20 {
			return off, false
		}
		hdrLen := int((data[off+12] >> 4) * 4)
		if hdrLen < 20 || len(data) < off+hdrLen {
			return off, false
		}
		fields := map[string]string{
			"sport": fmt.Sprintf("%d", binary.BigEndian.Uint16(data[off:off+2])),
			"dport": fmt.Sprintf("%d", binary.BigEndian.Uint16(data[off+2:off+4])),
		}
		if !matchLayerKV(layer.KV, fields) {
			return off, false
		}
		return off + hdrLen, true
	case "ipv6":
		if len(data) < off+40 {
			return off, false
		}
		if data[off]>>4 != 6 {
			return off, false
		}
		fields := map[string]string{
			"src":       formatIPv6(data[off+8 : off+24]),
			"dst":       formatIPv6(data[off+24 : off+40]),
			"protocol":  fmt.Sprintf("%d", data[off+6]),
			"hop_limit": fmt.Sprintf("%d", data[off+7]),
		}
		if !matchLayerKV(layer.KV, fields) {
			return off, false
		}
		return off + 40, true
	default:
		return off, false
	}
}

func decodeAndMatchProtocolSubset(proto *pdl.Protocol, expectKV map[string]psl.Value, data []byte, off *int, reg *pdl.Registry, pathPrefix string) (bool, error) {
	for _, f := range proto.Fields {
		name := strings.ToLower(f.Name)
		exp, hasExp := expectKV[name]
		switch f.Type {
		case pdl.TypeU8:
			if *off+1 > len(data) {
				return false, nil
			}
			val := uint64(data[*off])
			*off += 1
			if hasExp && (exp.Kind != psl.ValNumber || exp.Num != val) {
				return false, nil
			}
		case pdl.TypeU16:
			if *off+2 > len(data) {
				return false, nil
			}
			val := uint64(binary.BigEndian.Uint16(data[*off : *off+2]))
			*off += 2
			if hasExp && (exp.Kind != psl.ValNumber || exp.Num != val) {
				return false, nil
			}
		case pdl.TypeU32:
			if *off+4 > len(data) {
				return false, nil
			}
			val := uint64(binary.BigEndian.Uint32(data[*off : *off+4]))
			*off += 4
			if hasExp && (exp.Kind != psl.ValNumber || exp.Num != val) {
				return false, nil
			}
		case pdl.TypeU64:
			if *off+8 > len(data) {
				return false, nil
			}
			val := binary.BigEndian.Uint64(data[*off : *off+8])
			*off += 8
			if hasExp && (exp.Kind != psl.ValNumber || exp.Num != val) {
				return false, nil
			}
		case pdl.TypeMAC:
			if *off+6 > len(data) {
				return false, nil
			}
			val := formatMAC(data[*off : *off+6])
			*off += 6
			if hasExp && (exp.Kind != psl.ValMAC || !strings.EqualFold(exp.MAC, val)) {
				return false, nil
			}
		case pdl.TypeIPv4:
			if *off+4 > len(data) {
				return false, nil
			}
			val := formatIPv4(data[*off : *off+4])
			*off += 4
			if hasExp && (exp.Kind != psl.ValIP || !strings.EqualFold(exp.IP, val)) {
				return false, nil
			}
		case pdl.TypeIPv6:
			if *off+16 > len(data) {
				return false, nil
			}
			val := formatIPv6(data[*off : *off+16])
			*off += 16
			if hasExp && (exp.Kind != psl.ValIP || !strings.EqualFold(exp.IP, val)) {
				return false, nil
			}
		case pdl.TypeStructRef:
			st := reg.GetStruct(f.StructName)
			if st == nil {
				return false, fmt.Errorf("custom expect decode: struct %q not found at %s%s", f.StructName, pathPrefix, name)
			}
			var childKV map[string]psl.Value
			if hasExp {
				if exp.Kind != psl.ValMap {
					return false, fmt.Errorf("custom expect decode: expected map for field %s%s", pathPrefix, name)
				}
				childKV = exp.Map
			}
			ok, err := decodeAndMatchStructSubset(st, childKV, data, off, reg, pathPrefix+name+".")
			if err != nil || !ok {
				return ok, err
			}
		case pdl.TypeStructArray:
			return false, fmt.Errorf("custom expect decode: arrays are not supported yet (field %s%s)", pathPrefix, name)
		default:
			return false, fmt.Errorf("custom expect decode: unsupported field type at %s%s", pathPrefix, name)
		}
	}
	return true, nil
}

func decodeAndMatchStructSubset(st *pdl.Struct, expectKV map[string]psl.Value, data []byte, off *int, reg *pdl.Registry, pathPrefix string) (bool, error) {
	p := &pdl.Protocol{Name: st.Name, Fields: st.Fields}
	if expectKV == nil {
		expectKV = map[string]psl.Value{}
	}
	return decodeAndMatchProtocolSubset(p, expectKV, data, off, reg, pathPrefix)
}

func matchLayerKV(expect map[string]psl.Value, actual map[string]string) bool {
	for k, v := range expect {
		key := strings.ToLower(k)
		got, ok := actual[key]
		if !ok {
			return false
		}
		switch v.Kind {
		case psl.ValIP:
			if !strings.EqualFold(v.IP, got) {
				return false
			}
		case psl.ValMAC:
			if !strings.EqualFold(strings.ToLower(v.MAC), got) {
				return false
			}
		case psl.ValNumber:
			if got != fmt.Sprintf("%d", v.Num) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func matchExpectedPayload(expect *psl.Packet, got []byte, payloadOffset int) bool {
	if expect == nil || expect.Payload == nil {
		return true
	}
	if payloadOffset < 0 || payloadOffset > len(got) {
		return false
	}
	expected := []byte(expect.Payload.Raw)
	actual := got[payloadOffset:]
	return bytes.Equal(actual, expected)
}

type packetView struct {
	present map[string]bool
	fields  map[string]string
}

func parsePacketView(buf []byte) (packetView, bool) {
	v := packetView{present: map[string]bool{}, fields: map[string]string{}}
	if len(buf) < 14 {
		return v, false
	}
	v.present["eth"] = true
	v.fields["eth.dst"] = formatMAC(buf[0:6])
	v.fields["eth.src"] = formatMAC(buf[6:12])
	ethType := binary.BigEndian.Uint16(buf[12:14])
	v.fields["eth.type"] = fmt.Sprintf("%d", ethType)
	off := 14
	if ethType == 0x0800 {
		if len(buf) < off+20 {
			return v, true
		}
		v.present["ip"] = true
		ihl := int(buf[off]&0x0f) * 4
		if ihl < 20 || len(buf) < off+ihl {
			return v, true
		}
		v.fields["ip.src"] = formatIPv4(buf[off+12 : off+16])
		v.fields["ip.dst"] = formatIPv4(buf[off+16 : off+20])
		v.fields["ip.id"] = fmt.Sprintf("%d", binary.BigEndian.Uint16(buf[off+4:off+6]))
		v.fields["ip.ttl"] = fmt.Sprintf("%d", buf[off+8])
		proto := buf[off+9]
		v.fields["ip.protocol"] = fmt.Sprintf("%d", proto)
		off += ihl
		if proto == 17 && len(buf) >= off+8 {
			v.present["udp"] = true
			v.fields["udp.sport"] = fmt.Sprintf("%d", binary.BigEndian.Uint16(buf[off:off+2]))
			v.fields["udp.dport"] = fmt.Sprintf("%d", binary.BigEndian.Uint16(buf[off+2:off+4]))
		}
		if proto == 6 && len(buf) >= off+20 {
			v.present["tcp"] = true
			v.fields["tcp.sport"] = fmt.Sprintf("%d", binary.BigEndian.Uint16(buf[off:off+2]))
			v.fields["tcp.dport"] = fmt.Sprintf("%d", binary.BigEndian.Uint16(buf[off+2:off+4]))
		}
	}
	return v, true
}

func printRecvFrame(data []byte, recvView, tag string) {
	switch strings.ToLower(recvView) {
	case "packetview":
		fmt.Printf("[%s]\n%s\n", tag, packetViewText(data))
	case "both":
		fmt.Printf("[%s]\n%s\n", tag, packetViewText(data))
		fmt.Printf("[%s] %d bytes:\n%s\n", tag, len(data), FormatTCPDump(data, 0))
	default:
		fmt.Printf("[%s] %d bytes:\n%s\n", tag, len(data), FormatTCPDump(data, 0))
	}
}

func packetViewText(data []byte) string {
	v, ok := parsePacketView(data)
	if !ok {
		return fmt.Sprintf("len=%d parse=fail", len(data))
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("  len=%d", len(data)))
	if v.present["eth"] {
		lines = append(lines, fmt.Sprintf("  eth: src=%s dst=%s type=%s", v.fields["eth.src"], v.fields["eth.dst"], v.fields["eth.type"]))
	}
	if v.present["ip"] {
		lines = append(lines, fmt.Sprintf("  ip: src=%s dst=%s id=%s ttl=%s protocol=%s", v.fields["ip.src"], v.fields["ip.dst"], v.fields["ip.id"], v.fields["ip.ttl"], v.fields["ip.protocol"]))
	}
	if v.present["udp"] {
		lines = append(lines, fmt.Sprintf("  udp: sport=%s dport=%s", v.fields["udp.sport"], v.fields["udp.dport"]))
	}
	if v.present["tcp"] {
		lines = append(lines, fmt.Sprintf("  tcp: sport=%s dport=%s", v.fields["tcp.sport"], v.fields["tcp.dport"]))
	}
	return strings.Join(lines, "\n")
}

func matchExpectedField(fields map[string]string, key string, v psl.Value) bool {
	got, ok := fields[key]
	if !ok {
		return false
	}
	switch v.Kind {
	case psl.ValIP:
		return strings.EqualFold(got, v.IP)
	case psl.ValMAC:
		return strings.EqualFold(got, strings.ToLower(v.MAC))
	case psl.ValNumber:
		return got == fmt.Sprintf("%d", v.Num)
	case psl.ValString:
		return got == v.Str
	default:
		return false
	}
}

func formatMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func formatIPv4(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func formatIPv6(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(b[i*2:i*2+2]))
	}
	return strings.Join(parts, ":")
}
