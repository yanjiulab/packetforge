// pf: Register protocols based on PDL and send packets to the interface based on PSL script
package main

import (
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

func run(pslFile, pdlDir, iface string, dryRun bool, goLiteral, cLiteral, cppLiteral bool, builtinProto bool, recv bool, recvWait time.Duration, recvCount int, recvBpf string, recvWaitExplicit bool) error {
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
				fmt.Printf("[recv] %d bytes:\n%s\n", len(data), FormatTCPDump(data, 0))
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

	runErr := engine.Run(script, builder, sendFn)
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
