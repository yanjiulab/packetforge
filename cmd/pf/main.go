// pf: Register protocols based on PDL and send packets to the interface based on PSL script
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/yanjiulab/packetforge/pkg/engine"
	"github.com/yanjiulab/packetforge/pkg/packet"
	"github.com/yanjiulab/packetforge/pkg/pdl"
	"github.com/yanjiulab/packetforge/pkg/psl"
)

// FormatTCPDump converts binary buffer to tcpdump-style string
// Parameters:
//   buf: binary data to format
//   startOffset: starting address offset (e.g. 0 for 0x0000:)
// Returns:
//   tcpdump-style formatted string (each line: offset + hex + ASCII)
func FormatTCPDump(buf []byte, startOffset int) string {
	const bytesPerLine = 16 // tcpdump default: 16 bytes per line
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
		if i + bytesPerLine < len(buf) {
			dumpBuilder.WriteString("\n")
		}

		// Update offset for next line
		offset += bytesPerLine
	}

	return dumpBuilder.String()
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

			return run(pslFile, viper.GetString("proto"), viper.GetString("iface"), viper.GetBool("dry-run"), viper.GetBool("builtin-proto"))
		},
	}

	rootCmd.Version = VersionString()
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	flags := rootCmd.Flags()
	flags.StringP("proto", "p", "proto", "Protocol definition directory (.pdl files), optional")
	flags.StringP("stream", "s", "", "Packet stream language file (required)")
	flags.StringP("iface", "i", "lo", "Network interface to send packets (e.g. eth0, lo)")
	flags.BoolP("dry-run", "d", false, "Parse and build packets only, do not actually send")
	flags.BoolP("builtin-proto", "b", true, "Load built-in common protocols first (eth/vlan/arp/arp_request/arp_reply/ip/ipv6/icmp/icmp6/ndp_ns/ndp_na/udp/tcp)")
	flags.Int64("seed", 0, "Random seed for built-in random functions (0 means auto)")

	_ = viper.BindPFlag("proto", flags.Lookup("proto"))
	_ = viper.BindPFlag("stream", flags.Lookup("stream"))
	_ = viper.BindPFlag("iface", flags.Lookup("iface"))
	_ = viper.BindPFlag("dry-run", flags.Lookup("dry-run"))
	_ = viper.BindPFlag("builtin-proto", flags.Lookup("builtin-proto"))
	_ = viper.BindPFlag("seed", flags.Lookup("seed"))
	viper.SetEnvPrefix("PF")
	viper.AutomaticEnv()
	rootCmd.AddCommand(newBuiltinCmd())
	rootCmd.AddCommand(newExplainCmd())

	return rootCmd
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

func run(pslFile, pdlDir, iface string, dryRun bool, builtinProto bool) error {
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

	if err := engine.Run(script, builder, sendFn); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
