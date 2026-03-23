// pf: Register protocols based on PDL and send packets to the interface based on PSL script
package main

import (
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

	_ = viper.BindPFlag("proto", flags.Lookup("proto"))
	_ = viper.BindPFlag("stream", flags.Lookup("stream"))
	_ = viper.BindPFlag("iface", flags.Lookup("iface"))
	_ = viper.BindPFlag("dry-run", flags.Lookup("dry-run"))
	_ = viper.BindPFlag("builtin-proto", flags.Lookup("builtin-proto"))
	viper.SetEnvPrefix("PF")
	viper.AutomaticEnv()
	rootCmd.AddCommand(newBuiltinCmd())

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

func run(pslFile, pdlDir, iface string, dryRun bool, builtinProto bool) error {
	// 1. Load PDL protocols
	reg := pdl.NewRegistry()
	if builtinProto {
		if err := reg.LoadBuiltinCommonProtocols(); err != nil {
			return fmt.Errorf("load builtin protocols: %w", err)
		}
	}
	if pdlDir != "" {
		if _, err := os.Stat(pdlDir); err == nil {
			if err := reg.LoadPDLDir(pdlDir); err != nil {
				return fmt.Errorf("load PDL dir: %w", err)
			}
		} else if !os.IsNotExist(err) || pdlDir != "proto" {
			return fmt.Errorf("read proto dir %q: %w", pdlDir, err)
		}
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
