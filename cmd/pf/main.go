// pf: Register protocols based on PDL and send packets to the interface based on PSL script
package main

import (
	"flag"
	"strings"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	pdlDir := flag.String("proto", "proto", "Protocol definition directory (.pdl files)")
	pslFile := flag.String("stream", "", "Packet stream language file (required)")
	iface := flag.String("iface", "lo", "Network interface to send packets (e.g. eth0, lo)")
	dryRun := flag.Bool("dry-run", false, "Parse and build packets only, do not actually send")
	printVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Println(VersionString())
		return
	}

	if *pslFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -stream <script.psl> [-proto dir] [-iface interface] [-dry-run]\n", filepath.Base(os.Args[0]))
		flag.Usage()
		os.Exit(1)
	}

	// 1. Load PDL protocols
	reg := pdl.NewRegistry()
	if err := reg.LoadPDLDir(*pdlDir); err != nil {
		fmt.Fprintf(os.Stderr, "Load PDL: %v\n", err)
		os.Exit(1)
	}

	// 2. Parse PSL script
	pslData, err := os.ReadFile(*pslFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read PSL: %v\n", err)
		os.Exit(1)
	}
	parser := psl.NewParser(string(pslData))
	script, err := parser.ParseScript()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parse PSL: %v\n", err)
		os.Exit(1)
	}

	builder := packet.NewBuilder(reg)

	sendFn := func(data []byte) error {
		if *dryRun {
			fmt.Printf("[dry-run] Send %d bytes:\n%s\n", len(data), FormatTCPDump(data, 0))
			return nil
		}
		return nil
	}

	if !*dryRun {
		sender, err := packet.NewSender(*iface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Create sender: %v\n", err)
			os.Exit(1)
		}
		defer sender.Close()
		sendFn = sender.Send
	}

	if err := engine.Run(script, builder, sendFn); err != nil {
		fmt.Fprintf(os.Stderr, "Run: %v\n", err)
		os.Exit(1)
	}
}
