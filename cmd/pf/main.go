// pf: Register protocols based on PDL and send packets to the interface based on PSL script
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"github.com/yanjiulab/packetforge/pkg/engine"
	"github.com/yanjiulab/packetforge/pkg/packet"
	"github.com/yanjiulab/packetforge/pkg/pdl"
	"github.com/yanjiulab/packetforge/pkg/psl"
)

func main() {
	pdlDir := flag.String("proto", "proto", "Protocol definition directory (.pdl files)")
	pslFile := flag.String("stream", "", "Packet stream language file (required)")
	iface := flag.String("iface", "lo", "Network interface to send packets (e.g. eth0, lo)")
	dryRun := flag.Bool("dry-run", false, "Parse and build packets only, do not actually send")
	flag.Parse()

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
			fmt.Printf("[dry-run] Send %d bytes\n: %v\n", len(data), data)
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
