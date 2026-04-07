package engine

import (
	"testing"

	"github.com/yanjiulab/packetforge/pkg/packet"
	"github.com/yanjiulab/packetforge/pkg/pdl"
	"github.com/yanjiulab/packetforge/pkg/psl"
)

func TestRunExitAfterPacket(t *testing.T) {
	reg := pdl.NewRegistry()
	if err := reg.LoadBuiltinCommonProtocols(); err != nil {
		t.Fatalf("load builtin protocols: %v", err)
	}
	builder := packet.NewBuilder(reg)

	src := `
[ eth() ip(src=10.0.0.1, dst=10.0.0.2, id=1) ]
@exit
[ eth() ip(src=10.0.0.1, dst=10.0.0.3, id=2) ]
`
	script, err := psl.NewParser(src).ParseScript()
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}

	count := 0
	sendFn := func(data []byte) error {
		count++
		return nil
	}
	if err := Run(script, builder, sendFn); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 packet sent, got %d", count)
	}
}

func TestRunIgnorePacket(t *testing.T) {
	reg := pdl.NewRegistry()
	if err := reg.LoadBuiltinCommonProtocols(); err != nil {
		t.Fatalf("load builtin protocols: %v", err)
	}
	builder := packet.NewBuilder(reg)

	src := `
[ eth() ip(src=10.0.0.1, dst=10.0.0.2, id=1) ]
@ignore
[ eth() ip(src=10.0.0.1, dst=10.0.0.3, id=2) ]
`
	script, err := psl.NewParser(src).ParseScript()
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}

	count := 0
	sendFn := func(data []byte) error {
		count++
		return nil
	}
	if err := Run(script, builder, sendFn); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 packet sent (first ignored), got %d", count)
	}
}
