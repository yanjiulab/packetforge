package packet

import (
	"os"
	"testing"

	"github.com/yanjiulab/packetforge/pkg/pdl"
	"github.com/yanjiulab/packetforge/pkg/psl"
)

func TestBuildEthFromFile(t *testing.T) {
	reg := pdl.NewRegistry()
	for _, dir := range []string{"../../proto", "proto", "../proto"} {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if err := reg.LoadPDLDir(dir); err != nil {
			t.Fatal(err)
		}
		eth := reg.Get("eth")
		if eth == nil {
			t.Fatal("eth not found")
		}
		if len(eth.Fields) < 1 {
			t.Fatal("eth has no fields")
		}
		if eth.Fields[0].Default != pdl.DefaultLiteral {
			t.Errorf("eth dst default: got %v (Literal=%v)", eth.Fields[0].Default, eth.Fields[0].Literal)
		}
		b := NewBuilder(reg)
		pkt := &psl.Packet{
			Layers: []*psl.Layer{{Proto: "eth", KV: map[string]psl.Value{}}},
		}
		_, err := b.Build(pkt, nil)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Skip("no pdl dir found")
}

func TestBuildEthOnlyFromParsed(t *testing.T) {
	// Directly parse eth.pdl content to ensure default is correctly parsed
	ethPDL := `
protocol eth {
	dst  mac   = 00:00:00:00:00:00
	src  mac   = 00:00:00:00:00:01
	type u16   = 0x0800
}
`
	parser := pdl.NewParser(ethPDL)
	protos, structs, err := parser.ParseFile()
	if err != nil {
		t.Fatal(err)
	}
	reg := pdl.NewRegistry()
	for _, st := range structs {
		reg.RegisterStruct(st)
	}
	for _, p := range protos {
		reg.Register(p)
	}
	if reg.Get("eth").Fields[0].Default != pdl.DefaultLiteral {
		t.Errorf("dst default: got %v", reg.Get("eth").Fields[0].Default)
	}
	b := NewBuilder(reg)
	pkt := &psl.Packet{
		Layers: []*psl.Layer{{Proto: "eth", KV: map[string]psl.Value{}}},
	}
	_, err = b.Build(pkt, nil)
	if err != nil {
		t.Fatal(err)
	}
}
