package pdl

import (
	"os"
	"testing"
)

func TestLexIP(t *testing.T) {
	data, _ := os.ReadFile("../../proto/ip.pdl")
	l := NewLexer(string(data))
	for {
		tok := l.Lex()
		t.Logf("%v %q line=%d col=%d", tok.Kind, tok.Raw, tok.Line, tok.Col)
		if tok.Kind == TokenEOF {
			break
		}
	}
}

func TestLexEth(t *testing.T) {
	data, _ := os.ReadFile("../../proto/eth.pdl")
	l := NewLexer(string(data))
	for {
		tok := l.Lex()
		t.Logf("%v %q line=%d col=%d", tok.Kind, tok.Raw, tok.Line, tok.Col)
		if tok.Kind == TokenEOF {
			break
		}
	}
}

func TestParseEth(t *testing.T) {
	data, _ := os.ReadFile("../../proto/eth.pdl")
	p := NewParser(string(data))
	protos, _, err := p.ParseFile()
	if err != nil {
		t.Fatal(err)
	}
	if len(protos) != 1 || protos[0].Name != "eth" {
		t.Fatalf("expected one protocol eth, got %v", protos)
	}
	eth := protos[0]
	if len(eth.Fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(eth.Fields))
	}
	if eth.Fields[0].Name != "dst" || eth.Fields[0].Default != DefaultLiteral {
		t.Fatalf("dst should have default literal, got Default=%v", eth.Fields[0].Default)
	}
}

func TestParseIP(t *testing.T) {
	data, _ := os.ReadFile("../../proto/ip.pdl")
	p := NewParser(string(data))
	protos, _, err := p.ParseFile()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed %d protocols", len(protos))
	for _, pr := range protos {
		t.Logf("protocol %s: %d fields", pr.Name, len(pr.Fields))
	}
}

func TestParseStruct(t *testing.T) {
	src := "struct rip_entry { afi u16 = 2 }\nprotocol rip { cmd u8 = 2 version u8 = 2 entries []rip_entry }"
	p := NewParser(src)
	protos, structs, err := p.ParseFile()
	if err != nil {
		t.Fatal(err)
	}
	if len(structs) != 1 || structs[0].Name != "rip_entry" {
		t.Fatalf("expected one struct rip_entry, got %v", structs)
	}
	if len(protos) != 1 || protos[0].Name != "rip" {
		t.Fatalf("expected one protocol rip, got %v", protos)
	}
	if len(protos[0].Fields) != 3 {
		t.Fatalf("expected 3 fields in rip, got %d", len(protos[0].Fields))
	}
	var entriesField *Field
	for _, f := range protos[0].Fields {
		if f.Name == "entries" {
			entriesField = f
			break
		}
	}
	if entriesField == nil || entriesField.Type != TypeStructArray || entriesField.StructName != "rip_entry" {
		t.Fatalf("expected entries []rip_entry, got %+v", entriesField)
	}
}

func TestParseStructArrayOptions(t *testing.T) {
	src := `
struct opt {
	type u8
	len u8
}
protocol test_proto {
	f1 []opt
	f2 [3]opt
	num_opts u8
	f3 [num_opts]opt
}
`
	p := NewParser(src)
	protos, _, err := p.ParseFile()
	if err != nil {
		t.Fatal(err)
	}
	pr := protos[0]
	if pr.Fields[0].Array != ArrayDynamic {
		t.Errorf("f1 array kind = %v, want %v", pr.Fields[0].Array, ArrayDynamic)
	}
	if pr.Fields[1].Array != ArrayFixed || pr.Fields[1].ArrayLen != 3 {
		t.Errorf("f2 array kind = %v, len = %v, want %v, 3", pr.Fields[1].Array, pr.Fields[1].ArrayLen, ArrayFixed)
	}
	if pr.Fields[3].Array != ArrayField || pr.Fields[3].ArrayLenField != "num_opts" {
		t.Errorf("f3 array kind = %v, lenField = %q, want %v, 'num_opts'", pr.Fields[3].Array, pr.Fields[3].ArrayLenField, ArrayField)
	}
}

func TestParseRipPdl(t *testing.T) {
	data, err := os.ReadFile("../../proto/rip.pdl")
	if err != nil {
		t.Skipf("rip.pdl not found: %v", err)
		return
	}
	p := NewParser(string(data))
	protos, structs, err := p.ParseFile()
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(structs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(structs))
	}
	if len(protos) != 1 {
		t.Fatalf("expected 1 protocol, got %d", len(protos))
	}
}
