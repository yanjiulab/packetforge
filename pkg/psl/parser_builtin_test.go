package psl

import (
	"testing"
)

func TestParseBuiltinValue(t *testing.T) {
	src := "[\n  eth(dst=00:50:56:00:00:01, src=00:50:56:00:00:02, type=0x0800)\n  ip(src=192.168.1.1, dst=192.168.1.2, id=$seq(1, 1))\n  udp(sport=5000, dport=5000)\n  `ping`\n]"
	p := NewParser(src)
	script, err := p.ParseScript()
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}
	if len(script.Stmts) != 1 {
		t.Fatalf("expected 1 stmt, got %d", len(script.Stmts))
	}
	ps, ok := script.Stmts[0].(*PacketStmt)
	if !ok {
		t.Fatalf("expected PacketStmt, got %T", script.Stmts[0])
	}
	if ps.Packet == nil || len(ps.Packet.Layers) < 2 {
		t.Fatalf("expected at least 2 layers, got %d", len(ps.Packet.Layers))
	}
	ipLayer := ps.Packet.Layers[1]
	if ipLayer.Proto != "ip" {
		t.Fatalf("expected ip layer, got %s", ipLayer.Proto)
	}
	idVal, ok := ipLayer.KV["id"]
	if !ok {
		t.Fatalf("expected id in ip layer KV")
	}
	if idVal.Kind != ValBuiltin || idVal.BuiltinName != "$seq" {
		t.Fatalf("expected ValBuiltin $seq, got Kind=%v BuiltinName=%q", idVal.Kind, idVal.BuiltinName)
	}
	if len(idVal.BuiltinArgs) != 2 || idVal.BuiltinArgs[0] != 1 || idVal.BuiltinArgs[1] != 1 {
		t.Fatalf("expected BuiltinArgs [1,1], got %v", idVal.BuiltinArgs)
	}
}
