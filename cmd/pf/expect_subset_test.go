package main

import (
	"testing"

	"github.com/yanjiulab/packetforge/pkg/packet"
	"github.com/yanjiulab/packetforge/pkg/pdl"
	"github.com/yanjiulab/packetforge/pkg/psl"
)

func TestMatchExpectSubsetWithPayload(t *testing.T) {
	reg := pdl.NewRegistry()
	if err := reg.LoadBuiltinCommonProtocols(); err != nil {
		t.Fatalf("load builtin protocols: %v", err)
	}
	builder := packet.NewBuilder(reg)

	gotPkt := &psl.Packet{
		Layers: []*psl.Layer{
			{Proto: "eth", KV: map[string]psl.Value{}},
			{Proto: "ip", KV: map[string]psl.Value{
				"src": {Kind: psl.ValIP, IP: "10.0.0.1"},
				"dst": {Kind: psl.ValIP, IP: "10.0.0.2"},
				"id":  {Kind: psl.ValNumber, Num: 1},
			}},
			{Proto: "udp", KV: map[string]psl.Value{
				"sport": {Kind: psl.ValNumber, Num: 5000},
				"dport": {Kind: psl.ValNumber, Num: 6000},
			}},
		},
		Payload: &psl.Payload{Kind: psl.PayloadStr, Raw: "pong"},
	}
	gotBytes, err := builder.Build(gotPkt, &packet.BuildOptions{RepeatIndex: 0})
	if err != nil {
		t.Fatalf("build got packet: %v", err)
	}

	expectPkt := &psl.Packet{
		Layers: []*psl.Layer{
			{Proto: "eth", KV: map[string]psl.Value{}},
			{Proto: "ip", KV: map[string]psl.Value{}},
			{Proto: "udp", KV: map[string]psl.Value{}},
		},
		Payload: &psl.Payload{Kind: psl.PayloadStr, Raw: "pong"},
	}
	ok, err := matchExpectSubset(expectPkt, gotBytes, reg)
	if err != nil {
		t.Fatalf("match subset: %v", err)
	}
	if !ok {
		t.Fatalf("expected payload match to succeed")
	}

	expectPkt.Payload = &psl.Payload{Kind: psl.PayloadStr, Raw: "wrong"}
	ok, err = matchExpectSubset(expectPkt, gotBytes, reg)
	if err != nil {
		t.Fatalf("match subset: %v", err)
	}
	if ok {
		t.Fatalf("expected payload mismatch to fail")
	}
}
