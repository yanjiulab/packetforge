package packet

import (
	"encoding/binary"
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

func TestBuildVXLANOuterUDPChecksum(t *testing.T) {
	reg := pdl.NewRegistry()
	if err := reg.LoadPDLDir("../../proto"); err != nil {
		if err := reg.LoadPDLDir("proto"); err != nil {
			t.Skip("no proto dir found")
			return
		}
	}
	b := NewBuilder(reg)
	pkt := &psl.Packet{
		Layers: []*psl.Layer{
			{Proto: "eth", KV: map[string]psl.Value{
				"src":  {Kind: psl.ValMAC, MAC: "02:00:00:00:10:01"},
				"dst":  {Kind: psl.ValMAC, MAC: "02:00:00:00:10:02"},
				"type": {Kind: psl.ValNumber, Num: 0x0800},
			}},
			{Proto: "ip", KV: map[string]psl.Value{
				"src":      {Kind: psl.ValIP, IP: "10.10.10.1"},
				"dst":      {Kind: psl.ValIP, IP: "10.10.10.2"},
				"protocol": {Kind: psl.ValNumber, Num: 17},
			}},
			{Proto: "udp", KV: map[string]psl.Value{
				"sport": {Kind: psl.ValNumber, Num: 55000},
				"dport": {Kind: psl.ValNumber, Num: 4789},
			}},
			{Proto: "vxlan", KV: map[string]psl.Value{
				"vni_b1": {Kind: psl.ValNumber, Num: 0},
				"vni_b2": {Kind: psl.ValNumber, Num: 0},
				"vni_b3": {Kind: psl.ValNumber, Num: 100},
			}},
			{Proto: "eth", KV: map[string]psl.Value{
				"src":  {Kind: psl.ValMAC, MAC: "02:00:00:00:20:01"},
				"dst":  {Kind: psl.ValMAC, MAC: "02:00:00:00:20:02"},
				"type": {Kind: psl.ValNumber, Num: 0x0800},
			}},
			{Proto: "ip", KV: map[string]psl.Value{
				"src":      {Kind: psl.ValIP, IP: "192.168.100.1"},
				"dst":      {Kind: psl.ValIP, IP: "192.168.100.2"},
				"protocol": {Kind: psl.ValNumber, Num: 17},
			}},
			{Proto: "udp", KV: map[string]psl.Value{
				"sport": {Kind: psl.ValNumber, Num: 12345},
				"dport": {Kind: psl.ValNumber, Num: 9000},
			}},
		},
		Payload: &psl.Payload{Kind: psl.PayloadStr, Raw: "hello-from-inner-udp"},
	}

	raw, err := b.Build(pkt, nil)
	if err != nil {
		t.Fatal(err)
	}

	const outerIPStart = 14
	const outerUDPStart = 14 + 20
	const outerUDPChecksumOff = outerUDPStart + 6
	got := binary.BigEndian.Uint16(raw[outerUDPChecksumOff : outerUDPChecksumOff+2])

	verify := append([]byte(nil), raw...)
	verify[outerUDPChecksumOff] = 0
	verify[outerUDPChecksumOff+1] = 0
	want := udpChecksum(verify, outerIPStart, outerUDPStart, 8)

	if got != want {
		t.Fatalf("outer udp checksum mismatch: got=0x%04x want=0x%04x", got, want)
	}
}

func TestBuildICMPv6Checksum(t *testing.T) {
	reg := pdl.NewRegistry()
	if err := reg.LoadPDLDir("../../proto"); err != nil {
		if err := reg.LoadPDLDir("proto"); err != nil {
			t.Skip("no proto dir found")
			return
		}
	}
	b := NewBuilder(reg)
	pkt := &psl.Packet{
		Layers: []*psl.Layer{
			{Proto: "eth", KV: map[string]psl.Value{
				"src":  {Kind: psl.ValMAC, MAC: "02:00:00:00:00:11"},
				"dst":  {Kind: psl.ValMAC, MAC: "02:00:00:00:00:22"},
				"type": {Kind: psl.ValNumber, Num: 0x86dd},
			}},
			{Proto: "ipv6", KV: map[string]psl.Value{
				"src":         {Kind: psl.ValIP, IP: "fe80::1"},
				"dst":         {Kind: psl.ValIP, IP: "fe80::2"},
				"next_header": {Kind: psl.ValNumber, Num: 58},
				"hop_limit":   {Kind: psl.ValNumber, Num: 64},
			}},
			{Proto: "icmp6", KV: map[string]psl.Value{
				"type":   {Kind: psl.ValNumber, Num: 128},
				"code":   {Kind: psl.ValNumber, Num: 0},
				"data32": {Kind: psl.ValNumber, Num: 0x12340001},
			}},
		},
	}

	raw, err := b.Build(pkt, nil)
	if err != nil {
		t.Fatal(err)
	}

	const ipv6Start = 14
	const icmpStart = 14 + 40
	const icmpChecksumOff = icmpStart + 2
	got := binary.BigEndian.Uint16(raw[icmpChecksumOff : icmpChecksumOff+2])

	verify := append([]byte(nil), raw...)
	verify[icmpChecksumOff] = 0
	verify[icmpChecksumOff+1] = 0
	want := icmpv6Checksum(verify, ipv6Start, icmpStart, 8)

	if got != want {
		t.Fatalf("icmpv6 checksum mismatch: got=0x%04x want=0x%04x", got, want)
	}
}
