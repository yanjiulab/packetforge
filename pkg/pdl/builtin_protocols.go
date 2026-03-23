package pdl

import "fmt"

type builtinProtocolDef struct {
	Name    string
	Content string
}

func builtinCommonProtocolDefs() []builtinProtocolDef {
	return []builtinProtocolDef{
		{
			Name: "eth",
			Content: `protocol eth {
	dst  mac   = ff:ff:ff:ff:ff:ff
	src  mac   = 01:02:03:04:05:06
	type u16   = 0x0800
}
`,
		},
		{
			Name: "vlan",
			Content: `protocol vlan {
	tci u16 = 0x0001
	type u16 = 0x0800
}
`,
		},
		{
			Name: "arp",
			Content: `protocol arp {
	htype    u16 = 1
	ptype    u16 = 0x0800
	hlen     u8  = 6
	plen     u8  = 4
	oper     u16
	sha      mac
	spa      ipv4
	tha      mac
	tpa      ipv4
}
`,
		},
		{
			Name: "arp_request",
			Content: `protocol arp_request {
	htype    u16 = 1
	ptype    u16 = 0x0800
	hlen     u8  = 6
	plen     u8  = 4
	oper     u16 = 1
	sha      mac
	spa      ipv4
	tha      mac
	tpa      ipv4
}
`,
		},
		{
			Name: "arp_reply",
			Content: `protocol arp_reply {
	htype    u16 = 1
	ptype    u16 = 0x0800
	hlen     u8  = 6
	plen     u8  = 4
	oper     u16 = 2
	sha      mac
	spa      ipv4
	tha      mac
	tpa      ipv4
}
`,
		},
		{
			Name: "ip",
			Content: `protocol ip {
	version   u8   = 0x45
	tos       u8   = 0
	total_len u16  = $len
	id        u16  = 0
	flags     u16  = 0
	ttl       u8   = 64
	protocol  u8   = 17
	checksum  u16  = $cksum
	src       ipv4
	dst       ipv4
}
`,
		},
		{
			Name: "ipv6",
			Content: `protocol ipv6 {
	ver_tc_fl   u32 = 0x60000000
	payload_len u16 = $payload_len
	next_header u8  = 59
	hop_limit   u8  = 64
	src         ipv6
	dst         ipv6
}
`,
		},
		{
			Name: "icmp",
			Content: `protocol icmp {
	type     u8  = 8
	code     u8  = 0
	checksum u16 = $cksum
	id       u16 = 0
	seq      u16 = 0
}
`,
		},
		{
			Name: "icmp6",
			Content: `protocol icmp6 {
	type     u8  = 128
	code     u8  = 0
	checksum u16 = $cksum
	data32   u32 = 0
}
`,
		},
		{
			Name: "ndp_ns",
			Content: `protocol ndp_ns {
	type       u8   = 135
	code       u8   = 0
	checksum   u16  = $cksum
	reserved   u32  = 0
	target     ipv6
	opt_type   u8   = 1
	opt_len    u8   = 1
	opt_slla   mac
}
`,
		},
		{
			Name: "ndp_na",
			Content: `protocol ndp_na {
	type       u8   = 136
	code       u8   = 0
	checksum   u16  = $cksum
	flags      u32  = 0x60000000
	target     ipv6
	opt_type   u8   = 2
	opt_len    u8   = 1
	opt_tlla   mac
}
`,
		},
		{
			Name: "udp",
			Content: `protocol udp {
	sport    u16
	dport    u16
	length   u16 = $len
	checksum u16 = $cksum
}
`,
		},
		{
			Name: "tcp",
			Content: `protocol tcp {
	sport    u16
	dport    u16
	seq      u32 = 0
	ack      u32 = 0
	data_res u8  = 0x50
	flags    u8  = 0
	window   u16 = 65535
	checksum u16 = $cksum
	urgent   u16 = 0
}
`,
		},
	}
}

// BuiltinCommonProtocolNames returns builtin common protocol names in stable order.
func BuiltinCommonProtocolNames() []string {
	defs := builtinCommonProtocolDefs()
	names := make([]string, 0, len(defs))
	for _, def := range defs {
		names = append(names, def.Name)
	}
	return names
}

// LoadBuiltinCommonProtocols registers common protocol definitions directly.
// User-loaded PDL files can still override these by using the same protocol name.
func (r *Registry) LoadBuiltinCommonProtocols() error {
	for _, def := range builtinCommonProtocolDefs() {
		source := def.Name + ".pdl"
		if err := r.LoadPDLContent(source, def.Content); err != nil {
			return fmt.Errorf("load builtin %s: %w", source, err)
		}
	}
	return nil
}
