package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"github.com/yanjiulab/packetforge/pkg/pdl"
	"github.com/yanjiulab/packetforge/pkg/psl"
	"strings"
)

// Builder builds binary packets based on PDL definitions and PSL descriptions
type Builder struct {
	Registry *pdl.Registry
}

// BuildOptions contains options for packet building, used for $inc/$seq evaluation
type BuildOptions struct {
	RepeatIndex int // Current repeat index (0-based), valid only for the immediate packet/block
}

func NewBuilder(r *pdl.Registry) *Builder {
	return &Builder{Registry: r}
}

// Build constructs a binary packet from a PSL Packet (including auto-calculated fields and checksums).
// opts can be nil, in which case RepeatIndex is treated as 0 (for $inc/$seq evaluation).
func (b *Builder) Build(pkt *psl.Packet, opts *BuildOptions) ([]byte, error) {
	if opts == nil {
		opts = &BuildOptions{}
	}
	if len(pkt.Layers) == 0 {
		return nil, fmt.Errorf("packet has no layers")
	}
	payload := []byte(nil)
	if pkt.Payload != nil {
		payload = []byte(pkt.Payload.Raw)
	}

	// First pass: calculate the fixed header length of each layer (including []Struct elements)
	headerSizes := make([]int, len(pkt.Layers))
	totalHeader := 0
	for i, layer := range pkt.Layers {
		proto := b.Registry.Get(layer.Proto)
		if proto == nil {
			return nil, fmt.Errorf("unknown protocol: %s", layer.Proto)
		}
		kv := layer.KV
		if kv == nil {
			kv = make(map[string]psl.Value)
		}
		sz, err := b.protocolFixedSize(proto, kv)
		if err != nil {
			return nil, err
		}
		headerSizes[i] = sz
		totalHeader += sz
	}
	totalLen := totalHeader + len(payload)

	// Second pass: serialize layer by layer, fill in defaults and checksums
	out := make([]byte, 0, totalLen)
	offset := 0
	for i, layer := range pkt.Layers {
		proto := b.Registry.Get(layer.Proto)
		layerLen := headerSizes[i]
		fromHere := totalLen - offset
		payloadFromHere := fromHere - layerLen
		nextProto := ""
		if i+1 < len(pkt.Layers) {
			nextProto = pkt.Layers[i+1].Proto
		}
		kv := layer.KV
		if kv == nil {
			kv = make(map[string]psl.Value)
		}
		// IP protocol / IPv6 next_header can be automatically inferred from the next layer
		if strings.ToLower(layer.Proto) == "ip" && nextProto != "" {
			if _, has := kv["protocol"]; !has {
				kv = copyKV(kv)
				kv["protocol"] = psl.Value{Kind: psl.ValNumber, Num: ipProtocolNumber(nextProto)}
			}
		}
		if strings.ToLower(layer.Proto) == "ipv6" && nextProto != "" {
			if _, has := kv["next_header"]; !has {
				kv = copyKV(kv)
				kv["next_header"] = psl.Value{Kind: psl.ValNumber, Num: ipProtocolNumber(nextProto)}
			}
		}
		seg, err := b.buildLayer(proto, kv, fromHere, payloadFromHere, payload, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, seg...)
		offset += layerLen
	}
	out = append(out, payload...)

	// Third pass: backfill checksums (IP, TCP, UDP, ICMP, etc.)
	out = b.fillChecksums(pkt, out, headerSizes, len(payload))

	return out, nil
}

func copyKV(m map[string]psl.Value) map[string]psl.Value {
	out := make(map[string]psl.Value, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func ipProtocolNumber(proto string) uint64 {
	p := strings.ToLower(proto)
	if strings.HasPrefix(p, "pim") {
		return 103
	}
	switch p {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	default:
		return 0
	}
}

func (b *Builder) protocolFixedSize(proto *pdl.Protocol, kv map[string]psl.Value) (int, error) {
	n := 0
	for _, f := range proto.Fields {
		switch f.Type {
		case pdl.TypeU8:
			n++
		case pdl.TypeU16:
			n += 2
		case pdl.TypeU32:
			n += 4
		case pdl.TypeU64:
			n += 8
		case pdl.TypeMAC:
			n += 6
		case pdl.TypeIPv4:
			n += 4
		case pdl.TypeIPv6:
			n += 16
		case pdl.TypeStructRef:
			st := b.Registry.GetStruct(f.StructName)
			if st == nil {
				return 0, fmt.Errorf("unknown struct: %s", f.StructName)
			}
			var subKV map[string]psl.Value
			if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValMap {
				subKV = x.Map
			}
			sz, err := b.structFixedSize(st, subKV)
			if err != nil {
				return 0, err
			}
			n += sz
		case pdl.TypeStructArray:
			st := b.Registry.GetStruct(f.StructName)
			if st == nil {
				return 0, fmt.Errorf("unknown struct: %s", f.StructName)
			}
			if f.Array == pdl.ArrayFixed {
				// For fixed-length arrays, if not enough values are provided, we assume missing elements use defaults
				for i := 0; i < f.ArrayLen; i++ {
					var elemKV map[string]psl.Value
					if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValList && i < len(x.List) {
						elemKV = x.List[i]
					}
					sz, err := b.structFixedSize(st, elemKV)
					if err != nil {
						return 0, err
					}
					n += sz
				}
			} else {
				if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValList {
					for _, elemKV := range x.List {
						sz, err := b.structFixedSize(st, elemKV)
						if err != nil {
							return 0, err
						}
						n += sz
					}
				}
			}
		}
	}
	return n, nil
}

func (b *Builder) structFixedSize(st *pdl.Struct, kv map[string]psl.Value) (int, error) {
	if kv == nil {
		kv = make(map[string]psl.Value)
	}
	n := 0
	for _, f := range st.Fields {
		switch f.Type {
		case pdl.TypeU8:
			n++
		case pdl.TypeU16:
			n += 2
		case pdl.TypeU32:
			n += 4
		case pdl.TypeU64:
			n += 8
		case pdl.TypeMAC:
			n += 6
		case pdl.TypeIPv4:
			n += 4
		case pdl.TypeIPv6:
			n += 16
		case pdl.TypeStructRef:
			subSt := b.Registry.GetStruct(f.StructName)
			if subSt == nil {
				return 0, fmt.Errorf("unknown struct: %s", f.StructName)
			}
			var subKV map[string]psl.Value
			if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValMap {
				subKV = x.Map
			}
			sz, err := b.structFixedSize(subSt, subKV)
			if err != nil {
				return 0, err
			}
			n += sz
		case pdl.TypeStructArray:
			subSt := b.Registry.GetStruct(f.StructName)
			if subSt == nil {
				return 0, fmt.Errorf("unknown struct: %s", f.StructName)
			}
			if f.Array == pdl.ArrayFixed {
				for i := 0; i < f.ArrayLen; i++ {
					var elemKV map[string]psl.Value
					if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValList && i < len(x.List) {
						elemKV = x.List[i]
					}
					sz, err := b.structFixedSize(subSt, elemKV)
					if err != nil {
						return 0, err
					}
					n += sz
				}
			} else {
				if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValList {
					for _, elemKV := range x.List {
						sz, err := b.structFixedSize(subSt, elemKV)
						if err != nil {
							return 0, err
						}
						n += sz
					}
				}
			}
		}
	}
	return n, nil
}

func (b *Builder) buildLayer(proto *pdl.Protocol, kv map[string]psl.Value, totalFromHere, payloadFromHere int, payload []byte, opts *BuildOptions) ([]byte, error) {
	buf := make([]byte, 0, 256)

	// Pre-scan: find array lengths depending on previous fields ([field]type) to enable auto-backfilling
	autoLenMap := make(map[string]uint64)
	for _, f := range proto.Fields {
		if f.Type == pdl.TypeStructArray && f.Array == pdl.ArrayField {
			if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValList {
				autoLenMap[strings.ToLower(f.ArrayLenField)] = uint64(len(x.List))
			}
		}
	}

	for _, f := range proto.Fields {
		var v interface{}
		lowerName := strings.ToLower(f.Name)
		if x, ok := kv[lowerName]; ok {
			if x.Kind == psl.ValBuiltin {
				v = b.evalBuiltin(x, opts)
			} else if x.Kind == psl.ValList && f.Type == pdl.TypeStructArray {
				// Handled in the TypeStructArray branch below
				v = x
			} else if x.Kind == psl.ValMap && f.Type == pdl.TypeStructRef {
				v = x
			} else {
				var err error
				v, err = b.pslValueToGo(f.Type, x)
				if err != nil {
					return nil, fmt.Errorf("field %s: %w", f.Name, err)
				}
			}
		} else if autoLen, ok := autoLenMap[lowerName]; ok {
			// Auto-backfill dynamic array length
			v = autoLen
		} else {
			switch f.Default {
			case pdl.DefaultLiteral:
				v = f.Literal
			case pdl.DefaultLen:
				v = totalFromHere
			case pdl.DefaultPayloadLen:
				v = payloadFromHere
			case pdl.DefaultCksum:
				v = nil // to be filled later
			default:
				// Direct error if protocol provides no default and field is missing in PSL
				return nil, fmt.Errorf("proto %s field %s has no value and no default", proto.Name, f.Name)
			}
		}

		switch f.Type {
		case pdl.TypeU8:
			n := uint8(toU64(v))
			buf = append(buf, n)
		case pdl.TypeU16:
			n := uint16(toU64(v))
			buf = append(buf, byte(n>>8), byte(n))
		case pdl.TypeU32:
			n := uint32(toU64(v))
			buf = append(buf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		case pdl.TypeU64:
			n := toU64(v)
			buf = append(buf, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		case pdl.TypeMAC:
			var mac []byte
			if s, ok := v.(string); ok {
				m, err := pdl.ParseMAC(s)
				if err != nil {
					return nil, err
				}
				mac = m[:]
			} else {
				mac = make([]byte, 6)
			}
			buf = append(buf, mac...)
		case pdl.TypeIPv4:
			var ip []byte
			if s, ok := v.(string); ok {
				ip = net.ParseIP(s).To4()
				if ip == nil {
					return nil, fmt.Errorf("invalid ipv4: %s", s)
				}
			} else {
				ip = make([]byte, 4)
			}
			buf = append(buf, ip...)
		case pdl.TypeIPv6:
			var ip []byte
			if s, ok := v.(string); ok {
				ip = net.ParseIP(s).To16()
				if ip == nil {
					return nil, fmt.Errorf("invalid ipv6: %s", s)
				}
			} else {
				ip = make([]byte, 16)
			}
			buf = append(buf, ip...)
		case pdl.TypeStructRef:
			st := b.Registry.GetStruct(f.StructName)
			if st == nil {
				return nil, fmt.Errorf("unknown struct: %s", f.StructName)
			}
			var subKV map[string]psl.Value
			if x, ok := v.(psl.Value); ok && x.Kind == psl.ValMap {
				subKV = x.Map
			}
			seg, err := b.buildStruct(st, subKV, opts)
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", f.Name, err)
			}
			buf = append(buf, seg...)
		case pdl.TypeStructArray:
			st := b.Registry.GetStruct(f.StructName)
			if st == nil {
				return nil, fmt.Errorf("unknown struct: %s", f.StructName)
			}
			listVal, _ := v.(psl.Value)
			if listVal.Kind != psl.ValList {
				return nil, fmt.Errorf("field %s: expected list value for []%s", f.Name, f.StructName)
			}
			
			count := len(listVal.List)
			if f.Array == pdl.ArrayFixed {
				count = f.ArrayLen
			}
			
			for i := 0; i < count; i++ {
				var elemKV map[string]psl.Value
				if i < len(listVal.List) {
					elemKV = listVal.List[i]
				} else {
					elemKV = make(map[string]psl.Value) // Pad with default values
				}
				seg, err := b.buildStruct(st, elemKV, opts)
				if err != nil {
					return nil, fmt.Errorf("field %s index %d: %w", f.Name, i, err)
				}
				buf = append(buf, seg...)
			}
		}
	}

	return buf, nil
}

// buildStruct serializes a struct literal into bytes (for each element in []StructName)
func (b *Builder) buildStruct(st *pdl.Struct, kv map[string]psl.Value, opts *BuildOptions) ([]byte, error) {
	buf := make([]byte, 0, 64)

	autoLenMap := make(map[string]uint64)
	for _, f := range st.Fields {
		if f.Type == pdl.TypeStructArray && f.Array == pdl.ArrayField {
			if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValList {
				autoLenMap[strings.ToLower(f.ArrayLenField)] = uint64(len(x.List))
			}
		}
	}

	for _, f := range st.Fields {
		var v interface{}
		lowerName := strings.ToLower(f.Name)
		if x, ok := kv[lowerName]; ok {
			if x.Kind == psl.ValBuiltin {
				v = b.evalBuiltin(x, opts)
			} else if x.Kind == psl.ValList && f.Type == pdl.TypeStructArray {
				v = x
			} else if x.Kind == psl.ValMap && f.Type == pdl.TypeStructRef {
				v = x
			} else {
				var err error
				v, err = b.pslValueToGo(f.Type, x)
				if err != nil {
					return nil, fmt.Errorf("struct %s field %s: %w", st.Name, f.Name, err)
				}
			}
		} else if autoLen, ok := autoLenMap[lowerName]; ok {
			v = autoLen
		} else {
			switch f.Default {
			case pdl.DefaultLiteral:
				v = f.Literal
			default:
				return nil, fmt.Errorf("struct %s field %s has no value and no default", st.Name, f.Name)
			}
		}

		if f.Type == pdl.TypeStructArray {
			subSt := b.Registry.GetStruct(f.StructName)
			if subSt == nil {
				return nil, fmt.Errorf("unknown struct: %s", f.StructName)
			}
			listVal, _ := v.(psl.Value)
			if listVal.Kind != psl.ValList {
				return nil, fmt.Errorf("field %s: expected list value for []%s", f.Name, f.StructName)
			}
			
			count := len(listVal.List)
			if f.Array == pdl.ArrayFixed {
				count = f.ArrayLen
			}
			
			for i := 0; i < count; i++ {
				var elemKV map[string]psl.Value
				if i < len(listVal.List) {
					elemKV = listVal.List[i]
				} else {
					elemKV = make(map[string]psl.Value) // Pad with default values
				}
				seg, err := b.buildStruct(subSt, elemKV, opts)
				if err != nil {
					return nil, fmt.Errorf("field %s index %d: %w", f.Name, i, err)
				}
				buf = append(buf, seg...)
			}
			continue
		}

		seg, err := b.serializeFieldValue(f.Type, f.ByteSize, v)
		if err != nil {
			return nil, err
		}
		buf = append(buf, seg...)
	}
	return buf, nil
}

func (b *Builder) serializeFieldValue(ft pdl.FieldType, byteSize int, v interface{}) ([]byte, error) {
	switch ft {
	case pdl.TypeU8:
		return []byte{byte(toU64(v))}, nil
	case pdl.TypeU16:
		n := uint16(toU64(v))
		return []byte{byte(n >> 8), byte(n)}, nil
	case pdl.TypeU32:
		n := uint32(toU64(v))
		return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, nil
	case pdl.TypeU64:
		n := toU64(v)
		return []byte{byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, nil
	case pdl.TypeMAC:
		var mac []byte
		if s, ok := v.(string); ok {
			m, err := pdl.ParseMAC(s)
			if err != nil {
				return nil, err
			}
			mac = m[:]
		} else {
			mac = make([]byte, 6)
		}
		return mac, nil
	case pdl.TypeIPv4:
		var ip []byte
		if s, ok := v.(string); ok {
			ip = net.ParseIP(s).To4()
			if ip == nil {
				return nil, fmt.Errorf("invalid ipv4: %s", s)
			}
		} else {
			ip = make([]byte, 4)
		}
		return ip, nil
	case pdl.TypeIPv6:
		var ip []byte
		if s, ok := v.(string); ok {
			ip = net.ParseIP(s).To16()
			if ip == nil {
				return nil, fmt.Errorf("invalid ipv6: %s", s)
			}
		} else {
			ip = make([]byte, 16)
		}
		return ip, nil
	default:
		return nil, nil
	}
}

func toU64(v interface{}) uint64 {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case int:
		return uint64(x)
	case int64:
		return uint64(x)
	case uint64:
		return x
	case uint32:
		return uint64(x)
	case uint16:
		return uint64(x)
	case uint8:
		return uint64(x)
	default:
		return 0
	}
}

// evalBuiltin evaluates $inc/$seq based on current RepeatIndex (scope determined by opts passed from engine)
func (b *Builder) evalBuiltin(v psl.Value, opts *BuildOptions) uint64 {
	if opts == nil {
		opts = &BuildOptions{}
	}
	i := opts.RepeatIndex
	switch v.BuiltinName {
	case "$inc":
		step := uint64(1)
		if len(v.BuiltinArgs) > 0 {
			step = v.BuiltinArgs[0]
		}
		return uint64(i) * step
	case "$seq":
		start := uint64(0)
		step := uint64(1)
		if len(v.BuiltinArgs) > 0 {
			start = v.BuiltinArgs[0]
		}
		if len(v.BuiltinArgs) > 1 {
			step = v.BuiltinArgs[1]
		}
		return start + uint64(i)*step
	default:
		return 0
	}
}

func (b *Builder) pslValueToGo(ft pdl.FieldType, v psl.Value) (interface{}, error) {
	switch v.Kind {
	case psl.ValNumber:
		return v.Num, nil
	case psl.ValString:
		return v.Str, nil
	case psl.ValIP:
		return v.IP, nil
	case psl.ValMAC:
		return v.MAC, nil
	}
	return nil, fmt.Errorf("unsupported value kind")
}

func (b *Builder) fillChecksums(pkt *psl.Packet, raw []byte, headerSizes []int, payloadLen int) []byte {
	layerStarts := make([]int, len(headerSizes)+1)
	layerStarts[0] = 0
	for i := range headerSizes {
		layerStarts[i+1] = layerStarts[i] + headerSizes[i]
	}

	for i, layer := range pkt.Layers {
		proto := b.Registry.Get(layer.Proto)
		if proto == nil {
			continue
		}
		offset := layerStarts[i]
		hlen := headerSizes[i]
		kv := layer.KV
		if kv == nil {
			kv = make(map[string]psl.Value)
		}
		for _, f := range proto.Fields {
			if f.Default != pdl.DefaultCksum {
				continue
			}
			fieldOff := b.fieldOffset(proto, f.Name, kv)
			if fieldOff < 0 {
				continue
			}
			absOff := offset + fieldOff
			var cksum uint16
			switch strings.ToLower(layer.Proto) {
			case "ip":
				cksum = ipChecksum(raw[offset : offset+hlen])
			case "tcp":
				if i > 0 {
					prevStart := layerStarts[i-1]
					prevProto := strings.ToLower(pkt.Layers[i-1].Proto)
					if prevProto == "ipv6" {
						cksum = tcpChecksumIPv6(raw, prevStart, offset, hlen)
					} else {
						cksum = tcpChecksum(raw, prevStart, offset, hlen)
					}
				} else {
					cksum = tcpChecksum(raw, layerStarts[1], offset, hlen)
				}
			case "udp":
				if i > 0 {
					prevStart := layerStarts[i-1]
					prevProto := strings.ToLower(pkt.Layers[i-1].Proto)
					if prevProto == "ipv6" {
						cksum = udpChecksumIPv6(raw, prevStart, offset, hlen)
					} else {
						cksum = udpChecksum(raw, prevStart, offset, hlen)
					}
				} else {
					cksum = udpChecksum(raw, layerStarts[1], offset, hlen)
				}
			case "icmp":
				cksum = icmpChecksum(raw[offset:])
			default:
				cksum = genericChecksum(raw[offset:])
			}
			binary.BigEndian.PutUint16(raw[absOff:], cksum)
		}
	}
	return raw
}

func (b *Builder) fieldOffset(proto *pdl.Protocol, name string, kv map[string]psl.Value) int {
	off := 0
	for _, f := range proto.Fields {
		if f.Name == name {
			return off
		}
		switch f.Type {
		case pdl.TypeU8:
			off++
		case pdl.TypeU16:
			off += 2
		case pdl.TypeU32:
			off += 4
		case pdl.TypeU64:
			off += 8
		case pdl.TypeMAC:
			off += 6
		case pdl.TypeIPv4:
			off += 4
		case pdl.TypeIPv6:
			off += 16
		case pdl.TypeStructArray:
			st := b.Registry.GetStruct(f.StructName)
			if st == nil {
				return -1
			}
			if f.Array == pdl.ArrayFixed {
				for i := 0; i < f.ArrayLen; i++ {
					var elemKV map[string]psl.Value
					if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValList && i < len(x.List) {
						elemKV = x.List[i]
					}
					sz, _ := b.structFixedSize(st, elemKV)
					off += sz
				}
			} else {
				if x, ok := kv[strings.ToLower(f.Name)]; ok && x.Kind == psl.ValList {
					for _, elemKV := range x.List {
						sz, _ := b.structFixedSize(st, elemKV)
						off += sz
					}
				}
			}
		}
	}
	return -1
}

func ipChecksum(header []byte) uint16 {
	return onesComplementSum(header)
}

// tcpChecksum: ipStart = IP header start, tcpStart = TCP header start, tcpLen = TCP header length
func tcpChecksum(full []byte, ipStart, tcpStart, tcpLen int) uint16 {
	src := full[ipStart+12 : ipStart+16]
	dst := full[ipStart+16 : ipStart+20]
	// TCP segment length = from TCP header start to end of packet
	tcpTotal := uint16(len(full) - tcpStart)
	pseudo := make([]byte, 0, 12)
	pseudo = append(pseudo, src...)
	pseudo = append(pseudo, dst...)
	pseudo = append(pseudo, 0, 6)
	pseudo = append(pseudo, byte(tcpTotal>>8), byte(tcpTotal))
	seg := append(pseudo, full[tcpStart:]...)
	return onesComplementSum(seg)
}

func udpChecksum(full []byte, ipStart, udpStart, udpLen int) uint16 {
	pseudo := make([]byte, 12)
	if len(full) >= ipStart+20 {
		copy(pseudo[0:4], full[ipStart+12:ipStart+16])
		copy(pseudo[4:8], full[ipStart+16:ipStart+20])
	}
	pseudo[9] = 17
	l := uint16(len(full) - udpStart)
	pseudo[10] = byte(l >> 8)
	pseudo[11] = byte(l)
	seg := append(pseudo, full[udpStart:]...)
	return onesComplementSum(seg)
}

func tcpChecksumIPv6(full []byte, ipv6Start, tcpStart, tcpLen int) uint16 {
	upperLen := len(full) - tcpStart
	pseudo := make([]byte, 40)
	if ipv6Start+40 <= len(full) {
		copy(pseudo[0:16], full[ipv6Start+8:ipv6Start+24])
		copy(pseudo[16:32], full[ipv6Start+24:ipv6Start+40])
	}
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(upperLen))
	pseudo[39] = 6 // TCP
	seg := append(pseudo, full[tcpStart:]...)
	return onesComplementSum(seg)
}

func udpChecksumIPv6(full []byte, ipv6Start, udpStart, udpLen int) uint16 {
	upperLen := len(full) - udpStart
	pseudo := make([]byte, 40)
	if ipv6Start+40 <= len(full) {
		copy(pseudo[0:16], full[ipv6Start+8:ipv6Start+24])
		copy(pseudo[16:32], full[ipv6Start+24:ipv6Start+40])
	}
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(upperLen))
	pseudo[39] = 17 // UDP
	seg := append(pseudo, full[udpStart:]...)
	return onesComplementSum(seg)
}

func icmpChecksum(segment []byte) uint16 {
	return onesComplementSum(segment)
}

func genericChecksum(data []byte) uint16 {
	return onesComplementSum(data)
}

func onesComplementSum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(data[i])<<8 | uint32(data[i+1])
		} else {
			sum += uint32(data[i]) << 8
		}
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
