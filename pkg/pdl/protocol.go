package pdl

import "net"

// FieldType represents PDL field type
type FieldType int

const (
	TypeU8 FieldType = iota
	TypeU16
	TypeU32
	TypeU64
	TypeMAC
	TypeIPv4
	TypeIPv6
	TypeStructArray  // []StructName, repeated structure array
	TypeStructRef    // StructName, nested single structure
)

// DefaultKind represents default value kinds (literal or built-in function)
type DefaultKind int

const (
	DefaultNone DefaultKind = iota
	DefaultLiteral
	DefaultLen
	DefaultPayloadLen
	DefaultCksum
)

// ArrayKind describes the array type
type ArrayKind int

const (
	ArrayNone ArrayKind = iota // Not an array
	ArrayDynamic              // []type dynamic remaining length
	ArrayFixed                // [N]type fixed length
	ArrayField                // [field]type length relies on the value of a preceding field
)

// Field protocol field definition
type Field struct {
	Name          string
	Type          FieldType
	ByteSize      int    // reserved for potential custom-sized fields (currently unused)
	StructName    string // Referenced struct name when Type is TypeStructRef/TypeStructArray
	Array         ArrayKind
	ArrayLen      int    // N when Array == ArrayFixed
	ArrayLenField string // Referenced field name when Array == ArrayField
	Default       DefaultKind
	Literal       interface{} // Literal default value (number, mac, ip, etc.)
}

// Protocol definition (parsed from PDL)
type Protocol struct {
	Name   string
	Fields []*Field
}

// Struct definition (for struct Name { ... } in PDL, can be referenced by protocol field type []Name)
type Struct struct {
	Name   string
	Fields []*Field
}

// FieldValue represents the field value passed during packet sending (KV pairs parsed from PSL)
type FieldValue struct {
	Str string // Raw string, parsed by Builder according to protocol field type
}

// MACAddr 6 bytes
type MACAddr [6]byte

// ParseMAC parses "00:11:22:33:44:55" format
func ParseMAC(s string) (MACAddr, error) {
	var mac MACAddr
	_, err := net.ParseMAC(s)
	if err != nil {
		return mac, err
	}
	// Parse it manually to get []byte
	var v [6]uint8
	n, _ := parseMACBytes(s, v[:])
	if n != 6 {
		return mac, err
	}
	copy(mac[:], v[:])
	return mac, nil
}

func parseMACBytes(s string, out []byte) (int, error) {
	var hex byte
	idx := 0
	for i := 0; i < len(s) && idx < 6; {
		if s[i] == ':' || s[i] == '-' {
			i++
			continue
		}
		if i+1 >= len(s) {
			break
		}
		_, err := parseHexByte(s[i:i+2], &hex)
		if err != nil {
			return idx, err
		}
		out[idx] = hex
		idx++
		i += 2
	}
	return idx, nil
}

func parseHexByte(s string, out *byte) (int, error) {
	if len(s) < 2 {
		return 0, nil
	}
	var v byte
	for i := 0; i < 2; i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			v = v<<4 + (c - '0')
		} else if c >= 'a' && c <= 'f' {
			v = v<<4 + (c - 'a' + 10)
		} else if c >= 'A' && c <= 'F' {
			v = v<<4 + (c - 'A' + 10)
		} else {
			return 0, nil
		}
	}
	*out = v
	return 2, nil
}
