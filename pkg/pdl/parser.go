package pdl

import (
	"fmt"
	"strconv"
	"strings"
)

// Parser implements recursive descent parsing for PDL
type Parser struct {
	lex *Lexer
	tok Token
}

func NewParser(src string) *Parser {
	p := &Parser{lex: NewLexer(src)}
	p.advance()
	return p
}

func (p *Parser) advance() {
	p.tok = p.lex.Lex()
}

func (p *Parser) expect(kind TokenKind) error {
	if p.tok.Kind != kind {
		return fmt.Errorf("expected token kind %v, got %v at %d:%d", kind, p.tok.Kind, p.tok.Line, p.tok.Col)
	}
	p.advance()
	return nil
}

func (p *Parser) at(kind TokenKind) bool {
	return p.tok.Kind == kind
}

// ParseFile parses the entire PDL file, returning protocol and struct definitions
func (p *Parser) ParseFile() ([]*Protocol, []*Struct, error) {
	var protos []*Protocol
	var structs []*Struct
	for !p.at(TokenEOF) {
		if p.at(TokenProtocol) {
			proto, err := p.parseProtocol()
			if err != nil {
				return nil, nil, err
			}
			protos = append(protos, proto)
		} else if p.at(TokenStruct) {
			st, err := p.parseStruct()
			if err != nil {
				return nil, nil, err
			}
			structs = append(structs, st)
		} else {
			return nil, nil, fmt.Errorf("unexpected token %v at %d:%d", p.tok.Raw, p.tok.Line, p.tok.Col)
		}
	}
	return protos, structs, nil
}

// parseProtocol ::= "protocol" ident "{" field* "}"
func (p *Parser) parseProtocol() (*Protocol, error) {
	if err := p.expect(TokenProtocol); err != nil {
		return nil, err
	}
	if p.tok.Kind != TokenIdent {
		return nil, fmt.Errorf("expected protocol name at %d:%d", p.tok.Line, p.tok.Col)
	}
	name := p.tok.Raw
	p.advance()
	if err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	proto := &Protocol{Name: name}
	for !p.at(TokenRBrace) && !p.at(TokenEOF) {
		f, err := p.parseField()
		if err != nil {
			return nil, err
		}
		proto.Fields = append(proto.Fields, f)
	}
	if err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}
	return proto, nil
}

// parseStruct ::= "struct" ident "{" field* "}"
func (p *Parser) parseStruct() (*Struct, error) {
	if err := p.expect(TokenStruct); err != nil {
		return nil, err
	}
	if p.tok.Kind != TokenIdent {
		return nil, fmt.Errorf("expected struct name at %d:%d", p.tok.Line, p.tok.Col)
	}
	name := p.tok.Raw
	p.advance()
	if err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}
	st := &Struct{Name: name}
	for !p.at(TokenRBrace) && !p.at(TokenEOF) {
		f, err := p.parseField()
		if err != nil {
			return nil, err
		}
		st.Fields = append(st.Fields, f)
	}
	if err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}
	return st, nil
}

// parseField ::= ident type [ "=" ( number | ident ) ]
// Field names can be ordinary identifiers or keyword "protocol" (like IP header protocol field)
func (p *Parser) parseField() (*Field, error) {
	if p.tok.Kind != TokenIdent && p.tok.Kind != TokenProtocol {
		return nil, fmt.Errorf("expected field name at %d:%d", p.tok.Line, p.tok.Col)
	}
	name := p.tok.Raw
	p.advance()

	ft, size, structName, arrKind, arrLen, arrLenField, err := p.parseType()
	if err != nil {
		return nil, err
	}

	f := &Field{
		Name:          name,
		Type:          ft,
		ByteSize:      size,
		StructName:    structName,
		Array:         arrKind,
		ArrayLen:      arrLen,
		ArrayLenField: arrLenField,
		Default:       DefaultNone,
	}

	if p.tok.Kind == TokenAssign {
		p.advance() // Consume "="; p.tok is now the default value
		defKind, lit, err := p.parseDefaultValue()
		if err != nil {
			return nil, err
		}
		f.Default = defKind
		f.Literal = lit
	}

	return f, nil
}

// parseType parses type and consumes corresponding token(s)
func (p *Parser) parseType() (FieldType, int, string, ArrayKind, int, string, error) {
	if p.tok.Kind == TokenLBrack {
		p.advance() // consume '['
		
		arrKind := ArrayDynamic
		arrLen := 0
		arrLenField := ""
		
		if p.tok.Kind == TokenNumber || p.tok.Kind == TokenHex {
			// [N]
			n, err := strconv.Atoi(p.tok.Raw)
			if err != nil {
				return 0, 0, "", ArrayNone, 0, "", fmt.Errorf("invalid array size at %d:%d", p.tok.Line, p.tok.Col)
			}
			arrKind = ArrayFixed
			arrLen = n
			p.advance()
		} else if p.tok.Kind == TokenIdent {
			// [field]
			arrKind = ArrayField
			arrLenField = p.tok.Raw
			p.advance()
		}
		
		if err := p.expect(TokenRBrack); err != nil {
			return 0, 0, "", ArrayNone, 0, "", err
		}
		if p.tok.Kind != TokenIdent {
			return 0, 0, "", ArrayNone, 0, "", fmt.Errorf("expected struct name after ] at %d:%d", p.tok.Line, p.tok.Col)
		}
		name := p.tok.Raw
		p.advance()
		return TypeStructArray, 0, name, arrKind, arrLen, arrLenField, nil
	}
	if p.tok.Kind != TokenIdent {
		return 0, 0, "", ArrayNone, 0, "", fmt.Errorf("expected type at %d:%d", p.tok.Line, p.tok.Col)
	}
	s := strings.ToLower(p.tok.Raw)
	p.advance()
	switch s {
	case "u8":
		return TypeU8, 0, "", ArrayNone, 0, "", nil
	case "u16":
		return TypeU16, 0, "", ArrayNone, 0, "", nil
	case "u32":
		return TypeU32, 0, "", ArrayNone, 0, "", nil
	case "u64":
		return TypeU64, 0, "", ArrayNone, 0, "", nil
	case "mac":
		return TypeMAC, 0, "", ArrayNone, 0, "", nil
	case "ipv4":
		return TypeIPv4, 0, "", ArrayNone, 0, "", nil
	case "ipv6":
		return TypeIPv6, 0, "", ArrayNone, 0, "", nil
	}
	// If not a built-in type, treat it as StructName (nested structure)
	// Note: s was lowercased earlier, p.tok.Raw is the original token. But we advanced when assigning s,
	// so the original token name was saved and we shouldn\'t read p.tok.Raw again
	structName := s
	return TypeStructRef, 0, structName, ArrayNone, 0, "", nil
}

func (p *Parser) parseDefaultValue() (DefaultKind, interface{}, error) {
	if p.tok.Kind != TokenIdent && p.tok.Kind != TokenNumber && p.tok.Kind != TokenHex && p.tok.Kind != TokenString && p.tok.Kind != TokenMAC {
		return DefaultNone, nil, fmt.Errorf("expected default value at %d:%d", p.tok.Line, p.tok.Col)
	}
	raw := p.tok.Raw
	kind := p.tok.Kind
	p.advance()

	if kind == TokenMAC {
		return DefaultLiteral, raw, nil
	}
	if raw == "$len" {
		return DefaultLen, nil, nil
	}
	if raw == "$payload_len" {
		return DefaultPayloadLen, nil, nil
	}
	if raw == "$cksum" {
		return DefaultCksum, nil, nil
	}

	// Literal: number or hexadecimal
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		var v uint64
		_, err := fmt.Sscanf(raw, "0x%x", &v)
		if err != nil {
			return DefaultNone, nil, err
		}
		return DefaultLiteral, v, nil
	}
	// MAC address literal (containing colons, e.g. 00:00:00:00:00:00)
	if strings.Contains(raw, ":") && strings.Count(raw, ":") >= 2 {
		return DefaultLiteral, raw, nil
	}
	if p.tok.Kind == TokenNumber || (len(raw) > 0 && raw[0] >= '0' && raw[0] <= '9') {
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return DefaultNone, nil, err
		}
		return DefaultLiteral, v, nil
	}
	// Identifier or string literal
	return DefaultLiteral, raw, nil
}
