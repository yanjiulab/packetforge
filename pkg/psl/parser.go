package psl

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Parser implements recursive descent parsing for PSL
type Parser struct {
	lex  *Lexer
	tok  Token
	env  map[string]Value // Constant environment
	allowFuzz bool
}

func NewParser(src string) *Parser {
	return NewParserWithOptions(src, ParserOptions{})
}

type ParserOptions struct {
	AllowFuzz bool
}

func NewParserWithOptions(src string, opt ParserOptions) *Parser {
	p := &Parser{
		lex: NewLexer(src),
		env: make(map[string]Value),
		allowFuzz: opt.AllowFuzz,
	}
	p.advance()
	return p
}

func (p *Parser) advance() {
	p.tok = p.lex.Lex()
}

func (p *Parser) at(kind TokenKind) bool {
	return p.tok.Kind == kind
}

// ParseScript parses the entire script
func (p *Parser) ParseScript() (*Script, error) {
	var stmts []Stmt
	for !p.at(TokEOF) {
		if p.at(TokConst) {
			if err := p.parseConst(); err != nil {
				return nil, err
			}
			continue
		}
		stmt, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		if stmt != nil {
			stmts = append(stmts, stmt)
		} else {
			return nil, fmt.Errorf("unexpected token %q (kind %v) at %d:%d", p.tok.Raw, p.tok.Kind, p.tok.Line, p.tok.Col)
		}
	}
	return &Script{Stmts: stmts}, nil
}

// parseConst ::= "const" Ident "=" Value
func (p *Parser) parseConst() error {
	p.advance() // const
	if !p.at(TokIdent) {
		return fmt.Errorf("expected identifier after const at %d:%d", p.tok.Line, p.tok.Col)
	}
	name := p.tok.Raw
	p.advance()
	if !p.at(TokAssign) {
		return fmt.Errorf("expected = in const declaration at %d:%d", p.tok.Line, p.tok.Col)
	}
	p.advance()
	val, err := p.parseValue()
	if err != nil {
		return err
	}
	p.env[name] = val
	return nil
}

// parseStmt ::= AsyncBlockStmt | BlockStmt | PacketStmt
func (p *Parser) parseStmt() (Stmt, error) {
	if p.at(TokAsync) {
		return p.parseAsyncBlock()
	}
	if p.at(TokLBrace) {
		return p.parseBlock()
	}
	return p.parsePacketStmt()
}

// parseAsyncBlock ::= "async" Block Modifiers?
func (p *Parser) parseAsyncBlock() (Stmt, error) {
	p.advance() // async
	if !p.at(TokLBrace) {
		return nil, fmt.Errorf("expected { after async at %d:%d", p.tok.Line, p.tok.Col)
	}
	block, err := p.parseBlockContent()
	if err != nil {
		return nil, err
	}
	repeat, interval, _, _, exitAfter, ignore, expect, expectTimeout, err := p.parseModifiers()
	if err != nil {
		return nil, err
	}
	if exitAfter {
		return nil, fmt.Errorf("@exit is only allowed for packet statements at %d:%d", p.tok.Line, p.tok.Col)
	}
	if expect != nil {
		return nil, fmt.Errorf("@expect is only allowed for packet statements at %d:%d", p.tok.Line, p.tok.Col)
	}
	if expectTimeout.Nanoseconds() > 0 {
		return nil, fmt.Errorf("@expect_timeout is only allowed for packet statements at %d:%d", p.tok.Line, p.tok.Col)
	}
	block.Repeat = repeat
	block.Interval = interval
	block.Ignore = ignore
	block.Async = true
	return block, nil
}

// parseBlock ::= "{" Stmt+ "}" Modifiers?
func (p *Parser) parseBlock() (Stmt, error) {
	block, err := p.parseBlockContent()
	if err != nil {
		return nil, err
	}
	repeat, interval, _, _, exitAfter, ignore, expect, expectTimeout, err := p.parseModifiers()
	if err != nil {
		return nil, err
	}
	if exitAfter {
		return nil, fmt.Errorf("@exit is only allowed for packet statements at %d:%d", p.tok.Line, p.tok.Col)
	}
	if expect != nil {
		return nil, fmt.Errorf("@expect is only allowed for packet statements at %d:%d", p.tok.Line, p.tok.Col)
	}
	if expectTimeout.Nanoseconds() > 0 {
		return nil, fmt.Errorf("@expect_timeout is only allowed for packet statements at %d:%d", p.tok.Line, p.tok.Col)
	}
	block.Repeat = repeat
	block.Interval = interval
	block.Ignore = ignore
	return block, nil
}

func (p *Parser) parseBlockContent() (*BlockStmt, error) {
	p.advance() // {
	var stmts []Stmt
	for !p.at(TokRBrace) && !p.at(TokEOF) {
		s, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		if s != nil {
			stmts = append(stmts, s)
		}
	}
	if !p.at(TokRBrace) {
		return nil, fmt.Errorf("expected } at %d:%d", p.tok.Line, p.tok.Col)
	}
	p.advance() // }
	return &BlockStmt{Stmts: stmts}, nil
}

// parseModifiers parses optional @repeat / @interval, can be multi-line
func (p *Parser) parseModifiers() (repeat int, interval Dur, fuzzRules []FuzzRule, fuzzCount int, exitAfter bool, ignore bool, expect *Packet, expectTimeout Dur, err error) {
	repeat = 0
	fuzzCount = 0
	for {
		if p.at(TokRepeat) {
			p.advance()
			if p.at(TokForever) {
				p.advance()
				repeat = -1
			} else if p.at(TokNumber) {
				n, _ := strconv.Atoi(p.tok.Raw)
				repeat = n
				p.advance()
			}
			continue
		}
		if p.at(TokInterval) {
			p.advance()
			if p.at(TokNumber) {
				n, _ := strconv.ParseUint(p.tok.Raw, 10, 64)
				p.advance()
				unit := "ms"
				if p.at(TokIdent) {
					unit = strings.ToLower(p.tok.Raw)
					p.advance()
				}
				switch unit {
				case "ns":
					interval.Ns = n
				case "us":
					interval.Us = n
				case "ms":
					interval.Ms = n
				case "s":
					interval.Sec = n
				default:
					interval.Ms = n
				}
			}
			continue
		}
		if p.at(TokFuzz) {
			if !p.allowFuzz {
				return 0, Dur{}, nil, 0, false, false, nil, Dur{}, fmt.Errorf("@fuzz is only supported in pf fuzz mode at %d:%d", p.tok.Line, p.tok.Col)
			}
			p.advance()
			if p.at(TokIdent) && strings.EqualFold(p.tok.Raw, "count") {
				p.advance()
				if !p.at(TokNumber) {
					return 0, Dur{}, nil, 0, false, false, nil, Dur{}, fmt.Errorf("expected fuzz count number at %d:%d", p.tok.Line, p.tok.Col)
				}
				n, _ := strconv.Atoi(p.tok.Raw)
				fuzzCount = n
				p.advance()
				continue
			}
			layer, field, e := p.parseFuzzPath()
			if e != nil {
				return 0, Dur{}, nil, 0, false, false, nil, Dur{}, e
			}
			mode, args, e := p.parseFuzzStrategy()
			if e != nil {
				return 0, Dur{}, nil, 0, false, false, nil, Dur{}, e
			}
			fuzzRules = append(fuzzRules, FuzzRule{Layer: layer, Field: field, Mode: mode, Args: args})
			continue
		}
		if p.at(TokExpect) {
			p.advance()
			pkt, e := p.parsePacket()
			if e != nil {
				return 0, Dur{}, nil, 0, false, false, nil, Dur{}, e
			}
			if pkt == nil {
				return 0, Dur{}, nil, 0, false, false, nil, Dur{}, fmt.Errorf("expected packet after @expect at %d:%d", p.tok.Line, p.tok.Col)
			}
			expect = pkt
			continue
		}
		if p.at(TokExpectTimeout) {
			p.advance()
			dur, e := p.parseDurationValue()
			if e != nil {
				return 0, Dur{}, nil, 0, false, false, nil, Dur{}, e
			}
			expectTimeout = dur
			continue
		}
		if p.at(TokExit) {
			p.advance()
			exitAfter = true
			continue
		}
		if p.at(TokIgnore) {
			if strings.TrimSpace(p.tok.Raw) != "" {
				return 0, Dur{}, nil, 0, false, false, nil, Dur{}, fmt.Errorf("@ignore does not take arguments at %d:%d", p.tok.Line, p.tok.Col)
			}
			p.advance()
			ignore = true
			continue
		}
		if p.at(TokComment) {
			p.advance()
			continue
		}
		break
	}
	return repeat, interval, fuzzRules, fuzzCount, exitAfter, ignore, expect, expectTimeout, nil
}

// parsePacketStmt ::= Packet Modifiers?  (returns nil when no packet, does not consume modifiers)
func (p *Parser) parsePacketStmt() (Stmt, error) {
	packet, err := p.parsePacket()
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return nil, nil
	}
	repeat, interval, fuzzRules, fuzzCount, exitAfter, ignore, expect, expectTimeout, err := p.parseModifiers()
	if err != nil {
		return nil, err
	}
	return &PacketStmt{Packet: packet, Repeat: repeat, Interval: interval, Ignore: ignore, Exit: exitAfter, Expect: expect, ExpectTimeout: expectTimeout, FuzzRules: fuzzRules, FuzzCount: fuzzCount}, nil
}

func (p *Parser) parseDurationValue() (Dur, error) {
	if !p.at(TokNumber) {
		return Dur{}, fmt.Errorf("expected duration number at %d:%d", p.tok.Line, p.tok.Col)
	}
	n, _ := strconv.ParseUint(p.tok.Raw, 10, 64)
	p.advance()
	unit := "ms"
	if p.at(TokIdent) {
		unit = strings.ToLower(p.tok.Raw)
		p.advance()
	}
	var d Dur
	switch unit {
	case "ns":
		d.Ns = n
	case "us":
		d.Us = n
	case "ms":
		d.Ms = n
	case "s":
		d.Sec = n
	default:
		return Dur{}, fmt.Errorf("unsupported duration unit %q at %d:%d", unit, p.tok.Line, p.tok.Col)
	}
	return d, nil
}

func (p *Parser) parseFuzzPath() (string, string, error) {
	if !p.at(TokIdent) {
		return "", "", fmt.Errorf("expected fuzz layer name at %d:%d", p.tok.Line, p.tok.Col)
	}
	layer := p.tok.Raw
	p.advance()
	if !p.at(TokIdent) || p.tok.Raw != "." {
		return "", "", fmt.Errorf("expected '.' in fuzz path at %d:%d", p.tok.Line, p.tok.Col)
	}
	p.advance()
	if !p.at(TokIdent) {
		return "", "", fmt.Errorf("expected fuzz field name at %d:%d", p.tok.Line, p.tok.Col)
	}
	field := p.tok.Raw
	p.advance()
	return layer, field, nil
}

func (p *Parser) parseFuzzStrategy() (FuzzMode, []uint64, error) {
	if !p.at(TokIdent) {
		return 0, nil, fmt.Errorf("expected fuzz strategy at %d:%d", p.tok.Line, p.tok.Col)
	}
	name := strings.ToLower(p.tok.Raw)
	p.advance()
	switch name {
	case "boundary":
		return FuzzBoundary, nil, nil
	case "pick", "range":
		if !p.at(TokLParen) {
			return 0, nil, fmt.Errorf("expected '(' after fuzz strategy at %d:%d", p.tok.Line, p.tok.Col)
		}
		p.advance()
		var args []uint64
		for !p.at(TokRParen) && !p.at(TokEOF) {
			if !p.at(TokNumber) {
				return 0, nil, fmt.Errorf("expected numeric fuzz argument at %d:%d", p.tok.Line, p.tok.Col)
			}
			n, _ := strconv.ParseUint(p.tok.Raw, 0, 64)
			args = append(args, n)
			p.advance()
			if p.at(TokComma) {
				p.advance()
			}
		}
		if !p.at(TokRParen) {
			return 0, nil, fmt.Errorf("expected ')' for fuzz strategy at %d:%d", p.tok.Line, p.tok.Col)
		}
		p.advance()
		if name == "pick" {
			return FuzzPick, args, nil
		}
		return FuzzRange, args, nil
	default:
		return 0, nil, fmt.Errorf("unknown fuzz strategy %q at %d:%d", name, p.tok.Line, p.tok.Col)
	}
}

// parsePacket ::= MultiLinePacket | SingleLinePacket
func (p *Parser) parsePacket() (*Packet, error) {
	if p.at(TokLBrack) {
		return p.parseMultiLinePacket()
	}
	return p.parseSingleLinePacket()
}

// parseMultiLinePacket ::= "[" Layer+ Payload? "]"
func (p *Parser) parseMultiLinePacket() (*Packet, error) {
	p.advance() // [
	var layers []*Layer
	for !p.at(TokRBrack) && !p.at(TokEOF) {
		if p.at(TokBacktick) {
			payload, err := p.parsePayload()
			if err != nil {
				return nil, err
			}
			pkt := &Packet{Layers: layers, Payload: payload}
			if !p.at(TokRBrack) {
				return nil, fmt.Errorf("expected ] after payload at %d:%d", p.tok.Line, p.tok.Col)
			}
			p.advance()
			return pkt, nil
		}
		layer, err := p.parseLayer()
		if err != nil {
			return nil, err
		}
		if layer != nil {
			layers = append(layers, layer)
		}
	}
	if !p.at(TokRBrack) {
		return nil, fmt.Errorf("expected ] at %d:%d", p.tok.Line, p.tok.Col)
	}
	p.advance()
	return &Packet{Layers: layers}, nil
}

// parseSingleLinePacket ::= Layer+ Payload?
func (p *Parser) parseSingleLinePacket() (*Packet, error) {
	var layers []*Layer
	for p.at(TokIdent) && !p.isModifierKeyword() {
		layer, err := p.parseLayer()
		if err != nil {
			return nil, err
		}
		if layer != nil {
			layers = append(layers, layer)
		}
	}
	if len(layers) == 0 {
		return nil, nil
	}
	var payload *Payload
	if p.at(TokBacktick) {
		var err error
		payload, err = p.parsePayload()
		if err != nil {
			return nil, err
		}
	}
	return &Packet{Layers: layers, Payload: payload}, nil
}

func (p *Parser) isModifierKeyword() bool {
	return p.tok.Raw == "async" || p.tok.Raw == "forever"
}

// parseLayer ::= ProtoName "(" KVList? ")"
func (p *Parser) parseLayer() (*Layer, error) {
	if !p.at(TokIdent) {
		return nil, fmt.Errorf("expected protocol name at %d:%d", p.tok.Line, p.tok.Col)
	}
	proto := p.tok.Raw
	p.advance()
	kv := make(map[string]Value)
	if p.at(TokLParen) {
		p.advance()
		for !p.at(TokRParen) && !p.at(TokEOF) {
			key, val, err := p.parseKV()
			if err != nil {
				return nil, err
			}
			if key != "" {
				kv[key] = val
			}
			if p.at(TokComma) {
				p.advance()
			}
		}
		if !p.at(TokRParen) {
			return nil, fmt.Errorf("expected ) at %d:%d", p.tok.Line, p.tok.Col)
		}
		p.advance()
	}
	return &Layer{Proto: proto, KV: kv}, nil
}

func (p *Parser) parseKV() (string, Value, error) {
	if !p.at(TokIdent) {
		return "", Value{}, nil
	}
	key := p.tok.Raw
	p.advance()
	if !p.at(TokAssign) {
		return "", Value{}, fmt.Errorf("expected = at %d:%d", p.tok.Line, p.tok.Col)
	}
	p.advance()
	val, err := p.parseValue()
	if err != nil {
		return "", Value{}, err
	}
	return key, val, nil
}

func (p *Parser) parseValue() (Value, error) {
	if p.at(TokIdent) {
		name := p.tok.Raw
		if val, ok := p.env[name]; ok {
			p.advance()
			return val, nil
		}
		// If undefined, fallback or error out; currently only constants can be identifiers as values
		return Value{}, fmt.Errorf("undefined constant %q at %d:%d", name, p.tok.Line, p.tok.Col)
	}
	if p.at(TokNumber) {
		raw := p.tok.Raw
		p.advance()
		var n uint64
		if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
			_, _ = fmt.Sscanf(raw, "0x%x", &n)
		} else {
			n, _ = strconv.ParseUint(raw, 10, 64)
		}
		return Value{Kind: ValNumber, Num: n}, nil
	}
	if p.at(TokString) {
		s := p.tok.Raw
		p.advance()
		s = strings.ReplaceAll(s, "\\r", "\r")
		s = strings.ReplaceAll(s, "\\n", "\n")
		s = strings.ReplaceAll(s, "\\t", "\t")
		return Value{Kind: ValString, Str: s}, nil
	}
	if p.at(TokIP) {
		s := p.tok.Raw
		p.advance()
		return Value{Kind: ValIP, IP: s}, nil
	}
	if p.at(TokIPv6) {
		s := p.tok.Raw
		p.advance()
		return Value{Kind: ValIP, IP: s}, nil
	}
	if p.at(TokMAC) {
		s := p.tok.Raw
		p.advance()
		return Value{Kind: ValMAC, MAC: s}, nil
	}
	if p.at(TokBuiltin) {
		name := p.tok.Raw
		p.advance()
		var args []uint64
		if p.tok.Kind == TokLParen {
			p.advance() // (
			for {
				if p.tok.Kind != TokNumber {
					break
				}
				n, _ := strconv.ParseUint(p.tok.Raw, 0, 64)
				args = append(args, n)
				p.advance()
				if p.tok.Kind == TokRParen {
					break
				}
				if p.tok.Kind == TokComma {
					p.advance()
				}
			}
			if p.tok.Kind == TokRParen {
				p.advance()
			}
		}
		return Value{Kind: ValBuiltin, BuiltinName: name, BuiltinArgs: args}, nil
	}
	// Repeated structure list: [ { k=v, ... }, { ... } ], used for []StructName fields in PDL
	if p.at(TokLBrack) {
		p.advance()
		var list []map[string]Value
		for !p.at(TokRBrack) && !p.at(TokEOF) {
			if !p.at(TokLBrace) {
				return Value{}, fmt.Errorf("expected { for struct literal at %d:%d", p.tok.Line, p.tok.Col)
			}
			p.advance()
			m := make(map[string]Value)
			for !p.at(TokRBrace) && !p.at(TokEOF) {
				key, val, err := p.parseKV()
				if err != nil {
					return Value{}, err
				}
				if key != "" {
					m[key] = val
				}
				if p.at(TokComma) {
					p.advance()
				}
			}
			if !p.at(TokRBrace) {
				return Value{}, fmt.Errorf("expected } at %d:%d", p.tok.Line, p.tok.Col)
			}
			p.advance()
			list = append(list, m)
			if p.at(TokComma) {
				p.advance()
			}
		}
		if !p.at(TokRBrack) {
			return Value{}, fmt.Errorf("expected ] at %d:%d", p.tok.Line, p.tok.Col)
		}
		p.advance()
		return Value{Kind: ValList, List: list}, nil
	}
	// Nested single structure: { k=v, ... }, used for PDL TypeStructRef fields
	if p.at(TokLBrace) {
		p.advance()
		m := make(map[string]Value)
		for !p.at(TokRBrace) && !p.at(TokEOF) {
			key, val, err := p.parseKV()
			if err != nil {
				return Value{}, err
			}
			if key != "" {
				m[key] = val
			}
			if p.at(TokComma) {
				p.advance()
			}
		}
		if !p.at(TokRBrace) {
			return Value{}, fmt.Errorf("expected } at %d:%d", p.tok.Line, p.tok.Col)
		}
		p.advance()
		return Value{Kind: ValMap, Map: m}, nil
	}
	return Value{}, fmt.Errorf("expected value at %d:%d", p.tok.Line, p.tok.Col)
}

// parsePayload parses backtick payloads, supporting prefixes x / b / 64 / none
func (p *Parser) parsePayload() (*Payload, error) {
	if !p.at(TokBacktick) {
		return nil, nil
	}
	raw := strings.TrimSpace(p.tok.Raw)
	p.advance()

	pl := &Payload{Kind: PayloadStr, Raw: raw}
	if raw == "" {
		return pl, nil
	}
	if strings.HasPrefix(raw, "x ") {
		pl.Kind = PayloadHex
		hexStr := strings.ReplaceAll(raw[2:], " ", "")
		var data []byte
		for i := 0; i+2 <= len(hexStr); i += 2 {
			n, _ := strconv.ParseUint(hexStr[i:i+2], 16, 8)
			data = append(data, byte(n))
		}
		pl.Raw = string(data)
		return pl, nil
	}
	if strings.HasPrefix(raw, "b ") {
		pl.Kind = PayloadBin
		binStr := strings.ReplaceAll(raw[2:], " ", "")
		var data []byte
		for i := 0; i+8 <= len(binStr); i += 8 {
			n, _ := strconv.ParseUint(binStr[i:i+8], 2, 8)
			data = append(data, byte(n))
		}
		pl.Raw = string(data)
		return pl, nil
	}
	if strings.HasPrefix(raw, "64 ") {
		pl.Kind = PayloadBase64
		b64 := strings.ReplaceAll(raw[3:], " ", "")
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("invalid base64: %w", err)
		}
		pl.Raw = string(data)
		return pl, nil
	}
	// String: supports \r \n escape
	raw = strings.ReplaceAll(raw, "\\r", "\r")
	raw = strings.ReplaceAll(raw, "\\n", "\n")
	raw = strings.ReplaceAll(raw, "\\t", "\t")
	pl.Raw = raw
	return pl, nil
}
