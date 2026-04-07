package psl

import (
	"fmt"
	"unicode"
)

type TokenKind int

const (
	TokEOF TokenKind = iota
	TokIdent
	TokNumber
	TokString
	TokIP
	TokIPv6
	TokMAC
	TokLBrace
	TokRBrace
	TokLParen
	TokRParen
	TokLBrack
	TokRBrack
	TokAssign
	TokComma
	TokBacktick
	TokAt
	TokAsync
	TokForever
	TokRepeat
	TokInterval
	TokExit
	TokIgnore
	TokFuzz
	TokComment
	TokUnit   // ns, us, ms, s
	TokBuiltin // $inc, $seq
	TokConst
)

type Token struct {
	Kind TokenKind
	Raw  string
	Line int
	Col  int
}

type Lexer struct {
	src   string
	pos   int
	line  int
	col   int
	start int
}

func NewLexer(src string) *Lexer {
	return &Lexer{src: src, line: 1, col: 1}
}

func (l *Lexer) skipSpace() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == ' ' || c == '\t' || c == '\r' {
			l.pos++
			l.col++
			continue
		}
		if c == '\n' {
			l.pos++
			l.line++
			l.col = 1
			continue
		}
		if l.pos+1 < len(l.src) && l.src[l.pos:l.pos+2] == "//" {
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		break
	}
}

func (l *Lexer) peek() byte {
	if l.pos >= len(l.src) {
		return 0
	}
	return l.src[l.pos]
}

func (l *Lexer) next() byte {
	if l.pos >= len(l.src) {
		return 0
	}
	c := l.src[l.pos]
	l.pos++
	if c == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return c
}

func (l *Lexer) Lex() Token {
	l.skipSpace()
	l.start = l.pos
	line, col := l.line, l.col

	if l.pos >= len(l.src) {
		return Token{Kind: TokEOF, Line: line, Col: col}
	}

	c := l.peek()
	switch c {
	case '{':
		l.next()
		return Token{Kind: TokLBrace, Raw: "{", Line: line, Col: col}
	case '}':
		l.next()
		return Token{Kind: TokRBrace, Raw: "}", Line: line, Col: col}
	case '(':
		l.next()
		return Token{Kind: TokLParen, Raw: "(", Line: line, Col: col}
	case ')':
		l.next()
		return Token{Kind: TokRParen, Raw: ")", Line: line, Col: col}
	case '[':
		l.next()
		return Token{Kind: TokLBrack, Raw: "[", Line: line, Col: col}
	case ']':
		l.next()
		return Token{Kind: TokRBrack, Raw: "]", Line: line, Col: col}
	case '=':
		l.next()
		return Token{Kind: TokAssign, Raw: "=", Line: line, Col: col}
	case ',':
		l.next()
		return Token{Kind: TokComma, Raw: ",", Line: line, Col: col}
	case '@':
		return l.lexAt(line, col)
	case '`':
		return l.lexBacktick(line, col)
	case '"':
		return l.lexString(line, col)
	case '$':
		return l.lexBuiltin(line, col)
	}

	if unicode.IsLetter(rune(c)) || c == '_' {
		// Might be a MAC starting with a letter (like FF:FF:FF:FF:FF:FF)
		if l.looksLikeIPv6() {
			return l.lexIPv6(line, col)
		}
		if l.looksLikeMAC() {
			return l.lexMAC(line, col)
		}
		return l.lexIdentOrKeyword(line, col)
	}
	if c >= '0' && c <= '9' {
		return l.lexNumberOrIPOrMAC(line, col)
	}

	l.next()
	return Token{Kind: TokIdent, Raw: string(c), Line: line, Col: col}
}

func (l *Lexer) lexAt(line, col int) Token {
	l.next()
	for l.pos < len(l.src) && (unicode.IsLetter(rune(l.src[l.pos])) || l.src[l.pos] == '_') {
		l.pos++
	}
	raw := l.src[l.start:l.pos]
	l.col = col + (l.pos - l.start)
	if raw == "@repeat" {
		return Token{Kind: TokRepeat, Raw: raw, Line: line, Col: col}
	}
	if raw == "@interval" {
		return Token{Kind: TokInterval, Raw: raw, Line: line, Col: col}
	}
	if raw == "@exit" {
		return Token{Kind: TokExit, Raw: raw, Line: line, Col: col}
	}
	if raw == "@fuzz" {
		return Token{Kind: TokFuzz, Raw: raw, Line: line, Col: col}
	}
	if raw == "@ignore" {
		for l.pos < len(l.src) && (l.src[l.pos] == ' ' || l.src[l.pos] == '\t') {
			l.pos++
		}
		start := l.pos
		for l.pos < len(l.src) && l.src[l.pos] != '\n' {
			l.pos++
		}
		l.col = col + (l.pos - l.start)
		return Token{Kind: TokIgnore, Raw: l.src[start:l.pos], Line: line, Col: col}
	}
	return Token{Kind: TokAt, Raw: raw, Line: line, Col: col}
}

func (l *Lexer) lexBacktick(line, col int) Token {
	l.next() // `
	start := l.pos
	for l.pos < len(l.src) && l.src[l.pos] != '`' {
		l.next()
	}
	raw := l.src[start:l.pos]
	if l.pos < len(l.src) {
		l.next() // `
	}
	return Token{Kind: TokBacktick, Raw: raw, Line: line, Col: col}
}

func (l *Lexer) lexString(line, col int) Token {
	l.next()
	start := l.pos
	for l.pos < len(l.src) && l.src[l.pos] != '"' {
		if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
			l.pos += 2
			continue
		}
		l.pos++
	}
	raw := l.src[start:l.pos]
	if l.pos < len(l.src) {
		l.next()
	}
	return Token{Kind: TokString, Raw: raw, Line: line, Col: col}
}

// lexMAC parses MAC address like xx:xx:xx:xx:xx:xx (all hex), used for MACs starting with letter or digit
func (l *Lexer) lexMAC(line, col int) Token {
	start := l.pos
	for group := 0; group < 6; group++ {
		if l.pos+2 > len(l.src) {
			break
		}
		for i := 0; i < 2; i++ {
			c := l.src[l.pos]
			if !isHexDigit(c) {
				break
			}
			l.pos++
		}
		if group < 5 {
			if l.pos >= len(l.src) || l.src[l.pos] != ':' {
				break
			}
			l.pos++
		}
	}
	raw := l.src[start:l.pos]
	l.col = col + (l.pos - start)
	return Token{Kind: TokMAC, Raw: raw, Line: line, Col: col}
}

// looksLikeMAC roughly checks if current pos looks like xx:xx:xx:xx:xx:xx
func (l *Lexer) looksLikeMAC() bool {
	pos := l.pos
	for group := 0; group < 6; group++ {
		if pos+2 > len(l.src) {
			return false
		}
		for i := 0; i < 2; i++ {
			c := l.src[pos]
			if !isHexDigit(c) {
				return false
			}
			pos++
		}
		if group < 5 {
			if pos >= len(l.src) || l.src[pos] != ':' {
				return false
			}
			pos++
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

// lexBuiltin parses $ident (like $inc, $seq)
func (l *Lexer) lexBuiltin(line, col int) Token {
	l.next() // $
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '_' {
			l.pos++
		} else {
			break
		}
	}
	raw := l.src[l.start:l.pos]
	l.col = col + (l.pos - l.start)
	return Token{Kind: TokBuiltin, Raw: raw, Line: line, Col: col}
}

// looksLikeIPv6 roughly checks if current pos is an IPv6 literal (allows :: compression)
// Rule: composed of [0-9a-fA-F:], at least 2 \':\' and at least 1 hex digit
func (l *Lexer) looksLikeIPv6() bool {
	pos := l.pos
	colons := 0
	hexSeen := 0
	for pos < len(l.src) {
		c := l.src[pos]
		if isHexDigit(c) {
			hexSeen++
			pos++
			continue
		}
		if c == ':' {
			colons++
			pos++
			continue
		}
		break
	}
	return colons >= 2 && hexSeen > 0
}

// lexIPv6 consumes IPv6 literal (allows ::), returning TokIPv6
func (l *Lexer) lexIPv6(line, col int) Token {
	start := l.pos
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if isHexDigit(c) || c == ':' {
			l.pos++
			continue
		}
		break
	}
	raw := l.src[start:l.pos]
	l.col = col + (l.pos - start)
	return Token{Kind: TokIPv6, Raw: raw, Line: line, Col: col}
}

func (l *Lexer) lexIdentOrKeyword(line, col int) Token {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '_' {
			l.pos++
		} else {
			break
		}
	}
	raw := l.src[l.start:l.pos]
	l.col = col + (l.pos - l.start)
	if raw == "async" {
		return Token{Kind: TokAsync, Raw: raw, Line: line, Col: col}
	}
	if raw == "forever" {
		return Token{Kind: TokForever, Raw: raw, Line: line, Col: col}
	}
	if raw == "const" {
		return Token{Kind: TokConst, Raw: raw, Line: line, Col: col}
	}
	return Token{Kind: TokIdent, Raw: raw, Line: line, Col: col}
}

func (l *Lexer) lexNumberOrIPOrMAC(line, col int) Token {
	start := l.start
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':' || c == 'x' || c == 'X' {
			l.pos++
		} else {
			break
		}
	}
	raw := l.src[start:l.pos]
	l.col = col + (l.pos - start)
	// Check if it is MAC (6 segments), IPv4 (4 segments) or number
	colons := 0
	dots := 0
	for _, c := range raw {
		if c == ':' {
			colons++
		}
		if c == '.' {
			dots++
		}
	}
	if colons == 5 && len(raw) >= 17 {
		return Token{Kind: TokMAC, Raw: raw, Line: line, Col: col}
	}
	// IPv6: at least 2 colons, and not a MAC
	if colons >= 2 && dots == 0 {
		return Token{Kind: TokIPv6, Raw: raw, Line: line, Col: col}
	}
	if dots == 3 {
		return Token{Kind: TokIP, Raw: raw, Line: line, Col: col}
	}
	return Token{Kind: TokNumber, Raw: raw, Line: line, Col: col}
}

func (l *Lexer) PeekToken() Token {
	savePos, saveLine, saveCol := l.pos, l.line, l.col
	t := l.Lex()
	l.pos, l.line, l.col = savePos, saveLine, saveCol
	return t
}

type LexError struct {
	Msg  string
	Line int
	Col  int
}

func (e *LexError) Error() string {
	return fmt.Sprintf("psl at %d:%d: %s", e.Line, e.Col, e.Msg)
}
