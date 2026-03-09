package pdl

import (
	"fmt"
	"unicode"
)

type TokenKind int

const (
	TokenEOF TokenKind = iota
	TokenIdent
	TokenNumber
	TokenString
	TokenHex
	TokenMAC
	TokenProtocol
	TokenStruct
	TokenLBrack
	TokenRBrack
	TokenLBrace
	TokenRBrace
	TokenAssign
	TokenComma
	TokenComment
)

type Token struct {
	Kind TokenKind
	Raw  string
	Line int
	Col  int
}

func (t Token) String() string { return t.Raw }

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

func (l *Lexer) skipSpaceAndComment() {
	for l.pos < len(l.src) {
		// Line comment
		if l.pos+1 < len(l.src) && l.src[l.pos:l.pos+2] == "//" {
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		c := l.src[l.pos]
		if c == ' ' || c == '\t' || c == '\r' {
			l.pos++
			if c == '\t' {
				l.col += 4
			} else {
				l.col++
			}
			continue
		}
		if c == '\n' {
			l.pos++
			l.line++
			l.col = 1
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
	l.skipSpaceAndComment()
	l.start = l.pos
	line, col := l.line, l.col

	if l.pos >= len(l.src) {
		return Token{Kind: TokenEOF, Raw: "", Line: line, Col: col}
	}

	c := l.peek()
	switch c {
	case '{':
		l.next()
		return Token{Kind: TokenLBrace, Raw: "{", Line: line, Col: col}
	case '}':
		l.next()
		return Token{Kind: TokenRBrace, Raw: "}", Line: line, Col: col}
	case '=':
		l.next()
		return Token{Kind: TokenAssign, Raw: "=", Line: line, Col: col}
	case ',':
		l.next()
		return Token{Kind: TokenComma, Raw: ",", Line: line, Col: col}
	case '[':
		l.next()
		return Token{Kind: TokenLBrack, Raw: "[", Line: line, Col: col}
	case ']':
		l.next()
		return Token{Kind: TokenRBrack, Raw: "]", Line: line, Col: col}
	case '"':
		return l.lexString(line, col)
	}

	if unicode.IsLetter(rune(c)) || c == '_' || c == '$' {
		return l.lexIdent(line, col)
	}
	if c >= '0' && c <= '9' {
		// Might be a MAC literal 00:00:00:00:00:00
		if l.pos+2 <= len(l.src) && l.src[l.pos+1] >= '0' && l.src[l.pos+1] <= '9' {
			if l.pos+3 <= len(l.src) && l.src[l.pos+2] == ':' {
				return l.lexMAC(line, col)
			}
		}
		return l.lexNumber(line, col)
	}

	l.next()
	return Token{Kind: TokenIdent, Raw: string(c), Line: line, Col: col}
}

func (l *Lexer) lexString(line, col int) Token {
	l.next() // "
	start := l.pos
	for l.pos < len(l.src) && l.src[l.pos] != '"' {
		l.next()
	}
	raw := l.src[start:l.pos]
	if l.pos < len(l.src) {
		l.next() // "
	}
	return Token{Kind: TokenString, Raw: raw, Line: line, Col: col}
}

func (l *Lexer) lexIdent(line, col int) Token {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '_' || c == '$' {
			l.pos++
		} else if c == '[' {
			l.pos++
			for l.pos < len(l.src) && l.src[l.pos] != ']' {
				l.pos++
			}
			if l.pos < len(l.src) {
				l.pos++
			}
		} else {
			break
		}
	}
	raw := l.src[l.start:l.pos]
	// Update col (simplified: by character count only)
	l.col = col + (l.pos - l.start)

	kind := TokenIdent
	if raw == "protocol" {
		kind = TokenProtocol
	}
	if raw == "struct" {
		kind = TokenStruct
	}
	return Token{Kind: kind, Raw: raw, Line: line, Col: col}
}

// lexMAC parses MAC literal xx:xx:xx:xx:xx:xx (6 hex groups)
func (l *Lexer) lexMAC(line, col int) Token {
	start := l.pos
	for group := 0; group < 6; group++ {
		if l.pos+2 > len(l.src) {
			l.pos = start
			return l.lexNumber(line, col)
		}
		for i := 0; i < 2; i++ {
			c := l.src[l.pos]
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				l.pos++
			} else {
				l.pos = start
				return l.lexNumber(line, col)
			}
		}
		if group < 5 {
			if l.pos >= len(l.src) || l.src[l.pos] != ':' {
				l.pos = start
				return l.lexNumber(line, col)
			}
			l.pos++
		}
	}
	raw := l.src[start:l.pos]
	l.col = col + (l.pos - start)
	return Token{Kind: TokenMAC, Raw: raw, Line: line, Col: col}
}

func (l *Lexer) lexNumber(line, col int) Token {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if (c >= '0' && c <= '9') || c == 'x' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' {
			l.pos++
		} else {
			break
		}
	}
	raw := l.src[l.start:l.pos]
	l.col = col + (l.pos - l.start)
	kind := TokenNumber
	if len(raw) > 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X') {
		kind = TokenHex
	}
	return Token{Kind: kind, Raw: raw, Line: line, Col: col}
}

// PeekToken peeks at the next token without consuming it (skips whitespace first)
func (l *Lexer) PeekToken() Token {
	savePos, saveLine, saveCol := l.pos, l.line, l.col
	t := l.Lex()
	l.pos, l.line, l.col = savePos, saveLine, saveCol
	return t
}

type LexerError struct {
	Msg  string
	Line int
	Col  int
}

func (e *LexerError) Error() string {
	return fmt.Sprintf("pdl lexer at %d:%d: %s", e.Line, e.Col, e.Msg)
}
