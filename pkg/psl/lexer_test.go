package psl

import "testing"

func TestLexMacFF(t *testing.T) {
	src := "eth(dst=FF:FF:FF:FF:FF:FF)"
	l := NewLexer(src)
	for {
		tok := l.Lex()
		t.Logf("kind=%v raw=%q line=%d col=%d", tok.Kind, tok.Raw, tok.Line, tok.Col)
		if tok.Kind == TokEOF {
			break
		}
	}
}

func TestLexBuiltin(t *testing.T) {
	src := "id=$seq(1, 1)"
	l := NewLexer(src)
	for {
		tok := l.Lex()
		t.Logf("kind=%v raw=%q", tok.Kind, tok.Raw)
		if tok.Kind == TokEOF {
			break
		}
		if tok.Raw == "$seq" && tok.Kind != TokBuiltin {
			t.Fatalf("expected TokBuiltin for $seq, got %v", tok.Kind)
		}
	}
}

