package psl

import "testing"

func TestParseIgnoreDirective(t *testing.T) {
	src := `
[ ip(src=10.0.0.1, dst=10.0.0.2, id=1) ]
@ignore
`
	script, err := NewParser(src).ParseScript()
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}
	if len(script.Stmts) != 1 {
		t.Fatalf("expected 1 stmt, got %d", len(script.Stmts))
	}
	ps, ok := script.Stmts[0].(*PacketStmt)
	if !ok {
		t.Fatalf("expected PacketStmt, got %T", script.Stmts[0])
	}
	if !ps.Ignore {
		t.Fatalf("expected packet ignore modifier to be true")
	}
}

func TestParseIgnoreDirectiveMustBeModifier(t *testing.T) {
	src := `
@ignore invalid placement
[ ip(src=10.0.0.1, dst=10.0.0.2, id=1) ]
`
	if _, err := NewParser(src).ParseScript(); err == nil {
		t.Fatalf("expected parse error for @ignore before statement")
	}
}

func TestParseIgnoreDirectiveNoArgs(t *testing.T) {
	src := `
[ ip(src=10.0.0.1, dst=10.0.0.2, id=1) ]
@ignore has-args
`
	if _, err := NewParser(src).ParseScript(); err == nil {
		t.Fatalf("expected parse error for @ignore arguments")
	}
}

func TestParseExitDirectiveForPacket(t *testing.T) {
	src := `
[ ip(src=10.0.0.1, dst=10.0.0.2, id=1) ]
@exit
`
	script, err := NewParser(src).ParseScript()
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}
	if len(script.Stmts) != 1 {
		t.Fatalf("expected 1 stmt, got %d", len(script.Stmts))
	}
	ps, ok := script.Stmts[0].(*PacketStmt)
	if !ok {
		t.Fatalf("expected PacketStmt, got %T", script.Stmts[0])
	}
	if !ps.Exit {
		t.Fatalf("expected packet exit modifier to be true")
	}
}

func TestParseExpectDirectiveForPacket(t *testing.T) {
	src := `
[ ip(src=10.0.0.1, dst=10.0.0.2, id=1) ]
@expect [ ip(src=10.0.0.2, dst=10.0.0.1, id=1) ]
@expect_timeout 1500ms
`
	script, err := NewParser(src).ParseScript()
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}
	ps := script.Stmts[0].(*PacketStmt)
	if ps.Expect == nil {
		t.Fatalf("expected @expect packet")
	}
	if ps.ExpectTimeout.Ms != 1500 {
		t.Fatalf("expected timeout 1500ms, got %+v", ps.ExpectTimeout)
	}
}
