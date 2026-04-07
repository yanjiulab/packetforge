package psl

// Script root node: multiple statements
type Script struct {
	Stmts []Stmt
}

// Stmt statement: packet stmt | block stmt | parallel block stmt|// Stmt statement: packet stmt | block stmt | parallel block stmt|// Stmt statement: packet stmt | block stmt | parallel block stmt
type Stmt interface {
	stmt()
}

// PacketStmt packet statement: packet + optional modifiers
type PacketStmt struct {
	Packet    *Packet
	Repeat    int  // 0 = no repeat/once, >0 = count, -1 = forever
	Interval  Dur  // Transmission interval
	Ignore    bool // Skip this packet statement during execution
	Exit      bool // Exit script after this packet statement finishes
	FuzzRules []FuzzRule
	FuzzCount int // 0 means auto based on rules
}

func (*PacketStmt) stmt() {}

// BlockStmt normal block: { stmt+ } + optional modifiers
type BlockStmt struct {
	Stmts    []Stmt
	Async    bool
	Ignore   bool
	Repeat   int
	Interval Dur
}

func (*BlockStmt) stmt() {}

// Packet single packet: multi-layer protocol + optional payload
type Packet struct {
	Layers []*Layer
	Payload *Payload
}

// Layer protocol layer: protocol name + field kv pairs
type Layer struct {
	Proto string
	KV    map[string]Value
}

// Value field value (value type in PSL)
type Value struct {
	Kind  ValueKind
	Num   uint64
	Str   string
	IP    string
	MAC   string
	// Built-in functions (evaluated by scope during repeat): $inc(step), $seq(start[, step])
	BuiltinName string
	BuiltinArgs []uint64
	// Repeated structure list (for []StructName field in PDL): [ { k=v, ... }, ... ]
	List []map[string]Value
	// Nested single structure (for StructName field in PDL): { k=v, ... }
	Map map[string]Value
}

type ValueKind int

const (
	ValNumber ValueKind = iota
	ValString
	ValIP
	ValMAC
	ValBuiltin
	ValList
	ValMap
)

type FuzzMode int

const (
	FuzzBoundary FuzzMode = iota
	FuzzPick
	FuzzRange
)

type FuzzRule struct {
	Layer string
	Field string
	Mode  FuzzMode
	Args  []uint64
}

// Payload payload: encoding type + raw content
type Payload struct {
	Kind PayloadKind
	Raw  string // Decoded binary data (or string to encode)
}

type PayloadKind int

const (
	PayloadStr PayloadKind = iota
	PayloadHex
	PayloadBin
	PayloadBase64
)

// Dur time interval
type Dur struct {
	Ns  uint64
	Us  uint64
	Ms  uint64
	Sec uint64
}

func (d Dur) Nanoseconds() uint64 {
	return d.Ns + d.Us*1000 + d.Ms*1000000 + d.Sec*1000000000
}
