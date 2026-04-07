# PacketForge

PacketForge is a programmable packet crafting and injection tool based on two DSLs:

- `PDL` (Protocol Definition Language): define protocol headers and defaults.
- `PSL` (Packet Stream Language): describe packet streams and flow control.

## Installation

```bash
go install github.com/yanjiulab/packetforge/cmd/pf@latest
```

or:

```bash
git clone https://github.com/yanjiulab/packetforge.git
cd packetforge
go build -o pf ./cmd/pf
```

## Command Capability Matrix

| Command | Primary goal | Reads `@fuzz` | Sends real packets | Typical output |
|---|---|---|---|---|
| `pf` | normal parse/build/send | No (errors if present) | Yes (`--dry-run` disables) | send result or dry-run hexdump |
| `pf fuzz` | run fuzz rules from PSL | Yes | Yes (`--dry-run` disables) | per-case values + send/dry-run output |
| `pf explain` | visualize packet layout | No | No | layer offsets/length/hex (text or JSON) |
| `pf builtin` | list built-in protocols | N/A | No | protocol name list |
| `pf gen` | generate Go/C/C++ struct definitions from PDL | N/A | No | generated source/header files |

## Core CLI Usage

### `pf` (normal mode)

```bash
pf -s examples/test.psl -i eth0
pf -s examples/test.psl -d
```

Common flags:

- `-s, --stream` PSL file (required)
- `-p, --proto` PDL directory (default `proto`)
- `-i, --iface` interface (default `lo`)
- `-d, --dry-run` parse/build only
- `-r, --recv` start receiving before sending and print received packet hex
- `--recv-wait` drain wait after all sends when `--recv-count` is `0` (default `1s`). If `--recv-count` is set to a positive N, the default `1s` is **not** used as a cap: wait until N drain-phase packets, unless you explicitly set `--recv-wait` or `PF_RECV_WAIT` to limit total wait time
- `--recv-count` in the drain phase only, stop after N received packets (default `0`, unlimited; send phase does not count toward the limit)
- `--recv-bpf` tcpdump-style BPF filter for received packets (e.g. `icmp`, `tcp port 80`); on Linux, a filter requires a **CGO** build with **libpcap** (`CGO_ENABLED=1` and e.g. `libpcap-dev`); without CGO, omit `--recv-bpf` or rebuild with CGO
- `-b, --builtin-proto` load builtin protocols
- `--seed` random seed for `$rand*` builtins

### `pf fuzz`

```bash
pf fuzz -s examples/fuzz-basic.psl -i eth0
pf fuzz -s examples/fuzz-basic.psl -d --seed 42 --max-cases 20
```

Notes:

- `@fuzz` rules are parsed only in `pf fuzz`.
- In normal `pf` mode, scripts containing `@fuzz` return an error.

Supported rules:

- `@fuzz layer.field boundary`
- `@fuzz layer.field pick(v1,v2,...)`
- `@fuzz layer.field range(min,max[,step])`
- `@fuzz count N`

### `pf explain`

```bash
pf explain -s examples/basic.psl
pf explain -s examples/random-builtins.psl --seed 42 --format json
```

Output contains, per packet:

- layer name
- offset
- byte length
- layer hex bytes

### `pf builtin`

```bash
pf builtin
```

### `pf gen`

```bash
pf gen -p proto -o generated --lang go
pf gen -p proto -o generated --lang all
pf gen -p proto -o generated --lang cpp --expand-builtin-heads
```

Notes:

- Supported `--lang`: `go`, `c`, `cpp`, `all`.
- Dynamic arrays are supported:
  - Go: `[]T`
  - C: `T*` (for `[]T` an extra `<name>_len` field is generated)
  - C++: `std::vector<T>`
- C++ output is split into two files:
  - `pdl_gen.hpp`: type definitions
  - `pdl_gen_codec.hpp`: serialize/deserialize codec functions and usage comments
- Field-length arrays (`[field]Type`) are generated as pointer + comment (length is referenced field).
- By default builtin head fields (`mac`, `ipv4`, `ipv6`) are kept as named types (`Mac`/`IPv4`/`IPv6`); use `--expand-builtin-heads` to expand to raw byte arrays.
- C/C++ generated struct names no longer use `pf_` / `Pf` prefixes.

## DSL Highlights

### PDL

- Built-in types: `u8`, `u16`, `u32`, `u64`, `mac`, `ipv4`, `ipv6`
- Auto values: `$len`, `$payload_len`, `$cksum`
- Struct arrays: `[]Type`, `[N]Type`, `[field]Type`
- Nested structures via `struct` + field references

### PSL

- Layer fields: `proto(field=value,...)`
- Packet wrappers: `[...]` (single-line packet may omit brackets)
- Payload: backticks with optional prefixes:
  - string (default): `` `hello` ``
  - hex: `` `x 48656c6c6f` ``
  - binary: `` `b 01000001` ``
  - base64: `` `64 SGVsbG8=` ``
- Flow control:
  - `@repeat N` / `@repeat forever`
  - `@interval 100ms|1s|...`
  - `@exit` (for packet stmt: exit script after this packet statement finishes)
  - `@ignore` (stmt modifier, place after packet/block like `@interval`; skip executing that packet/block)
  - `async { ... }`
- Constants: `const NAME = ...`
- Builtins:
  - sequence: `$inc(step)`, `$seq(start[,step])`
  - random: `$rand()`, `$randn(max)`, `$randrange(min,max)`, `$randport()`, `$randmac()`, `$randipv4()`, `$randhex(n)`

## Quick Start Example

`examples/test.psl`:

```psl
const SOURCE = 192.168.1.1
const TARGET = 192.168.1.100

async {
  [eth() ip(src=SOURCE, dst=TARGET) icmp() `ping`]
  @repeat forever
  @interval 1s
}

[
  eth()
  ip(src=SOURCE, dst=TARGET, id=$seq(1, 1))
  tcp(sport=1234, dport=80)
  `GET / HTTP/1.1\r\n\r\n`
]
@repeat 10
@interval 100ms
```

Run:

```bash
pf -s examples/test.psl -i eth0
```

Directive demo:

```bash
pf -s examples/directives-ignore-exit.psl -d
```

More examples are in `examples/`, and protocol definitions are in `proto/`.
