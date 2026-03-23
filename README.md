# PacketForge

PacketForge is a highly flexible, fully programmable network packet crafting and injection tool driven by two domain-specific languages (DSLs): **PDL (Protocol Definition Language)** and **PSL (Packet Stream Language)**. 

It is designed for rapid packet construction, flow control (loops, intervals, concurrency), and dynamic protocol definition. It is particularly well-suited for network testing, protocol simulation, and low-level packet forging.

---

## 1. Core Features

### 1.1 Protocol Definition Language (PDL)
PDL allows you to define custom protocol headers similar to Go structs. The tool automatically handles field offsets, checksum calculations, and default value population.

- **Built-in Types**: `u8`, `u16`, `u32`, `u64`, `mac`, `ipv4`, `ipv6`.
- **Dynamic & Fixed Arrays**: Supports struct arrays such as `[]StructName` (dynamic length), `[N]StructName` (fixed length, padded automatically), and `[field]StructName` (length is derived from a preceding field, which is **auto-filled during packet building**).
- **Auto-Calculations**: Use built-in functions like `$len` (calculate total length), `$payload_len` (calculate payload length), and `$cksum` (automatically calculate IPv4, TCP, UDP, ICMP checksums).
- **Nested Structures**: Define inner structs and reuse them within multiple protocol definitions.

### 1.2 Packet Stream Language (PSL)
PSL is a concise, unambiguous DSL designed for constructing packet streams, defining their contents, and controlling their flow.

- **Bracket System**: 
  - `()` configures protocol layer fields (e.g. `tcp(sport=1234, dport=80)`).
  - `[]` wraps a single packet (can be omitted for single-line packets).
  - `{}` groups multiple packets into a block for collective flow control.
- **Payload Formatting**: Supported directly via backticks (`` `...` ``) with prefixes for strings (default), hex (`x`), binary (`b`), and base64 (`64`).
- **Flow Control**:
  - `@repeat N` or `@repeat forever`: Loops the preceding packet or block.
  - `@interval [time]`: Pauses between transmissions (e.g., `100ms`, `1s`).
- **Variables & Macros**: Define constants at the top level (e.g., `const BRD = FF:FF:FF:FF:FF:FF`) to simplify address typing.
- **Dynamic Field Iteration**: Use `$inc(step)` or `$seq(start, step)` in loops to auto-increment fields (like IP IDs) natively per repeat.

### 1.3 Asynchronous Execution (`async` blocks)
You can prefix a block with `async` to run it in a background goroutine without blocking the main stream execution. This is extremely useful for background keep-alives or heartbeat packets.
*Note: Once the main execution thread finishes its sequence, the application will exit and tear down any running `async` blocks immediately.*

---

## 2. Usage

### Installation

Download `packetforge` from `go install`:
```bash
go install github.com/yanjiulab/packetforge/cmd/pf@latest
```

Or clone and build the project:
```bash
git clone https://github.com/yanjiulab/packetforge.git
cd packetforge
go build -o pf ./cmd/pf
```

### Command-Line Arguments
```bash
Usage:
  pf [flags]

Flags:
      --builtin-proto    Load built-in common protocols first (eth/vlan/arp/arp_request/arp_reply/ip/ipv6/icmp/icmp6/ndp_ns/ndp_na/udp/tcp) (default true)
      --dry-run          Parse and build packets only, do not actually send
  -h, --help             help for pf
      --iface string     Network interface to send packets (e.g. eth0, lo) (default "lo")
      --proto string     Protocol definition directory (.pdl files), optional (default "proto")
      --stream string    Packet stream language file (required)
  -v, --version          version for pf
```

Show builtin protocol list:
```bash
pf builtin
```

Visualize packet layout and per-layer bytes:
```bash
pf explain -s examples/basic.psl
pf explain -s examples/random-builtins.psl --seed 42 --format json
```

Run fuzz mode (only `pf fuzz` parses `@fuzz` rules):
```bash
pf fuzz -s examples/fuzz-basic.psl -d --seed 42
```

### Quick Example
**1. Protocol Definition (`proto/myproto.pdl`)**
```pdl
protocol myproto {
    magic u32 = 0xdeadbeef
    len u8 = $payload_len
    reserved u16 = 0
}
```

**2. Packet Stream Script (`examples/test.psl`)**
```psl
const SOURCE = 192.168.1.1
const TARGET = 192.168.1.100

// Background ping (runs asynchronously)
async {
  [eth() ip(src=SOURCE, dst=TARGET) icmp() `ping`]
  @repeat forever
  @interval 1s
}

// Mainline TCP stream
[
  eth()
  ip(src=SOURCE, dst=TARGET, id=$seq(1, 1))
  tcp(sport=1234, dport=80)
  `GET / HTTP/1.1\r\n\r\n`
]
@repeat 10
@interval 100ms
```

**3. Execution**
```bash
sudo ./pf -stream examples/test.psl -iface eth0
```

---

*For detailed syntax rules and advanced protocol features (like array population or nested structs), please check the `.pdl` definitions in `proto/` and the examples in `examples/`.*