# PSL Examples

The following examples can be used for parsing/building/sending tests (it is recommended to verify them with `-dry-run` first).

**Conventions**:
- **Brackets**: Square brackets can be omitted in single-line mode; if `[ ... ]` is used, it **must contain the payload** (the payload is written inside the brackets, after the last protocol layer).
- **Required Fields**: To simulate real-world packets, try to explicitly fill in non-default fields (e.g., `src`/`dst` for `ip`, `sport`/`dport` for `tcp`/`udp`, `dst`/`src` for `eth`), otherwise a "no default value" error might be triggered.

| File | Description |
|------|-------------|
| `single.psl` | A single UDP packet |
| `loop.psl` | Single packet + `@repeat 5`, `@interval 100ms` |
| `async-heartbeat.psl` | An async block with `@repeat forever` for heartbeat + mainline TCP |
| `async-repeat-n.psl` | An async block with `@repeat 3` (finite times) for testing |
| `block-repeat.psl` | A regular block (non-async) + `@repeat 2` |
| `multi-packet.psl` | Multiple single packets without blocks |
| `payload-formats.psl` | Four payload types: string, hex (`x`), binary (`b`), base64 (`64`) |
| `eth-mac.psl` | All-F broadcast MAC and regular MAC addresses |
| `single-tcp.psl` | A single complete TCP packet |
| `arp-icmp.psl` | ICMP packet |
| `ipv6.psl` | IPv6 header + payload (demonstrates parsing IPv6 PSL literals) |
| `ipv6-tcp.psl` | IPv6 + TCP, checksum computed using the IPv6 pseudo-header |
| `inc-seq.psl` | `$seq(1,1)` with `@repeat 5`: `ip.id` increments per repeat (1, 2, 3, 4, 5) |
| `rip-repeat.psl` | PDL repeated structure: `rip(entries=[ { addr=..., metric=... }, ... ])` |
| `pim-hello.psl` | PIM Hello example (using `[]type` dynamic array) |
| `pim-join-prune.psl`| PIM Join/Prune example (with `[field]type` length field auto-filled) |
| `const.psl` | Using `const` macro definitions in PSL to simplify formatting |
| `basic.psl` | Basic example showing standard protocol stacking |
| `eth.psl` | Ethernet frame focused example |
| `myproto.psl` | Example using custom protocol |
| `nested.psl` | Example with nested structures (e.g. TypeStructRef) |
| `test.psl` | Example in README.md |

### Key Features Highlighted
- **$inc / $seq**: Written in field values as `$inc(step)` or `$seq(start[, step])`. During `@repeat`, it is evaluated based on the **repeat index of the current packet statement**; the scope is limited to that statement, and multiple packets within a block are independent.
- **Constants**: Use `const Identifier = Value` at the top level of PSL for macro replacement, making it easy to reuse complex values (like MAC addresses).
- **PDL Arrays**: Supports three array types: `[]type` (dynamic length), `[N]type` (fixed length, padded with default values if insufficient), and `[field]type` (length is associated with a preceding field, **the Builder automatically auto-fills the actual number of elements during packet creation**). In PSL, they are consistently populated using `field=[ { k=v, ... }, { ... } ]`.