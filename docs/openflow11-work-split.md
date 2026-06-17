# OpenFlow 1.1 for POX — Work Split & Interface Contract

> University of Caxias do Sul — Computer Networks
> Prof. Maria de Fátima · Students: Gabriel Vieira and Rafael Graunke
>
> Goal: add **OpenFlow 1.1 write capability** to POX (only `FlowMod` carrying
> instructions), coexisting with the existing `libopenflow_01.py`. This is **not**
> full OF 1.1 support — see scope below.

---

## 1. Scope (shared — read first)

**In scope**
- Build `FlowMod` messages using the OF 1.1 hierarchy:
  `FlowMod → Instruction (APPLY_ACTIONS) → Action (OUTPUT)`.
- Serialize (`pack()`) the new instruction structures to correct wire bytes.
- A proof-of-concept component that installs one working flow ("port 1 → port 2")
  on a switch and proves it via Wireshark + Mininet/Open vSwitch.

**Out of scope (do NOT implement)**
- Multiple tables, `GOTO_TABLE`, groups, meters.
- Full OF 1.1 handshake / version negotiation.
- `unpack()` of incoming 1.1 messages (we only *send*).

---

## 2. The split

Two independent files, clean interface between them. They can be coded in
parallel once the contract in section 3 is fixed.

| Part | Owner | File | Responsibility |
|---|---|---|---|
| **A — Library** | **Gabriel** | `pox/openflow/libopenflow_11.py` | Define the binary structures and their `pack()` methods. Pure data + serialization. No networking. |
| **B — Proof of Concept** | **Rafael** | `ext/of11_instruction_poc.py` | Use Part A to build a `FlowMod` and send it on `ConnectionUp`. Set up Mininet + Open vSwitch, capture in Wireshark, confirm ping. |

```
   Part A (Gabriel)                      Part B (Rafael)
   libopenflow_11.py        ───imports──►   of11_instruction_poc.py
   classes + pack()         (the contract)  builds FlowMod, sends it,
                                            validates on OVS/Mininet
```

**Dependency direction:** B depends on A. A does not depend on B. A can be tested
in isolation (print bytes, compare hex). That is why the interface in section 3
must be agreed up front and not changed silently.

---

## 3. Interface Contract (the agreement between A and B)

Part B will write code that looks like this. Part A must provide exactly these
classes, names, and constructor keywords.

```python
from pox.openflow import libopenflow_11 as of11

# 1. an output action (8 bytes on the wire) — same layout as OF 1.0
act = of11.ofp_action_output(port=2)

# 2. an APPLY_ACTIONS instruction wrapping a list of actions
instr = of11.ofp_instruction_actions(actions=[act])
#   type defaults to OFPIT_APPLY_ACTIONS

# 3. every structure exposes pack() -> bytes and __len__()
raw = instr.pack()        # -> bytes, big-endian
n   = len(instr)          # total length in bytes (header + padding + actions)
```

### Required public API for Part A

| Symbol | Kind | Notes |
|---|---|---|
| `OFPIT_APPLY_ACTIONS` | constant | value `4` (OF 1.1) |
| `OFPAT_OUTPUT` | constant | value `0` |
| `OFP_VERSION` | constant | value `0x02` (OF 1.1 wire version; same name idiom as `libopenflow_01`) |
| `ofp_action_output(port=..., max_len=...)` | class | `pack()` → 16 bytes `!HHIH6x` (type, len, port(32b), max_len, 6 pad) |
| `ofp_instruction_actions(type=OFPIT_APPLY_ACTIONS, actions=[...])` | class | `pack()` → 4-byte header + 4-byte padding + packed actions |
| `.pack()` | method on every class | returns `bytes`, network byte order |
| `.__len__()` | method on every class | returns total byte length |

### Field defaults Part A must honor

- `ofp_action_output`: `max_len` defaults to `0` (only relevant for `OFPP_CONTROLLER`).
- `ofp_instruction_actions`: `type` defaults to `OFPIT_APPLY_ACTIONS`; `actions`
  defaults to an empty list.
- `len` fields are **computed in `pack()`**, never hardcoded — they depend on the
  number/size of nested actions.

### Hand-off rule

If either side needs to change a name, a keyword, or a default in section 3, it
must be agreed by both before changing — otherwise B breaks against A. Treat this
table as frozen once coding starts.

---

## 4. Wire-format reference (what `pack()` must produce)

Target hierarchy captured in Wireshark:
`FlowMod → Instructions → Apply_Actions → Action_Output`.

```
ofp_action_output            (16 bytes)  struct "!HHIH6x"  (port is 32-bit in 1.1)
  ┌────────────┬────────────┬─────────────────────────┐
  │ type=0     │ len=16     │ port (32 bits)           │
  ├────────────┼────────────┴─────────────────────────┤
  │ max_len=0  │ padding (6 bytes total)              │
  └────────────┴──────────────────────────────────────┘

ofp_instruction_actions      (8 + actions)
  ┌────────────┬────────────┐
  │ type=4     │ len=total  │   header  ("!HH", 4 bytes)
  ├────────────┴────────────┤
  │ padding = 00 00 00 00   │   alignment (4 bytes)
  ├─────────────────────────┤
  │ packed actions here ... │   e.g. one ofp_action_output (16 bytes)
  └─────────────────────────┘

Example bytes for APPLY_ACTIONS{ OUTPUT(port=2) }, total len = 24 (0x18):
  00 04 00 18  00 00 00 00  00 00 00 10 00 00 00 02 00 00 00 00 00 00 00 00
  └instr hdr┘  └ padding ┘  └─ action OUTPUT: type len port(32b) max_len pad6 ─┘
```

> Note: 8-byte alignment is mandatory in OpenFlow. The instruction header is only
> 4 bytes, so the 4 padding bytes push the first action to an 8-byte boundary. A
> wrong `len` or missing padding makes the switch reject the message.

---

## 5. Definition of Done (per part)

**Part A (Gabriel) — done when:**
- [ ] `libopenflow_11.py` exists with the classes/constants from section 3.
- [ ] `ofp_action_output(port=2).pack()` returns the correct 16 bytes.
- [ ] `ofp_instruction_actions(actions=[ofp_action_output(port=2)]).pack()`
      returns the 24-byte sequence in section 4.
- [ ] `len()` matches the `len` field written inside `pack()`.
- [ ] A tiny self-test (print + assert hex) runs without POX, no switch needed.

**Part B (Rafael) — done when:**
- [ ] `ext/of11_instruction_poc.py` listens for `ConnectionUp` and sends a
      `FlowMod` built from Part A's classes.
- [ ] Mininet topology (2 hosts + 1 Open vSwitch) connects to POX.
- [ ] Wireshark capture shows `FlowMod → Instructions → Apply_Actions →
      Action_Output`.
- [ ] `ping` between the two hosts succeeds with the installed flow.

**Integration (both):**
- [ ] B runs against A unchanged (the contract held).
- [ ] One capture (.pcapng) + screenshot saved as evidence for the report.

---

## 6. Suggested order of work

1. **Together:** confirm section 3 (interface) — 10 minutes, freeze it.
2. **Gabriel (A):** build classes + self-test against the section-4 bytes. This
   unblocks B and is independently verifiable.
3. **Rafael (B):** in parallel, prepare Mininet/OVS environment and write the
   component against the agreed API (can stub A with fake bytes until A lands).
4. **Together:** integrate, capture in Wireshark, run the ping test, collect
   evidence.

---

## 7. Git suggestion (avoid stepping on each other)

- Work on separate files (already the case) → minimal merge conflicts.
- Optional: one short-lived branch per part (e.g. `of11-lib`, `of11-poc`),
  merge when the contract integration passes.
