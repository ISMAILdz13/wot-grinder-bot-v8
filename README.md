# 🎮 WoT Grinder Bot — BigWorld Protocol Client

> A Python-based World of Tanks automation bot using the BigWorld/Mercury UDP protocol.  
> Reverse-engineered from scratch — protocol version, Cuckoo PoW, Blowfish encryption, and all.

---

## 🎯 Status

| Component | Status | Notes |
|-----------|--------|-------|
| WG Login (Keccak-512 POW) | ✅ Working | Email + password via Wargaming API |
| BigWorld PING | ✅ Working | Element 0x02, UDP to login server |
| Protocol Version | ✅ Found | **17.1.0 (5)** = `285278213` |
| Login Request | ✅ Working | Server responds with Cuckoo challenge |
| Cuckoo PoW Challenge | ✅ Received | `0x42` — server issues `cuckoo_cycle` |
| Cuckoo Solver | ✅ Fixed | Exact BigWorld source algorithm (mean/cuckoo array) |
| ChallengeResponse | 🔄 Next Step | Element 0x03 with 42-nonce solution |
| LoginSuccess | ⏳ Pending | Blowfish-encrypted base app address |
| Base App Connection | ⏳ Pending | Post-login game server handshake |
| Battle Automation | ⏳ Future | Entity methods, movement, combat |

---

## 🔑 Key Discoveries

### Protocol Version
```
BigWorld.protocolVersion = "17.1.0 (5)"
major=17, minor=1, patch=0, subpatch=5
struct(5, 0, 1, 17) = 5 + 0×256 + 1×65536 + 17×16777216 = 285278213
```
Found via `Kurzdor/wot.bigworld-placeholder` — a WoT mod that exposes `BigWorld.protocolVersion`.

### Packet Format (BigWorld/Mercury UDP)
```
┌──────────────────────────────────────────────────────┐
│ HEADER (6 bytes)                                     │
│   Prefix  (4B u32 LE)  — XOR-shift checksum            │
│   Flags   (2B u16 LE)  — bitfield for footers          │
├──────────────────────────────────────────────────────┤
│ BODY / ELEMENTS                                       │
│   Element: [ID(1B)] [Length(NB)] [RID(4B)] [Next(2B)] │
│            [Payload...]                                │
├──────────────────────────────────────────────────────┤
│ FOOTERS                                                │
│   HAS_REQUESTS (0x0001): first_request_offset (2B)    │
│   ... (checksums, acks, sequence, etc.)               │
└──────────────────────────────────────────────────────┘
```

### Login Request Format (Element 0x00, Variable16)
```
[protocol(4B LE)] [LogOnParams...]
```

**IMPORTANT:** No `encrypted_flag` byte between protocol and LogOnParams!  
The `wg-toolkit-rs` Rust implementation adds one, but the original BigWorld C++ code does NOT.

### LogOnParams Format
```
[flags(1B)] [username(packed_str)] [password(packed_str)]
[blowfish_key(packed_blob)] [nonce(4B LE)]
```

**NOTE:** No `context` field — the Rust implementation added it, C++ doesn't have it.

### Cuckoo Cycle Challenge
When the server receives a valid LoginRequest, it responds with `0x42` (Challenge):
- **Type:** `cuckoo_cycle`
- **Key prefix:** variable bytes (hash with SHA-256 → SipHash key)
- **Max nonce:** u32 (search space for PoW)

The client must find a 42-edge cycle in the Cuckoo graph and send it back as `ChallengeResponse` (Element 0x03).

### Server Response Codes
| Code | Name | Meaning |
|------|------|---------|
| 0x01 | Success | Login succeeded |
| 0x40 | MalformedRequest | Can't parse request |
| 0x41 | BadProtocolVersion | Wrong protocol version |
| 0x42 | Challenge | Cuckoo PoW challenge issued |
| 0x47 | InvalidUser | Bad username |
| 0x48 | InvalidPassword | Bad password |
| 0x53 | RateLimited | Too many attempts |
| 0x54 | Banned | Account banned |

---

## 📁 Project Structure

```
wot-grinder-bot-v8/
├── bw_bot_v31.py        # Main bot — complete login flow
├── bw_bot_v3.py          # Base library (packet framing, PING)
├── bw_protocol.py        # BigWorld protocol definitions
├── battle_awareness.py   # Battle tracking & entity parsing
├── wot_grinder.py        # Full grinder (WG login + game logic)
├── grinder_config.json   # Bot configuration
├── requirements.txt      # Python dependencies
├── setup_vps.sh           # One-click VPS setup
├── VPS_GUIDE.md           # VPS deployment guide
└── archive/               # Old versions (v1-v29, tests, experiments)
    ├── bw_bot_v2.py       # First Cuckoo solver implementation
    ├── bw_bot_v25.py      # Element format fix (length = body only)
    ├── bw_bot_v29.py      # Protocol version discovery (17.1.0.5)
    └── ...                # All other iterations
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- VPS with unrestricted UDP access (Algerian ISPs block game server UDP)
- A Wargaming account (email + password)

### Install
```bash
git clone https://github.com/ISMAILdz13/wot-grinder-bot-v8.git
cd wot-grinder-bot-v8
pip3 install -r requirements.txt
```

### Run
```bash
python3 bw_bot_v31.py
```

### VPS Setup (one-click)
```bash
bash setup_vps.sh
python3 bw_bot_v31.py
```

---

## 🔬 Technical Details

### BigWorld Protocol Stack
- **Transport:** UDP (ports 20016/20018 for EU login servers)
- **Encryption:** RSA (login params) → Blowfish (session)
- **PoW:** Cuckoo Cycle (SipHash-2-4, 42-edge cycle)
- **Packet max size:** 1472 bytes (UDP MTU)

### Login Flow
```
Client                    Server
  │                         │
  │──── PING (0x02) ───────→│
  │←─── PING Reply ─────────│
  │                         │
  │──── LoginRequest(0x00) ─→│  [proto=285278213] [LogOnParams]
  │←─── Challenge (0x42) ────│  [cuckoo_cycle] [key_prefix] [max_nonce]
  │                         │
  │    (solve Cuckoo PoW)    │
  │                         │
  │── ChallengeResponse(0x03)→│  [duration] [42-nonce solution]
  │←─── Response ───────────│
  │                         │
  │──── LoginRequest(0x00) ─→│  [same BF key]
  │←─── LoginSuccess(0x01) ─│  [Blowfish-encrypted base app addr]
  │                         │
  │──── BaseApp Connect ────→│
  │←─── Game Session ───────│
  │                         │
  ▼                         ▼
    GAME STARTED — GRINDING
```

### Protocol Version History (BigWorld Engine)
```
v2.0.6   — Converted from old-style protocol 59
v2.2.255 — Server-controlled entities
v2.6.255 — Login challenges added (Cuckoo cycle!)
v2.9.0   — BigWorld 14.4.1 release (open source)
v17.1.0  — Current WoT version (proprietary, Wargaming)
```

---

## 📜 Research Sources

- **BigWorld Engine 14.4.1** (open source): `v2v3v4/BigWorld-Engine-14.4.1`
- **wg-toolkit-rs** (Rust implementation): `theorzr/wg-toolkit-rs`
- **WoT BigWorld Placeholder** (protocol version): `Kurzdor/wot.bigworld-placeholder`
- **WoT Decompiled Scripts**: `testingsomescripts/WorldOfTanks-Decompiled`

---

## ⚠️ Disclaimer

This project is for educational and research purposes only. Automating gameplay may violate Wargaming's Terms of Service. Use at your own risk.
