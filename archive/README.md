# Archive — Historical Bot Versions

This directory contains all previous iterations of the WoT Grinder Bot, preserving the full evolution from initial concept to the current version.

## Notable Versions

| Version | Lines | Achievement |
|---------|-------|-------------|
| **v2** | ~500 | First Cuckoo solver, SipHash-2-4, Blowfish encryption, full protocol attempt |
| **v3** | ~600 | Base library — packet framing, PING element, XOR-shift checksum |
| **v4** | ~100 | Minimal test — first WG API login attempt |
| **v5** | ~150 | Keccak-512 POW discovery (original Keccak, not NIST SHA3) |
| **v6** | ~170 | WG login confirmed working, first BigWorld packet attempts |
| **v7** | ~160 | Element ID scan (0x00–0x0F) to find valid request types |
| **v8** | ~120 | Systematic protocol version testing |
| **v9** | ~200 | Packet format debugging — flags, footers, request offsets |
| **v10** | ~180 | PING working — server responds to element 0x02 |
| **v11** | ~180 | Login request format testing — V16 vs Fixed element types |
| **v12** | ~200 | Element length bug discovery — length = body only (not body + 6) |
| **v13** | ~180 | Bundle structure — first_request_offset + 2 encoding |
| **v14** | ~180 | Packed_u24 string encoding — variable-length prefix |
| **v15** | ~170 | Context field discovery — wg-toolkit-rs reads context in LogOnParams |
| **v16** | ~180 | 56-byte Blowfish key (not 16) — wg-toolkit-rs reference |
| **v17** | ~180 | CDN URL investigation — game file download analysis |
| **v18** | ~250 | Combined CR + Login in single UDP packet — C++ bundle style |
| **v19** | ~300 | **Protocol version discovery: 17.1.0 (5) = 285278213** |
| **v20** | ~350 | Cuckoo challenge received (0x42) — server issues `cuckoo_cycle` |
| **v20b/c** | ~250 | Cuckoo solver tuning — SIZESHIFT, NODEMASK, HALFSIZE |
| **v21** | ~300 | SIZESHIFT=21 hypothesis (disproved — actually 20) |
| **v22** | ~280 | EDGEMASK vs NODEMASK investigation |
| **v23** | ~260 | Cuckoo verification — 21 U-nodes + 21 V-nodes = 42 nodes |
| **v24** | ~260 | Cuckoo cycle math — bipartite graph verification |
| **v25** | ~350 | **Element length fix confirmed** — body-only length, no +6 |
| **v26** | ~180 | Cuckoo solver with standard Tromp verification |
| **v27** | ~200 | SIPROUND order verification — 2 rounds then 4 rounds |
| **v28** | ~200 | ChallengeResponse format — addBlob vs packed_u24 |
| **v29** | ~220 | **Complete login flow — CR accepted, 0x40 destream** |

## Key Milestones

```
v2   ───▶ First Cuckoo solver
v10  ───▶ PING working
v19  ───▶ Protocol version found (17.1.0)
v20  ───▶ Cuckoo challenge received
v25  ───▶ Element length bug fixed
v29  ───▶ ChallengeResponse accepted
v35  ───▶ Unencrypted login rejected (0x40 → need RSA)
v41  ───▶ RSA encryption accepted (0x42 → need Cuckoo)
v50  ───▶ Official RSA key obtained → current version
```

## Test Scripts

| File | Purpose |
|------|---------|
| `dns_check.py` | DNS resolution test for WoT servers |
| `final_test.py` | Integration test combining all components |
| `quick_tcp_test.py` | Quick TCP connectivity check |
| `smart_test.py` | Smart format detection test |
| `tcp_test.py` | TCP port scan of WoT servers |
| `bw_bot.py` | Early bot prototype (pre-versioning) |
