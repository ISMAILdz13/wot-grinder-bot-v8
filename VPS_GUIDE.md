# WoT BigWorld Bot — VPS Guide

## What you need
- Any Linux VPS with UDP access (AquiaVPS works!)
- Python 3.8+

## Setup
```bash
git clone https://github.com/ISMAILdz13/wot-grinder-bot-v8.git
cd wot-grinder-bot-v8
pip3 install pycryptodome  # for Blowfish decryption
```

## Run
```bash
# Self-test (no network needed)
python3 bw_bot_v2.py test

# Full connection test
python3 bw_bot_v2.py
```

## What to expect
1. **PING** — sends correct BigWorld PING with request framing
   - If timeout: UDP is blocked (try different VPS/network)
   - If reply: ✅ server is reachable, protocol works!

2. **LoginRequest** — sends guest login with random Blowfish key
   - Server may respond with Challenge, Success, or Error
   - Challenge = Cuckoo cycle proof-of-work

3. **Cuckoo Challenge** — solves proof-of-work
   - May take 10-30 seconds per attempt (Python is slow)
   - Tries up to 3 different keys if no solution found
   - For faster solving, use the Rust version (rust-bot/)

4. **LoginSuccess** — if login works, shows base app address + login key
   - Response is Blowfish-encrypted, needs pycryptodome

## Protocol details (from wg-toolkit-rs analysis)
- UDP only, no TCP fallback
- Packet: [4B prefix(xorshift)] [2B flags] [content] [footer]
- PING element: [0x02] [request_id(4B)] [next(2B)] [num(1B)]
- LoginRequest: [0x00] [len(2B)] [request_id(4B)] [next(2B)] [body]
- Reply: [0xFF] [len(4B)] [request_id(4B)] [response_data]
- ChallengeResponse: [0x03] [len(2B)] [request_id(4B)] [next(2B)] [duration(f32)] [key(blob_var)] [solution(u32*42)]
- Footer: [first_request_offset(2B)] when HAS_REQUESTS flag set
- Flags: 0x0001=HAS_REQUESTS, 0x0008=ON_CHANNEL, 0x0010=IS_RELIABLE

## Files
- `bw_bot_v2.py` — Main bot (Python, current)
- `bw_bot.py` — Earlier version
- `bw_protocol.py` — Protocol reference
- `rust-bot/` — Rust version using wg-toolkit-rs (faster Cuckoo)
