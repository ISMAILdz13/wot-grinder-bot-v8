# WoT Bot — Rust Edition

Real BigWorld protocol implementation using [wg-toolkit-rs](https://github.com/theorzr/wg-toolkit-rs).

## Build

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build
cd rust-bot
cargo build --release

# Run (needs UDP access!)
./target/release/wot-bot
```

## Why Rust?

The Python bot (V8/V9) was sending plaintext BigWorld packets. The real protocol requires:
- Proper packet framing (prefix + flags + content + footer)
- Bundle structure for elements
- Request/reply tracking with request IDs
- Cuckoo cycle challenge solving
- RSA encryption for login
- Blowfish encryption for game packets

The wg-toolkit-rs library implements all of this correctly. Instead of porting it to Python
(error-prone), we use the real Rust implementation.
