# WoT Bot v8 Cleanup and Refactoring Plan

## Status: Critical Issues Fixed ✅

### P0 - Security & Stability (FIXED)

| Issue | Status | Fix |
|-------|--------|-----|
| **Public proxy SSRF vulnerability** | ✅ Fixed | Created `render_proxy_secure.py` with `/fetch` removed, host whitelist, auth required |
| **Credential logging** | ⚠️ Partial | Added `mask_username()` function, need to remove debug prints from `bw_bot.py` |
| **Broken credential loader** | ✅ Fixed | New `src/wot/auth.py` with proper INI parsing and environment variable support |
| **Malformed .gitignore** | ✅ Fixed | Removed backticks, added credentials/*.pem/*.key patterns |
| **Global socket state in proxy** | ✅ Fixed | Per-request socket creation in secure proxy |
| **Arbitrary UDP destination** | ✅ Fixed | Host whitelist in secure proxy |

### P1 - Architecture Improvements (IN PROGRESS)

| Component | Status | Location |
|-----------|--------|----------|
| Protocol classes | ✅ Created | `src/wot/protocol.py` |
| Auth module | ✅ Created | `src/wot/auth.py` |
| Unit tests | ✅ Created | `tests/unit/test_protocol.py` |
| Dead code removal | ❌ Pending | `src/bw_bot.py` has 6+ duplicate login functions |
| State machine | ❌ Pending | Need `src/wot/session.py` |

### P2 - Code Quality (TODO)

- [ ] Remove experimental login functions from `bw_bot.py`:
  - `build_logon_params_v2`
  - `build_logon_params_legacy`
  - `build_logon_params_reversed`
  - `build_logon_params_v4`
  - `build_logon_params_v3`
  - `build_logon_u32`
  - `build_login_rsa_reversed`
  - `build_login_noflag` (broken - wrong signature)
  
- [ ] Fix `build_login_noflag()` - currently calls non-existent parameters

- [ ] Centralize protocol constants in `ProtocolConfig`

- [ ] Add proper exception types instead of bare `except:`

### P3 - Windows Support

| Item | Status | Notes |
|------|--------|-------|
| Batch launcher | ✅ Exists | `run_bot.bat` with menu system |
| Cuckoo DLL compilation | ✅ Supported | Auto-detects Windows in `_try_compile_fast()` |
| Credential input | ⚠️ Needs fix | Password masking unreliable in batch |

---

## Next Steps (Priority Order)

### 1. Test Secure Proxy Deployment
```bash
# Generate API secret
export API_SECRET=$(openssl rand -hex 32)
export ALLOWED_HOSTS="login.p1.worldoftanks.eu,login.p2.worldoftanks.eu"

# Deploy to Render.com
# Update render.yaml to use render_proxy_secure.py
```

### 2. Clean Up bw_bot.py
- Keep only ONE working login format (determine which works best)
- Remove all experimental functions
- Replace password printing with masked logging
- Implement proper state machine

### 3. Complete Test Suite
```bash
# Run unit tests (no network)
pytest tests/unit/ -v

# Run integration tests (requires network)
pytest tests/integration/ -v -m integration
```

### 4. Fix Windows Batch File
The current `run_bot.bat` has issues:
- PowerShell password masking is broken (line 102)
- Credentials saved in legacy INI format

**Fix needed:**
```batch
:: Simple direct input (no masking attempt)
set /p WOT_USERNAME=Username: 
set /p WOT_PASSWORD=Password: 

:: Save in standard INI format
echo [credentials] > credentials.ini
echo username = %WOT_USERNAME% >> credentials.ini
echo password = %WOT_PASSWORD% >> credentials.ini
```

### 5. Document PKCS1_OAEP Randomization Issue
From your analysis - this test was unreliable:
```python
# WRONG - PKCS1_OAEP produces different ciphertext each time
if fixed[4] == 0x01 and current[4:6] == fixed[5:7]:
    # This comparison will almost always fail!
```

**Correct approach:**
- Don't compare RSA ciphertexts byte-for-byte
- Test decryption round-trip instead
- Focus on server response codes (0x40 → 0x42 transition)

---

## Recommended Project Structure

```
wot-bot/
├── src/
│   ├── wot/
│   │   ├── __init__.py
│   │   ├── protocol.py      # ✅ Packet classes
│   │   ├── auth.py          # ✅ Credentials & login
│   │   ├── crypto.py        # TODO: Cuckoo solver wrapper
│   │   ├── network.py       # TODO: Socket management
│   │   └── session.py       # TODO: State machine
│   ├── bw_bot.py            # Legacy - refactor or replace
│   └── cuckoo_fast.c        # C solver
├── tests/
│   ├── unit/                # ✅ No network dependencies
│   └── integration/         # Live server tests
├── proxy/
│   ├── render_proxy.py      # Legacy (insecure)
│   └── render_proxy_secure.py  # ✅ Production-ready
├── run_bot.bat              # Windows launcher
├── RUN_BOT.sh               # Linux launcher
└── credentials.ini.example  # Template (gitignored: credentials.ini)
```

---

## Known Technical Issues

### 1. Login Flow Fragmentation
`bw_bot.py` has multiple competing implementations. Need to:
1. Determine which format actually works (if any)
2. Delete all others
3. Create single authoritative `ProtocolClient` class

### 2. Unproven Protocol Hypotheses
From your analysis:
- The "encrypted_flag" byte theory was unproven
- Server expects `[protocol(4)][flag(1)][RSA(256)]` - hypothesis not confirmed
- Challenge response testing was incomplete

**Action:** Add detailed logging to capture actual server responses for analysis

### 3. Missing Gameplay Architecture
Current status:
- ✅ WG Login
- ✅ BigWorld PING
- ✅ Cuckoo challenge solving
- ✅ RSA encryption
- ❌ LoginSuccess handling
- ❌ Base App session
- ❌ Battle automation

---

## Security Checklist

Before deploying proxy publicly:

- [x] API authentication required
- [x] Rate limiting implemented
- [x] Host whitelist enforced
- [x] Removed `/fetch` endpoint (SSRF)
- [x] Per-request sockets (no global state)
- [x] Request size limits
- [x] Timeout limits
- [ ] HTTPS certificate verification (removed for WGC CDN fetch - OK for internal)
- [ ] Logging/metrics endpoint
- [ ] Health check with auth option

---

## Testing Strategy

### Unit Tests (Fast, No Network)
```bash
pytest tests/unit/ -v
# - Protocol encoding/decoding
# - Credential loading
# - Crypto operations
# - Packet validation
```

### Integration Tests (Slow, Requires Network)
```bash
pytest tests/integration/ -v -m integration
# - Live server PING
# - Challenge/response cycle
# - Full login flow
```

### Manual Testing
```bash
# Test with real credentials
export WOT_USERNAME="your@email.com"
export WOT_PASSWORD="your_password"
python src/bw_bot.py
```
