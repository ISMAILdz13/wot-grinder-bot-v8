# WoT Real Bot v3.0 — World of Tanks Automation

## What This Bot Does
Connects to REAL Wargaming servers:
1. WG API authentication (HTTPS, port 443) — get account info
2. TCP connection to WoT login server (port 5222) — XMPP handshake
3. Enter garage — select tank — queue for battle
4. Auto-play battle (human-like timing) — exit — repeat

## Setup (Termux)
```bash
pkg install python
pip install requests
```

## Get Your Credentials

### 1. Application ID
- Go to https://developers.wargaming.net/applications/
- Click "Create application"
- Copy your application_id

### 2. Access Token
- Visit the WG OpenID login URL (bot prints it for you)
- Login with your WoT account
- Copy access_token from the redirect URL

## Run
```bash
# Basic
python3 wot_real_bot.py --realm EU --app-id YOUR_ID --access-token YOUR_TOKEN

# 50 cycles, fast speed
python3 wot_real_bot.py --realm EU --app-id YOUR_ID --access-token YOUR_TOKEN --cycles 50 --speed fast

# Team battles
python3 wot_real_bot.py --realm EU --app-id YOUR_ID --access-token YOUR_TOKEN --queue-type team

# Save/load config
python3 wot_real_bot.py --realm EU --app-id YOUR_ID --access-token YOUR_TOKEN --save-config wot_config.json
python3 wot_real_bot.py --config wot_config.json
```

## Realms
| Realm | API | Login Servers |
|-------|-----|--------------|
| EU | api.worldoftanks.eu | login.p1-p5.worldoftanks.eu |
| NA | api.worldoftanks.com | wotna3-4.login.wargaming.net |
| ASIA | api.worldoftanks.asia | wotasia1.login.wargaming.net |

## Ports
| Port | Protocol | Purpose |
|------|----------|---------|
| 443 | HTTPS | WG API (works on any plan) |
| 5222 | TCP | WoT login/garage (XMPP) |
| 5223 | TCP+TLS | WoT login/garage (TLS) |
| 50010-50014 | TCP | Game server (battle) |

Note: Ports 5222, 5223, 50010+ are non-443.
Free plans only allow HTTPS (port 443).
Run from Termux (full network access) or paid plan.

## Speed Presets
| Preset | Multiplier | Use Case |
|--------|-----------|----------|
| turbo | 0.2x | Testing |
| fast | 0.5x | Quick farming |
| normal | 1.0x | Human-like (default) |
| slow | 1.5x | Cautious |
| relaxed | 2.5x | Very human-like |
