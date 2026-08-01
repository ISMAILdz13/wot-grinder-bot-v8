#!/bin/bash
# WoT BigWorld Bot — VPS Setup & Run
# Works on any Linux VPS with UDP access (AquiaVPS, Oracle, GCloud)

echo "=== WoT BigWorld Bot Setup ==="

# Install Python if needed
if ! command -v python3 &>/dev/null; then
    apt update -qq && apt install -y python3 -qq
fi

# Clone repo
if [ ! -d wot-grinder-bot-v8 ]; then
    git clone https://github.com/ISMAILdz13/wot-grinder-bot-v8.git
fi
cd wot-grinder-bot-v8
git pull

# Run the bot
echo "Starting WoT BigWorld Bot..."
python3 bw_bot.py
