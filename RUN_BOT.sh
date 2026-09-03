#!/bin/bash
# WoT Grinder Bot v52 - Quick Start Script
# =========================================

set -e

echo ""
echo "========================================================"
echo "  WoT Grinder Bot v52 - Setup & Launch"
echo "========================================================"
echo ""

# Check for credentials
if [ ! -f "credentials.ini" ]; then
    echo "[SETUP] No credentials.ini found!"
    echo ""
    echo "Please choose an option:"
    echo "  1) Copy example and edit manually"
    echo "  2) Set environment variables"
    echo "  3) Exit and configure later"
    echo ""
    read -p "Choice (1-3): " choice
    
    case $choice in
        1)
            cp credentials.ini.example credentials.ini
            echo ""
            echo "[INFO] Created credentials.ini from example"
            echo "[EDIT] Please edit credentials.ini with your WoT credentials:"
            echo "       nano credentials.ini  (or use your favorite editor)"
            echo ""
            exit 0
            ;;
        2)
            echo ""
            echo "[INFO] To set environment variables, run:"
            echo "       export WOT_USERNAME='your_username'"
            echo "       export WOT_PASSWORD='your_password'"
            echo ""
            read -p "Set them now? (y/n): " setenv
            if [ "$setenv" = "y" ]; then
                read -p "Username: " username
                read -s -p "Password: " password
                echo ""
                export WOT_USERNAME="$username"
                export WOT_PASSWORD="$password"
                echo "[OK] Environment variables set for this session"
            fi
            ;;
        3)
            echo "[EXIT] Configure credentials and run again."
            exit 0
            ;;
        *)
            echo "[ERROR] Invalid choice"
            exit 1
            ;;
    esac
fi

# Compile Cuckoo solver if needed
if [ ! -f "src/cuckoo_fast.so" ] && [ ! -f "src/cuckoo_fast.dll" ]; then
    echo ""
    echo "[BUILD] Compiling Cuckoo Cycle solver..."
    if command -v gcc &> /dev/null; then
        gcc -O3 -shared -fPIC -o src/cuckoo_fast.so src/cuckoo_fast.c
        echo "[OK] Compiled src/cuckoo_fast.so"
    elif command -v clang &> /dev/null; then
        clang -O3 -shared -fPIC -o src/cuckoo_fast.so src/cuckoo_fast.c
        echo "[OK] Compiled src/cuckoo_fast.so (clang)"
    else
        echo "[WARN] No C compiler found. Will use slower Python solver."
        echo "       Install gcc or clang for 10x speedup."
    fi
fi

# Check Python dependencies
echo ""
echo "[CHECK] Verifying Python dependencies..."
python3 -c "from Crypto.Cipher import PKCS1_OAEP" 2>/dev/null || {
    echo "[WARN] pycryptodome not installed. Installing..."
    pip install pycryptodome --quiet
}

# Run the bot
echo ""
echo "[LAUNCH] Starting WoT Grinder Bot..."
echo "========================================================"
echo ""
python3 src/bw_bot.py
