#!/bin/bash

# Real-time arbitrage trading script
# This script runs the AI trading agent in real-time arbitrage mode

# Check if .env file exists
if [ ! -f "$(dirname "$0")/.env" ]; then
  echo "Error: .env file not found. Please create it with your wallet credentials."
  echo "Example .env file contents:"
  echo "WALLET_KEY=your_private_key_here"
  echo "WALLET_ADDRESS=your_wallet_address_here"
  echo "AVALANCHE_RPC_URL=https://api.avax.network/ext/bc/C/rpc"
  exit 1
fi

# Load wallet credentials from .env file
source "$(dirname "$0")/.env"

# Set logging level
export RUST_LOG=info

# Ensure required environment variables are set
if [ -z "$WALLET_KEY" ] || [ -z "$WALLET_ADDRESS" ] || [ -z "$AVALANCHE_RPC_URL" ]; then
  echo "Error: Missing required environment variables in .env file."
  echo "Please ensure WALLET_KEY, WALLET_ADDRESS, and AVALANCHE_RPC_URL are set."
  exit 1
fi

echo "Starting AI Trading Agent in real-time arbitrage mode..."
echo "Using wallet address: ${WALLET_ADDRESS:0:6}...${WALLET_ADDRESS: -4}"
echo "RPC URL: $AVALANCHE_RPC_URL"
echo ""
echo "⚠️ WARNING: This will execute REAL trades on the Avalanche C-Chain ⚠️"
echo "Press Ctrl+C at any time to stop trading"
echo ""
echo "Starting in 5 seconds..."
sleep 5

# Run the trading agent in real-time arbitrage mode
cargo run --release --bin ai-trading-agent -- real-time-arbitrage
