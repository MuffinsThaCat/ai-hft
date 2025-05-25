#!/bin/bash

# Trading agent execution script
# This script loads wallet credentials from a secure .env file

# Check if .env file exists
if [ ! -f "$(dirname "$0")/.env" ]; then
  echo "Error: .env file not found. Please create it with your WALLET_KEY and WALLET_ADDRESS."
  echo "Example .env file contents:"
  echo "WALLET_KEY=your_private_key_here"
  echo "WALLET_ADDRESS=your_wallet_address_here"
  exit 1
fi

# Load wallet credentials from .env file
source "$(dirname "$0")/.env"

# Set logging level
export RUST_LOG=debug

# Run the trading agent in production mode
cd "$(dirname "$0")"

# Set additional environment variables for production trading
export RUST_LOG=info,ai_trading_agent=debug
export PRODUCTION_MODE=true

# Set network to Avalanche C-Chain
export NETWORK_CHAIN_ID=43114

# Run the trading agent with flash arbitrage strategy
echo "Starting AI Trading Agent in PRODUCTION MODE on Avalanche C-Chain"
echo "WALLET ADDRESS: $WALLET_ADDRESS"
echo "WARNING: This will execute REAL transactions with REAL funds"
echo "Press Ctrl+C within 5 seconds to cancel"
sleep 5

# Start the trading agent with flash arbitrage strategy
cargo run --release --bin ai-trading-agent -- flash-arbitrage
