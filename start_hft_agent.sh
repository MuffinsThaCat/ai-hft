#!/bin/bash

# High-Frequency Trading Agent Startup Script
# This script starts the high-frequency trading agent in production mode

# Configuration
LOG_LEVEL=info                                # Logging level (debug, info, warn, error)
STATELESSVM_ENDPOINT="http://localhost:7548"    # Local StatelessVM service endpoint
AVALANCHE_RPC_URL="https://api.avax.network/ext/bc/C/rpc"  # Avalanche C-Chain RPC

# Wallet configuration
KEYSTORE_PATH="./keystore/wallet.json"         # Path to wallet keystore file
# KEYSTORE_PASSWORD must be set in the environment or securely provided
if [ -z "$KEYSTORE_PASSWORD" ]; then
    echo "ERROR: KEYSTORE_PASSWORD environment variable must be set"
    echo "For security, do not store this password in the script"
    exit 1
fi

# Chain and transaction settings
CHAIN_ID=43114                               # Avalanche C-Chain ID
CONFIG_DIR="./config"                         # Directory for config files

# Security settings
SECURITY_VERIFICATION_ENABLED=true           # Enable security verification
MAX_RISK_SCORE=50                           # Maximum acceptable risk score (0-100)

# Create necessary directories
mkdir -p logs
mkdir -p $CONFIG_DIR

# Check if keystore file exists
if [ ! -f "$KEYSTORE_PATH" ]; then
    echo "ERROR: Keystore file not found at $KEYSTORE_PATH"
    echo "Run 'node generate_wallet.js' to create a new wallet"
    exit 1
fi

# Create default transaction limits if they don't exist
if [ ! -f "$CONFIG_DIR/transaction_limits.json" ]; then
    echo "Creating default transaction limits configuration..."
    cat > "$CONFIG_DIR/transaction_limits.json" << EOF
{
    "max_transaction_amount_usd": 1000.0,
    "max_gas_price_gwei": 300.0,
    "max_daily_transactions": 100,
    "current_daily_transactions": 0
}
EOF
fi

# Executable path
EXECUTABLE="./target/release/examples/high_frequency_example"

# Start the trading agent with all necessary environment variables
echo "Starting high-frequency trading agent in production mode..."
RUST_LOG=$LOG_LEVEL \
STATELESSVM_URL=$STATELESSVM_ENDPOINT \
AVALANCHE_RPC_URL=$AVALANCHE_RPC_URL \
KEYSTORE_PATH=$KEYSTORE_PATH \
CHAIN_ID=$CHAIN_ID \
CONFIG_DIR=$CONFIG_DIR \
SECURITY_VERIFICATION_ENABLED=$SECURITY_VERIFICATION_ENABLED \
MAX_RISK_SCORE=$MAX_RISK_SCORE \
nohup $EXECUTABLE > logs/hft_agent_$(date +%Y%m%d_%H%M%S).log 2>&1 &

# Get the process ID
PID=$!
echo "High-frequency trading agent started with PID: $PID"
echo $PID > hft_agent.pid

echo "Agent logs are being written to logs/ directory"
echo "To stop the agent, run: kill \$(cat hft_agent.pid)"
