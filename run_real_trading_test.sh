#!/bin/bash

# Simplified StatelessVM Test Script
# This script builds and runs a basic test to verify StatelessVM connectivity

echo "=== StatelessVM Connection Test ==="
echo "This will execute a basic test to verify StatelessVM connectivity"
echo ""

# Create logs directory
mkdir -p logs

# Add reqwest and hex dependencies if needed
REQWEST_DEP=$(grep "reqwest" Cargo.toml || echo "")
if [ -z "$REQWEST_DEP" ]; then
    echo "Adding reqwest dependency to Cargo.toml..."
    echo "reqwest = { version = \"0.11\", features = [\"json\"] }" >> Cargo.toml
fi

HEX_DEP=$(grep "hex" Cargo.toml || echo "")
if [ -z "$HEX_DEP" ]; then
    echo "Adding hex dependency to Cargo.toml..."
    echo "hex = \"0.4\"" >> Cargo.toml
fi

# Build the real trading test
echo "Building StatelessVM test..."
cargo build --release --example real_trading_test

# Make sure the StatelessVM service is running
if ! curl -s http://localhost:7548/health > /dev/null; then
    echo "StatelessVM service is not running. Starting it..."
    cd ../stateless-vm && ./start_statelessvm_service.sh
    cd - > /dev/null
    
    # Wait for service to start
    echo "Waiting for StatelessVM service to start..."
    sleep 5
    
    if ! curl -s http://localhost:7548/health > /dev/null; then
        echo "ERROR: Failed to start StatelessVM service"
        exit 1
    fi
    
    echo "StatelessVM service started successfully"
else
    echo "StatelessVM service is already running"
fi

# Run the StatelessVM test
echo ""
echo "=== Running StatelessVM Connection Test ==="
echo "This will verify basic connectivity to the StatelessVM service."
echo ""

RUST_LOG=info \
STATELESSVM_URL=http://localhost:7548 \
AVALANCHE_RPC_URL=https://api.avax.network/ext/bc/C/rpc \
./target/release/examples/real_trading_test

echo ""
echo "=== Test Complete ==="
echo "Check the output above for results"
