#!/bin/bash

# Trading Executor Test Runner
# This script verifies connectivity to the StatelessVM service and executes a test trade

echo "=== Trading Executor Connectivity Test ==="
echo "This script will verify that the trading executor can connect to the StatelessVM service"
echo ""

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
    echo "StatelessVM service is already running on port 7548"
fi

# Build the trading executor test
echo "Building trading executor test..."
cargo build --example trading_executor_test

# Run the test with environment variables set
echo ""
echo "Running trading executor test..."
echo "----------------------------------------"
RUST_LOG=debug STATELESSVM_URL=http://localhost:7548 ./target/debug/examples/trading_executor_test

echo ""
echo "=== Test Complete ==="
