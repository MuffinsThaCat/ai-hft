#!/bin/bash

# StatelessVM Connection Test Script
# This script builds and runs a basic test to verify StatelessVM connectivity

echo "=== StatelessVM Connection Test ==="
echo "This script will verify connectivity to the StatelessVM service"
echo ""

# Make sure the dependencies are installed
if ! grep -q "reqwest" Cargo.toml; then
    echo "Adding reqwest dependency to Cargo.toml..."
    echo "reqwest = { version = \"0.11\", features = [\"json\"] }" >> Cargo.toml
fi

# Build the connection test
echo "Building StatelessVM connection test..."
cargo build --example statelessvm_connection_test

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

# Run the connection test
echo ""
echo "=== Running StatelessVM Connection Test ==="
RUST_LOG=info STATELESSVM_URL=http://localhost:7548 ./target/debug/examples/statelessvm_connection_test

echo ""
echo "=== Test Complete ==="
