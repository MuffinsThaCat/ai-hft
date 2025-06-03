#!/bin/bash
# Script to reliably build and run security verification tests
# This resolves stalling issues by using a clean approach

# Stop on first error
set -e

# Colors for better output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Cleaning previous build artifacts...${NC}"
rm -rf target

echo -e "${YELLOW}Building with reduced parallelism...${NC}"
CARGO_BUILD_JOBS=2 RUST_BACKTRACE=1 cargo test --test security_verification_test --no-run

echo -e "${YELLOW}Running security verification tests...${NC}"
RUST_BACKTRACE=1 cargo test --test security_verification_test -- --nocapture

echo -e "${GREEN}Build and tests completed!${NC}"
