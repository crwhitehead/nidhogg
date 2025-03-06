#!/bin/bash
# debug_docker.sh - Run a Docker container for debugging Nidhogg

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Building debug container...${NC}"
docker build -f Dockerfile.debug -t nidhogg-debug .

echo -e "${YELLOW}Starting debug container...${NC}"
echo -e "${YELLOW}This will give you a shell inside the container for debugging${NC}"

# Run the Docker container with the debug image
PACKAGE_DIR="$1"
if [ -z "$PACKAGE_DIR" ]; then
    PACKAGE_DIR="evasive_samples"
    echo -e "${YELLOW}No package specified, using default: $PACKAGE_DIR${NC}"
fi

docker run --rm -it \
    -v "$(pwd)/packages:/data/input" \
    -v "$(pwd)/results:/data/output" \
    -e PACKAGE_FILE="$PACKAGE_DIR" \
    nidhogg-debug

# The container will give you a shell prompt where you can run and debug
# the scanner manually