#!/bin/bash
# run_scanner.sh - Run Nidhogg scanner in Docker container

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_usage() {
    echo -e "${BLUE}Usage:${NC}"
    echo -e "  $0 [options] <package-file-or-directory>"
    echo
    echo -e "${BLUE}Options:${NC}"
    echo -e "  -h, --help             Show this help message"
    echo -e "  -v, --verbose          Enable verbose output"
    echo -e "  -c, --coverage         Enable enhanced code coverage analysis"
    echo -e "  -n, --no-extract       Don't extract the package before scanning"
    echo -e "  -o, --output DIR       Set output directory (default: ./results)"
    echo -e "  -i, --input DIR        Set input directory (default: ./packages)"
    echo -e "  -t, --timeout SECONDS  Set timeout in seconds (default: 30)"
    echo
    echo -e "${BLUE}Example:${NC}"
    echo -e "  $0 --verbose suspicious_package.tar.gz"
    echo -e "  $0 --input /tmp/downloads --output /tmp/reports malicious_pkg"
}

# Default options
VERBOSE=""
COVERAGE=""
EXTRACT="--extract"
INPUT_DIR="./packages"
OUTPUT_DIR="./results"
TIMEOUT=30

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE="--verbose"
            shift
            ;;
        -c|--coverage)
            COVERAGE="--coverage"
            shift
            ;;
        -n|--no-extract)
            EXTRACT=""
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -i|--input)
            INPUT_DIR="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        *)
            PACKAGE_FILE="$1"
            shift
            ;;
    esac
done

# Check if package file was provided
if [ -z "$PACKAGE_FILE" ]; then
    echo -e "${RED}Error: Package file or directory is required${NC}"
    print_usage
    exit 1
fi

# Create directories if they don't exist
mkdir -p "$INPUT_DIR" "$OUTPUT_DIR"

# If package path is not inside INPUT_DIR, copy it there
PACKAGE_PATH=$(realpath "$PACKAGE_FILE")
PACKAGE_NAME=$(basename "$PACKAGE_PATH")
DEST_PATH="$INPUT_DIR/$PACKAGE_NAME"

if [[ "$PACKAGE_PATH" != "$DEST_PATH"* ]]; then
    echo -e "${YELLOW}Copying package to input directory...${NC}"
    
    if [ -d "$PACKAGE_PATH" ]; then
        # Copy directory
        cp -r "$PACKAGE_PATH" "$DEST_PATH"
    else
        # Copy file
        cp "$PACKAGE_PATH" "$DEST_PATH"
    fi
    
    echo -e "${GREEN}Package copied to: $DEST_PATH${NC}"
fi

echo -e "${YELLOW}Starting Nidhogg analysis of: $PACKAGE_NAME${NC}"
echo -e "${YELLOW}This will run in an isolated Docker container with no network access${NC}"
echo -e "${YELLOW}Timeout set to $TIMEOUT seconds${NC}"


# Run the Docker container with timeout
DOCKER_CMD="PACKAGE_FILE=$PACKAGE_NAME docker-compose run --rm nidhogg-scanner $VERBOSE $COVERAGE $EXTRACT /data/input/$PACKAGE_NAME"
echo "${BLUE} Updating docker image!"
docker-compose build

echo -e "${BLUE}Running command: $DOCKER_CMD${NC}"
timeout "$TIMEOUT" bash -c "$DOCKER_CMD" || {
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 124 ]; then
        echo -e "${RED}Analysis timed out after $TIMEOUT seconds!${NC}"
        echo -e "${YELLOW}This could indicate a hang or infinite loop in the malicious code.${NC}"
    else
        echo -e "${RED}Analysis failed with exit code: $EXIT_CODE${NC}"
    fi
}
echo -e "Comamnd finished!"

# Check if report was generated
REPORT_PATH="$OUTPUT_DIR/${PACKAGE_NAME}_report.json"
if [ -f "$REPORT_PATH" ]; then
    echo -e "${GREEN}Analysis complete!${NC}"
    echo -e "${GREEN}Report saved to: $REPORT_PATH${NC}"
    
    # Show a summary of the report
    echo -e "${BLUE}Summary:${NC}"
    
    # Extract some key information from the JSON report
    if command -v jq &> /dev/null; then
        RISK_LEVEL=$(jq -r '.risk_level' "$REPORT_PATH")
        SUSPICIOUS_COUNT=$(jq '.suspicious_functions | length' "$REPORT_PATH")
        TAINTED_VARS=$(jq '.taint_analysis.total_tainted_vars' "$REPORT_PATH")
        EXFIL_ATTEMPTS=$(jq '.taint_analysis.total_exfiltration_attempts' "$REPORT_PATH")
        
        echo -e "Risk level: ${YELLOW}$RISK_LEVEL${NC}"
        echo -e "Suspicious functions: ${YELLOW}$SUSPICIOUS_COUNT${NC}"
        echo -e "Tainted variables: ${YELLOW}$TAINTED_VARS${NC}"
        echo -e "Exfiltration attempts: ${YELLOW}$EXFIL_ATTEMPTS${NC}"
    else
        echo -e "${YELLOW}Install jq for a better summary view${NC}"
        echo -e "See the full report at: $REPORT_PATH"
    fi
else
    echo -e "${RED}No report was generated!${NC}"
fi

echo -e "${GREEN}Done!${NC}"