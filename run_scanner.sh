#!/bin/bash
# run_scanner.sh - Run Nidhogg scanner in Docker container with secure permissions

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
    echo -e "  -t, --timeout SECONDS  Set timeout in seconds (default: 30)"
    echo -e "  -o, --output DIR       Set output directory (default: ./results)"
    echo
    echo -e "${BLUE}Example:${NC}"
    echo -e "  $0 --verbose suspicious_package.tar.gz"
    echo -e "  $0 --output ./my-results malicious_pkg"
}

# Default options
VERBOSE=""
COVERAGE=""
EXTRACT="--extract"
INPUT_DIR="./nidhogg-operating-packages"
TEMP_OUTPUT_DIR="./nidhogg-operating-results"
OUTPUT_DIR="./results" # Default final destination for the report
TIMEOUT=30
OUTPUT_PATH=""

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
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_PATH="$2"
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

# Clean up packages directory
echo -e "${YELLOW}Cleaning packages directory...${NC}"
if [ -d "$INPUT_DIR" ]; then
    # Remove all files in the directory
    rm -rf "${INPUT_DIR:?}"/*
fi

# Create input directory if it doesn't exist
if [ ! -d "$INPUT_DIR" ]; then
    echo -e "${YELLOW}Creating input directory...${NC}"
    mkdir -p "$INPUT_DIR"
fi

# Ensure input directory has correct permissions
echo -e "${YELLOW}Setting input directory permissions...${NC}"
chmod 755 "$INPUT_DIR" || true
chown $(id -u):$(id -g) "$INPUT_DIR" || true

# Handle custom output path if specified
if [ -n "$OUTPUT_PATH" ]; then
    OUTPUT_DIR="$OUTPUT_PATH"
    echo -e "${YELLOW}Will copy final results to: $OUTPUT_DIR${NC}"
fi

# Clean up temporary results directory
echo -e "${YELLOW}Cleaning temporary results directory...${NC}"
if [ -d "$TEMP_OUTPUT_DIR" ]; then
    # Remove all files in the directory
    rm -rf "${TEMP_OUTPUT_DIR:?}"/*
fi

# Create temporary output directory if it doesn't exist
if [ ! -d "$TEMP_OUTPUT_DIR" ]; then
    echo -e "${YELLOW}Creating temporary output directory...${NC}"
    mkdir -p "$TEMP_OUTPUT_DIR"
fi

# Ensure temporary output directory has correct permissions
echo -e "${YELLOW}Setting temporary output directory permissions...${NC}"
chmod 755 "$TEMP_OUTPUT_DIR" || true
chown $(id -u):$(id -g) "$TEMP_OUTPUT_DIR" || true

# Create final output directory if it doesn't exist
if [ ! -d "$OUTPUT_DIR" ]; then
    echo -e "${YELLOW}Creating final output directory...${NC}"
    mkdir -p "$OUTPUT_DIR"
fi

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
    
    # Set restrictive permissions on the copied package
    if [ -d "$DEST_PATH" ]; then
        find "$DEST_PATH" -type d -exec chmod 755 {} \;
        find "$DEST_PATH" -type f -exec chmod 644 {} \;
    else
        chmod 644 "$DEST_PATH"
    fi
    
    echo -e "${GREEN}Package copied to: $DEST_PATH with secure permissions${NC}"
fi

# Temporarily make input directory readable by Docker
echo -e "${YELLOW}Temporarily adjusting permissions for Docker...${NC}"
chmod 755 "$INPUT_DIR"
chmod -R 755 "$DEST_PATH"

# Ensure temporary output directory is writable by Docker
chmod 777 "$TEMP_OUTPUT_DIR"

# Clean up any previous result in the final output directory
FINAL_REPORT_PATH="$OUTPUT_DIR/$PACKAGE_NAME-results.json"
if [ -f "$FINAL_REPORT_PATH" ]; then
    echo -e "${YELLOW}Removing previous report file: $FINAL_REPORT_PATH${NC}"
    rm -f "$FINAL_REPORT_PATH"
fi

echo -e "${YELLOW}Starting Nidhogg analysis of: $PACKAGE_NAME${NC}"
echo -e "${YELLOW}This will run in an isolated Docker container with no network access${NC}"
echo -e "${YELLOW}Timeout set to $TIMEOUT seconds${NC}"

# Create a temporary docker-compose override file
echo "Creating temporary docker-compose override file..."
cat > docker-compose.override.yml << EOF
version: '3'

services:
  nidhogg-scanner:
    volumes:
      - ${INPUT_DIR}:/data/input
      - ${TEMP_OUTPUT_DIR}:/data/output
    command: $VERBOSE $COVERAGE $EXTRACT /data/input/$PACKAGE_NAME --output-file=results.json
    user: "$(id -u):$(id -g)"
EOF

# Run the Docker container with timeout
echo -e "${BLUE}Running docker-compose with override file...${NC}"
export PACKAGE_FILE="$PACKAGE_NAME"
timeout --foreground "$TIMEOUT" docker-compose run --rm nidhogg-scanner
EXIT_CODE=$?

# Clean up the temporary override file
rm -f docker-compose.override.yml

# Process exit code
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}Command completed successfully!${NC}"
elif [ $EXIT_CODE -eq 124 ]; then
    echo -e "${RED}Analysis timed out after $TIMEOUT seconds!${NC}"
    echo -e "${YELLOW}This could indicate a hang or infinite loop in the malicious code.${NC}"
else
    echo -e "${RED}Analysis failed with exit code: $EXIT_CODE${NC}"
fi

echo -e "${BLUE}Command finished!${NC}"

# Reset secure permissions after Docker run
echo -e "${YELLOW}Resetting secure permissions...${NC}"
chmod 700 "$INPUT_DIR"
find "$INPUT_DIR" -type d -exec chmod 700 {} \;
find "$INPUT_DIR" -type f -exec chmod 600 {} \;

# Define the source and destination report paths
TEMP_REPORT_PATH="$TEMP_OUTPUT_DIR/results.json"
FINAL_REPORT_PATH="$OUTPUT_DIR/$PACKAGE_NAME-results.json"

# Check if report was generated
if [ -f "$TEMP_REPORT_PATH" ]; then
    echo -e "${GREEN}Analysis complete!${NC}"
    
    # Copy the report to the final destination
    echo -e "${YELLOW}Copying report to final destination...${NC}"
    cp "$TEMP_REPORT_PATH" "$FINAL_REPORT_PATH"
    
    # Set secure permissions on the final report
    chmod 644 "$FINAL_REPORT_PATH"
    chown $(id -u):$(id -g) "$FINAL_REPORT_PATH"
    
    echo -e "${GREEN}Report saved to: $FINAL_REPORT_PATH${NC}"
    
    # Show a summary of the report
    echo -e "${BLUE}Summary:${NC}"
    
    # Extract key information from the JSON report
    if command -v jq &> /dev/null; then
        RISK_LEVEL=$(jq -r '.risk_level' "$FINAL_REPORT_PATH")
        # Use the specific suspicious_functions_count field or count the array length
        SUSPICIOUS_COUNT=$(jq '.suspicious_functions_count // (.suspicious_functions | length)' "$FINAL_REPORT_PATH")
        
        echo -e "Risk level: ${YELLOW}$RISK_LEVEL${NC}"
        echo -e "Suspicious functions: ${YELLOW}$SUSPICIOUS_COUNT${NC}"
    else
        echo -e "${YELLOW}Install jq for a better summary view${NC}"
        echo -e "See the full report at: $FINAL_REPORT_PATH"
        # Simple grep fallback for systems without jq
        echo -e "Risk level: $(grep -o '"risk_level":[^,]*' "$FINAL_REPORT_PATH" | cut -d ':' -f2 | tr -d '"')"
        echo -e "Suspicious functions: $(grep -o '"suspicious_functions_count":[^,]*' "$FINAL_REPORT_PATH" | cut -d ':' -f2 || echo "unknown")"
    fi
else
    echo -e "${RED}No report was generated!${NC}"
    # Check if there are any JSON files in the temp output directory
    JSON_FILES=$(find "$TEMP_OUTPUT_DIR" -name "*.json" | head -1)
    if [ -n "$JSON_FILES" ]; then
        echo -e "${YELLOW}Found alternative report file: $(basename "$JSON_FILES")${NC}"
        cp "$JSON_FILES" "$FINAL_REPORT_PATH"
        echo -e "${GREEN}Copied alternative report to: $FINAL_REPORT_PATH${NC}"
    fi
fi

echo -e "${GREEN}Done! Cleaning up...${NC}"

# Final cleanup of input directory
echo -e "${YELLOW}Final cleanup of input directory...${NC}"
rm -rf "${INPUT_DIR:?}"/*

# Final cleanup of temporary output directory
echo -e "${YELLOW}Final cleanup of temporary output directory...${NC}"
rm -rf "${TEMP_OUTPUT_DIR:?}"/*

# Make sure we're leaving the output directory with correct permissions
chmod 755 "$OUTPUT_DIR" || true

echo -e "${GREEN}Analysis complete. Final report is in: $FINAL_REPORT_PATH${NC}"