#!/bin/bash
# docker-entrypoint.sh - Simple entrypoint script for Nidhogg container
# This script just executes scan_package.py with the provided arguments

set -e

echo "Starting Nidhogg scanner with arguments: $@"

# Run the scan_package.py script with all arguments passed to this script
exec python /app/scan_package.py "$@"

exit