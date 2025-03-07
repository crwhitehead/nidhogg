#!/bin/bash
# docker-entrypoint.sh - Simple entrypoint script for Nidhogg container
# This script just executes scan_package.py with the provided arguments

set -e

echo "Starting Nidhogg scanner with arguments: $@"

# Check if we have at least one argument (the target path)
if [ "$#" -lt 1 ]; then
    echo "Error: Missing target path. Please specify a file or directory to analyze."
    echo "Usage: $0 path/to/target [options]"
    exit 1
fi

# Check if the target exists
target_path=$(echo "$@" | grep -o '/data/input/[^ ]*')
if [[ -n "$target_path" ]] && [[ ! -e "$target_path" ]]; then
    echo "Error: Target path does not exist: $target_path"
    exit 1
fi

# Run the scan_package.py script with all arguments passed to this script
exec timeout 60 python /app/scan_package.py "$@"

exit