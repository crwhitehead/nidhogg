# nidhogg/main.py
import sys
import argparse
from pathlib import Path

from nidhogg.analysis.analyzer import detect_malware
from nidhogg.utils.debug import set_debug

def main():
    """Main entry point for the Nidhogg security analyzer"""
    parser = argparse.ArgumentParser(description="Nidhogg - Python security analyzer with taint tracking")
    parser.add_argument("targets", nargs="+", help="Files or directories to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--coverage", action="store_true", help="Optimize for maximum code coverage")
    
    args = parser.parse_args()
    
    if args.verbose:
        set_debug(True)
    
    sys.exit(detect_malware(args.targets, args.verbose, args.coverage, enable_taint=False))

if __name__ == "__main__":
    main()
