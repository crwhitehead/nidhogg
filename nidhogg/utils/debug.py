import sys

# Global debug flag
_DEBUG = False

def set_debug(enable=True):
    """Enable or disable debug output"""
    global _DEBUG
    _DEBUG = enable

def debug(message):
    """Print debug message if debug is enabled"""
    if _DEBUG:
        print(f"[DEBUG] {message}", file=sys.stderr)