# Nidhogg

Nidhogg is a Python security analysis tool that combines suspicious function detection with taint analysis to identify potential security vulnerabilities in Python code.

## Features

- Detects and safely replaces dangerous functions like `eval()`, `exec()`, and `os.system()`
- Tracks the flow of sensitive data through variable tainting
- Identifies potential data exfiltration attempts
- Achieves high code coverage using CrossHair's symbolic execution engine
- Simulates I/O and environment to safely execute potentially malicious code

## Installation

```bash
pip install nidhogg
```

## Usage

```bash
# Basic usage
nidhogg path/to/file.py

# Analyze a directory
nidhogg path/to/directory

# Enable verbose output
nidhogg -v path/to/file.py

# Only perform taint analysis
nidhogg --taint-only path/to/file.py
```

## Taint Analysis

Nidhogg tracks the flow of sensitive information through your code:

- **Source Tainting**: Functions that access sensitive data (files, environment variables, user input, etc.)
- **Propagation**: Tracking how tainted data flows through variables
- **Sink Detection**: Identifying when tainted data reaches potentially dangerous functions (network, file operations, etc.)

## License

MIT