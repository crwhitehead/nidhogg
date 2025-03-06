# Nidhogg: Advanced Python Security Analysis Tool

## Project Overview

Nidhogg is a comprehensive Python security analysis tool that combines multiple security analysis techniques:

1. **Suspicious Function Detection**: Identifies and neutralizes potentially dangerous function calls like `eval()`, `exec()`, and `system()`.
2. **Variable Tainting**: Tracks the flow of sensitive information through code to detect data exfiltration.
3. **Enhanced Code Coverage**: Uses CrossHair to achieve high code coverage, exploring paths that normal execution wouldn't reach.

## Project Structure

```
nidhogg/
├── nidhogg/
│   ├── main.py                   # Command-line entry point
│   ├── core/                     # Core functionality
│   │   ├── module_loader.py      # Module loading and execution
│   │   ├── safe_replacements.py  # Safe function replacements
│   │   └── simulator.py          # I/O and environment simulation
│   ├── analysis/                 # Analysis components
│   │   ├── analyzer.py           # Main analysis orchestration
│   │   ├── coverage.py           # CrossHair configuration and coverage
│   │   ├── suspicious.py         # Suspicious function detection
│   │   └── taint.py              # Taint analysis and tracking
│   └── utils/                    # Utility functions
│       └── debug.py              # Debugging utilities
└── examples/                     # Example files for testing
    ├── data_exfiltration.py
    └── code_execution.py
```

## Key Components

### 1. Suspicious Function Detection

The `SuspiciousFunctionTracer` class monitors for calls to dangerous functions and replaces them with safe alternatives. This prevents actual execution of potentially harmful code while allowing analysis to continue.

**Key features**:
- Detection of 15+ dangerous function types
- Risk categorization (high/medium/low)
- Detailed reporting of suspicious calls
- Safe replacement functions for neutralized calls

### 2. Variable Tainting

The `TaintTrackingTracer` and `TaintTracker` classes implement sophisticated taint analysis:

**Key features**:
- Multiple taint types (file data, credentials, personal info, etc.)
- Propagation tracking across variable assignments
- Sensitive pattern detection in string literals
- Detection of exfiltration attempts via network, files, and commands

### 3. Enhanced Code Coverage

Integration with CrossHair for comprehensive code path exploration:

**Key features**:
- Symbolic execution to explore multiple execution paths
- Boundary value testing to trigger edge cases
- Exception handler targeting
- Configurable analysis options

### 4. Safe Execution Environment

The tool creates a sandboxed environment for analyzing potentially malicious code:

**Key features**:
- Simulated I/O operations
- Safe replacements for dangerous functions
- Controlled module loading
- Exception handling for robust analysis

## Usage

```bash
# Basic analysis
nidhogg path/to/file.py

# Verbose output
nidhogg -v path/to/directory

# Enable maximum code coverage
nidhogg --coverage path/to/file.py

# Enable maximum code coverage
nidhogg --coverage path/to/file.py
```

## Example Outputs

For suspicious function detection:
```
=== SUSPICIOUS FUNCTIONS ===
examples/code_execution.py:15: high risk: Dynamic code execution - Call to builtins.exec
examples/code_execution.py:25: high risk: Unsafe deserialization - Call to pickle.loads
examples/code_execution.py:32: medium risk: Network access - Call to urllib.request.urlopen
examples/code_execution.py:36: high risk: Dynamic code execution - Call to builtins.exec
```

For taint analysis:
```
=== DATA FLOW ANALYSIS ===
Found 5 tainted variables
Detected 3 potential data exfiltration attempts
  - examples/data_exfiltration.py:42: Potential exfiltration via requests.post
    Keyword payload: cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo=
    Tainted with: FILE_DATA from builtins.open (line 9, DERIVED)
```

## Benefits Over Original Implementation

1. **Modularity**: Code is now organized into logical components for better maintainability
2. **Extended Functionality**: Added multiple taint types and exfiltration vectors
3. **Improved Coverage**: Enhanced code path exploration with CrossHair
4. **Better User Experience**: Clearer reporting and command-line options
5. **Organized Project Structure**: Follows Python package conventions