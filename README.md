# Nidhogg: Python Bytecode Analysis and Malware Detection Tool

Nidhogg is an advanced bytecode analysis tool that examines Python code execution at the bytecode level to detect suspicious or malicious patterns. Named after the dragon from Norse mythology that gnaws at the roots of Yggdrasil, Nidhogg digs deep into your Python code to find potential security issues.

## Features

- **Bytecode-level Analysis**: Examines Python code at the bytecode instruction level
- **Multiple Analyzers**:
  - **Opcode Analyzer**: Detects suspicious opcode patterns (eval/exec, obfuscation, etc.)
  - **Call Analyzer**: Monitors function calls for suspicious behavior (system commands, file operations, etc.)
  - **Import Analyzer**: Tracks module imports to detect malicious patterns
  - **Behavioral Analyzer**: Identifies complex malicious behavior patterns
- **Configurable Sensitivity**: Adjust detection sensitivity to reduce false positives
- **Flexible Reporting**: Output results as console text, JSON, or HTML reports
- **Extensible Architecture**: Easy to add new analyzers and detection rules

## Installation

```bash
pip install nidhogg
```

## Usage

Basic usage:

```bash
nidhogg example.py
```

Run a specific function in the file:

```bash
nidhogg example.py --function main arg1 arg2
```

Adjust sensitivity and output:

```bash
nidhogg example.py --sensitivity high --format html --output report.html
```

## How It Works

Nidhogg uses CrossHair's tracing capabilities to monitor bytecode execution and detect suspicious patterns. Each analyzer focuses on different aspects of code behavior:

1. **Opcode Analyzer**: Monitors bytecode instructions to detect patterns like `eval`/`exec` usage, code object construction, and suspicious string manipulation.

2. **Call Analyzer**: Tracks function calls to detect system command execution, file operations, network connections, and other potentially malicious activities.

3. **Import Analyzer**: Monitors module imports to detect suspicious modules or combinations of modules that may indicate malicious intent.

4. **Behavioral Analyzer**: Looks for higher-level patterns across multiple events to detect complex malicious behaviors.

## Example

When analyzing a file with suspicious code:

```python
# suspicious.py
import base64, os
encoded_cmd = "bHMgLWxh"  # Base64 for "ls -la"
os.system(base64.b64decode(encoded_cmd).decode())
```

Nidhogg can detect this:

```bash
$ nidhogg suspicious.py

===============================================================================
 NIDHOGG ANALYSIS REPORT: suspicious.py
===============================================================================

--------------------------------------------------------------------------------
[HIGH] Use of potentially dangerous function 'system'
Location: suspicious.py:3
Rule ID: CALL-COMMAND_EXECUTION

--------------------------------------------------------------------------------
[MEDIUM] Potential obfuscated/encoded data detected
Location: suspicious.py:2
Rule ID: OPCODE-001

--------------------------------------------------------------------------------
[MEDIUM] Suspicious module import: base64
Location: suspicious.py:1
Rule ID: IMPORT-OBFUSCATION

===============================================================================
 SUMMARY
===============================================================================
Total findings: 3
  HIGH: 1
  MEDIUM: 2

Analysis duration: 0.52 seconds
===============================================================================
```

## Advanced Configuration

Nidhogg can be configured with a JSON configuration file:

```bash
nidhogg example.py --config config.json
```

Example configuration:

```json
{
  "sensitivity": "medium",
  "trace_stdlib": false,
  "enabled_analyzers": ["opcode", "call", "import", "behavioral"],
  "report_format": "console",
  "output_file": null
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.