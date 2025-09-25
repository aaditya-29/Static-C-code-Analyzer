# C Security Static Analyzer

A static code analyzer for detecting insecure C programming practices. This tool scans C source files for common security vulnerabilities such as buffer overflows, unsafe function usage, format string vulnerabilities, and command injection risks.

## Features

- Detects usage of dangerous C functions (`gets`, `strcpy`, `strcat`, `sprintf`, `system`, `exec*`, etc.)
- Identifies unsafe `scanf` usage without width specifiers
- Warns about potential format string vulnerabilities
- Supports both regex-based and parser-based analysis (experimental)
- Generates detailed security reports with severity levels
- Can analyze single files or entire directories (recursively)
- Command-line interface with filtering and output options

## Project Structure

```
c_security_analyzer/
    analyzer.py      # Security analysis logic
    lexer.py         # C language lexer (PLY)
    main.py          # Command-line interface
    parser.py        # C language parser (PLY)
    test_samples/    # Example C files (safe and vulnerable)
    requirements.txt # Python dependencies
    README.md        # Project documentation
Commands to run.txt  # Example usage commands
```

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/aaditya-29/Static-C-code-Analyzer.git
   ```

2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
   > Requires Python 3.7+ and [PLY](https://www.dabeaz.com/ply/).

## Usage

Run the analyzer from the `c_security_analyzer` directory:

### Analyze a single file

```sh
python main.py -f test_samples/vulnerable_sample.c
```

### Analyze a directory recursively

```sh
python main.py -d ./test_samples -r
```

### Save report to a file

```sh
python main.py -f test_samples/vulnerable_sample.c -o security_report.txt
```

### Filter by severity level

```sh
python main.py -f test_samples/vulnerable_sample.c --severity high
```

### Use experimental parser mode

```sh
python main.py -f test_samples/safe_sample.c --parser
```

## Output

The analyzer prints a detailed report, including:

- Issue type and severity
- Line number
- Description and recommendation
- Function context (if available)

Example output:
```
================================================================================
SECURITY ANALYSIS REPORT: vulnerable_sample.c
================================================================================
Total Issues Found: 7
Critical: 3, High: 3, Medium: 1, Low: 0
--------------------------------------------------------------------------------
[CRITICAL] Line 21
  Issue: Use of system() can lead to command injection
  Recommendation: Use execve() family functions with proper input validation
  Function: vulnerable_function

...
================================================================================
```

## Test Samples

- [test_samples/safe_sample.c](test_samples/safe_sample.c): Example of secure C code.
- [test_samples/vulnerable_sample.c](test_samples/vulnerable_sample.c): Example with multiple vulnerabilities.

