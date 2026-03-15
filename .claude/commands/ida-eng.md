---
description: IDA Pro headless binary analysis (idalib)
allowed-tools: Bash, Read, Write, Glob, Grep, Agent, TodoWrite
---

# IDA Headless Binary Analysis Skill

Follow this workflow when a binary analysis is requested.

## Entry Point
All IDA operations are performed exclusively via `python tools/ida_cli.py`.
Do not use MCP or other tools.

## Workflow

### 1. Environment Check (first time only)
```bash
python tools/ida_cli.py --check
python tools/ida_cli.py --init
```

### 2. Start Instance
```bash
python tools/ida_cli.py start <binary_path>
# To save IDB locally in the project:
python tools/ida_cli.py start <binary_path> --idb-dir <project_directory>
# Note the instance_id from the output
python tools/ida_cli.py wait <id> --timeout 300
```
- If an .i64 already exists, it is automatically reused (completes in seconds)
- Use `--idb-dir` to specify a per-project IDB storage path
- Use `--fresh` to ignore existing .i64 and reanalyze from scratch
- Use `--force` to allow duplicate instances of the same binary
- You can do other work while waiting for analysis

### 3. Initial Reconnaissance
Survey the binary in this order:
```bash
# Basic info
python tools/ida_cli.py -b <hint> status
python tools/ida_cli.py -b <hint> imagebase
python tools/ida_cli.py -b <hint> segments

# Data collection (use --out to save context window space)
python tools/ida_cli.py -b <hint> strings --count 50 --out /tmp/strings.txt
python tools/ida_cli.py -b <hint> imports --count 50 --out /tmp/imports.txt
python tools/ida_cli.py -b <hint> exports --out /tmp/exports.txt
python tools/ida_cli.py -b <hint> functions --filter <keyword> --out /tmp/funcs.txt

# Pagination for large function lists
python tools/ida_cli.py -b <hint> functions --offset 100 --count 100
```
- Use `status` first to check decompiler availability and function count
- Use `-b <hint>` to auto-select an instance by binary name substring

### 4. Deep Analysis
```bash
# Find function
python tools/ida_cli.py -b <hint> find_func <name> [--regex]

# Decompile
python tools/ida_cli.py -b <hint> decompile <addr|name> [--out /tmp/func.c]

# Batch decompile
python tools/ida_cli.py -b <hint> decompile_batch <addr1> <addr2> ... [--out /tmp/batch.c]

# Disassembly
python tools/ida_cli.py -b <hint> disasm <addr|name> --count 50

# Function details
python tools/ida_cli.py -b <hint> func_info <addr|name>

# Cross-references
python tools/ida_cli.py -b <hint> xrefs <addr> --direction both

# Read bytes
python tools/ida_cli.py -b <hint> bytes <addr> <size>

# Byte pattern search
python tools/ida_cli.py -b <hint> find_pattern "48 8B ? ? 00" --max 20

# Get comments
python tools/ida_cli.py -b <hint> comments <addr>

# List available RPC methods
python tools/ida_cli.py -b <hint> methods
```

### 5. Modification & Iterative Analysis
```bash
python tools/ida_cli.py -b <hint> rename <addr> <new_name>
python tools/ida_cli.py -b <hint> set_type <addr> "int __fastcall func(int a, int b)"
python tools/ida_cli.py -b <hint> comment <addr> "description text"
python tools/ida_cli.py -b <hint> save
```
> **Iterative analysis pattern**: After applying rename/set_type, decompile again —
> variable names and types will be reflected, producing much more readable code.
> Repeat this cycle for key functions.

### 6. Shutdown
```bash
python tools/ida_cli.py stop <id>
```

## Multi-Instance Workflow

When analyzing a main binary and its libraries simultaneously:
```bash
# Start both binaries
python tools/ida_cli.py start ./main_binary
python tools/ida_cli.py start ./libcrypto.so

# Use -b hint to target each instance
python tools/ida_cli.py -b main decompile 0x401000
python tools/ida_cli.py -b crypto decompile 0x12340

# Check instance list
python tools/ida_cli.py list
```

## Analysis Strategies

### String Tracing Pattern (most fundamental RE technique)
The fastest way to reach target code:
1. `strings --filter <keyword>` → find suspicious strings
2. `xrefs <string_addr>` → locate code that references the string
3. `decompile <xref_addr>` → analyze the calling function
4. Trace xrefs again if needed (callers of callers)

### Security Solution Analysis
1. Search for security keywords via strings/imports (root, jailbreak, ssl, cert, integrity, frida, xposed, magisk, etc.)
2. List related functions with find_func
3. Decompile key functions
4. Trace call relationships with xrefs
5. Record results with rename/set_type/comment → decompile again for cleaner view

### Firmware/IoT Analysis
1. `segments` to understand memory layout (ROM/RAM regions)
2. `strings` to find device identifiers, commands, protocol keywords
3. `find_func --regex "uart|spi|i2c|gpio"` → hardware interface functions
4. `exports` to identify public symbols → find main entry points
5. `find_pattern` to search for magic bytes / struct headers

### Vulnerability Research
1. Search imports for dangerous functions (memcpy, strcpy, sprintf, system, exec, etc.)
2. `xrefs` on each dangerous function → find call sites
3. `decompile` to analyze call context (buffer sizes, input validation)
4. `func_info` to check function size and arguments
5. `bytes` to verify stack buffer sizes and offsets

### Malware Analysis
1. `strings` to find C2 domains, IPs, registry keys, file paths
2. Check imports for networking (socket, connect, send), file manipulation, process injection APIs
3. `find_func --regex "crypt|encode|decode|xor"` → crypto/encoding routines
4. `decompile_batch` for bulk analysis of suspicious functions
5. `find_pattern` for hardcoded keys/IVs/XOR tables

### Handling Large Results
- Always save to file with `--out`, then read with Read tool
- Limit result scope with `--count`, `--filter`
- Use `--offset` for pagination (browsing large function lists)
- Use `--json` mode for structured data

## Error Handling
- Analysis failure: `python tools/ida_cli.py logs <id> --tail 20`
- Locked/corrupted .i64 (`open_database returned 2`): delete the .i64 file, then restart with `--fresh`
- Rebuild .i64: `python tools/ida_cli.py start <binary> --fresh`
- Instance list: `python tools/ida_cli.py list`
- Cleanup: `python tools/ida_cli.py cleanup`

## Decision Criteria: IDA vs Other Tools
- Java/Kotlin code → JADX
- Simple .so inspection → Ghidra
- Security solution core logic, unclear Ghidra results → **Use IDA CLI**
- Multi-architecture (ARM/MIPS/PPC/V850/ARC) → **Use IDA CLI**
- Firmware/IoT binaries → **Use IDA CLI**

## User Argument: $ARGUMENTS
When invoked as `/ida-eng <binary_path>`, immediately start analysis on the specified binary.
If no binary path is provided, ask the user what to analyze.
