# NullSec RootCheck

<div align="center">

```
██████╗  ██████╗  ██████╗ ████████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██████╔╝██║   ██║██║   ██║   ██║   ██║     ███████║█████╗  ██║     █████╔╝ 
██╔══██╗██║   ██║██║   ██║   ██║   ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
██║  ██║╚██████╔╝╚██████╔╝   ██║   ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
```

**Hardened Rootkit Detection System in D**

[![D Language](https://img.shields.io/badge/D-B03931?style=for-the-badge&logo=d&logoColor=white)](https://dlang.org/)
[![Security](https://img.shields.io/badge/Security-Maximum-red?style=for-the-badge)](https://github.com/bad-antics)
[![NullSec](https://img.shields.io/badge/NullSec-Framework-purple?style=for-the-badge)](https://github.com/bad-antics)

</div>

## Security Hardening Features

### Memory Safety (@safe by default)
- `@safe` annotations throughout the codebase
- `@nogc` operations where possible for predictability
- SecureBuffer with automatic memory zeroing on destruction
- RAII resource management via scoped allocations

### Type System Safety
- **ValidatedPath**: Smart constructor preventing path traversal attacks
- **ValidatedPID**: Bounded PID validation (1 to 4194304)
- Immutable data structures for thread safety
- Compile-time validation of security constants

### Bounded Operations
- MAX_PATH_LENGTH = 4096
- MAX_PROCESS_COUNT = 65536
- MAX_FILE_SIZE = 100MB
- MAX_HIDDEN_THRESHOLD = 100

### Defense-in-Depth
- Input validation using D contracts (`in`, `out`, `invariant`)
- Rate limiting for resource protection
- Overflow checking with -boundscheck=on
- DIP1000 scope safety enabled

## Detection Capabilities

| Category | Description |
|----------|-------------|
| Hidden Processes | Detects processes hidden from /proc enumeration |
| Rootkit Files | Checks for known rootkit file signatures |
| Kernel Modules | Analyzes loaded modules for suspicious patterns |
| Network Backdoors | Identifies connections on known backdoor ports |
| Binary Analysis | Entropy analysis and suspicious string detection |
| LD_PRELOAD Hooks | Detects library injection attempts |

## Build

```bash
# Using dub
dub build --build=release

# Using dmd directly
dmd -O -boundscheck=on -of=rootcheck rootcheck.d

# Run tests
dub test
```

## Usage

```bash
# Run as root for full access
sudo ./rootcheck

# Results are color-coded by severity:
# - RED: Critical (severity 8-10)
# - YELLOW: High (severity 6-7)
# - CYAN: Medium (severity 4-5)
# - WHITE: Low (severity 1-3)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NullSec RootCheck                        │
├─────────────────────────────────────────────────────────────┤
│  Input Validation Layer                                     │
│  ├── ValidatedPath (path traversal protection)             │
│  ├── ValidatedPID (range checking)                         │
│  └── SecureBuffer (memory safety)                          │
├─────────────────────────────────────────────────────────────┤
│  Analysis Modules                                           │
│  ├── Process Analysis (hidden process detection)           │
│  ├── Filesystem Analysis (rootkit file detection)          │
│  ├── Kernel Analysis (suspicious module detection)         │
│  ├── Network Analysis (backdoor port detection)            │
│  └── Binary Analysis (entropy/string analysis)             │
├─────────────────────────────────────────────────────────────┤
│  Result Accumulator (bounded growth, thread-safe)          │
└─────────────────────────────────────────────────────────────┘
```

## License

NullSec Proprietary - Part of the NullSec Security Framework
