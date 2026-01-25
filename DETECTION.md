# Rootkit Detection Guide

## Overview
Techniques for detecting rootkits and kernel-level malware.

## Rootkit Types

### User-Mode Rootkits
- Library injection
- IAT hooking
- Inline hooking
- Process hiding

### Kernel-Mode Rootkits
- DKOM (Direct Kernel Object Manipulation)
- SSDT hooking
- IDT hooking
- Filter drivers

### Bootkits
- MBR infection
- VBR modification
- UEFI implants
- Boot process hijacking

## Detection Methods

### Cross-View Detection
- API vs raw comparison
- File system discrepancies
- Registry comparison
- Process listing differences

### Memory Analysis
- Hidden processes
- Suspicious drivers
- Hooked functions
- Code injection

### Integrity Checking
- System file hashes
- Kernel checksum
- Driver signatures
- Boot sector verification

## Analysis Tools

### Live System
- GMER
- RootkitRevealer
- chkrootkit
- rkhunter

### Memory Forensics
- Volatility plugins
- Rekall modules
- WinDbg analysis

## Indicators
- Hidden files
- Suspicious network connections
- Kernel modifications
- Process anomalies

## Legal Notice
For authorized security analysis.
