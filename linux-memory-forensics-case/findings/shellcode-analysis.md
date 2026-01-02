# In-Memory Shellcode Analysis Report

**Case Identifier:** CASE_20251228_0001  
**Examination Date:** 2025-12-30  
**Analyst:** Sai (DFIR Analyst)  
**Target Process:** .injector (PID 20480)  
**Memory Image:** mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime

---

## Executive Summary

Memory forensic examination of process ID 20480 (.injector) revealed evidence of malicious code injection through dynamically allocated executable memory regions. Analysis identified a 4096-byte RWX (Read-Write-Execute) anonymous memory mapping containing position-independent shellcode, corroborated by self-documenting strings discovered within the process heap space.

---

## Methodology

### Memory Acquisition
- **Tool:** Volatility 3 Framework v2.26.2
- **Plugin:** linux.proc.Maps with --dump option
- **Target:** PID 20480 memory mappings

### Analysis Tools
- **Disassembler:** ndisasm (NASM Disassembler) - x86-64 mode
- **Binary Analysis:** readelf, strings, hexdump
- **Hash Verification:** SHA-256

### Procedure
1. Identified suspicious memory regions via linux.malware.malfind
2. Dumped all virtual memory areas for PID 20480
3. Isolated RWX anonymous mapping at 0x7f3396a68000
4. Performed static disassembly and string analysis
5. Reconstructed executable from memory segments
6. Cross-validated findings against heap artifacts

---

## Findings

### 1. Suspicious Memory Region Identification

**Memory Range:** 0x7f3396a68000 - 0x7f3396a69000  
**Size:** 4096 bytes (1 page)  
**Permissions:** rwx (Read-Write-Execute)  
**Type:** Anonymous mapping (no file backing)  
**Significance:** Executable anonymous memory is a strong indicator of process injection or runtime code generation [1][2]

### 2. Shellcode Disassembly

**File:** shellcode_20480.ndisasm.txt  
**Size:** 15 bytes (active code)

```
00000000  90                nop           ; NOP sled (8 bytes)
00000001  90                nop
00000002  90                nop
00000003  90                nop
00000004  90                nop
00000005  90                nop
00000006  90                nop
00000007  90                nop
00000008  CC                int3          ; Breakpoint instruction
00000009  31C0              xor eax,eax   ; Zero EAX register
0000000B  4831FF            xor rdi,rdi   ; Zero RDI register
0000000E  C3                ret           ; Return to caller
```

**Analysis:** The shellcode exhibits characteristics of a trampoline or hook function rather than a full payload. The NOP sled provides alignment padding, followed by a breakpoint instruction (anti-debugging technique), register cleanup operations, and immediate return.

### 3. Heap Memory Artifacts

**Memory Range:** 0x55be0b535000 - 0x55be0b556000  
**Evidence Type:** ASCII string (self-documentation)

```
RWX_region_allocated=0x7f3396a68000 size=4096 shellcode_size=19
```

**Significance:** This string provides direct attribution, confirming the malware intentionally allocated the RWX region. However, the documented shellcode size (19 bytes) does not match the actual disassembled instruction count (15 bytes), indicating potential self-documentation error by the malware author or incomplete reconstruction.

### 4. Binary Reconstruction

**File:** injector_reconstructed.elf  
**Type:** ELF 64-bit LSB shared object, x86-64, stripped  
**Entry Point:** 0x1120  
**Dynamic Linking:** Yes (libc.so.6, ld-linux-x86-64.so.2)

#### Imported Functions
- `mmap` - Memory allocation with executable permissions
- `fopen` / `fclose` - File I/O operations
- `fprintf` - Formatted output (likely logging)
- `sleep` - Execution delay (potential sandbox evasion)
- `__stack_chk_fail` - Stack canary protection

#### Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|-------|---------|
| File Path | `/var/log/.injector.log` | Hidden log file in system directory |
| Format String | `RWX_region_allocated=%p size=4096 shellcode_size=%zu` | Debug/logging string |
| Memory Operation | `mmap()` with executable permissions | Dynamic code allocation |

---

## Technical Assessment

### Threat Classification
**Category:** In-Memory Code Injection  
**Technique:** Process hollowing / Memory manipulation  
**MITRE ATT&CK:** T1055.001 (Process Injection: Dynamic-link Library Injection)

### Behavioral Indicators
1. **Anomalous Memory Permissions:** RWX mappings are rarely legitimate in modern binaries
2. **Hidden Process Name:** Leading dot (`.injector`) suggests intentional obfuscation
3. **Persistence Mechanism:** Log file in `/var/log/` requires elevated privileges
4. **Anti-Analysis:** INT3 breakpoint instruction may detect debuggers

### Operational Intent
The minimal shellcode suggests this is not the primary payload but rather:
- A stub function for calling dynamically resolved code
- A hook trampoline for API interception
- A placeholder for future payload injection
- A test/verification routine for the injection framework

---

## Evidence Preservation

### File Inventory
```
shellcode_analysis/
|-- SHELLCODE_ANALYSIS_REPORT.md (this document)
|-- shellcode_20480.ndisasm.txt (disassembled shellcode)
|-- injector_reconstructed.elf (reconstructed malware binary)
|-- injector_strings.txt (extracted strings and IOCs)
|-- injector_main.asm (main executable disassembly)
|-- pid.20480.vma.0x7f3396a68000-0x7f3396a69000.asm (shellcode region)
|-- pid.20480.vma.0x7f3396a60000-0x7f3396a68000.asm (adjacent memory)
\-- memory_dumps/ (22 raw memory segments)
```

### Chain of Custody
- **Original Image:** mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime
- **SHA-256 Hash:** [Documented in ../hashes/]
- **Extraction Time:** 2025-12-30 06:18 IST
- **Tools:** Volatility 3.26.2, ndisasm
- **Integrity:** Verified via SHA-256 checksums

---

## Conclusions

Memory forensic analysis conclusively demonstrates malicious code injection activity by process .injector (PID 20480). The combination of RWX memory allocation, position-independent shellcode, and self-documenting heap artifacts provides strong evidence of intentional malware operation. The threat exhibits operational security awareness through obfuscation techniques and anti-debugging measures.

### Recommended Actions
1. **Immediate:** Isolate affected system from network
2. **Investigation:** Analyze network connections from PID 20480 (see sockstat output)
3. **Persistence Check:** Search for `/var/log/.injector.log` and associated files
4. **Threat Hunting:** Scan for similar hidden processes with leading dot notation
5. **Reverse Engineering:** Conduct full static/dynamic analysis of reconstructed ELF binary

---

## References

[1] Trovent Security GmbH. "Exploiting RWX Memory Regions." https://trovent.io/en/exploiting-rwx-memory-regions/  
[2] Elastic Security. "Network Connection from Binary with RWX Memory Region." https://www.elastic.co/guide/en/security/8.19/network-connection-from-binary-with-rwx-memory-region.html

---

**Report Status:** COMPLETE  
