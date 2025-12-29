# Volatility3 Linux Plugins Reference

## Plugins Used in CASE_20251228_0001

This document provides detailed information about each Volatility3 plugin executed during the investigation.

---

## Validation Plugins

### banners.Banners
**Purpose:** Display Linux kernel banner and version information  
**Output File:** 01_banners.txt  
**Command:** `vol -f $DUMP -s $SYMS banners.Banners`  
**Use Case:** Verify dump file is valid Linux memory and identify kernel version  
**Confidence:** Excellent - Direct kernel structure read

### isfinfo.IsfInfo
**Purpose:** Display loaded ISF (Intermediate Symbol Format) symbol information  
**Output File:** 02_isfinfo.txt  
**Command:** `vol -f $DUMP -s $SYMS isfinfo.IsfInfo`  
**Use Case:** Verify correct symbol file loaded for kernel version  
**Confidence:** Excellent - Symbol table metadata

---

## Process Analysis Plugins

### linux.pslist.PsList
**Purpose:** List running processes from kernel task_struct list  
**Output File:** 11_pslist.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.pslist.PsList`  
**Output Columns:** OFFSET, PID, TID, PPID, COMM, UID, GID, ...  
**Use Case:** Primary process enumeration, identify suspicious processes  
**Confidence:** Excellent - Direct kernel structure traversal  
**Limitations:** May miss hidden processes (use psscan for validation)

### linux.pstree.PsTree
**Purpose:** Display process tree with parent-child relationships  
**Output File:** 12_pstree.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.pstree.PsTree`  
**Output Format:** Hierarchical tree with indentation  
**Use Case:** Visualize process ancestry, identify suspicious parent-child relationships  
**Confidence:** Excellent - Based on PPID relationships  
**Key Insight:** Shows sshd → bash → sudo → malware chain

### linux.psscan.PsScan
**Purpose:** Scan physical memory for process structures (detects hidden processes)  
**Output File:** 13_psscan.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.psscan.PsScan`  
**Output Columns:** Similar to pslist  
**Use Case:** Detect processes hidden from pslist (rootkit detection)  
**Confidence:** Excellent - Physical memory scan  
**Cross-Reference:** Compare with pslist to find anomalies

### linux.psaux.PsAux
**Purpose:** Display process command-line arguments (like `ps aux`)  
**Output File:** 14_psaux.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.psaux.PsAux`  
**Output Columns:** PID, COMMAND (full command line)  
**Use Case:** **CRITICAL** - Recover attacker commands, identify scripts and arguments  
**Confidence:** Excellent - Memory string extraction  
**Key Artifact:** Shows exact commands including sudo, compilation, execution

### linux.lsof.Lsof
**Purpose:** List open files and file descriptors per process  
**Output File:** 15_lsof.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.lsof.Lsof`  
**Output Columns:** PID, FD, PATH  
**Use Case:** Identify files accessed by suspicious processes, network sockets  
**Confidence:** Excellent - File descriptor table walk  
**Key Insight:** Shows LiME acquisition in progress, network sockets

---

## Network Analysis Plugins

### linux.sockstat.Sockstat
**Purpose:** Display network socket statistics and connections  
**Output File:** 20_sockstat.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.sockstat.Sockstat`  
**Output Columns:** NetNS, Proto, SAddr, SPort, DAddr, DPort, State, Inode, PID/Comm  
**Use Case:** Identify network connections, C2 communication, listening services  
**Confidence:** Excellent - Socket table enumeration  
**Key Findings:** SSH connections, Apache listeners, C2 attempts

---

## Kernel Analysis Plugins

### linux.lsmod.Lsmod
**Purpose:** List loaded kernel modules  
**Output File:** 30_lsmod.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.lsmod.Lsmod`  
**Output Columns:** Offset, Name, Size, Taints  
**Use Case:** Detect suspicious kernel modules, rootkits, validate LiME module  
**Confidence:** Excellent - Kernel module list traversal  
**Key Findings:** LiME module (expected), taint flags (OOT_MODULE, UNSIGNED_MODULE)

### linux.kmsg.Kmsg
**Purpose:** Extract kernel message buffer (dmesg equivalent)  
**Output File:** 40_kmsg.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.kmsg.Kmsg`  
**Output:** Kernel log messages with timestamps  
**Use Case:** Hardware initialization, module loading events, kernel errors  
**Confidence:** Good - Ring buffer may be overwritten  
**Key Insight:** LiME module loading messages, network initialization

---

## Artifact Recovery Plugins

### linux.bash.Bash
**Purpose:** Recover bash command history from process memory  
**Output File:** 41_bash.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.bash.Bash`  
**Output Columns:** PID, Process, CommandTime, Command  
**Use Case:** **CRITICAL** - Reconstruct attacker actions, build timeline  
**Confidence:** Very High - Memory string extraction (subject to overwriting)  
**Key Artifact:** Complete attacker command history (50+ commands) preserved

---

## Malware Detection Plugins

### linux.malfind.Malfind
**Purpose:** Detect suspicious memory regions (RWX pages, shellcode patterns)  
**Output File:** 50_malfind.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.malfind.Malfind`  
**Output:** PID, Name, Start, End, Protection, Hexdump, Disasm  
**Use Case:** **CRITICAL** - Code injection detection, identify RWX pages  
**Confidence:** Very High - Memory permission analysis  
**Key Findings:** PID 20480 (.injector) with RWX anonymous page containing shellcode

### linux.malware.modxview.Modxview
**Purpose:** Cross-reference kernel modules for integrity validation  
**Output File:** 51_modxview.txt  
**Command:** `vol -f $DUMP -s $SYMS linux.malware.modxview.Modxview`  
**Output:** Module consistency checks  
**Use Case:** Detect kernel module manipulation, rootkit verification  
**Confidence:** Excellent - Multiple data structure cross-reference  
**Key Findings:** No hidden modules, LiME module validated

---

## Plugin Selection Rationale

### Why Multiple Process Plugins?
- **pslist:** Fast, standard process list
- **psscan:** Physical memory scan (catches hidden processes)
- **pstree:** Visualize relationships
- **psaux:** Command-line arguments (attack reconstruction)
- **lsof:** Open files and network sockets per process

**Cross-validation:** All 5 plugins provide redundancy and confirm findings

### Why Both sockstat and lsof?
- **sockstat:** Network connections with state
- **lsof:** Includes file descriptors and socket inodes
- **Overlap:** Confirms network findings from two sources

### Critical Plugins for This Case
1. **psaux** - Recovered full attacker command history
2. **malfind** - Detected code injection with shellcode
3. **bash** - Reconstructed attack timeline from memory
4. **pstree** - Showed attack chain (ssh → bash → sudo → malware)

---

## Volatility3 Version Information
- **Framework:** Volatility3 v2.26 or higher
- **Python:** 3.8+
- **Symbol Format:** ISF (Intermediate Symbol Format) JSON
- **Symbol File:** Ubuntu_5.4.0-216-generic_5.4.0-216.236_amd64.json

## Plugin Execution Time
- Total runtime: ~45 minutes
- Fastest: banners, boottime (<1 sec)
- Slowest: lsof, malfind (5-10 min each)

---

## Additional Plugins (Not Used)

### Available but Not Executed:
- **linux.yarascan.YaraScan** - YARA rule scanning (no rules provided)
- **linux.elfs.Elfs** - Extract ELF binaries from memory
- **linux.proc.Maps.Maps** - Detailed memory maps per process
- **linux.library_list** - Shared libraries per process
- **linux.envars.Envars** - Environment variables
- **linux.check_syscall** - Syscall table integrity check

### Why Not Used:
- YARA: No custom rules available for this case
- ELF extraction: Not required (binaries available on filesystem)
- Memory maps: Malfind provided sufficient detail
- Others: Out of scope for this investigation

---

## References
- Volatility3 Documentation: https://volatility3.readthedocs.io/
- Linux Plugin List: https://github.com/volatilityfoundation/volatility3/tree/develop/volatility3/framework/plugins/linux
- ISF Format: https://github.com/volatilityfoundation/dwarf2json

---

Last Updated: 2025-12-29
Analyst: labadmin
