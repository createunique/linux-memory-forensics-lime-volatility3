# DFIR Procedures & Methodology

**Case:** CASE_20251228_0001  
**Date:** 2025-12-31  
**Analyst:** Sai (DFIR Analyst)  
**Classification:** Confidential - Incident Response  

---

## Table of Contents

1. [Phase 0: Environment Setup](#phase-0-environment-setup)
2. [Phase 1: Evidence Collection](#phase-1-evidence-collection)
3. [Phase 2: Examination & Analysis](#phase-2-examination--analysis)
4. [Phase 3: Advanced Analysis](#phase-3-advanced-analysis)
5. [Phase 4: Reporting & Remediation](#phase-4-reporting--remediation)
6. [Quality Assurance & Chain of Custody](#quality-assurance--chain-of-custody)

---

## Phase 0: Environment Setup

### Objectives
- Establish secure forensic lab environment
- Configure isolated network for victim VM
- Prepare analysis workstation with required tools
- Document baseline configurations

### Procedures

#### 0.1 Lab Network Configuration

**Topology:**
```
[Analyst VM (192.168.164.130)]
      |
      | Host-Only Network (VMnet1)
      | 192.168.164.0/24
      |
[Victim VM (192.168.164.129)]
      NAT Network: 172.16.179.143
      (for updates only)
```

**Host-Only Network Isolation:**
- Disable NAT between host and guest
- Configure firewall rules to allow only lab traffic
- Verify no external network access

**Validation Command:**
```bash
# From analyst VM
ping -c 2 192.168.164.129
ssh labadmin@192.168.164.129 'ip -br a'
```

#### 0.2 Forensic Tools Installation

**Analyst VM Tools:**
```bash
# System packages
sudo apt update
sudo apt install -y \
  git curl wget netcat-openbsd openssh-client jq tree \
  python3-pip python3-venv build-essential

# Volatility 3 environment
python3 -m venv ~/dfir_tools/vol3_env
source ~/dfir_tools/vol3_env/bin/activate
pip install volatility3

# Additional utilities
sudo apt install -y \
  yara sleuthkit autopsy exiftool \
  capstone ndisasm radare2
```

**Victim VM Tools:**
```bash
# LiME prerequisites
sudo apt update
sudo apt install -y git build-essential linux-headers-$(uname -r)

# Clone and build LiME
cd ~/dfir_tools
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make
```

#### 0.3 Symbol File Collection

**Ubuntu 20.04.6 Kernel Symbols:**
```bash
# On analyst VM
mkdir -p ~/dfir_symbols/linux

# Method 1: Download from Ubuntu symbol server
url="http://ddebs.ubuntu.com/pool/main/l/linux/"
wget -P ~/dfir_symbols/linux "$url/linux-image-5.4.0-216-generic-dbgsym_5.4.0-216.236_amd64.ddeb"

# Extract symbols
cd ~/dfir_symbols/linux
dpkg -x *.ddeb .

# Method 2: Build ISF from kernel image (if Method 1 fails)
vol -f ~/dfir_symbols/linux/5.4.0-216/ isfinfo.IsfInfo
```

---

## Phase 1: Evidence Collection

### Objectives
- Acquire memory image with cryptographic verification
- Collect volatile system artifacts (processes, network, ARP)
- Document chain of custody from start
- Minimize system alteration (RFC 3227 principle)

### Procedures

#### 1.1 Pre-Acquisition Baseline

**On Analyst VM:**
```bash
# Case variables
export CASE_ID="CASE_20251228_0001"
export CASE_UTC="$(date -u +%Y%m%dT%H%M%SZ)"
export VICTIM_IP="192.168.164.129"
export VICTIM_USER="labadmin"
export CASE_DIR="$HOME/dfir-cases/$CASE_ID"

# Create case structure
mkdir -p "$CASE_DIR"/{evidence,hashes,logs,notes,tmp}
chmod 750 "$CASE_DIR"
```

**Collect Volatile Artifacts (minimal system impact):**
```bash
# 1) System identity & processes
ssh "${VICTIM_USER}@${VICTIM_IP}" \
  "hostname; uname -a; uptime; ps auxww" \
  | tee "$CASE_DIR/logs/pre_acq_identity_${CASE_UTC}.txt"

# 2) Network state
ssh "${VICTIM_USER}@${VICTIM_IP}" \
  "ss -anp; ip neigh; iptables -L -n" \
  | tee "$CASE_DIR/logs/pre_acq_network_${CASE_UTC}.txt"

# 3) Hash baselines for comparison
ssh "${VICTIM_USER}@${VICTIM_IP}" \
  "sha256sum /etc/passwd /etc/shadow /bin/sh" \
  | tee "$CASE_DIR/hashes/baseline_files_${CASE_UTC}.sha256"

# Document analyst system info
uname -a > "$CASE_DIR/logs/analyst_os_${CASE_UTC}.txt"
```

#### 1.2 LiME Memory Acquisition (Victim VM)

**Login to Victim VM:**
```bash
ssh "${VICTIM_USER}@${VICTIM_IP}"
```

**Build LiME Module:**
```bash
cd ~/dfir_tools/LiME/src
make clean || true
make

# Verify module
uname -r
modinfo ./lime-$(uname -r).ko | grep vermagic
```

**Perform Memory Dump:**
```bash
# Remove any previous LiME loads
sudo rmmod lime 2>/dev/null || true

# Define output path
DUMP_PATH="$HOME/dfir_acq/mem_$(hostname)_$(uname -r)_$(date -u +%Y%m%dT%H%M%SZ).lime"
mkdir -p "$HOME/dfir_acq"

echo "Dumping memory to: $DUMP_PATH"

# Load LiME module (timeout=0 disables page read timeout for slow storage)
sudo insmod ./lime-$(uname -r).ko \
  path="$DUMP_PATH" \
  format=lime \
  timeout=0

# Remove module
sudo rmmod lime

# Verify dump
ls -lh "$DUMP_PATH"
sha256sum "$DUMP_PATH" | tee "$DUMP_PATH.sha256"

# Exit victim VM
exit
```

#### 1.3 Verify Hash & Transfer Evidence

**On Analyst VM:**
```bash
# Get dump filename from victim
DUMP_FILE="$(ssh "${VICTIM_USER}@${VICTIM_IP}" 'ls -1t ~/dfir_acq/*.lime | head -n 1')"
DUMP_NAME="$(basename "$DUMP_FILE")"

echo "[INFO] Transferring: $DUMP_FILE"

# Copy dump to analyst evidence directory
scp -p "${VICTIM_USER}@${VICTIM_IP}:${DUMP_FILE}" \
  "$CASE_DIR/evidence/"

scp -p "${VICTIM_USER}@${VICTIM_IP}:${DUMP_FILE}.sha256" \
  "$CASE_DIR/hashes/original_${DUMP_NAME}.sha256"

# Create analyst-local verification file (handles path differences)
cd "$CASE_DIR"
awk '{print $1 "  evidence/'$DUMP_NAME'"}' \
  "hashes/original_${DUMP_NAME}.sha256" \
  > "hashes/${DUMP_NAME}.local.sha256"

# Verify integrity
echo "[VERIFY] Hash validation..."
sha256sum -c "hashes/${DUMP_NAME}.local.sha256"

# Record in chain of custody
printf "%s UTC | Evidence transferred and verified | hash=%s | file=%s\n" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$(awk '{print $1}' hashes/${DUMP_NAME}.local.sha256)" \
  "$DUMP_NAME" \
  >> "$CASE_DIR/notes/CHAIN_OF_CUSTODY.txt"

# Optional: Clean up victim dump
ssh "${VICTIM_USER}@${VICTIM_IP}" \
  "rm -f '${DUMP_FILE}' '${DUMP_FILE}.sha256'"
```

---

## Phase 2: Examination & Analysis

### Objectives
- Extract baseline system information from memory
- Identify suspicious processes and network connections
- Detect injected code and malware signatures
- Catalog all findings with evidence mapping

### Procedures

#### 2.1 Volatility 3 Setup

**Configure environment variables:**
```bash
# Activate Volatility 3 environment
source ~/dfir_tools/vol3_env/bin/activate

# Case variables
export CASE_ID="CASE_20251228_0001"
export CASE_DIR="$HOME/dfir-cases/$CASE_ID"
export DUMP="$CASE_DIR/evidence/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime"
export SYMS="$HOME/dfir_symbols"
export EXAM_DIR="$CASE_DIR/examination/vol3"

# Create output directory
mkdir -p "$EXAM_DIR"

# Clear cache for fresh analysis
rm -rf ~/.cache/volatility3
```

#### 2.2 Baseline Extraction

**Kernel validation:**
```bash
# Banner and ISF verification
vol -f "$DUMP" -s "$SYMS" banners.Banners \
  | tee "$EXAM_DIR/01_banners.txt"

vol -f "$DUMP" -s "$SYMS" isfinfo.IsfInfo \
  | tee "$EXAM_DIR/02_isfinfo.txt"

# Boot time (temporal anchor)
vol -f "$DUMP" -s "$SYMS" linux.boottime \
  | tee "$EXAM_DIR/10_boottime.txt"
```

**Process enumeration:**
```bash
# Three-method comparison (catch DKOM, hidden processes)
vol -f "$DUMP" -s "$SYMS" linux.pslist \
  | tee "$EXAM_DIR/11_pslist.txt"

vol -f "$DUMP" -s "$SYMS" linux.pstree \
  | tee "$EXAM_DIR/12_pstree.txt"

vol -f "$DUMP" -s "$SYMS" linux.psscan \
  | tee "$EXAM_DIR/13_psscan.txt"

# Command-line arguments (critical for malware detection)
vol -f "$DUMP" -s "$SYMS" linux.psaux \
  | tee "$EXAM_DIR/14_psaux.txt"

# Open file descriptor analysis
vol -f "$DUMP" -s "$SYMS" linux.lsof \
  | tee "$EXAM_DIR/15_lsof.txt"
```

#### 2.3 Network Analysis

**Active connections:**
```bash
# Socket enumeration (identifies C2 channels)
vol -f "$DUMP" -s "$SYMS" linux.sockstat \
  | tee "$EXAM_DIR/20_sockstat.txt"

# Extract IPv4 established connections
grep -i "established\|listen" "$EXAM_DIR/20_sockstat.txt" | head -20
```

#### 2.4 Kernel & Malware Analysis

**Kernel inspection:**
```bash
# Loaded modules (detect LKM rootkits)
vol -f "$DUMP" -s "$SYMS" linux.lsmod \
  | tee "$EXAM_DIR/30_lsmod.txt"

# Kernel ring buffer (boot-time artifacts, module loads)
vol -f "$DUMP" -s "$SYMS" linux.kmsg \
  | tee "$EXAM_DIR/40_kmsg.txt" \
  | head -100  # Usually long; check first 100 lines
```

**Malware detection:**
```bash
# Critical: RWX memory region detection
vol -f "$DUMP" -s "$SYMS" linux.malfind \
  | tee "$EXAM_DIR/50_malfind.txt"

# Cross-reference modules with memory
vol -f "$DUMP" -s "$SYMS" linux.malware.modxview \
  | tee "$EXAM_DIR/51_modxview.txt"

# Extract hexdump from malfind output
grep -A 20 "RWX" "$EXAM_DIR/50_malfind.txt"
```

---

## Phase 3: Advanced Analysis

### Objectives
- Disassemble injected shellcode
- Recover Python source code from process memory
- Perform RWX region comparative analysis
- Extract indicators of compromise (IOCs)

### Procedures

#### 3.1 Shellcode Analysis (PID-Specific)

**Target: PID 20480 (.injector)**

```bash
# Create analysis directory
mkdir -p "$CASE_DIR/examination/shellcode_analysis"
SHELL_DIR="$CASE_DIR/examination/shellcode_analysis"

# Dump all memory regions for PID 20480
vol -f "$DUMP" -s "$SYMS" \
  -o "$SHELL_DIR/dumps/" \
  linux.proc.Maps --pid 20480 --dump

# Identify RWX region (from malfind output: 0x7f3396a68000-0x7f3396a69000)
RWX_DUMP="$SHELL_DIR/dumps/pid.20480.vma.0x7f3396a68000-0x7f3396a69000.dmp"

# Disassemble shellcode
ndisasm -b 64 "$RWX_DUMP" \
  | tee "$SHELL_DIR/shellcode_20480.ndisasm.txt"

# Extract strings from heap (locate self-documenting artifacts)
HEAP_DUMP="$SHELL_DIR/dumps/pid.20480.vma.0x55be0b535000-0x55be0b556000.dmp"
strings -n 8 "$HEAP_DUMP" \
  | grep -E "(RWX|shellcode|allocated|size)" \
  | tee "$SHELL_DIR/heap_strings.txt"

# Hash RWX region for comparison
sha256sum "$RWX_DUMP" \
  | tee "$SHELL_DIR/rwx_20480.sha256"
```

#### 3.2 Python Process Memory Analysis

**Targets: PID 19442 (.memmarker.py), PID 19983 (.rsim.py)**

```bash
# Create analysis directory
mkdir -p "$CASE_DIR/examination/python_analysis"
PY_DIR="$CASE_DIR/examination/python_analysis"

# Dump process memory
for PID in 19442 19983; do
  echo "[EXTRACT] Dumping PID $PID"
  vol -f "$DUMP" -s "$SYMS" \
    -o "$PY_DIR/pid_${PID}/" \
    linux.proc.Maps --pid "$PID" --dump
done

# Extract and search for Python source code patterns
for DUMP_FILE in "$PY_DIR"/pid_*/pid.*.dmp; do
  strings "$DUMP_FILE" | grep -E \
    "(import|socket|create_connection|send|recv|C2|beacon|RSIM)" \
    >> "$PY_DIR/python_iocs.txt"
done

# Search for hardcoded C2 infrastructure
grep -r "192.168.164" "$PY_DIR"/ | tee "$PY_DIR/c2_strings.txt"

# Extract recovered Python source code
strings "$PY_DIR/pid_19983/"*.dmp \
  | sed -n '/#!/,/^[^ ]/p' \
  | tee "$PY_DIR/rsim_source_recovered.py"
```

#### 3.3 RWX Region Comparative Analysis

**Compare PIDs 1048 vs 1140**

```bash
# Create comparison directory
mkdir -p "$CASE_DIR/examination/rwx_comparison"
CMP_DIR="$CASE_DIR/examination/rwx_comparison"

# Dump both processes
for PID in 1048 1140; do
  echo "[EXTRACT] Dumping PID $PID"
  vol -f "$DUMP" -s "$SYMS" \
    -o "$CMP_DIR/pid_${PID}/" \
    linux.proc.Maps --pid "$PID" --dump
done

# Hash all memory segments (identify shared vs unique)
for DUMP_DIR in "$CMP_DIR"/pid_*/; do
  PID=$(basename "$DUMP_DIR" | sed 's/pid_//')
  sha256sum "$DUMP_DIR"*.dmp \
    | tee "$CMP_DIR/pid_${PID}_hashes.txt"
done

# Compare RWX regions
RWX_1048="$CMP_DIR/pid_1048/pid.1048.vma.0x7fed1a3a6000-0x7fed1a3a7000.dmp"
RWX_1140="$CMP_DIR/pid_1140/pid.1140.vma.0x7f0129900000-0x7f0129901000.dmp"

# Byte-level comparison
cmp -l "$RWX_1048" "$RWX_1140" | head -20 \
  | tee "$CMP_DIR/rwx_byte_differences.txt"

# Calculate similarity
cmp "$RWX_1048" "$RWX_1140" && \
  echo "IDENTICAL" || \
  (DIFF=$(cmp -l "$RWX_1048" "$RWX_1140" | wc -l); \
   TOTAL=4096; \
   SIMILARITY=$(echo "scale=2; (100 * ($TOTAL - $DIFF) / $TOTAL)" | bc); \
   echo "Similarity: $SIMILARITY%")

# Disassemble both for pattern comparison
ndisasm -b 64 "$RWX_1048" \
  | tee "$CMP_DIR/rwx_1048_disasm.txt"

ndisasm -b 64 "$RWX_1140" \
  | tee "$CMP_DIR/rwx_1140_disasm.txt"

# Create unified diff
diff -u "$CMP_DIR/rwx_1048_disasm.txt" "$CMP_DIR/rwx_1140_disasm.txt" \
  | tee "$CMP_DIR/rwx_disasm_diff.txt"
```

---

## Phase 4: Reporting & Remediation

### Objectives
- Compile findings into structured report
- Generate IOC list for network defense
- Recommend containment and remediation steps
- Archive evidence and analysis artifacts

### Procedures

#### 4.1 IOC Extraction

**Create machine-readable IOC file:**
```bash
# IOCs file
IOC_FILE="$CASE_DIR/iocs/indicators.txt"
mkdir -p "$(dirname "$IOC_FILE")"

cat > "$IOC_FILE" <<'EOF'
# INDICATORS OF COMPROMISE - CASE_20251228_0001
# Date: 2025-12-31
# Severity: CRITICAL

## Network IOCs
C2_SERVER: 192.168.164.1:4444 (TCP ESTABLISHED)
SOURCE_IP: 192.168.164.129
SOURCE_PORT: 47540
PROTOCOL: TCP

## File IOCs
/opt/.cache/.rsim.py
/opt/.cache/.memmarker.py
/var/log/.injector.log
/var/log/.rsim.log

## Process IOCs (PIDs at capture time)
PID 20480: .injector
PID 19983: python3 .rsim.py
PID 19442: python3 .memmarker.py
PID 1048: networkd-dispatcher (compromised)
PID 1140: unattended-upgrades (compromised)

## Memory Signatures
SHA256 (RWX PID 1048): 32bc517b828aa81ed1a08eaf2508cfc6ae051fe31d4d0dd770fc8710643f49a9
SHA256 (RWX PID 1140): 29fccdb43739f665b76b4c41cbed2837a6a74dc662c5b2bbb50a63dadac47d9d

## Shellcode Pattern
BYTES: 4C 8D 15 F9 FF FF FF FF 25 03 00 00 00 0F 1F 00
NAME: Process_Injection_Trampoline

## Behavioral IOCs
- RWX anonymous memory in system services
- Python socket.create_connection() to 192.168.164.1:4444
- RSIM_BEACON hello message (15-second heartbeat)
- sudo nohup execution of Python scripts
- Leading dot (.) process names
EOF

cat "$IOC_FILE"
```

#### 4.2 Timeline Reconstruction

```bash
TIMELINE_FILE="$CASE_DIR/reports/TIMELINE.md"
mkdir -p "$(dirname "$TIMELINE_FILE")"

cat > "$TIMELINE_FILE" <<'EOF'
# INCIDENT TIMELINE - CASE_20251228_0001

## Pre-Compromise Phase
- 2025-12-27 ~20:00 UTC: System boot (from linux.boottime analysis)

## Attack Phase
- 2025-12-27 20:09:02 UTC: Initial C2 connection attempt (failed)
- 2025-12-27 21:49:03 UTC: Memory image acquired (LiME dump timestamp)
- 2025-12-27 21:49:05 UTC: Successful C2 beacon sent ("connected+beacon_sent")

## Evidence Discovery Phase
- 2025-12-30: Memory examination (Phase 2 analysis)
- 2025-12-30: Shellcode disassembly & Python source recovery
- 2025-12-31: RWX region comparative analysis
- 2025-12-31: Report generation

**Dwell Time:** ~1 hour 40 minutes between first attempt and successful compromise
EOF

cat "$TIMELINE_FILE"
```

#### 4.3 Containment Procedures

**Immediate Actions (Within 1 Hour):**
```bash
# 1) Network isolation
sudo ip link set eth0 down  # Disconnect from network

# 2) Kill malicious processes
sudo kill -9 1048 1140  # Will likely auto-restart (indicates persistence)

# 3) Block outbound C2
sudo iptables -I OUTPUT -d 192.168.164.1 -p tcp --dport 4444 -j DROP
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

**24-Hour Remediation:**
```bash
# Search for persistence mechanisms
sudo find / -name ".cache*" -type d 2>/dev/null
sudo find /opt -name ".*py" -type f 2>/dev/null
sudo find /var/log -name ".*" -type f 2>/dev/null

# Check systemd services
sudo systemctl list-units --type=service | grep -E "(rsim|injector|memmarker)"

# Verify package integrity
apt-cache policy networkd-dispatcher unattended-upgrades
debsums -c networkd-dispatcher unattended-upgrades

# Check cron/systemd timers
sudo crontab -l
sudo systemctl list-timers
```

#### 4.4 Evidence Archival & Hash Verification

```bash
# Create final evidence archive
cd "$CASE_DIR"

# Hash all artifacts
find . -type f -not -path './evidence/*' ! -name '*.sha256' \
  -exec sha256sum {} \; \
  | tee "FINAL_HASH_MANIFEST.sha256"

# Verify integrity
sha256sum -c "FINAL_HASH_MANIFEST.sha256"

# Create compressed archive for long-term storage
tar -czf \
  "${CASE_ID}_EVIDENCE_$(date -u +%Y%m%dT%H%M%SZ).tar.gz" \
  --exclude='evidence/*.lime' \
  .

# Hash archive
sha256sum "${CASE_ID}_EVIDENCE_"*.tar.gz \
  | tee "${CASE_ID}_ARCHIVE.sha256"
```

---

## Quality Assurance & Chain of Custody

### Procedures

#### QA.1 Hash Verification

**At each phase, verify integrity:**
```bash
# After collection
sha256sum -c "$CASE_DIR/hashes/${DUMP_NAME}.local.sha256"

# After transfer
md5sum "$CASE_DIR/evidence/$DUMP_NAME"

# After analysis
sha256sum -c "$CASE_DIR/examination/"*".sha256"
```

#### QA.2 Chain of Custody Documentation

**Create and maintain:**
```bash
COC_FILE="$CASE_DIR/CHAIN_OF_CUSTODY.txt"

# Template entry
printf "%s | [ACTION] | [CUSTODIAN] | [NOTES]\n" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  >> "$COC_FILE"

# Example entries:
# 2025-12-27T21:49:03Z | Collection | labadmin (victim) | LiME dump acquired, timeout=0
# 2025-12-27T21:50:00Z | Transfer | analyst@lab | scp to analyst VM, hash verified
# 2025-12-30T06:00:00Z | Analysis | analyst | Phase 2 examination began
# 2025-12-31T14:00:00Z | Archival | analyst | Final archive created and hashed
```

#### QA.3 Tool & Environment Documentation

```bash
# Document all tools and versions
cat > "$CASE_DIR/TOOL_INVENTORY.txt" <<'EOF'
=== FORENSIC TOOLS USED ===

Acquisition:
  - LiME 2.0 (kernel module for memory dump)
  - sha256sum (hash verification)

Analysis:
  - Volatility 3.26.2 (memory forensics framework)
  - ndisasm (x86-64 disassembler)
  - strings (binary string extraction)
  - readelf (ELF binary analysis)

Environment:
  - Ubuntu 20.04.6 LTS (analyst VM)
  - Python 3.8+ (Volatility 3)
  - Kernel 5.4.0-216 (victim VM)

Symbol Files:
  - Ubuntu Linux dbgsym for 5.4.0-216 kernel
EOF

cat "$CASE_DIR/TOOL_INVENTORY.txt"
```

---

## Summary of Procedures

| Phase | Duration | Objectives | Key Artifacts |
|-------|----------|--------------|----------------|
| **Phase 0** | 2-4 hours | Lab setup, tool install, symbol download | Environment docs |
| **Phase 1** | 1-2 hours | Evidence acquisition, volatile artifacts | LiME dump, hashes, logs |
| **Phase 2** | 4-8 hours | Volatility 3 analysis, baseline extraction | 13 analysis files |
| **Phase 3** | 8-16 hours | Shellcode, Python, RWX analysis | Disassembly, recovered source, IOCs |
| **Phase 4** | 2-4 hours | Reporting, archival, remediation | Final reports, IOC list, archive |
| **Total** | ~20-34 hours | Complete DFIR investigation | Case closed with evidence preserved |

---

**Procedures Approved By:** Digital Forensics Team  
**Date:** 2025-12-31  
**Classification:** Confidential - Incident Response
