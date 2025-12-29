# Phase 1: Memory Acquisition (LiME)

## Overview
Memory acquisition performed using LiME (Linux Memory Extractor) kernel module on a live Ubuntu 20.04 system. Follows RFC 3227 volatile data collection guidelines with complete documentation of commands, timestamps, and integrity verification.

## Case Information
- **Case ID:** CASE_20251228_0001
- **Victim System:** victim-u20 (192.168.164.129)
- **Analyst Workstation:** analystvmu20 (192.168.164.130)
- **Acquisition Date:** 2025-12-27
- **Acquisition Time:** 21:48:36 UTC
- **Analyst:** labadmin

## Lab Topology
- **Victim VM (Ubuntu 20.04):**
  - ens34 (Host-only): 192.168.164.129 (used for SSH + evidence transfer)
  - ens33 (NAT): 172.16.179.143 (internet access)
  
- **Analyst VM:**
  - Host-only: 192.168.164.130 (connects to victim)

## Pre-Acquisition Volatile Data Collection

Before memory acquisition, the following volatile data was captured via SSH:

### System Identity
```bash
ssh labadmin@192.168.164.129 "hostname; uname -a; uname -r; date -u; uptime; free -m; ip addr show"
```

**Output saved to:** `logs/victim_identity_20251227T214836Z.txt`

### Running Processes
```bash
ssh labadmin@192.168.164.129 "ps auxww"
```

**Output saved to:** `logs/pre_acq_processes_20251227T214836Z.txt`

### Network Connections
```bash
ssh labadmin@192.168.164.129 "ss -anp"
```

**Output saved to:** `logs/pre_acq_network_20251227T214836Z.txt`

### ARP/Neighbor Cache
```bash
ssh labadmin@192.168.164.129 "ip neigh"
```

**Output saved to:** `logs/pre_acq_arp_20251227T214836Z.txt`

## LiME Kernel Module Acquisition

### Prerequisites Installation
```bash
sudo apt update
sudo apt install -y git build-essential linux-headers-$(uname -r)
```

### Directory Setup
```bash
mkdir -p ~/dfir_tools ~/dfir_acq ~/dfir_symbols/linux
```

### LiME Compilation
```bash
cd ~/dfir_tools
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make clean
make
```

**Module Built:** `lime-5.4.0-216-generic.ko`

### Module Verification
```bash
uname -r
modinfo ./lime-5.4.0-216-generic.ko | egrep 'filename|vermagic|depends'
```

**Vermagic Match:** 5.4.0-216-generic SMP mod_unload

### Memory Acquisition Command
```bash
sudo rmmod lime 2>/dev/null || true

OUT="$HOME/dfir_acq/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime"

sudo insmod ./lime-5.4.0-216-generic.ko "path=$OUT format=lime timeout=0"
sudo rmmod lime
```

**Parameters:**
- `path=` — Output file location
- `format=lime` — LiME format (preserves physical memory layout)
- `timeout=0` — Disable page-read timeout (complete acquisition)

### Post-Acquisition Steps
```bash
# Fix ownership
sudo chown labadmin:labadmin "$OUT"
chmod 640 "$OUT"

# Generate SHA-256 hash
sha256sum "$OUT" | tee "$OUT.sha256"
```

## Evidence Transfer to Analyst Workstation

### Transfer Commands
```bash
# From analyst VM
VICTIM_IP="192.168.164.129"
VICTIM_USER="labadmin"
CASE_DIR="$HOME/dfir-cases/CASE_20251228_0001"

# Identify latest dump
LATEST_OUT="$(ssh "${VICTIM_USER}@${VICTIM_IP}" "ls -1t ~/dfir_acq/*.lime | head -n 1")"

# Transfer evidence file
scp -p "${VICTIM_USER}@${VICTIM_IP}:${LATEST_OUT}" "$CASE_DIR/evidence/"

# Transfer hash file
scp -p "${VICTIM_USER}@${VICTIM_IP}:${LATEST_OUT}.sha256" "$CASE_DIR/hashes/"
```

## Integrity Verification

### Hash Verification on Analyst Workstation
```bash
cd "$CASE_DIR"

# Original hash file (victim path)
HASHFILE="$CASE_DIR/hashes/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime.sha256"

# Create local verification file
LOCALSUM="$CASE_DIR/hashes/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime.local.sha256"

# Convert victim absolute path to analyst relative path
awk '{print $1 "  evidence/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime"}' "$HASHFILE" > "$LOCALSUM"

# Verify integrity
sha256sum -c "$LOCALSUM"
```

**Expected Output:**
```
evidence/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime: OK
```

## Acquisition Metadata

### Evidence Details
- **Filename:** mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime
- **File Size:** ~1.2 GB (approximately 4 GB system RAM)
- **SHA-256:** [Hash value stored in evidence.sha256]
- **Acquisition Method:** Live response (LiME kernel module)
- **Acquisition Tool:** LiME (504ensicsLabs)
- **Kernel Version:** 5.4.0-216-generic
- **Module Vermagic:** Verified match

### Acquisition Timeline
- **System Boot:** 2025-12-27 19:02:00 UTC
- **Pre-acquisition baselines:** 2025-12-27 21:48:00 UTC
- **LiME module load:** 2025-12-27 21:48:36 UTC
- **Acquisition complete:** 2025-12-27 21:49:03 UTC
- **Evidence transfer:** 2025-12-27 21:50:15 UTC
- **Hash verification:** 2025-12-27 21:51:00 UTC

**Total Acquisition Time:** ~27 seconds

### Chain of Custody Entry
```
2025-12-27T21:48:36Z UTC | Memory acquisition initiated on victim-u20 | Analyst: labadmin
2025-12-27T21:49:03Z UTC | Memory dump completed successfully | Size: ~1.2GB
2025-12-27T21:50:15Z UTC | Evidence transferred to analyst workstation via SCP
2025-12-27T21:51:00Z UTC | SHA-256 integrity verified: OK
```

## Case Directory Structure (Analyst)
```
dfir-cases/CASE_20251228_0001/
├── evidence/
│   └── mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime
├── hashes/
│   ├── mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime.sha256
│   ├── mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime.local.sha256
│   └── pre_acq_baselines_20251227T214836Z.sha256
├── logs/
│   ├── victim_identity_20251227T214836Z.txt
│   ├── pre_acq_processes_20251227T214836Z.txt
│   ├── pre_acq_network_20251227T214836Z.txt
│   ├── pre_acq_arp_20251227T214836Z.txt
│   └── analyst_actions_20251227T214836Z.log
└── notes/
    └── NOTES_20251227T214836Z.txt
```

## Best Practices Followed
- ✅ Minimal system interaction (via SSH, no local console)
- ✅ Volatile data captured before memory acquisition
- ✅ Module vermagic verified before loading
- ✅ timeout=0 parameter used for complete acquisition
- ✅ SHA-256 integrity hashing at source and destination
- ✅ Chain of custody documented with timestamps
- ✅ Evidence stored with restricted permissions (chmod 640)
- ✅ All commands logged with UTC timestamps

## Notes and Caveats
- LiME acquisition is non-invasive but does load a kernel module
- System remained powered on and unmodified during acquisition
- No pagefile/swap acquisition performed (not required for this case)
- Evidence file excluded from git repository (see .gitignore)
- Original evidence remains on analyst workstation outside git tree

## References
- RFC 3227: Guidelines for Evidence Collection and Archiving
- LiME GitHub: https://github.com/504ensicsLabs/LiME
- Volatility3 Linux Memory Forensics Documentation
