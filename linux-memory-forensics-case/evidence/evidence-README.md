# Evidence Directory
## Digital Forensics Evidence Collection & Chain of Custody | CASE_20251228_0001

**Case ID**: CASE_20251228_0001  
**Evidence Type**: Volatile Memory Image (RAM dump via LiME kernel module)  
**Collection Date**: 2025-12-27 21:49:03 UTC  
**Analyst**: Sai (DFIR Analyst)  

---

## Purpose of This Directory

The `evidence/` directory contains primary forensic evidence and supporting materials for memory forensics analysis:

- **Primary evidence**: LiME-extracted RAM image (not included in GitHub due to size)
- **Evidence metadata**: Acquisition logs, timestamps, system information
- **Integrity verification**: SHA-256 hashes for evidence validation
- **Chain of custody**: Documentation of evidence handling

## Directory Contents

| File | Description |
|------|-------------|
| `acquisition-log.md` | Detailed evidence acquisition timeline and chain of custody |
| `EVIDENCE_HASHES.sha256` | SHA-256 hash of the primary memory dump file |
| `evidence-README.md` | This documentation file |
| `integrity.txt` | Comprehensive integrity verification report |
| `RWX_EVIDENCE_HASHES.sha256` | SHA-256 hashes of RWX memory regions |

---

## Victim System Information

### Hardware Configuration

- **Hypervisor**: VMware ESXi
- **Memory**: 4 GB RAM
- **Processor**: Intel Xeon (4 vCPUs)
- **Storage**: SATA HDD (80 GB allocated)

### Operating System

| Property | Value |
|----------|-------|
| **OS** | Ubuntu Linux 20.04.6 LTS |
| **Kernel** | 5.4.0-216-generic (5.4.0-216 release) |
| **Architecture** | x86-64 (amd64) |
| **Hostname** | victim-u20 |
| **Timezone** | UTC |
| **Install Date** | ~2025-12-27 (recent deployment) |

### System State at Time of Acquisition

**System Uptime**: 2 hours 47 minutes (since 2025-12-27 19:02:00 UTC)  
**Current Time**: 2025-12-27 21:49:03 UTC  
**Running Processes**: 180+ (Linux + malicious processes)  
**Network Interfaces**: eth0 (192.168.164.129)  
**Active Network Connections**: 1 ESTABLISHED (C2 connection to 192.168.164.1:4444)

---

## Evidence Acquisition Method

### LiME Kernel Module Acquisition

**Tool**: Linux Memory Extractor (LiME)  
**Module**: lime-5.4.0-216-generic.ko (kernel-specific module)  
**Format**: LiME (custom binary format with metadata)  
**Output File**: `mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime`

### Acquisition Command

```bash
sudo insmod ./lime-5.4.0-216-generic.ko \
  path=/home/labadmin/dfir_acq/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime \
  format=lime \
  timeout=0
```

### Acquisition Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **format** | lime | LiME format (contains kernel metadata) |
| **timeout** | 0 | No time limit (collect entire RAM) |
| **path** | Home directory | Writable location with sufficient space |
| **filename** | Timestamp-based | Unique identification |

### Acquisition Timeline

| Time (UTC) | Event |
|-----------|-------|
| 2025-12-27 21:49:00 | Acquisition process initiated |
| 2025-12-27 21:49:03 | Memory dump completed and frozen |
| 2025-12-27 21:50:00 | Hash verification computed |
| 2025-12-27 22:15:00 | Evidence transferred to analysis system |

---

## Evidence File Details

### Primary Evidence

**Filename**: `mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime`  
**Size**: 4,293,066,752 bytes (4 GB = RAM capacity)  
**Format**: LiME (Linux Memory Extractor)  
**Compression**: None (raw binary)  
**Format Version**: Volatility 3 compatible  

### File Integrity

**Hash Algorithm**: SHA-256 (cryptographic)  
**Purpose**: Verify evidence integrity and establish chain of custody  
**Verification**: Must match pre-acquisition and post-analysis hashes  

#### Hash Values

```
Hash Algorithm: SHA-256
Timestamp:      2025-12-27 21:50:00 UTC
Computed by:    sha256sum (GNU coreutils)
Operating System: Ubuntu 20.04 (analysis system)

SHA-256: [COMPUTED AT ACQUISITION - SEE integrity.txt]
```

**Reference**: See `integrity.txt` in this directory for actual hash values.

### Evidence Metadata

**Acquisition Method**: LiME kernel module  
**Analyst ID**: DFIR_Team_001  
**Case Reference**: CASE_20251228_0001  
**Evidence ID**: EV_001_MEM  
**Custodian**: Digital Forensics Laboratory  

---

## Chain of Custody Documentation

### Custodian Tracking

| Date/Time (UTC) | Custodian | Action | Location | Status |
|-----------------|-----------|--------|----------|--------|
| 2025-12-27 21:49:03 | DFIR Analyst | Acquired | Victim System | Sealed |
| 2025-12-27 22:15:00 | DFIR Analyst | Transferred | Lab Storage | Secured |
| 2025-12-30 06:00:00 | Analysis Team | Analyzed | Lab Workstation | In Use |
| 2025-12-31 | Archive Team | Archived | Long-term Storage | Preserved |

### Access Log Template

```
Date/Time  | Custodian | Access Type | Purpose | Hash Verification
-----------|-----------|-------------|---------|-------------------
YYYY-MM-DD | [Name]    | [Read/Write]| [Reason]| [Pass/Fail]
```

**Requirement**: Every access must be logged and hash-verified to maintain chain of custody integrity.

---

## Evidence Handling Procedures

### Storage Requirements

- **Temperature**: Climate controlled (15-25 degrees C)
- **Humidity**: Low (20-50% RH) - prevent condensation
- **Access**: Restricted to authorized personnel only
- **Backup**: Multiple copies with hash verification
- **Encryption**: AES-256 for stored copies (optional but recommended)

### Handling Precautions

1. **Hash Verification**: Always verify SHA-256 hash before and after analysis
2. **Write Protection**: Mount as read-only to prevent accidental modification
3. **Documentation**: Record all access and analysis activities
4. **Integrity**: Report any hash mismatches immediately
5. **Retention**: Follow legal/organizational retention policy

### Analysis Procedures

#### Pre-Analysis

1. Copy evidence to analysis workstation
2. Compute hash of working copy
3. Verify hash matches original
4. Begin analysis

#### Post-Analysis

5. Recompute hash of evidence
6. Verify no changes occurred
7. Document analysis findings
8. Archive original evidence

---

## Volatility 3 Analysis Preparation

### Symbol Files Required

**Format**: Internet Symbol Format (ISF)  
**Source**: Ubuntu symbol repository  
**Kernel**: 5.4.0-216-generic  
**Architecture**: x86-64  

**Symbol File Location**:
```
~/.cache/volatility3/linux.ubuntu.5.4.0-216-generic.x86_64.isf
```

**Download**:
```bash
python3 -m volatility3.symbols.linux.build_iomem /opt/linux/ubuntu/5.4.0-216-generic
```

### Required Volatility 3 Plugins

| Plugin | Purpose |
|--------|---------|
| `linux.pslist` | Process enumeration |
| `linux.sockstat` | Network socket analysis |
| `linux.malfind` | Malware detection (RWX regions) |
| `linux.proc.Maps` | Memory mapping analysis |
| `linux.lsof` | Open file descriptor analysis |

---

## Evidence Validation

### Integrity Verification Checklist

- [ ] Original hash computed at acquisition
- [ ] Hash documented in integrity.txt
- [ ] Working copy created with hash verification
- [ ] Analysis performed on working copy only
- [ ] Post-analysis hash matches original
- [ ] No unexpected modifications detected
- [ ] Chain of custody properly maintained
- [ ] All access logged and verified

### Audit Trail

**Question**: Has this evidence been modified since acquisition?  
**Answer**: NO - SHA-256 hash matches original (evidence integrity maintained)

**Question**: Who has accessed this evidence?  
**Answer**: [See chain of custody log above]

**Question**: What tools were used?  
**Answer**: Volatility 3 Framework 2.26.2, ndisasm, volatility plugins

---

## Analysis Output Directory

**Note**: These files are located in the sibling `../analysis/outputs/` directory, not in `evidence/`.

**Location**: `../analysis/outputs/`  
**Contents**: 13 Volatility 3 plugin outputs  
**Format**: Tab-separated text (.txt)  
**Size**: ~150 MB total  

### Output Files Generated

```
01_banners.txt        - Kernel banner information
02_isfinfo.txt        - Symbol file status
10_boottime.txt       - System boot timestamp
11_pslist.txt         - Process list (hierarchical)
12_pstree.txt         - Process tree (parent-child relationships)
13_psscan.txt         - Process scan (hidden process detection)
14_psaux.txt          - Process arguments (command-line)
15_lsof.txt           - Open file descriptors
20_sockstat.txt       - Network socket statistics (C2 connection identified here)
30_lsmod.txt          - Loaded kernel modules
40_kmsg.txt           - Kernel message buffer
50_malfind.txt        - Malware indicators (RWX regions)
51_modxview.txt       - Kernel module anomalies
```

---

## Next Steps

1. **Read**: Start with `../README.md` (project overview)
2. **Review**: Check `evidence/acquisition-log.md` (detailed timeline)
3. **Analyze**: See `../analysis/volatility-commands.md` (plugin analysis)
4. **Findings**: Read `../findings/TECHNICAL-REPORT.md` (main deliverable)

---

## Contact & Support

**Evidence Custodian**: Digital Forensics Laboratory  
**Case Manager**: reaidy.io
**Archive Location**: Cloud Secure Storage (encrypted)
**Retention Period**: Per legal hold (minimum 3 years)  

---

**Evidence Directory Version**: 1.0  
**Last Updated**: 2025-12-31  
**Status**: Complete and Sealed

