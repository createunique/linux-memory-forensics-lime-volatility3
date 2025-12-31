# Linux Memory Forensics Investigation — CASE_20251228_0001

<div align="center">

**SECURITY STATUS: ACTIVELY COMPROMISED — CRITICAL**

[![DFIR](https://img.shields.io/badge/DFIR-Memory%20Forensics-red?style=for-the-badge)](https://github.com/createunique/linux-memory-forensics-lime-volatility3)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)](https://ubuntu.com)
[![Volatility3](https://img.shields.io/badge/Analysis-Volatility3-blue?style=for-the-badge)](https://github.com/volatilityfoundation/volatility3)

</div>

---

## Executive Overview

This repository documents a **professional Digital Forensics and Incident Response (DFIR)** investigation into a **confirmed compromise** of an Ubuntu 20.04 server. The investigation utilizes industry-standard memory acquisition and analysis techniques to identify attacker activity, extract Indicators of Compromise (IOCs), and reconstruct the attack timeline.

**Classification:** UNCLASSIFIED  
**Handling:** TLP: WHITE (Disclosure not limited)  
**Investigation Type:** Post-Incident Forensic Analysis  
**Methodology:** NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response)

---

## Case Information

| **Field** | **Details** |
|-----------|-------------|
| **Case ID** | CASE_20251228_0001 |
| **Incident Type** | Unauthorized Access, Post-Exploitation, Persistence |
| **System Identifier** | victim-u20 |
| **Operating System** | Ubuntu 20.04.6 LTS (Focal Fossa) |
| **Kernel Version** | 5.4.0-216-generic (x86_64) |
| **Memory Size** | ~1.2 GB RAM |
| **Evidence Format** | LiME raw memory dump (. lime) |
| **Acquisition Date** | 2025-12-27 21:48:36 UTC |
| **Analysis Date** | 2025-12-28 |
| **Lead Analyst** | labadmin |
| **Status** | ⚠️ **CRITICAL - Immediate Containment Required** |

---

## Key Findings

### Attack Vector
- **Initial Access:** SSH compromise (credentials unknown — likely brute force or credential theft)
- **First Attacker Activity:** 2025-12-27 19:04:43 UTC

### Attacker Tactics, Techniques and Procedures (TTPs)

#### 🔴 **MITRE ATT&CK Mapping**

| **Tactic** | **Technique** | **Evidence** |
|------------|---------------|--------------|
| **Initial Access** | T1078 - Valid Accounts | SSH login as legitimate user |
| **Execution** | T1059.004 - Unix Shell | 50+ bash commands executed via SSH |
| **Persistence** | T1543.002 - Systemd Service | Malicious service `backup-monitor.service` |
| **Privilege Escalation** | T1078. 003 - Local Accounts | Hidden user account:  `backupsvc` (UID 1001) |
| **Defense Evasion** | T1140 - Deobfuscate/Decode Files | Staged shellcode in process memory |
| **Command and Control** | T1071.001 - Web Protocols | Reverse shell to 192.168.164.1:4444 |
| **Collection** | T1005 - Data from Local System | Multiple file access operations |

### Critical IOCs Identified

#### **Network Indicators**
- **C2 Server:** `192.168.164.1:4444` (TCP)
- **Protocol:** Reverse shell (likely netcat or similar)

#### **Host-Based Indicators**
- **Malicious Systemd Service:** `/etc/systemd/system/backup-monitor.service`
- **Rogue User Account:** `backupsvc` (UID:  1001, GID: 1001)
- **Suspicious Process:** PID with injected shellcode (rwx memory regions)
- **Persistence Location:** Systemd unit configured for automatic startup

#### **Memory Artifacts**
- **Code Injection:** Executable shellcode in RWX memory pages
- **Active SSH Session:** Long-duration connection with command history
- **Credential Material:** Potential cleartext secrets in memory

---

## 📁 Repository Structure

```
linux-memory-forensics-lime-volatility3/
│
├── 📂 case-info/                    # Case Management & Chain of Custody
│   ├── case-manifest.txt            # Case identification and scope
│   ├── chain-of-custody.csv         # Evidence handling log
│   └── investigator-notes.txt       # Analyst observations
│
├── 📂 phase-0-environment/          # Lab Environment Setup
│   ├── vm-setup/                    # VM configuration and deployment
│   ├── attacker-artifacts/          # Simulated attack scripts (for educational context)
│   └── environment-details.txt      # Infrastructure documentation
│
├── 📂 phase-1-collection/           # Memory Acquisition Phase
│   ├── lime-acquisition/            # LiME kernel module and dump
│   ├── acquisition-logs.txt         # Collection metadata and timestamps
│   └── hash-verification.txt        # SHA-256 checksums for integrity
│
├── 📂 phase-2-examination/          # Forensic Analysis Phase
│   ├── volatility3-setup/           # Tool configuration and ISF symbols
│   ├── examination-outputs/         # Raw plugin outputs (JSON/TXT)
│   ├── strings-analysis/            # Memory strings extraction
│   └── analysis-notes.md            # Detailed technical findings
│
├── 📂 phase-3-reporting/            # Deliverables & Documentation
│   ├── executive-summary.txt        # Non-technical summary for stakeholders
│   ├── analysis-report.md           # Complete technical report
│   ├── iocs-found.csv               # Structured IOC list (OpenIOC/STIX compatible)
│   ├── timeline.txt                 # Chronological attack reconstruction
│   └── recommendations.md           # Remediation and hardening guidance
│
├── 📂 reference-docs/               # Supporting Documentation
│   ├── volatility3-plugins-used.md  # Plugin reference and methodology
│   ├── linux-forensics-notes.md     # Linux memory forensics primer
│   └── dfir-resources.md            # Additional reading and tools
│
└── README.md                        # This file
```

---

## Forensic Methodology

### Tools & Techniques

#### **Memory Acquisition**
- **Tool:** [LiME (Linux Memory Extractor)](https://github.com/504ensicsLabs/LiME)
- **Method:** Loadable Kernel Module (LKM) for live memory dumping
- **Format:** Raw physical memory image (.lime)
- **Integrity:** SHA-256 cryptographic hash verification

#### **Memory Analysis**
- **Framework:** [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- **Symbol Files:** Intermediate Symbol Format (ISF) for Linux kernel 5.4.0-216-generic
- **Plugins Used:**
  - `linux. pslist` — Process enumeration
  - `linux.bash` — Bash command history extraction
  - `linux.proc. maps` — Memory region analysis
  - `linux.check_syscall` — Rootkit detection
  - `linux.sockstat` — Network connection enumeration
  - `linux.mount` — Filesystem analysis
  - `linux.keyboard_notifiers` — Keylogger detection

#### **Supporting Analysis**
- **Strings Extraction:** ASCII/Unicode artifact recovery
- **Timeline Analysis:** Temporal correlation of events
- **IOC Extraction:** Structured threat intelligence output

### Forensic Standards Compliance
- **NIST SP 800-86:** Guide to Integrating Forensic Techniques into Incident Response
- **ISO/IEC 27037: 2012:** Guidelines for identification, collection, acquisition, and preservation of digital evidence
- **RFC 3227:** Guidelines for Evidence Collection and Archiving

---

## 📊 Attack Timeline

| **UTC Timestamp** | **Event** | **Artifact Source** | **Significance** |
|-------------------|-----------|---------------------|------------------|
| `2025-12-27 19:02:00` | System boot | Kernel logs / pslist | Baseline establishment |
| `2025-12-27 19:04:43` | **Attacker SSH login** | `/var/log/auth.log`, bash history | **Initial Access** (T1078) |
| `2025-12-27 19:05-19:30` | Reconnaissance commands | Bash history (50+ commands) | Discovery phase (whoami, uname, ps, netstat) |
| `2025-12-27 19:30-20:00` | Privilege escalation attempts | Command history, file access | Potential sudo/SUID exploitation |
| `2025-12-27 20:10:39` | **Systemd persistence installed** | `/etc/systemd/system/` modification | **Persistence** (T1543.002) |
| `2025-12-27 20:15:00` | Hidden user creation (`backupsvc`) | `/etc/passwd`, `/etc/shadow` | **Privilege Escalation** (T1078.003) |
| `2025-12-27 20:30-21:00` | Shellcode injection | Process memory maps (rwx regions) | **Defense Evasion** (T1055) |
| `2025-12-27 21:00-21:45` | C2 staging | Network artifacts, memory strings | **Command & Control** (T1071) |
| `2025-12-27 21:48:36` | **Memory dump acquired** | LiME acquisition log | **Evidence Collection** |

---

## Evidence Integrity

All evidence has been cryptographically verified to ensure integrity and admissibility. 

```bash
# Verification command (example)
sha256sum phase-1-collection/lime-acquisition/victim-u20.lime
# Expected: <hash value recorded in chain-of-custody. csv>
```

**Hash Algorithm:** SHA-256  
**Verification Status:** VERIFIED  
**Chain of Custody:** Complete (see `case-info/chain-of-custody.csv`)

---

## How to Use This Repository

### For DFIR Analysts
1. **Review Executive Summary**  
   ```bash
   cat phase-3-reporting/executive-summary.txt
   ```

2. **Examine Attack Timeline**  
   ```bash
   cat phase-3-reporting/timeline.txt
   ```

3. **Extract IOCs**  
   ```bash
   cat phase-3-reporting/iocs-found.csv
   ```

4. **Analyze Raw Volatility3 Outputs**  
   ```bash
   ls phase-2-examination/examination-outputs/
   ```

### For Educators & Students
- This repository serves as a **complete case study** for teaching Linux memory forensics
- Follow the investigation phases sequentially (0 → 1 → 2 → 3)

### For Security Operations Centers (SOCs)
- Import IOCs from `phase-3-reporting/iocs-found.csv` into SIEM/TIP platforms
- Use TTPs for threat hunting correlation
- Adapt methodology for similar Linux compromises

---

## Incident Response Recommendations

### Immediate Actions (CRITICAL)
1. **Isolate the system** from the network (disconnect NIC or VLAN quarantine)
2. **Terminate the malicious systemd service:**  
   ```bash
   sudo systemctl stop backup-monitor.service
   sudo systemctl disable backup-monitor.service
   ```
3. **Kill any suspicious processes** (identified in `phase-2-examination/`)
4. **Block C2 IP at perimeter firewall:** `192.168.164.1`

### Short-Term Remediation
1. **Remove the rogue user account:**  
   ```bash
   sudo userdel -r backupsvc
   ```
2. **Delete malicious systemd unit file:**  
   ```bash
   sudo rm /etc/systemd/system/backup-monitor.service
   sudo systemctl daemon-reload
   ```
3. **Force password reset** for all accounts (assume credential compromise)
4. **Review all SSH keys** in `/home/*/.ssh/authorized_keys`

### Long-Term Hardening
- Implement **SSH key-based authentication** (disable password auth)
- Deploy **Intrusion Detection System** (AIDE, OSSEC, or Wazuh)
- Enable **SELinux/AppArmor** mandatory access controls
- Configure **centralized logging** to SIEM (immutable logs)
- Conduct **threat hunting** for similar TTPs across environment

**Full recommendations:** See `phase-3-reporting/recommendations.md`

---

## Additional Resources

### Volatility 3 Documentation
- [Volatility 3 Official Docs](https://volatility3.readthedocs.io/)
- [Linux Memory Forensics with Volatility3](https://volatility-labs.blogspot.com/)

### DFIR Learning Resources
- [SANS FOR508:  Advanced Incident Response](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)
- [Digital Forensics Discord Community](https://discord.gg/digitalforensics)
- [DFIR. Training](https://www.dfir.training/)

### Linux Forensics
- [Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [Hal Pomeranz's Linux Forensics Tools](https://github.com/brimorlabs/KernelForge)

### MITRE ATT&CK for Linux
- [Linux ATT&CK Matrix](https://attack.mitre.org/matrices/enterprise/linux/)

---

## Contributing

This is an **educational case study**. Contributions welcome: 
- Additional analysis techniques
- Improved documentation
- Volatility3 plugin enhancements

**Please open an issue before submitting PRs.**

---

## Legal & Ethical Notice

This repository contains **simulated attack artifacts** for educational purposes only. 

- **DO NOT** use these techniques against systems without explicit authorization
- All activity in this repository occurred in an **isolated lab environment**
- Unauthorized computer intrusion is illegal under CFAA, GDPR, and international law

**For educational and authorized security research only.**

---

# License

This investigation documentation is released under **MIT License** for educational use.

See [LICENSE](LICENSE) for details.

---

<div align="center">

**Investigation Status:** COMPLETE  
**Last Updated:** 2025-12-28  
**Next Review:** Post-Remediation Validation Required

---

*"In memory, truth persists."*

</div>
