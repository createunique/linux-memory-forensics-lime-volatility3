# Evidence Acquisition Log
## Chain of Custody & Timeline | CASE_20251228_0001

## Global Case Header

**Analyst**: Sai (DFIR Analyst)
**Role**: Lead Forensic Examiner
**Context**: Forensic Investigation

**Case ID**: CASE_20251228_0001
**Case Title**: Linux Memory Compromise
**Time Standard**: UTC (all timestamps are UTC unless explicitly stated)

**Victim Host**: victim-u20 (Ubuntu 20.04.6 LTS, kernel 5.4.0-216-generic, x86_64)
**Analyst Host**: analystvmu20 (Ubuntu 20.04.6 LTS, kernel 5.4.0-216-generic, x86_64)

**Evidence File**: mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime (4,294,967,296 bytes)
**Evidence SHA-256**: a2b17a37b0250034bb9857ba0c0e34f2724b04b0bf8b51f92d7595682f94c748

**Lab LAN**: victim 192.168.164.129 <-> analyst 192.168.164.130
**Confirmed C2**: 192.168.164.1:4444

---

**Case ID**: CASE_20251228_0001
**Evidence Type**: Linux Memory Dump (LiME format)
**Acquisition Method**: Kernel Module (LiME)
**Analysis Date**: 2025-12-31

---

## Acquisition Timeline

| Date/Time (UTC) | Event | Details | Custodian | Status |
|---|---|---|---|---|
| 2025-12-27 21:49:03 | **Pre-Acquisition Baseline** | System identity + volatile data captured before memory acquisition | Sai (DFIR Analyst) | Complete |
| 2025-12-27 21:49:03 | Hostname/Kernel Version | `uname -a` executed | Sai (DFIR Analyst) | Verified |
| 2025-12-27 21:49:04 | Process Enumeration | `ps auxww` captured pre-acquisition | Sai (DFIR Analyst) | Verified |
| 2025-12-27 21:49:05 | Network State | `ss -anp` captured | Sai (DFIR Analyst) | Verified |
| 2025-12-27 21:49:05 | ARP/Neighbor Cache | `ip neigh` captured | Sai (DFIR Analyst) | Verified |
| 2025-12-27 21:49:06 | Baseline Hash | SHA-256 computed for pre-acq files | Sai (DFIR Analyst) | Verified |
| **2025-12-27 21:49:10** | **LiME Memory Acquisition Start** | Kernel module loaded: `insmod lime-5.4.0-216-generic.ko path=[dump_path] format=lime timeout=0` | Sai (DFIR Analyst) | Complete |
| 2025-12-27 21:52:00 | Acquisition In Progress | LiME acquiring 4 GB RAM (4,294,967,296 bytes) | Sai (DFIR Analyst) | Running |
| 2025-12-27 21:54:33 | **LiME Memory Acquisition Complete** | Module unloaded successfully. RAM dump written to file | Sai (DFIR Analyst) | Complete |
| 2025-12-27 21:54:34 | Permissions Fixed | `chown` and `chmod 640` executed on dump file | Sai (DFIR Analyst) | Complete |
| **2025-12-27 21:54:35** | **Initial Hash** | SHA-256 computed on victim system: **a2b17a37b0250034bb9857ba0c0e34f2724b04b0bf8b51f92d7595682f94c748** | Sai (DFIR Analyst) | Verified |
| 2025-12-27 21:54:40 | Evidence Transfer | `scp` copy initiated from victim to analyst workstation | Sai (DFIR Analyst) | Complete |
| 2025-12-27 21:56:00 | Evidence Received | Memory dump + hash file copied to analyst evidence/ directory | Sai (DFIR Analyst) | Complete |
| **2025-12-27 21:56:05** | **Analyst Hash Verification** | SHA-256 re-computed on analyst system: **a2b17a37b0250034bb9857ba0c0e34f2724b04b0bf8b51f92d7595682f94c748** (MATCH) | Sai (DFIR Analyst) | VERIFIED |
| 2025-12-30 06:00:00 | Evidence Access | Forensic analysis initiated (Volatility 3 examination) | Sai (DFIR Analyst) | In Progress |
