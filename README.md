# Linux Memory Forensics Investigation — CASE_20251228_0001

## Overview
Professional DFIR memory forensics investigation of a compromised Ubuntu 20.04 system.

**Status: ACTIVELY COMPROMISED**

## Quick Facts
- **Case ID:** CASE_20251228_0001
- **System:** victim-u20 (Ubuntu 20.04.6, kernel 5.4.0-216-generic)
- **Evidence:** LiME memory dump (~1.2 GB)
- **Analysis Tool:** Volatility3 + Linux ISF symbols
- **Key Finding:** Multi-stage post-exploitation with persistence + C2 staging

## Attack Summary
- Attacker SSH session with 50+ commands executed
- Persistence: Systemd service + hidden user (backupsvc)
- Code injection: rwx memory pages with shellcode
- C2: Reverse shell configured to 192.168.164.1:4444

## Folder Structure
```
├── case-info/           # Case metadata and chain of custody
├── phase-0-environment/ # Lab VM setup and planted artifacts
├── phase-1-collection/  # Memory acquisition (LiME)
├── phase-2-examination/ # Volatility3 analysis outputs
├── phase-3-reporting/   # Final findings and IOCs
├── reference-docs/      # Supporting documentation
└── evaluator/           # Checklist and grading rubric
```

## Key Documents
- **Executive Summary:** phase-3-reporting/executive-summary.txt
- **Full Analysis Report:** phase-3-reporting/analysis-report.md
- **IOCs (CSV):** phase-3-reporting/iocs-found.csv
- **Attack Timeline:** phase-3-reporting/timeline.txt

## How to Review
1. Read `phase-3-reporting/executive-summary.txt` for overview
2. Review `phase-3-reporting/timeline.txt` for attack sequence
3. Check `phase-3-reporting/iocs-found.csv` for indicators
4. Examine `phase-2-examination/examination-outputs/` for raw Volatility3 results

## Tools Used
- **Memory Acquisition:** LiME (Linux Memory Extractor)
- **Memory Analysis:** Volatility3 + Linux ISF JSON
- **Case Artifacts:** Ubuntu 20.04 filesystem + memory strings

## Evidence Integrity
All evidence files are SHA-256 hashed and verified.

## Timeline Summary
- **2025-12-27 19:02:00 UTC** — System boot
- **2025-12-27 19:04:43 UTC** — Attacker SSH login
- **2025-12-27 20:10:39 UTC** — Systemd persistence installed
- **2025-12-27 21:48:36 UTC** — Memory dump acquired

---
**Investigation Complete:** 2025-12-28  
**System Status:** CRITICAL - Immediate isolation recommended  
**Analyst:** labadmin
