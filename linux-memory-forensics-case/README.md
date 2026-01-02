# Forensic Case Repository: CASE_20251228_0001

**Case ID**: CASE_20251228_0001
**Case Title**: Linux Memory Compromise
**Analyst**: Sai (DFIR Analyst)
**Date**: 2025-12-31
**Status**: Closed / Archived

---

## Case Summary

This repository contains the complete forensic record for CASE_20251228_0001, involving a confirmed memory injection attack against a Linux system (Ubuntu 20.04). Analysis confirmed the presence of malicious processes, active Command & Control (C2) channels, and code injection into system services.

**Primary Findings:**
*   **Compromise Type**: Memory Injection / Process Hollowing
*   **Affected System**: victim-u20 (192.168.164.129)
*   **Confirmed C2**: 192.168.164.1:4444
*   **Malware Type**: Python-based Reverse Shell / Shellcode Injector

---

## Repository Structure

### 1. Evidence (`evidence/`)
Contains chain of custody documentation, acquisition logs, and cryptographic integrity hashes.
*   `acquisition-log.md`: Primary chain of custody record.
*   `integrity.txt`: SHA-256 verification hashes.

### 2. Analysis (`analysis/`)
Contains technical examination outputs and processing logs.
*   `outputs/`: Raw output from Volatility 3 plugins.
*   `volatility-commands.md`: Log of executed analysis commands.

### 3. Findings (`findings/`)
Contains formal forensic reports and detailed artifact analysis.
*   `executive-summary.md`: High-level incident overview.
*   `TECHNICAL-REPORT.md`: Comprehensive forensic analysis report.
*   `malicious-processes.md`: Detailed analysis of compromised PIDs.
*   `network-c2-analysis.md`: Analysis of C2 infrastructure.
*   `memory-injection.md`: Analysis of injected code segments.
*   `shellcode-analysis.md`: Disassembly and analysis of payloads.
*   `python-malware-analysis.md`: Analysis of recovered Python artifacts.

### 4. Indicators of Compromise (`iocs/`)
Contains actionable threat intelligence derived from analysis.
*   `indicators.txt`: List of file, network, and memory indicators.
*   `yara-rules.yar`: YARA signatures for detection.

### 5. Methodology (`methodology/`)
Contains documentation of tools and procedures used during the investigation.
*   `procedures.md`: Investigative procedure documentation.
*   `tools-used.md`: Versioning and configuration of forensic tools.

---

## Administrative Information

**Classification**: CONFIDENTIAL - FORENSIC RECORD
**Retention**: Indefinite
**Legal Note**: This repository constitutes the formal record of investigation. All timestamps are UTC.
