# Case Notes - CASE_20251228_0001

## Investigation Objective
Perform comprehensive memory forensics analysis of a potentially compromised Linux system to identify indicators of compromise, establish attack timeline, and document all malicious artifacts for incident response.

## Scope

### In Scope:
- ✅ Complete RAM memory analysis via Volatility3
- ✅ Process identification and analysis
- ✅ Network connection forensics
- ✅ Code injection detection (malfind)
- ✅ Bash history recovery from memory
- ✅ Kernel module analysis
- ✅ Timeline reconstruction
- ✅ IOC extraction
- ✅ Detailed technical reporting

### Out of Scope:
- ❌ Disk/filesystem forensics (no disk image acquired)
- ❌ Pagefile/swap analysis (not captured)
- ❌ Network traffic capture (PCAP) - not available
- ❌ Real-time monitoring/live forensics beyond memory
- ❌ Malware reverse engineering (binaries not extracted for RE)
- ❌ Threat attribution or APT identification
- ❌ Legal proceedings or court admissibility requirements

## Investigation Approach

### Phase 0: Environment Setup
Documented victim VM configuration, network topology, and intentionally planted artifacts for training purposes.

### Phase 1: Memory Acquisition
Used LiME kernel module for live memory acquisition following RFC 3227 guidelines. Captured volatile data (process list, network connections) before acquisition.

### Phase 2: Examination
Executed 13 Volatility3 plugins systematically:
1. Validation (banners, isfinfo)
2. Process analysis (pslist, pstree, psscan, psaux, lsof)
3. Network analysis (sockstat)
4. Kernel analysis (lsmod, kmsg)
5. Artifact recovery (bash history)
6. Malware detection (malfind, modxview)

### Phase 3: Analysis & Reporting
Cross-referenced all plugin outputs, constructed attack timeline, extracted IOCs, and produced professional technical report with executive summary.

## Assumptions

1. **Lab Environment**: This is a controlled DFIR training environment on a host-only network (192.168.164.0/24). All activity is isolated from production networks.

2. **Planted Artifacts**: The compromise scenario includes deliberately planted artifacts for educational purposes:
   - Hidden user accounts
   - Systemd persistence
   - Code injection binaries
   - C2 simulation scripts

3. **Timing Accuracy**: Process start times estimated from PID ordering and bash command timestamps. Boot time from `linux.boottime` plugin is authoritative (confidence: very high).

4. **Memory Completeness**: LiME acquisition with `timeout=0` captured complete physical RAM. No pages were skipped due to access restrictions.

5. **Network Topology**: Victim VM dual-NIC configuration:
   - ens33 (NAT): Internet access only
   - ens34 (Host-only): Forensic workstation access and attacker ingress

6. **SSH Access**: Attacker accessed via SSH on host-only network. No evidence of external/internet-based compromise vector.

7. **No Anti-Forensics**: Attacker did not employ memory anti-forensics techniques (no kernel rootkits, no process hiding beyond dot-prefix naming, complete bash history preserved).

8. **Tool Accuracy**: Volatility3 2.26+ with correct ISF symbols for Ubuntu 5.4.0-216-generic assumed to produce accurate results. All plugin outputs validated against expected headers.

## Deviations from Standard IR

- **No Disk Image**: Standard IR would include full disk forensics. This investigation focused solely on memory due to scope/training objectives.

- **No Real-Time Containment**: In production IR, system would be isolated immediately upon compromise detection. Here, compromise remained active through memory acquisition for forensic training purposes.

- **Documentation Emphasis**: Unusually complete documentation (all bash commands, exact timestamps) due to training environment. Real-world attackers typically employ anti-forensic techniques to destroy command history.

## Key Decisions

### Why LiME vs. Other Methods?
- ✅ LiME: Kernel module, complete physical memory, preserves page layout
- ❌ /dev/mem: Deprecated in modern kernels, incomplete capture
- ❌ /proc/kcore: Does not capture all physical memory
- ❌ Hardware freezing: Not available in VM environment

### Why Volatility3 vs. Volatility2?
- ✅ Volatility3: Active development, better Linux support, ISF symbol format
- ❌ Volatility2: Deprecated, DWARF profiles harder to generate

### Plugin Selection Rationale
- **pslist + psscan + pstree**: Cross-validation for hidden processes
- **psaux**: Command-line recovery (rare in compromises)
- **lsof**: Network sockets tied to PIDs
- **sockstat**: Network connections confirmation
- **bash**: Command history from memory (critical for timeline)
- **malfind**: RWX page detection (code injection)
- **modxview**: Kernel module integrity (rootkit detection)

## Challenges Encountered

1. **ISF Symbol Mismatch** (Resolved):
   - Initial attempt used wrong kernel version symbols
   - Solution: Downloaded exact Ubuntu_5.4.0-216-generic ISF JSON

2. **Large Output Files** (Managed):
   - lsof.txt (135 KB) and kmsg.txt (188 KB) were large
   - Solution: Used `tee` for simultaneous display and file save

3. **Process Start Time Estimation** (Limitation):
   - Volatility3 does not provide precise process creation timestamps
   - Solution: Inferred from bash history, PID ordering, and boottime

4. **Bash History Completeness** (Unexpected Benefit):
   - Full attacker command history preserved in memory
   - Rare in real attacks (usually cleared with `history -c`)
   - Provided complete attack narrative

## Lessons Learned

1. **Memory Forensics Power**: Single memory image revealed entire attack chain from initial access to persistence to code injection.

2. **Bash History Gold**: The `linux.bash` plugin recovered complete attacker command history—a forensic artifact often destroyed in real attacks.

3. **Cross-Validation Critical**: Multiple plugins (pslist, psscan, pstree, psaux) provided redundancy and confidence in findings.

4. **Timeline Precision**: Boot time + bash timestamps + PID ordering enabled 1-minute precision timeline reconstruction.

5. **Documentation Value**: Detailed notes and command logs (following RFC 3227) enabled complete reproducibility.

## Follow-Up Questions (If Real Incident)

1. How did attacker obtain SSH credentials? (password spray, credential stuffing, insider threat?)
2. Was Apache2 installation legitimate or attacker-added?
3. Are there additional backdoors in filesystem not visible in memory?
4. What was attacker's ultimate objective? (data exfil, ransomware, persistence for pivot?)
5. Is 192.168.164.1:4444 attacker workstation or compromised internal host?

## References

- RFC 3227: Guidelines for Evidence Collection and Archiving
- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- LiME GitHub: https://github.com/504ensicsLabs/LiME
- Volatility3 Documentation: https://volatility3.readthedocs.io/

---

Last Updated: 2025-12-29
Investigator: labadmin
Status: INVESTIGATION COMPLETE
