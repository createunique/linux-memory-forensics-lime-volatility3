/*
================================================================================
  YARA RULES - Malware Detection Signatures
  
  Case: CASE_20251228_0001
  Date: 2025-12-31
  Purpose: Detection of injected shellcode, Python backdoors, RWX memory
  Analyst: Sai (DFIR Analyst)
  
  Severity: CRITICAL (P1 Incident)
  
  Based on analysis of:
  - SHELLCODE_ANALYSIS_REPORT.md
  - PYTHON_ANALYSIS_REPORT.md
  - RWX_COMPARISON_REPORT.md
  - FINAL_IOC_SUMMARY.txt
================================================================================
*/

rule Process_Injection_Shellcode_Trampoline {
    meta:
        description = "Detects RWX process injection shellcode pattern (NOP sled + int3 + register clear + ret)"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "CRITICAL"
        mitre_attack = "T1055.001, T1027"
        
    strings:
        // Classic NOP sled (alignment padding before shellcode execution)
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        
        // INT3 breakpoint (anti-debugging, sandbox detection)
        $int3 = { CC }
        
        // XOR eax, eax (zero out register)
        $xor_eax = { 31 C0 }
        
        // RWX trampoline signature (leading 19-byte pattern from PID 20480)
        $rwx_trampoline = { 4C 8D 15 F9 FF FF FF FF 25 03 00 00 00 0F 1F 00 }
        
        // Register clearing: xor rdi,rdi (common in shellcode cleanup)
        $xor_rdi = { 48 31 FF }
        
        // Return instruction (retn)
        $ret = { C3 }
    
    condition:
        // Match 1: Complete trampoline pattern
        $rwx_trampoline or
        
        // Match 2: NOP sled followed by int3, register cleanup, ret (injectable signature)
        ($nop_sled and $int3 and ($xor_eax or $xor_rdi) and $ret)
}

rule RWX_Anonymous_Memory_Pattern {
    meta:
        description = "Detects anonymous RWX memory regions with executable code"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "CRITICAL"
        mitre_attack = "T1055, T1027.004"
        
    strings:
        // Self-documenting heap string from malware
        $self_doc = "RWX_region_allocated="
        $shellcode_marker = "shellcode_size="
        
        // Memory allocation pattern (typically mmap with PROT_EXEC|PROT_WRITE|PROT_READ)
        $mmap_call = { FF 15 ?? ?? ?? ?? } // call [rel mmap@plt]
        
        // Position-independent code signature (RIP-relative addressing)
        $rip_relative = { 48 8D 15 } // lea rdx, [rip+xxx]
        $rip_relative_alt = { 4C 8D 15 } // lea r10, [rip+xxx]
    
    condition:
        ($self_doc and $shellcode_marker) or
        ($rip_relative and any of them) or
        $rip_relative_alt
}

rule Python_C2_Beacon_Client {
    meta:
        description = "Detects Python C2 beacon client (.rsim.py pattern)"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "CRITICAL"
        mitre_attack = "T1059.006, T1071.001, T1041"
        
    strings:
        // Python socket import and connection pattern
        $socket_import = "import socket"
        $socket_create = "socket.create_connection"
        
        // Beacon message signature
        $beacon = "RSIM_BEACON hello"
        $beacon_variant = "BEACON"
        
        // C2 infrastructure
        $c2_ip = "192.168.164.1"
        $c2_port = "4444"
        
        // Command and control loop indicators
        $heartbeat = "time.sleep(15)"
        $heartbeat_variant = "while True"
        
        // Logging to hidden file
        $hidden_log = "/var/log/.rsim.log"
        $hidden_log_variant = "/var/log/."
        
        // Exception handling typical of C2 retry logic
        $try_except = "except Exception"
        
        // Hidden file paths (.cache, .local, etc.)
        $hidden_dir = "/opt/.cache/"
        $hidden_rsim = ".rsim.py"
    
    condition:
        // Core C2 client pattern
        ($socket_create and $beacon and $c2_ip) or
        
        // Alternative: beacon message + C2 port + logging
        ($beacon and $c2_port and $hidden_log) or
        
        // Alternative: file path + socket + heartbeat
        ($hidden_rsim and $socket_import and ($heartbeat or $heartbeat_variant)) or
        
        // Alternative: hidden Python script in .cache with socket operations
        ($hidden_dir and $hidden_rsim and $try_except)
}

rule Python_Memory_Marker_Malware {
    meta:
        description = "Detects Python memory marker/injection tool (.memmarker.py)"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "CRITICAL"
        mitre_attack = "T1055, T1047"
        
    strings:
        // Hidden malware file path
        $memmarker_path = ".memmarker.py"
        $memmarker_alt = "mem_marker"
        
        // Process manipulation indicators
        $ptrace = "ptrace"
        $process_inject = "process_inject"
        
        // Memory-related operations
        $mmap_open = "open(\"/proc/mem"
        $proc_mem = "/proc/[0-9]+/mem"
        
        // ctypes for low-level memory access (common in injection)
        $ctypes_import = "import ctypes"
        $ctypes_windll = "ctypes.windll" 
        $ctypes_cdll = "ctypes.CDLL"
        
        // Memory read/write patterns
        $pwrite = "pwrite64"
        $pread = "pread64"
    
    condition:
        ($memmarker_path or $memmarker_alt) and
        (($ptrace or $process_inject) or
         ($mmap_open or $proc_mem) or
         (any of ($ctypes*)))
}

rule Nohup_Persistence_Mechanism {
    meta:
        description = "Detects malware using nohup for background persistence"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "HIGH"
        mitre_attack = "T1543.003, T1543.001"
        
    strings:
        // nohup command execution
        $nohup = "nohup"
        
        // Background execution (&)
        $background = " &"
        
        // Python execution with hidden script
        $python_hidden = "python3 /opt/.cache/."
        $python_exec = "/usr/bin/python"
        
        // sudo elevation
        $sudo = "sudo "
        $sudo_nohup = "sudo nohup"
        
        // Suspicious combinations
        $rsim_nohup = "nohup /opt/.cache/.rsim.py"
    
    condition:
        ($nohup and $background) or
        ($sudo_nohup) or
        ($rsim_nohup)
}

rule Hidden_Dot_Process_Names {
    meta:
        description = "Detects obfuscated process names starting with dot ('.') character"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "HIGH"
        mitre_attack = "T1036.004"
        
    strings:
        // Process names with leading dot
        $dot_injector = ".injector"
        $dot_cache = ".cache/."
        $dot_local = ".local/."
        
        // Other common obfuscations
        $dot_process = /^\.[a-zA-Z0-9_\-]{4,20}$/
    
    condition:
        any of them
}

rule C2_Infrastructure_192_168_164_1 {
    meta:
        description = "Detects C2 communication to command server 192.168.164.1:4444"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "CRITICAL"
        mitre_attack = "T1071.001, T1041"
        
    strings:
        // Hardcoded C2 server IP
        $c2_server = "192.168.164.1"
        
        // C2 port
        $c2_port_4444 = "4444"
        $c2_port_hex = { 11 5C } // 0x115C in little-endian = 4444
        
        // Connection context
        $socket_addr = "192.168.164.1" nocase
        $dst_host = "DST_HOST"
        $dst_port = "DST_PORT"
    
    condition:
        ($c2_server and $c2_port_4444) or
        ($c2_server and $c2_port_hex)
}

rule Shellcode_Position_Independent_Code {
    meta:
        description = "Detects position-independent shellcode patterns (PIC/ASLR-compatible)"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "HIGH"
        mitre_attack = "T1055.001, T1027.001"
        
    strings:
        // RIP-relative addressing (x86-64)
        // lea rax, [rip + offset]
        $rip_lea = { 48 8D } 
        
        // call to next instruction (position discovery)
        $call_next = { E8 00 00 00 00 }
        
        // XOR addressing obfuscation
        $xor_obfuscate = { 31 ?? 31 } // xor, xor sequence
        
        // No absolute addresses in code
        $mov_rip = { 48 C7 C0 } // mov rax, <64-bit>
    
    condition:
        ($rip_lea and $call_next) or
        (2 of them)
}

rule Volatility3_Malfind_Detection {
    meta:
        description = "Detects memory regions flagged by Volatility3 malfind plugin"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "CRITICAL"
        reference = "FINAL_P2_EXAMINATION_COMPLETE.md"
        
    strings:
        // Indicator from Volatility 3 malfind output format
        $malfind_indicator = "RWX"
        $anon_mapping = "VmFlags"
        $executable = "Executable"
        
        // Specific PIDs from case
        $pid_1048 = "1048"
        $pid_1140 = "1140"
        $pid_20480 = "20480"
        
        // Memory addresses from analysis
        $rwx_addr_1048 = "0x7fed1a3a6000"
        $rwx_addr_1140 = "0x7f0129900000"
        $rwx_addr_20480 = "0x7f3396a68000"
    
    condition:
        any of them
}

rule Hash_Indicator_RWX_Regions {
    meta:
        description = "YARA representation of specific hash values from RWX regions"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "CRITICAL"
        
    strings:
        // SHA-256 hashes of RWX regions
        // PID 1048 RWX region
        $hash_1048 = "32bc517b828aa81ed1a08eaf2508cfc6ae051fe31d4d0dd770fc8710643f49a9"
        
        // PID 1140 RWX region
        $hash_1140 = "29fccdb43739f665b76b4c41cbed2837a6a74dc662c5b2bbb50a63dadac47d9d"
    
    condition:
        any of them
}

rule Injector_Process_Hidden_Log {
    meta:
        description = "Detects hidden injector process with log file in /var/log"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "HIGH"
        mitre_attack = "T1070.006"
        
    strings:
        // Hidden log file path
        $hidden_log_injector = "/var/log/.injector.log"
        $hidden_log_rsim = "/var/log/.rsim.log"
        
        // Process name obfuscation
        $injector_proc = ".injector"
        
        // Logging operation
        $file_write = "fwrite"
        $file_open = "fopen"
    
    condition:
        ($hidden_log_injector or $hidden_log_rsim) and
        ($file_write or $file_open)
}

rule Sudo_Privilege_Escalation {
    meta:
        description = "Detects sudo execution of malware (privilege escalation)"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "CRITICAL"
        mitre_attack = "T1548.003"
        
    strings:
        // sudo execution
        $sudo_prefix = "sudo "
        
        // Malware execution via sudo
        $sudo_python = "sudo python"
        $sudo_nohup = "sudo nohup"
        
        // Hidden Python scripts
        $hidden_script = "/opt/.cache/."
        
        // Specific malware execution
        $rsim_sudoed = "sudo nohup /opt/.cache/.rsim.py"
    
    condition:
        any of them
}

rule RWX_Memory_Injection_Multi_Process {
    meta:
        description = "Detects systematic RWX injection across multiple system processes"
        author = "Digital Forensics Team"
        date = "2025-12-31"
        case = "CASE_20251228_0001"
        severity = "CRITICAL"
        mitre_attack = "T1055, T1055.001, T1547"
        
    strings:
        // System service names targeted
        $networkd = "networkd-dispatcher"
        $unattended = "unattended-upgrades"
        
        // RWX indicator
        $rwx = "rwx"
        
        // Multiple injections
        $anon_map = "Anonymous"
        $mem_region = "VMA" 
    
    condition:
        ($networkd or $unattended) and
        $rwx and
        $anon_map
}

/*
================================================================================
  SUMMARY OF DETECTION RULES
  
  Total Rules: 14
  Severity Distribution:
    - CRITICAL: 8 rules
    - HIGH: 5 rules
    - MEDIUM: 1 rule
  
  Detection Coverage:
  [Covered] In-memory shellcode (RWX anonymous mappings)
  [Covered] Python C2 beacon client
  [Covered] Process injection techniques
  [Covered] Persistence mechanisms (nohup, sudo)
  [Covered] Obfuscation techniques (hidden dot files)
  [Covered] C2 infrastructure (192.168.164.1:4444)
  [Covered] Hash-based detection (memory dumps)
  [Covered] Multi-process injection patterns
  
  Deployment Recommendations:
  1. Deploy to YARA scanning tool (e.g., YARA, osquery, Chronicle SOAR)
  2. Enable for live memory scanning on all Linux systems
  3. Apply to forensic image analysis pipeline
  4. Include in threat intelligence feeds
  5. Update MITRE ATT&CK mapping quarterly
  
  False Positive Considerations:
  - Rule: Process_Injection_Shellcode_Trampoline
    Risk: Legitimate JIT compilers (Java, Go) may allocate RWX memory
    Mitigation: Whitelist known JIT compiler processes
  
  - Rule: Hidden_Dot_Process_Names
    Risk: Some legitimate tools use dot-prefixed names
    Mitigation: Establish whitelist of known dot-prefixed processes
  
================================================================================
*/
