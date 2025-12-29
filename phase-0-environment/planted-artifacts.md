# Planted Forensic Artifacts

## Overview
The following artifacts were intentionally planted on the victim VM to create realistic forensic traces for memory analysis training. All timestamps are UTC.

---

## Artifact 1: In-Memory Marker Process

**File:** `/opt/.cache/mem_marker.py`  
**Created:** 2025-12-27 19:47:06 UTC  
**Size:** ~9 MB in memory  
**Purpose:** Large in-memory process easily detectable with Volatility3

**Description:**
Python script that allocates a large memory buffer and keeps it resident. Creates a distinctive process name for pslist/pstree analysis.

**Detection Method:**
- Volatility3: `linux.pslist` → Look for python3 with large RSS
- Volatility3: `linux.psaux` → Command line shows full script path

**Command Used:**
```bash
mkdir -p /opt/.cache
python3 /opt/.cache/mem_marker.py &
```

---

## Artifact 2: Hidden User Account

**Username:** `backupsvc`  
**UID:** 997  
**Created:** 2025-12-27 20:09:13 UTC  
**Home Directory:** `/home/backupsvc`  
**Shell:** `/bin/bash`  
**Sudo Access:** NOPASSWD:ALL

**Purpose:** Privilege escalation detection and unauthorized user identification

**Description:**
System user account with unrestricted sudo privileges, mimicking a common persistence technique.

**Sudoers Entry:**
```bash
# File: /etc/sudoers.d/010-backupsvc
backupsvc ALL=(ALL) NOPASSWD:ALL
```

**Detection Method:**
- Filesystem: `/etc/passwd`, `/etc/sudoers.d/010-backupsvc`
- Memory: Bash history may contain user creation commands
- Volatility3: `linux.bash` → Look for useradd commands

**Commands Used:**
```bash
sudo useradd -r -u 997 -s /bin/bash -m backupsvc
echo "backupsvc ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/010-backupsvc
sudo chmod 0440 /etc/sudoers.d/010-backupsvc
```

---

## Artifact 3: Systemd Persistence Service

**Service Name:** `kworker-update.service`  
**Installed:** 2025-12-27 20:10:39 UTC  
**Location:** `/etc/systemd/system/kworker-update.service`  
**Script:** `/usr/local/bin/.kworker_update.sh`

**Purpose:** Systemd persistence mechanism with process masquerading

**Description:**
Service mimics legitimate kernel worker name (`kworker`) to blend in with system processes.

**Service File Content:**
```ini
[Unit]
Description=Kernel Worker Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/.kworker_update.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

**Detection Method:**
- Filesystem: `/etc/systemd/system/` for suspicious services
- Process list: `.kworker_update` (note leading dot)
- Volatility3: `linux.pslist` → Look for masqueraded names
- Volatility3: `linux.bash` → systemctl commands in history

**Commands Used:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable kworker-update.service
sudo systemctl start kworker-update.service
```

---

## Artifact 4: Code Injection Test Binaries

**Binaries:** `.uhelper`, `.injector`  
**Location:** `/opt/.cache/`  
**Compiled:** 2025-12-27 20:11:00 UTC  
**Purpose:** Code injection and rwx memory page detection

**Description:**
Custom ELF binaries that create anonymous rwx (read-write-execute) memory mappings containing shellcode-like patterns.

**Shellcode Pattern:**
```
90 90 90 90 90 90 90 90  # NOP sled
CC                       # INT3 breakpoint
31 C0                    # xor eax, eax
48 31 FF                 # xor rdi, rdi
C3                       # ret
```

**Detection Method:**
- Volatility3: `linux.malfind` → Identifies rwx anonymous pages
- Volatility3: `linux.proc.Maps` → Memory region permissions
- YARA: Rules targeting NOP sleds and INT3 instructions

**Processes Created:**
- PID 20375 (`.uhelper`)
- PID 20480 (`.injector`)

---

## Artifact 5: Reverse Shell Simulator

**Script:** `/opt/.cache/.rsim.py`  
**Target:** 192.168.164.1:4444  
**Executed:** 2025-12-27 20:07:22 UTC  
**Log File:** `/var/log/.rsim.log`

**Purpose:** Network connection forensics and C2 detection

**Description:**
Python script that attempts to connect to a simulated C2 server on the host-only network.

**Detection Method:**
- Volatility3: `linux.sockstat` → Active/attempted connections
- Volatility3: `linux.lsof` → Open file descriptors (sockets)
- Network logs: Outbound connection attempts

**Command Used:**
```bash
python3 /opt/.cache/.rsim.py > /var/log/.rsim.log 2>&1 &
```

---

## Artifact 6: Staging Directories

**Directories Created:**
- `/opt/.cache/` (Primary staging, created 2025-12-27 19:23:09 UTC)
- `/var/tmp/.dbus/` (Code injection staging)
- `/var/tmp/.cache-update/` (Secondary persistence)

**Purpose:** Hidden directory detection and suspicious file placement

**Detection Method:**
- Filesystem: Hidden directories (leading dot)
- Volatility3: `linux.bash` → mkdir commands in history
- Volatility3: `linux.lsof` → Files open from suspicious paths

**Permissions:**
```bash
drwxr-xr-x /opt/.cache/
drwxr-xr-x /var/tmp/.dbus/
drwxr-xr-x /var/tmp/.cache-update/
```

---

## Attack Timeline Summary

| Time (UTC) | Artifact | Action |
|------------|----------|--------|
| 19:23:09 | Staging dirs | Created /opt/.cache, /var/tmp/.dbus |
| 19:47:06 | Memory marker | Launched mem_marker.py (9MB) |
| 20:07:22 | C2 connection | Reverse shell attempt to 192.168.164.1:4444 |
| 20:09:13 | Hidden user | Created backupsvc with sudo NOPASSWD |
| 20:10:39 | Persistence | Installed kworker-update.service |
| 20:11:00 | Code injection | Compiled and ran .uhelper, .injector |

---

## Forensic Value

These artifacts enable detection and analysis of:
1. **Process anomalies:** Hidden names, unusual parents
2. **Memory injection:** rwx pages, shellcode patterns
3. **Persistence:** Systemd services, user accounts, sudoers
4. **Network activity:** C2 connections, suspicious outbound traffic
5. **Command history:** Full attack chain in bash.txt from memory
6. **Filesystem artifacts:** Hidden directories, staged binaries

All artifacts are safe for educational use and do not contain functional malware.
