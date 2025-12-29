# Phase 0: Lab Environment Setup

## Victim VM Configuration

### Hardware Specifications
- **VM Name:** U20-DFIR-Victim
- **Platform:** VMware Workstation
- **CPU:** 2 vCPU
- **RAM:** 4096 MB (4 GB)
- **Disk:** 60 GB
- **Firmware:** UEFI

### Operating System
- **Distribution:** Ubuntu 20.04.6 LTS (Focal Fossa)
- **Kernel:** 5.4.0-216-generic
- **Architecture:** x86_64
- **Installation Type:** Live Server (Subiquity installer)
- **Hostname:** victim-u20
- **User Account:** labadmin

### Network Configuration
Two network interfaces configured:

#### NIC 1 (ens33) - NAT
- **Purpose:** Internet access for package updates
- **IP Address:** 172.16.179.143/24
- **Gateway:** 172.16.179.2
- **MAC:** 00:0c:29:3a:ab:ca
- **Configuration:** DHCP

#### NIC 2 (ens34) - Host-only (VMnet1)
- **Purpose:** Host-to-VM SSH access and forensic acquisition
- **IP Address:** 192.168.164.129/24
- **MAC:** 00:0c:29:3a:ab:d4
- **Configuration:** DHCP
- **Host Access:** `ssh labadmin@192.168.164.129`

### Routing Table
```plaintext
default via 172.16.179.2 dev ens33 proto dhcp src 172.16.179.143 metric 100
172.16.179.0/24 dev ens33 proto kernel scope link src 172.16.179.143
192.168.164.0/24 dev ens34 proto kernel scope link src 192.168.164.129
```

### Services Installed
```bash
# OpenSSH Server (installed during OS installation)
sudo systemctl status ssh

# Apache2 Web Server
sudo apt update
sudo apt install -y apache2
sudo systemctl enable apache2

# PHP
sudo apt install -y php libapache2-mod-php
sudo systemctl restart apache2

# Build tools (for LiME compilation)
sudo apt install -y build-essential linux-headers-$(uname -r)
```

### VMware Tools
```bash
sudo apt install -y open-vm-tools
```

## Initial System State

### Boot Time
- **First Boot:** 2025-12-27 19:02:00 UTC
- **Timezone:** UTC (default)

### Key Directories
Standard Ubuntu 20.04 filesystem layout with no modifications.

### Security Baseline
- SSH enabled with password authentication
- Firewall: UFW inactive (default)
- SELinux/AppArmor: AppArmor active (default Ubuntu)

## Planted Forensic Artifacts (for DFIR training)

### Purpose
To create realistic forensic traces for memory analysis training, the following artifacts were intentionally planted on the system.

### Artifact 1: In-Memory Marker Process
```bash
# Created: /opt/.cache/mem_marker.py
# Purpose: 9MB in-memory process for easy Volatility detection
# Command: python3 /opt/.cache/mem_marker.py &
```

### Artifact 2: Hidden User Account
```bash
# Username: backupsvc
# UID: 997
# Purpose: Test account with sudo NOPASSWD for privilege escalation detection
# Created: 2025-12-27 20:09:13 UTC
sudo useradd -r -u 997 -s /bin/bash -m backupsvc
echo "backupsvc ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/010-backupsvc
```

### Artifact 3: Systemd Persistence Service
```bash
# Service: kworker-update.service
# Location: /etc/systemd/system/kworker-update.service
# Purpose: Masqueraded kernel worker for persistence detection
# Installed: 2025-12-27 20:10:39 UTC
```

### Artifact 4: Code Injection Test Binaries
```bash
# Binaries: .uhelper, .injector
# Location: /opt/.cache/
# Purpose: Test code injection detection (rwx memory pages)
# Compiled: 2025-12-27 20:11:00 UTC
```

### Artifact 5: Reverse Shell Simulator
```bash
# Script: /opt/.cache/.rsim.py
# Target: 192.168.164.1:4444 (C2 server simulation)
# Purpose: Network connection forensics
# Executed: 2025-12-27 20:07:22 UTC
```

### Artifact 6: Staging Directories
```bash
/opt/.cache/              # Primary staging location
/var/tmp/.dbus/           # Code injection staging
/var/tmp/.cache-update/   # Secondary persistence
```

## Verification Steps

### Network Connectivity
```bash
# From victim VM
ping -c 4 8.8.8.8                    # NAT internet access
ping -c 4 192.168.164.1              # Host-only network

# From host machine
ping -c 4 192.168.164.129            # Victim reachable
ssh labadmin@192.168.164.129         # SSH functional
```

### Service Status
```bash
sudo systemctl status ssh            # SSH active
sudo systemctl status apache2        # Apache2 active
curl http://localhost                # Apache default page
```

### Kernel Version Verification
```bash
uname -r                             # 5.4.0-216-generic
cat /proc/version                    # Full kernel string
```

## Documentation Notes

- All timestamps in UTC
- Network configuration via netplan DHCP (no custom static config)
- No firewall rules applied (default allow all)
- System prepared for LiME memory acquisition at any time
- Snapshot taken before artifact planting for clean baseline

## Related Files
- Network details: `network-config.txt`
- Planted artifacts: `planted-artifacts.md`
- System baseline: `victim-baseline.txt`
