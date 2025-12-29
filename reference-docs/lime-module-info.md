# LiME (Linux Memory Extractor) Reference

## Overview
LiME is a Loadable Kernel Module (LKM) that enables volatile memory acquisition from Linux systems. It produces a memory dump in a format directly usable by forensic analysis tools like Volatility.

## Why LiME for This Investigation?

### Advantages:
- ✅ **Complete Physical Memory:** Captures all physical RAM pages
- ✅ **Kernel-Level Access:** Direct access to memory via kernel module
- ✅ **No Missing Pages:** Unlike /dev/mem (deprecated) or /proc/kcore
- ✅ **Preserves Layout:** LiME format preserves physical memory layout
- ✅ **Minimal Footprint:** Small module, quick acquisition
- ✅ **Open Source:** Auditable code, widely trusted in forensics community

### Alternatives Considered:
- ❌ **/dev/mem:** Deprecated in modern kernels (CONFIG_STRICT_DEVMEM)
- ❌ **/proc/kcore:** Does not capture all physical memory, only kernel virtual
- ❌ **dd of /dev/crash:** Not available on standard Ubuntu
- ❌ **Hardware freezing:** Requires physical access, not available in VMs

---

## LiME Acquisition Details for CASE_20251228_0001

### Module Information
- **Filename:** lime-5.4.0-216-generic.ko
- **Build Date:** 2025-12-27
- **Kernel Version:** 5.4.0-216-generic (Ubuntu 20.04)
- **Vermagic:** 5.4.0-216-generic SMP mod_unload
- **Size:** 24,576 bytes
- **Taint Flags:** OOT_MODULE (Out-Of-Tree), UNSIGNED_MODULE

### Compilation Steps
```bash
# Install prerequisites
sudo apt install -y git build-essential linux-headers-$(uname -r)

# Clone LiME
cd ~/dfir_tools
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src

# Build for current kernel
make clean
make

# Verify module built
ls -lh lime-$(uname -r).ko
modinfo lime-$(uname -r).ko | grep vermagic
```

### Acquisition Command
```bash
sudo insmod lime-5.4.0-216-generic.ko \
  "path=/home/labadmin/dfir_acq/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime \
  format=lime \
  timeout=0"
```

### Parameters Explained

#### path=
**Value:** `/home/labadmin/dfir_acq/mem_victim-u20_5.4.0-216-generic_20251227T214903Z.lime`  
**Purpose:** Output file location for memory dump  
**Note:** Must be writable by root (insmod runs as root)

#### format=lime
**Options:** `lime`, `raw`, `padded`  
**Selected:** `lime`  
**Reason:** LiME format preserves physical memory layout with headers indicating memory ranges. Volatility3 parses this format natively.

**Format Comparison:**
- **lime:** Headers + physical memory ranges (recommended)
- **raw:** Raw physical memory dump (no headers)
- **padded:** Pads missing regions with zeros (larger file)

#### timeout=0
**Value:** `0` (disable timeout)  
**Purpose:** Ensures complete memory acquisition without skipping slow-access pages  
**Default:** Non-zero timeout may skip pages that take too long to read  
**Risk:** Slower acquisition, but ensures completeness  
**Recommendation:** Always use `timeout=0` for forensics

### Module Unloading
```bash
sudo rmmod lime
```

**Important:** Module must be unloaded after acquisition to:
- Release file handle
- Finalize dump file
- Free kernel memory

---

## LiME Format Structure

### File Layout
```
[LiME Header 1]
[Memory Range 1 Data]
[LiME Header 2]
[Memory Range 2 Data]
...
[LiME Header N]
[Memory Range N Data]
```

### Header Fields
- Magic: `EMiL` (0x4c694d45)
- Version: 1
- Start Address: Physical start of range
- End Address: Physical end of range
- Reserved: Padding

### Why This Matters
Volatility3 reads LiME headers to understand physical memory layout, enabling correct virtual-to-physical address translation during analysis.

---

## Verification Steps

### 1. Check Module Vermagic
```bash
modinfo lime-5.4.0-216-generic.ko | grep vermagic
# Output should match: uname -r
```

**Purpose:** Ensure module was compiled for correct kernel version

### 2. Verify Acquisition Success
```bash
# Check file size (should be close to RAM size)
ls -lh /home/labadmin/dfir_acq/*.lime

# Check for LiME magic bytes
hexdump -C /home/labadmin/dfir_acq/*.lime | head -n 2
# Should show: 45 4d 69 4c (EMiL in little-endian)
```

### 3. Generate Integrity Hash
```bash
sha256sum /home/labadmin/dfir_acq/*.lime | tee *.lime.sha256
```

---

## Taint Flags Explained

### OOT_MODULE (Out-Of-Tree Module)
**Meaning:** Module not included in mainline kernel  
**Source:** LiME is external, not part of Ubuntu kernel  
**Concern:** None - expected for forensic tools

### UNSIGNED_MODULE
**Meaning:** Module not signed with kernel signing key  
**Source:** Ubuntu kernel has CONFIG_MODULE_SIG but LiME not signed  
**Concern:** None for forensic acquisition  
**Production Note:** Signed modules preferred in production environments

---

## Best Practices Followed

1. ✅ **Kernel Headers Installed:** Ensured `linux-headers-$(uname -r)` present
2. ✅ **Vermagic Verified:** Confirmed module matches running kernel
3. ✅ **timeout=0 Parameter:** Complete acquisition without skipping pages
4. ✅ **Immediate Hashing:** SHA-256 generated immediately after acquisition
5. ✅ **Permissions:** File ownership changed to analyst, restricted permissions (640)
6. ✅ **Documentation:** Full command logged with timestamps
7. ✅ **Module Unloaded:** Proper cleanup with `rmmod lime`

---

## Common Issues and Solutions

### Issue: Module Load Fails with "Invalid module format"
**Cause:** Vermagic mismatch (module built for wrong kernel)  
**Solution:** Rebuild LiME against correct `linux-headers-$(uname -r)`

### Issue: "Permission denied" when writing dump
**Cause:** Output path not writable  
**Solution:** Ensure path exists and is writable: `mkdir -p ~/dfir_acq`

### Issue: Dump file smaller than expected
**Cause:** Timeout parameter caused page skips  
**Solution:** Use `timeout=0` parameter

### Issue: Module won't unload
**Cause:** File still in use or kernel panic  
**Solution:** Check `dmesg` for errors, may require system reboot

---

## Forensic Considerations

### Minimal System Impact
- LiME reads memory but does not modify it
- No process termination or service interruption
- System remains operational during acquisition

### Order of Volatility (RFC 3227)
1. Registers, cache (not captured)
2. **RAM (LiME captures this)** ✅
3. Network connections (captured separately via netstat)
4. Running processes (captured via ps)
5. Disk (not captured in this investigation)

### Chain of Custody
- Module loaded by: root (via sudo)
- Dump owned by: labadmin
- Hash generated: immediately after acquisition
- Transfer: SCP with hash verification

---

## LiME vs. Other Tools

| Tool | Access Method | Completeness | Kernel Required | Production Use |
|------|---------------|--------------|-----------------|----------------|
| **LiME** | Kernel module | Complete | Headers needed | ✅ Trusted |
| /dev/mem | Device file | Incomplete | N/A | ❌ Deprecated |
| /proc/kcore | Pseudo-file | Kernel only | N/A | ❌ Incomplete |
| dd /dev/crash | Device file | Varies | Crash driver | ❌ Rare |
| PMEM (Rekall) | Kernel module | Complete | Headers needed | ⚠️ Less common |

**Verdict:** LiME is industry standard for Linux memory forensics

---

## References
- LiME GitHub: https://github.com/504ensicsLabs/LiME
- LiME Paper: "LiME - Linux Memory Extractor" (2012)
- RFC 3227: Guidelines for Evidence Collection
- Linux Kernel Module Programming Guide

---

## Module Used in This Investigation
- **Repository:** https://github.com/504ensicsLabs/LiME
- **Commit:** Latest as of 2025-12-27
- **Build Host:** victim-u20 (Ubuntu 20.04.6)
- **Kernel:** 5.4.0-216-generic #236-Ubuntu SMP
- **Acquisition Date:** 2025-12-27 21:48:36 UTC

---

Last Updated: 2025-12-29
Analyst: labadmin
