# Akira Ransomware - Focused Threat Intelligence Report

## Threat Actor Profile
**Name:** Akira Ransomware Group
**Type:** Ransomware-as-a-Service (RaaS)
**Active Since:** March 2023
**Motivation:** Financial (double extortion)

## Executive Summary
Akira ransomware operators employ a multi-stage attack chain targeting Windows and Linux systems. This focused analysis covers three critical TTPs observed in recent Akira incidents that produce detectable telemetry in system logs.

## Attack Chain Overview
1. Initial access via VPN exploitation or credential theft
2. Discovery and enumeration of target environment
3. **Defense evasion through shadow copy deletion** ← TTP 1
4. **Service disruption to disable security/backup tools** ← TTP 2
5. Lateral movement and privilege escalation
6. **Data encryption for impact** ← TTP 3
7. Ransom note deployment

## TTP 1: Shadow Copy Deletion (T1490 - Inhibit System Recovery)

### Description
Akira operators delete Volume Shadow Copies to prevent victims from restoring encrypted files. This is executed before encryption to maximize pressure on victims.

### Commands Observed
```cmd
vssadmin.exe delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled no
bcdedit /set {default} bootstatuspolicy ignoreallfailures
```

### Detection Opportunities
- **Process Execution:** `vssadmin.exe` with `delete shadows` arguments
- **CommandLine:** Contains "delete shadows /all" or "shadowcopy delete"
- **Parent Process:** Often launched from malicious executables or scripts
- **User Context:** Typically executed with elevated privileges
- **Event IDs:** Windows Event 4688 (Process Creation), Sysmon Event 1

### MITRE ATT&CK
- **Technique:** T1490 - Inhibit System Recovery
- **Tactic:** Impact
- **Platform:** Windows

---

## TTP 2: Service Stop (T1489 - Service Stop)

### Description
Prior to encryption, Akira stops critical services to unlock files and disable security protections. Target services include backup agents, database services, and endpoint protection.

### Commands Observed
```cmd
net stop "Veeam Backup Service" /y
net stop "SQL Server (MSSQLSERVER)" /y
net stop "Sophos Agent" /y
sc config "service_name" start= disabled
taskkill /F /IM sqlservr.exe
```

### Targeted Services
- Backup software: Veeam, Acronis, BackupExec
- Database services: MSSQL, MySQL, Oracle
- Security tools: Windows Defender, Sophos, CrowdStrike
- Virtualization: VMware Tools, Hyper-V

### Detection Opportunities
- **Service Control Manager Events:** Event ID 7040 (service start type changed)
- **Service Stop Events:** Event ID 7036 (service entered stopped state)
- **Process Execution:** `net.exe stop`, `sc.exe config`
- **CommandLine Patterns:** Multiple service stops in rapid succession
- **Unusual User Context:** Service stops from non-admin or unexpected accounts

### MITRE ATT&CK
- **Technique:** T1489 - Service Stop
- **Tactic:** Impact
- **Platform:** Windows, Linux

---

## TTP 3: Data Encrypted for Impact (T1486 - Data Encrypted for Impact)

### Description
Akira encrypts files using a combination of asymmetric and symmetric encryption. The ransomware targets specific file extensions while avoiding system-critical files to maintain system operability for ransom payment.

### Behavioral Indicators
- Rapid file modifications across multiple directories
- File extension changes (e.g., .txt → .txt.akira)
- Creation of ransom notes (akira_readme.txt) in multiple folders
- High disk I/O activity
- Encryption of network shares and mapped drives

### Targeted File Extensions
.doc, .docx, .xls, .xlsx, .ppt, .pptx, .pdf, .jpg, .png, .zip, .sql, .bak, .vhd, .vmdk

### Detection Opportunities
- **File System Activity:** Mass file rename/modify operations
- **Entropy Analysis:** Files with significantly increased entropy
- **Ransom Note Creation:** Presence of .txt files with ransom demands
- **Network Activity:** Encryption of SMB shares
- **Performance:** Unusual CPU/disk spikes during off-hours

### MITRE ATT&CK
- **Technique:** T1486 - Data Encrypted for Impact
- **Tactic:** Impact
- **Platform:** Windows, Linux

---

## Detection Summary

| TTP | Primary Detection Method | Event Sources | Priority |
|-----|--------------------------|---------------|----------|
| Shadow Copy Deletion (T1490) | Process monitoring, command-line analysis | Windows Event 4688, Sysmon Event 1 | HIGH |
| Service Stop (T1489) | Service control events, process monitoring | Event 7036, 7040, Sysmon Event 1 | HIGH |
| Data Encryption (T1486) | File system monitoring, entropy analysis | Windows Security, Sysmon Event 11, EDR | CRITICAL |

## Recommended Actions
1. Enable process creation logging (Event ID 4688) with command-line arguments
2. Deploy Sysmon with configuration monitoring file creation and process execution
3. Alert on multiple service stops within short time windows
4. Implement file integrity monitoring on critical directories
5. Monitor for vssadmin.exe and bcdedit.exe execution outside maintenance windows

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1490/
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1489/
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1486/
- CISA Alert: Akira Ransomware (AA23-353A)
