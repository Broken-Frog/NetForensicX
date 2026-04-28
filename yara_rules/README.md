# YARA Rules - Recon-Net Network Forensics

This folder contains a comprehensive, production-grade YARA rule collection designed for **network forensics**, PCAP analysis, and malware detection.

## 📊 Overview

- **Total Rule Files**: **8**
- **Total Individual Rules**: **98+**
- **Focus Areas**: Ransomware, C2 Communication, Fileless Malware, Web Attacks, Persistence, Evasion, and MITRE ATT&CK mapping.

## 📁 Rule Files

| File Name                        | Category                          | Number of Rules | Description |
|-------------------------------|-----------------------------------|------------------|-----------|
| `network_forensics.yar`       | General + Flood + DNS            | 12              | Core network attack detection |
| `aggressive_attacks.yar`      | File Activity + Ransomware       | 18              | Aggressive file modification & ransomware behavior |
| `c2_infrastructure.yar`       | C2 Domains & IPs                 | 9               | Known C2 beacons and infrastructure |
| `web_attacks.yar`             | Web Attacks                      | 12              | XSS, SQLi, Web Shells, Brute Force |
| `fileless_malware.yar`        | Fileless Malware                 | 11              | In-memory execution, PowerShell abuse |
| `downloaders_droppers.yar`    | Downloaders & Droppers           | 13              | Downloader patterns + AMSI bypass |
| `persistence_mechanisms.yar`  | Persistence                      | 12              | Registry, Scheduled Tasks, WMI, Services |
| `mitre_evasion.yar`           | MITRE ATT&CK + Evasion           | 11              | Defense evasion, process injection, sandbox detection |

**Total Rules ≈ 98**

## 🛡️ Rule Families / Categories Covered

- **Ransomware Families**: BlackCat/ALPHV, Medusa, LockBit, Hive, 8Base, Conti, Ryuk, REvil, Qilin, BianLian
- **C2 Frameworks**: Cobalt Strike, Sliver, Generic beacons
- **Flood Attacks**: UDP Flood, SYN Flood, Slowloris
- **Web Attacks**: XSS, SQL Injection, Web Shells, Command Injection
- **Fileless Malware**: PowerShell abuse, AMSI Bypass, Reflective loading
- **Persistence**: Registry Run keys, Scheduled Tasks, WMI, Services, Startup folder, COM Hijacking
- **Evasion Techniques**: AMSI Bypass, ETW Bypass, Sandbox Detection, Anti-Debugging
- **Data Exfiltration**: DNS Tunneling, Bulk compression, HTTP uploads
- **Lateral Movement**: SMB, PowerShell remoting, PsExec

## 🔧 How to Use

All rules are automatically loaded by `YARAScanner` in `analysis/yara_scanner.py`.

```python
# In your scanner, it loads every .yar file in this folder