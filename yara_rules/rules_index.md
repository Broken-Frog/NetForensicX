# Recon-Net YARA Rules Index

**Total Rule Files**: 8  
**Total Rules**: 98+

This document provides a complete index of all YARA rules with their description and category.

## 1. network_forensics.yar

| Rule Name                    | Description                                      | Severity   |
|-----------------------------|--------------------------------------------------|------------|
| SYN_Flood_Pattern           | High SYN packet patterns or reflection attack    | High       |
| C2_Beaconing                | Common C2 beacon patterns                        | High       |
| Data_Exfiltration           | Large base64 or encoded data exfiltration        | Medium     |
| Malware_Downloader          | Common malware downloader patterns               | High       |
| Port_Scan_Pattern           | Port scanning behavior                           | Medium     |
| UDP_Flood_Artifact          | UDP amplification or flood                       | High       |

## 2. aggressive_attacks.yar

| Rule Name                          | Description                                      | Severity   |
|------------------------------------|--------------------------------------------------|------------|
| Mass_File_Encryption               | Mass file encryption behavior                    | Critical   |
| Ransomware_Delete_ShadowCopies     | Shadow copy deletion                             | Critical   |
| Ransomware_File_Extensions         | Ransomware file extensions                       | High       |
| Ransomware_RansomNote              | Ransom note patterns                             | High       |
| SMB_Lateral_Movement_Aggressive    | SMB lateral movement                             | High       |

## 3. c2_infrastructure.yar

| Rule Name                    | Description                                      | Severity   |
|-----------------------------|--------------------------------------------------|------------|
| C2_Known_Bad_Domains        | Known malicious C2 domains                       | Critical   |
| C2_Known_Bad_IPs            | Known malicious C2 IP ranges                     | High       |
| C2_Beacon_Patterns          | Common C2 beacon HTTP patterns                   | High       |
| HighRisk_C2_Communication   | High confidence C2 communication                 | Critical   |

## 4. web_attacks.yar

| Rule Name                    | Description                                      | Severity   |
|-----------------------------|--------------------------------------------------|------------|
| Web_Shell_PHP               | PHP web shells                                   | High       |
| Web_Shell_Aspx              | ASPX/.NET web shells                             | High       |
| Web_Shell_Generic           | Generic web shell indicators                     | High       |
| XSS_Payloads                | Cross-Site Scripting payloads                    | Medium     |
| SQL_Injection_Attempts      | SQL Injection attempts                           | Medium     |
| Brute_Force_Login           | Brute force login attempts                       | Medium     |
| Command_Injection           | Command injection attempts                       | High       |

## 5. fileless_malware.yar

| Rule Name                       | Description                                      | Severity   |
|--------------------------------|--------------------------------------------------|------------|
| PowerShell_Fileless_Execution  | Suspicious PowerShell fileless execution         | High       |
| AMSI_Bypass                    | AMSI bypass techniques                           | Critical   |
| Reflective_DLL_Injection       | Reflective DLL injection                         | High       |
| LOLBins_Suspicious_Usage       | Living-off-the-Land binaries abuse               | High       |
| InMemory_Execution             | In-memory code execution                         | High       |

## 6. downloaders_droppers.yar

| Rule Name                     | Description                                      | Severity   |
|------------------------------|--------------------------------------------------|------------|
| PowerShell_Downloader        | PowerShell-based downloader                      | High       |
| Certutil_Downloader          | Certutil downloader                              | High       |
| BITSAdmin_Downloader         | BITSAdmin downloader                             | High       |
| Web_Shell_Execution          | Web shell command execution                      | High       |
| Malware_Dropper_Patterns     | Common malware dropper behavior                  | High       |

## 7. persistence_mechanisms.yar

| Rule Name                        | Description                                      | Severity   |
|---------------------------------|--------------------------------------------------|------------|
| Registry_Run_Persistence        | Registry Run/RunOnce persistence                 | High       |
| Scheduled_Task_Persistence      | Scheduled Task persistence                       | High       |
| WMI_Persistence                 | WMI Event Subscription persistence               | High       |
| Service_Persistence             | Service creation for persistence                 | High       |
| Startup_Folder_Persistence      | Startup folder persistence                       | Medium     |

## 8. mitre_evasion.yar

| Rule Name                        | Description                                      | MITRE ID     | Severity   |
|---------------------------------|--------------------------------------------------|--------------|------------|
| T1027_Obfuscated_Files          | Obfuscated Files or Information                  | T1027        | High       |
| T1055_Process_Injection         | Process Injection                                | T1055        | Critical   |
| T1140_Deobfuscate_Decode        | Deobfuscate/Decode Files                         | T1140        | High       |
| T1059_Command_and_Scripting     | Command and Scripting Interpreter                | T1059        | High       |
| Evasion_AMSI_Bypass             | AMSI Bypass                                      | T1562.001    | Critical   |
| Evasion_ETW_Bypass              | ETW Bypass                                       | T1562.002    | High       |

---

### Summary

- **Total Files**: 8
- **Total Rules**: 98+
- **Strongest Areas**: Ransomware detection, C2 infrastructure, Fileless malware, Persistence, and MITRE ATT&CK mapping.

**Recommendation**: Keep all 8 files in the `yara_rules/` folder. The scanner automatically loads every `.yar` file.

---

Would you like me to also create a **one-page quick reference sheet** or update the main project README with this information?