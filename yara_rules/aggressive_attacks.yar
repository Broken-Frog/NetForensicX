/*
   Recon-Net ULTRA AGGRESSIVE YARA Rules
   Focused on File Activity, Mass Encryption, Lateral Movement, Web Attacks, and Advanced Threats
   Use this file together with network_forensics.yar for maximum coverage
*/

import "math"

// ====================== RANSOMWARE FILE ACTIVITY (Ultra Aggressive) ======================

rule Mass_File_Encryption {
    meta:
        description = "Mass file encryption behavior - strong ransomware indicator"
        severity = "CRITICAL"
    strings:
        $write = "WriteFile" nocase
        $create = "CreateFile" nocase
        $close = "CloseHandle" nocase
        $locked = ".locked" nocase
        $encrypted = ".encrypted" nocase
        $crypt = ".crypt" nocase
    condition:
        (3 of ($write, $create, $close)) and any of ($locked, $encrypted, $crypt)
}

rule Ransomware_Shadow_Delete {
    meta:
        description = "Shadow copy deletion - typical ransomware"
        severity = "CRITICAL"
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wmic shadowcopy delete" nocase
        $c = "bcdedit /set" nocase
        $d = "wbadmin delete catalog" nocase
    condition:
        any of them
}

rule Ransomware_File_Extensions_Aggressive {
    meta:
        description = "Wide range of ransomware file extensions"
        severity = "HIGH"
    strings:
        $ext1 = ".locked" $ext2 = ".encrypted" $ext3 = ".crypt" $ext4 = ".medusa"
        $ext5 = ".8base" $ext6 = ".qilin" $ext7 = ".blackcat" $ext8 = ".hive"
        $ext9 = ".lockbit" $ext10 = ".cont" $ext11 = ".ryuk" $ext12 = ".revil"
    condition:
        any of them
}

rule Ransomware_Ransom_Note {
    meta:
        description = "Ransomware ransom note patterns"
        severity = "HIGH"
    strings:
        $note1 = "your files have been encrypted" nocase
        $note2 = "pay the ransom" nocase
        $note3 = "bitcoin" nocase
        $note4 = "decryptor" nocase
        $note5 = "private key" nocase
    condition:
        2 of them
}

// ====================== LATERAL MOVEMENT & FILE ACTIVITY ======================

rule SMB_Lateral_Movement_Aggressive {
    meta:
        description = "SMB lateral movement and file copy"
        severity = "HIGH"
    strings:
        $smb1 = "SMB2 WRITE" $smb2 = "ADMIN$" $smb3 = "C$\\" $smb4 = "IPC$"
        $smb5 = "psexec" nocase $smb6 = "wmic" nocase
    condition:
        2 of them
}

rule PowerShell_Lateral {
    meta:
        description = "Suspicious PowerShell lateral movement"
        severity = "HIGH"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "Invoke-Command" nocase
        $ps3 = "Enter-PSSession" nocase
        $ps4 = "winrm" nocase
    condition:
        2 of them
}

// ====================== WEB & EXPLOIT ATTACKS ======================

rule XSS_Payload {
    meta:
        description = "Cross-Site Scripting (XSS) payloads"
        severity = "MEDIUM"
    strings:
        $xss1 = "<script>" nocase
        $xss2 = "javascript:" nocase
        $xss3 = "onerror=" nocase
        $xss4 = "alert(" nocase
        $xss5 = "eval(" nocase
    condition:
        2 of them
}

rule SQL_Injection {
    meta:
        description = "SQL Injection attempts"
        severity = "MEDIUM"
    strings:
        $sql1 = "SELECT " nocase
        $sql2 = "UNION SELECT" nocase
        $sql3 = "1=1" nocase
        $sql4 = "--" 
        $sql5 = "OR 1=1" nocase
    condition:
        2 of them
}

rule Web_Shell_Commands {
    meta:
        description = "Web shell command execution"
        severity = "HIGH"
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "whoami" nocase
        $cmd4 = "id;" nocase
        $cmd5 = "system(" nocase
    condition:
        2 of them
}

// ====================== DATA EXFILTRATION & COMPRESSION ======================

rule Bulk_Exfiltration {
    meta:
        description = "Bulk data compression and exfiltration"
        severity = "HIGH"
    strings:
        $zip = "zip " nocase
        $tar = "tar " nocase
        $7z = "7z " nocase
        $rsync = "rsync " nocase
        $scp = "scp " nocase
    condition:
        any of them
}

// ====================== HIGH CONFIDENCE ANOMALIES ======================

rule High_Entropy_Encrypted {
    meta:
        description = "Very high entropy - likely encrypted ransomware or C2"
        severity = "CRITICAL"
    condition:
        filesize > 10KB and math.entropy(0, filesize) > 7.6
}

rule Suspicious_Downloader {
    meta:
        description = "Suspicious downloader patterns"
        severity = "HIGH"
    strings:
        $ps = "powershell" nocase
        $dl = "DownloadString" nocase
        $ie = "Invoke-Expression" nocase
        $curl = "curl " nocase
        $wget = "wget " nocase
    condition:
        2 of them
}