/*
   Recon-Net Malware Downloaders, Droppers & Web Shell Execution Rules
   Includes: Downloaders, Droppers, AMSI Bypass, Web Shell Execution
   Version: 2026.04
*/

import "math"

// ====================== MALWARE DOWNLOADERS & DROPPERS ======================

rule PowerShell_Downloader {
    meta:
        description = "PowerShell-based downloader"
        severity = "HIGH"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "DownloadString" nocase
        $ps3 = "DownloadFile" nocase
        $ps4 = "WebClient" nocase
        $ps5 = "Invoke-Expression" nocase
        $ps6 = "IEX" nocase
        $ps7 = "-exec bypass" nocase
    condition:
        $ps1 and 3 of them
}

rule Curl_Wget_Downloader {
    meta:
        description = "Curl / Wget downloader patterns"
        severity = "MEDIUM"
    strings:
        $curl1 = "curl -s" nocase
        $curl2 = "curl -o" nocase
        $wget1 = "wget -q" nocase
        $wget2 = "wget --quiet" nocase
        $output = "-O " nocase
    condition:
        any of them
}

rule Certutil_Downloader {
    meta:
        description = "Certutil downloader (common LOLBin)"
        severity = "HIGH"
    strings:
        $cert1 = "certutil" nocase
        $cert2 = "-urlcache" nocase
        $cert3 = "-split" nocase
        $cert4 = "-f" nocase
    condition:
        $cert1 and 2 of them
}

rule BITSAdmin_Downloader {
    meta:
        description = "BITSAdmin downloader"
        severity = "HIGH"
    strings:
        $bits1 = "bitsadmin" nocase
        $bits2 = "/transfer" nocase
        $bits3 = "/download" nocase
        $bits4 = "/create" nocase
    condition:
        $bits1 and 2 of them
}

// ====================== AMSI BYPASS TECHNIQUES ======================

rule AMSI_Bypass {
    meta:
        description = "AMSI bypass techniques (very common in fileless malware)"
        severity = "CRITICAL"
    strings:
        $amsi1 = "AmsiUtils" nocase
        $amsi2 = "amsiInitFailed" nocase
        $amsi3 = "Antimalware Scan Interface" nocase
        $amsi4 = " [Ref].Assembly.GetType" nocase
        $amsi5 = "System.Management.Automation.Amsi" nocase
        $bypass1 = "Bypass" nocase
        $bypass2 = "Disable" nocase
    condition:
        2 of them
}

// ====================== WEB SHELL EXECUTION ======================

rule Web_Shell_Execution {
    meta:
        description = "Web shell command execution patterns"
        severity = "HIGH"
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell.exe" nocase
        $cmd3 = "whoami" nocase
        $cmd4 = "id;" nocase
        $cmd5 = "system(" nocase
        $cmd6 = "exec(" nocase
        $cmd7 = "shell_exec" nocase
        $cmd8 = "passthru" nocase
    condition:
        2 of them
}

rule PHP_Web_Shell {
    meta:
        description = "PHP-based web shell"
        severity = "HIGH"
    strings:
        $php = "<?php" nocase
        $shell1 = "eval(" nocase
        $shell2 = "system(" nocase
        $shell3 = "exec(" nocase
        $shell4 = "shell_exec(" nocase
        $shell5 = "base64_decode" nocase
    condition:
        $php and 2 of ($shell*)
}

rule ASPX_Web_Shell {
    meta:
        description = "ASPX / .NET web shell"
        severity = "HIGH"
    strings:
        $aspx = "<%@ Page" nocase
        $shell1 = "Process.Start" nocase
        $shell2 = "RunShellCommand" nocase
        $shell3 = "cmd.exe" nocase
    condition:
        $aspx and any of ($shell*)
}

// ====================== DROPPER & STAGER PATTERNS ======================

rule Malware_Dropper_Patterns {
    meta:
        description = "Common malware dropper behavior"
        severity = "HIGH"
    strings:
        $drop1 = "temp.exe" nocase
        $drop2 = "%TEMP%" nocase
        $drop3 = "AppData" nocase
        $drop4 = "WriteAllBytes" nocase
        $drop5 = "FromBase64String" nocase
    condition:
        3 of them
}

rule Reflective_Loader {
    meta:
        description = "Reflective PE loader / in-memory execution"
        severity = "CRITICAL"
    strings:
        $ref1 = "VirtualAlloc" nocase
        $ref2 = "WriteProcessMemory" nocase
        $ref3 = "CreateRemoteThread" nocase
        $ref4 = "LoadLibrary" nocase
    condition:
        3 of them
}

// ====================== HIGH ENTROPY DROPPER ======================

rule HighEntropy_Dropper {
    meta:
        description = "High entropy downloader/dropper payload"
        severity = "HIGH"
    condition:
        filesize > 5KB and filesize < 8MB and
        math.entropy(0, filesize) > 7.3
}