import "math"

// ===================== RANSOMWARE =====================

rule Ransomware_Generic_Strong {
    meta:
        description = "Generic ransomware behavior"
        severity = "CRITICAL"

    strings:
        $a = "your files have been encrypted" nocase
        $b = "decrypt your files" nocase
        $c = "bitcoin" nocase
        $d = /\.onion/ nocase

    condition:
        2 of ($a,$b) and ($c or $d)
}

rule LockBit_Ransomware_Strong {
    meta:
        description = "LockBit ransomware"
        severity = "CRITICAL"

    strings:
        $a = "lockbit" nocase fullword
        $b = /\.lockbit/ nocase
        $c = /https?:\/\/[a-z0-9]{12,}\.(onion|top|xyz)/ nocase

    condition:
        ($a and $b) or ($a and $c)
}

// ===================== PHISHING =====================

rule Phishing_Page_Strong {
    meta:
        description = "Phishing credential harvesting"
        severity = "HIGH"

    strings:
        $a = "<form" nocase
        $b = "login" nocase
        $c = "verify your account" nocase
        $d = "password" nocase

    condition:
        $a and 2 of ($b,$c,$d)
}

// ===================== WEB ATTACKS =====================

rule SQL_Injection_Strong {
    meta:
        description = "SQL Injection"
        severity = "HIGH"

    strings:
        $a = "UNION SELECT" nocase
        $b = /OR\s+1=1/ nocase
        $c = "--"
        $d = "SLEEP(" nocase

    condition:
        any of them and filesize < 5KB
}

rule XSS_Attack_Strong {
    meta:
        description = "XSS attack"
        severity = "HIGH"

    strings:
        $a = /<script[^>]*>/ nocase
        $b = "javascript:" nocase
        $c = /on\w+=/ nocase

    condition:
        2 of them
}

// ===================== MALWARE =====================

rule PowerShell_Downloader_Strong {
    meta:
        description = "Malicious PowerShell"
        severity = "CRITICAL"

    strings:
        $a = "powershell" nocase
        $b = "DownloadString" nocase
        $c = "Invoke-Expression" nocase
        $d = "-enc" nocase

    condition:
        $a and 2 of ($b,$c,$d)
}

rule Web_Shell_Strong {
    meta:
        description = "Web shell activity"
        severity = "CRITICAL"

    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
        $c = "system(" nocase
        $d = "whoami" nocase

    condition:
        2 of them
}

// ===================== NETWORK =====================

rule DNS_Tunneling_Strong {
    meta:
        description = "DNS tunneling"
        severity = "HIGH"

    strings:
        $a = /[a-z0-9]{40,}/ nocase
        $b = /[A-Za-z0-9+\/=]{50,}/
        $c = /(TXT|CNAME)/ ascii

    condition:
        (#a > 10 or #b > 8) and #c > 5
}

rule High_Entropy_Payload_Tuned {
    meta:
        description = "Encrypted payload"
        severity = "MEDIUM"

    condition:
        filesize > 500 and math.entropy(0, filesize) > 7.6
}