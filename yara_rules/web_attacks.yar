/*
   Recon-Net Web Attacks & Exploitation YARA Rules
   Covers: Web Shells, XSS, SQL Injection, Brute Force, Command Injection
   Version: 2026.04
*/

import "math"

// ====================== WEB SHELLS ======================

rule Web_Shell_PHP {
    meta:
        description = "Common PHP web shells"
        severity = "HIGH"
    strings:
        $php1 = "<?php" nocase
        $shell1 = "eval(" nocase
        $shell2 = "system(" nocase
        $shell3 = "exec(" nocase
        $shell4 = "passthru(" nocase
        $shell5 = "shell_exec(" nocase
        $shell6 = "base64_decode" nocase
        $shell7 = "cmd=" nocase
    condition:
        $php1 and 2 of ($shell*)
}

rule Web_Shell_Aspx {
    meta:
        description = "ASPX / .NET web shells"
        severity = "HIGH"
    strings:
        $aspx = "<%@ Page" nocase
        $shell1 = "RunShellCommand" nocase
        $shell2 = "Process.Start" nocase
        $shell3 = "cmd.exe" nocase
    condition:
        $aspx and any of ($shell*)
}

rule Web_Shell_Generic {
    meta:
        description = "Generic web shell indicators"
        severity = "HIGH"
    strings:
        $ws1 = "whoami" nocase
        $ws2 = "id;" nocase
        $ws3 = "uname -a" nocase
        $ws4 = "net user" nocase
        $ws5 = "ls -la" nocase
    condition:
        2 of them
}

// ====================== XSS (Cross-Site Scripting) ======================

rule XSS_Payloads {
    meta:
        description = "XSS attack payloads"
        severity = "MEDIUM"
    strings:
        $xss1 = "<script>" nocase
        $xss2 = "</script>" nocase
        $xss3 = "javascript:" nocase
        $xss4 = "onerror=" nocase
        $xss5 = "alert(" nocase
        $xss6 = "eval(" nocase
        $xss7 = "document.cookie" nocase
    condition:
        2 of them
}

// ====================== SQL INJECTION ======================

rule SQL_Injection_Attempts {
    meta:
        description = "SQL Injection patterns"
        severity = "MEDIUM"
    strings:
        $sql1 = "SELECT " nocase
        $sql2 = "UNION SELECT" nocase
        $sql3 = "1=1" nocase
        $sql4 = "--" 
        $sql5 = "OR 1=1" nocase
        $sql6 = "' OR '" nocase
        $sql7 = "DROP TABLE" nocase
    condition:
        2 of them
}

// ====================== BRUTE FORCE & LOGIN ATTACKS ======================

rule Brute_Force_Login {
    meta:
        description = "Brute force login attempts"
        severity = "MEDIUM"
    strings:
        $login1 = "login" nocase
        $login2 = "password" nocase
        $login3 = "username" nocase
        $failed = "failed" nocase
        $attempt = "attempt" nocase
    condition:
        2 of ($login*) and ($failed or $attempt)
}

rule Admin_Brute_Force {
    meta:
        description = "Admin panel brute force"
        severity = "HIGH"
    strings:
        $admin = "/admin" nocase
        $login = "login" nocase
        $wp = "wp-login" nocase
        $phpmyadmin = "phpmyadmin" nocase
    condition:
        2 of them
}

// ====================== COMMAND INJECTION ======================

rule Command_Injection {
    meta:
        description = "Command injection attempts"
        severity = "HIGH"
    strings:
        $cmd1 = "; ls" nocase
        $cmd2 = "; cat" nocase
        $cmd3 = "| nc " nocase
        $cmd4 = "&& whoami" nocase
        $cmd5 = "&& id" nocase
        $cmd6 = "; rm -rf" nocase
    condition:
        any of them
}

// ====================== HIGH ENTROPY WEB PAYLOADS ======================

rule Suspicious_Web_Payload {
    meta:
        description = "High entropy web payloads (possible obfuscated shell)"
        severity = "HIGH"
    condition:
        filesize > 500 and filesize < 50KB and
        math.entropy(0, filesize) > 7.2
}