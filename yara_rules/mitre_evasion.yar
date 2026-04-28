/*
   Recon-Net MITRE ATT&CK & Evasion Techniques YARA Rules
   Maps common TTPs (Tactics, Techniques, Procedures) to YARA detections
   Version: 2026.04
*/

import "math"

// ====================== MITRE ATT&CK - DEFENSE EVASION ======================

rule T1027_Obfuscated_Files {
    meta:
        description = "T1027: Obfuscated Files or Information"
        mitre_technique = "T1027"
        severity = "HIGH"
    condition:
        math.entropy(0, filesize) > 7.3
}

rule T1036_Masquerading {
    meta:
        description = "T1036: Masquerading (legitimate process names)"
        mitre_technique = "T1036"
        severity = "MEDIUM"
    strings:
        $masq1 = "svchost.exe" nocase
        $masq2 = "explorer.exe" nocase
        $masq3 = "lsass.exe" nocase
        $masq4 = "services.exe" nocase
    condition:
        any of them
}

rule T1055_Process_Injection {
    meta:
        description = "T1055: Process Injection"
        mitre_technique = "T1055"
        severity = "CRITICAL"
    strings:
        $inj1 = "VirtualAlloc" nocase
        $inj2 = "WriteProcessMemory" nocase
        $inj3 = "CreateRemoteThread" nocase
        $inj4 = "QueueUserAPC" nocase
    condition:
        2 of them
}

rule T1140_Deobfuscate_Decode {
    meta:
        description = "T1140: Deobfuscate/Decode Files or Information"
        mitre_technique = "T1140"
        severity = "HIGH"
    strings:
        $dec1 = "FromBase64String" nocase
        $dec2 = "base64_decode" nocase
        $dec3 = "XOR" nocase
        $dec4 = "Invoke-Expression" nocase
    condition:
        2 of them
}

// ====================== MITRE ATT&CK - EXECUTION ======================

rule T1059_Command_and_Scripting {
    meta:
        description = "T1059: Command and Scripting Interpreter"
        mitre_technique = "T1059"
        severity = "HIGH"
    strings:
        $cmd1 = "powershell" nocase
        $cmd2 = "cmd.exe" nocase
        $cmd3 = "bash" nocase
        $cmd4 = "sh -c" nocase
    condition:
        any of them
}

rule T1204_User_Execution {
    meta:
        description = "T1204: User Execution (malicious documents)"
        mitre_technique = "T1204"
        severity = "MEDIUM"
    strings:
        $macro1 = "AutoOpen" nocase
        $macro2 = "Document_Open" nocase
        $macro3 = "Workbook_Open" nocase
    condition:
        any of them
}

// ====================== MITRE ATT&CK - PERSISTENCE ======================

rule T1547_Boot_or_Logon_Autostart {
    meta:
        description = "T1547: Boot or Logon Autostart Execution"
        mitre_technique = "T1547"
        severity = "HIGH"
    strings:
        $run = "Run" nocase
        $runonce = "RunOnce" nocase
        $startup = "Startup" nocase
    condition:
        any of them
}

rule T1543_Create_or_Modify_System_Process {
    meta:
        description = "T1543: Create or Modify System Process"
        mitre_technique = "T1543"
        severity = "HIGH"
    strings:
        $svc = "sc create" nocase
        $service = "New-Service" nocase
    condition:
        any of them
}

// ====================== EVASION TECHNIQUES ======================

rule Evasion_AMSI_Bypass {
    meta:
        description = "AMSI Bypass - Defense Evasion"
        mitre_technique = "T1562.001"
        severity = "CRITICAL"
    strings:
        $amsi1 = "AmsiUtils" nocase
        $amsi2 = "amsiInitFailed" nocase
        $amsi3 = "Antimalware Scan Interface" nocase
    condition:
        any of them
}

rule Evasion_ETW_Bypass {
    meta:
        description = "ETW (Event Tracing for Windows) Bypass"
        mitre_technique = "T1562.002"
        severity = "HIGH"
    strings:
        $etw1 = "EtwEventWrite" nocase
        $etw2 = "NtTraceEvent" nocase
        $etw3 = "EventWrite" nocase
    condition:
        any of them
}

rule Evasion_Sandbox_Check {
    meta:
        description = "Sandbox / VM Detection (Evasion)"
        mitre_technique = "T1497"
        severity = "MEDIUM"
    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "QEMU" nocase
        $vm4 = "sand" nocase
        $vm5 = "debugger" nocase
    condition:
        2 of them
}

rule Evasion_Anti_Debug {
    meta:
        description = "Anti-Debugging techniques"
        mitre_technique = "T1622"
        severity = "MEDIUM"
    strings:
        $dbg1 = "IsDebuggerPresent" nocase
        $dbg2 = "CheckRemoteDebuggerPresent" nocase
        $dbg3 = "OutputDebugString" nocase
    condition:
        any of them
}

// ====================== HIGH CONFIDENCE EVASION ======================

rule Multiple_Evasion_Techniques {
    meta:
        description = "Multiple evasion techniques detected"
        severity = "CRITICAL"
    strings:
        $ev1 = "AmsiUtils" nocase
        $ev2 = "VirtualAlloc" nocase
        $ev3 = "IsDebuggerPresent" nocase
        $ev4 = "sandbox" nocase
    condition:
        2 of them
}