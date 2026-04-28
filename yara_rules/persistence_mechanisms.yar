/*
   Recon-Net Persistence Mechanisms YARA Rules
   Focused on common persistence techniques used by malware and ransomware
   Version: 2026.04
*/

import "math"

// ====================== REGISTRY PERSISTENCE ======================

rule Registry_Run_Persistence {
    meta:
        description = "Registry Run/RunOnce persistence"
        severity = "HIGH"
    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $run3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $setitem = "Set-ItemProperty" nocase
        $newitem = "New-ItemProperty" nocase
    condition:
        any of ($run*) and any of ($setitem, $newitem)
}

rule Registry_Persistence_Aggressive {
    meta:
        description = "Aggressive registry persistence techniques"
        severity = "CRITICAL"
    strings:
        $reg1 = "CurrentVersion\\Run" nocase
        $reg2 = "CurrentVersion\\Policies\\Explorer\\Run" nocase
        $reg3 = "Winlogon\\Shell" nocase
        $reg4 = "Winlogon\\Userinit" nocase
        $reg5 = "Windows\\CurrentVersion\\Explorer\\StartupApproved" nocase
    condition:
        2 of them
}

// ====================== SCHEDULED TASKS PERSISTENCE ======================

rule Scheduled_Task_Persistence {
    meta:
        description = "Scheduled Task persistence"
        severity = "HIGH"
    strings:
        $task1 = "schtasks" nocase
        $task2 = "/create" nocase
        $task3 = "/tn" nocase
        $task4 = "Task Scheduler" nocase
        $task5 = "Register-ScheduledTask" nocase
    condition:
        2 of them
}

// ====================== WMI & SERVICE PERSISTENCE ======================

rule WMI_Persistence {
    meta:
        description = "WMI Event Subscription persistence"
        severity = "HIGH"
    strings:
        $wmi1 = "Win32_ActiveScriptEventConsumer" nocase
        $wmi2 = "Win32_PerfFormattedData" nocase
        $wmi3 = "FilterToConsumerBinding" nocase
        $wmi4 = "PermanentEventConsumer" nocase
    condition:
        2 of them
}

rule Service_Persistence {
    meta:
        description = "Service creation or modification for persistence"
        severity = "HIGH"
    strings:
        $svc1 = "sc create" nocase
        $svc2 = "New-Service" nocase
        $svc3 = "services.exe" nocase
        $svc4 = "Start-Service" nocase
    condition:
        2 of them
}

// ====================== STARTUP FOLDER PERSISTENCE ======================

rule Startup_Folder_Persistence {
    meta:
        description = "Startup folder persistence"
        severity = "MEDIUM"
    strings:
        $start1 = "Startup" nocase
        $start2 = "Start Menu\\Programs\\Startup" nocase
        $start3 = "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
    condition:
        any of them
}

// ====================== LNK & SHORTCUT PERSISTENCE ======================

rule LNK_Persistence {
    meta:
        description = "LNK file persistence"
        severity = "MEDIUM"
    strings:
        $lnk1 = ".lnk" nocase
        $lnk2 = "TargetPath" nocase
        $lnk3 = "ShellLink" nocase
    condition:
        2 of them
}

// ====================== ADVANCED PERSISTENCE ======================

rule Bootkit_Or_Driver_Persistence {
    meta:
        description = "Bootkit or kernel driver persistence"
        severity = "CRITICAL"
    strings:
        $drv1 = ".sys" nocase
        $drv2 = "DriverService" nocase
        $drv3 = "ServiceDll" nocase
    condition:
        2 of them
}

rule COM_Hijacking_Persistence {
    meta:
        description = "COM Hijacking persistence"
        severity = "HIGH"
    strings:
        $com1 = "InprocServer32" nocase
        $com2 = "LocalServer32" nocase
        $com3 = "CLSID" nocase
    condition:
        2 of them
}

// ====================== HIGH CONFIDENCE PERSISTENCE ======================

rule Multiple_Persistence_Techniques {
    meta:
        description = "Multiple persistence mechanisms detected"
        severity = "CRITICAL"
    strings:
        $reg = "Run" nocase
        $task = "schtasks" nocase
        $wmi = "Win32_" nocase
        $svc = "sc create" nocase
    condition:
        2 of them
}

rule HighEntropy_Persistence_Payload {
    meta:
        description = "High entropy payload used for persistence"
        severity = "HIGH"
    condition:
        filesize > 5KB and filesize < 10MB and
        math.entropy(0, filesize) > 7.2
}