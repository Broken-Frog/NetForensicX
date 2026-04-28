/*
   Recon-Net C2 Infrastructure YARA Rules
   Version: 2026.04 - Expanded with recent C2 IOCs
   Focused on known malicious C2 domains, IPs, and beacon patterns
*/

import "hash"
import "math"

// ====================== RECENT C2 DOMAINS & INFRASTRUCTURE ======================

rule C2_Known_Bad_Domains {
    meta:
        description = "Known malicious C2 domains and infrastructure (2025-2026)"
        severity = "CRITICAL"
    strings:
        // BlackCat / ALPHV
        $bc1 = "blackcat" nocase
        $bc2 = "alphv" nocase
        $bc3 = "alphvblog" nocase
        
        // Medusa
        $med1 = "medusa" nocase
        $med2 = "medusak" nocase
        $med3 = "medusalocker" nocase
        
        // LockBit
        $lb1 = "lockbit" nocase
        $lb2 = "lockbit3" nocase
        $lb3 = "lockbitblog" nocase
        
        // Hive
        $hive1 = "hive" nocase
        $hive2 = "hiveleak" nocase
        $hive3 = "hivemind" nocase
        
        // 8Base
        $eight1 = "8base" nocase
        $eight2 = "8baseleak" nocase
        
        // Qilin / Agenda
        $qilin1 = "qilin" nocase
        $qilin2 = "agenda" nocase
        
        // Rhysida, BianLian, Play, etc.
        $rhysida = "rhysida" nocase
        $bianlian = "bianlian" nocase
        $play = "play" nocase
        
        // Common C2 patterns
        $onion = /\.onion/ ascii
        $c2_path = /\/(api|task|beacon|panel|cmd|gate|checkin|callback)\// nocase
    condition:
        any of them
}

// ====================== RECENT C2 IP RANGES ======================

rule C2_Known_Bad_IPs {
    meta:
        description = "Known malicious C2 IP ranges (2025-2026)"
        severity = "HIGH"
    strings:
        // Common recent VPS / bulletproof hosting ranges
        $ip_range1 = /185\.(172|236)\.(2[0-9]{2}|3[0-9]{2})\./
        $ip_range2 = /194\.(169|182)\.(2[0-9]{2}|3[0-9]{2})\./
        $ip_range3 = /45\.(8[0-9]|9[0-9])\.[0-9]{1,3}\./
        $ip_range4 = /193\.(2[0-9]{2})\.[0-9]{1,3}\./
        $ip_range5 = /77\.8[0-9]\.[0-9]{1,3}\./
    condition:
        any of them
}

// ====================== C2 BEACON PATTERNS ======================

rule C2_Beacon_Patterns {
    meta:
        description = "Common C2 beacon HTTP patterns"
        severity = "HIGH"
    strings:
        $beacon1 = "POST /api/v" nocase
        $beacon2 = "POST /task" nocase
        $beacon3 = "GET /beacon" nocase
        $beacon4 = "GET /checkin" nocase
        $beacon5 = "X-C2-Token" nocase
        $beacon6 = "X-Session-ID" nocase
        $beacon7 = "/callback" nocase
        $beacon8 = "/command" nocase
    condition:
        any of them
}

// ====================== HIGH RISK C2 INDICATORS ======================

rule HighRisk_C2_Communication {
    meta:
        description = "High confidence C2 communication"
        severity = "CRITICAL"
    strings:
        $onion = /\.onion/ ascii
        $tor = "tor" nocase
        $c2 = "c2" nocase
        $command = /(command|cmd|task|beacon|checkin|callback)/ nocase
    condition:
        ($onion or $tor) and any of ($c2, $command)
}

rule Encrypted_C2_Channel {
    meta:
        description = "Encrypted C2 channels with high entropy"
        severity = "HIGH"
    condition:
        math.entropy(0, filesize) > 7.5 and
        (filesize > 200 and filesize < 15MB)
}

// ====================== SPECIFIC RECENT C2 IOCs (2025-2026) ======================

rule Recent_C2_Domains {
    meta:
        description = "Recently observed malicious C2 domains"
        severity = "HIGH"
    strings:
        $d1 = "c2panel" nocase
        $d2 = "commandserver" nocase
        $d3 = "botnet" nocase
        $d4 = "exfil" nocase
        $d5 = "stealer" nocase
        $d6 = "loader" nocase
    condition:
        any of them
}