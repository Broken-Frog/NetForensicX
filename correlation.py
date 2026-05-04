#!/usr/bin/env python3
"""
correlation.py
Phase 3: Correlation & Scoring Engine

Turns raw signals into investigation-ready attack chains.
Reads raw logs from the Data Lake and unified intelligence from Phase 2 to
build an IP -> Domain -> Session -> File -> Alert relationship.
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Set, Optional
import ipaddress
import datetime
from config import VOLUMETRIC_THRESHOLD_DOS, VOLUMETRIC_THRESHOLD_PORT_SCAN

def _load_json_lines(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records

def _load_json(path: Path) -> Dict:
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

import statistics

# Data exfiltration threshold (bytes) — used in multi-factor scoring
DATA_EXFIL_THRESHOLD_BYTES = 50 * 1024 * 1024  # 50 MB

# Lateral movement ports and their labels
LATERAL_MOVEMENT_PORTS = {445: "SMB", 3389: "RDP", 135: "RPC", 139: "NetBIOS", 22: "SSH", 23: "Telnet"}

def _is_ipv6_artifact(ip_str: str) -> bool:
    """Returns True for link-local, loopback, or multicast IPv6 that are not real endpoints."""
    if not ip_str: return False
    lower = ip_str.lower()
    return lower.startswith("fe80:") or lower == "::1" or lower.startswith("ff02:") or lower.startswith("ff0")

def classify_host_roles(sessions: Dict[str, Dict], host_profiles: Dict[str, Dict]) -> Dict[str, Dict]:
    """
    Classifies each host as PATIENT_ZERO, CO_PRIMARY, INFECTOR, INFECTED, C2_NODE, ATTACKER, VICTIM, or UNKNOWN.
    Returns a dict: ip -> {role, lateral_movements: [(src, dst, port, proto)]}
    """
    def is_internal(ip_str):
        if not ip_str or _is_ipv6_artifact(ip_str): return False
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    # --- Phase A: Identify lateral movement (internal → internal on suspicious ports) ---
    lateral_map = {}  # src_ip -> set of (dst_ip, port, proto)
    receives_lateral = {}  # dst_ip -> set of src_ip

    for s in sessions.values():
        if s["score"] == 0: continue
        orig, resp, port = s.get("orig_h"), s.get("resp_h"), s.get("resp_p")
        if is_internal(orig) and is_internal(resp) and port in LATERAL_MOVEMENT_PORTS:
            lateral_map.setdefault(orig, set()).add((resp, port, LATERAL_MOVEMENT_PORTS[port]))
            receives_lateral.setdefault(resp, set()).add(orig)

    # --- Phase B: Identify C2 nodes (external IPs receiving beaconing) ---
    c2_nodes = set()
    for s in sessions.values():
        hit_str = " ".join(s.get("intel_hits", []))
        if "beaconing_score" in s or "C2" in hit_str or "Backdoor" in hit_str:
            resp = s.get("resp_h")
            if resp and not is_internal(resp):
                c2_nodes.add(resp)

    # --- Phase C: Identify DoS attackers & victims ---
    attackers = set()
    victims = set()
    for s in sessions.values():
        hit_str = " ".join(s.get("intel_hits", []))
        if "Volumetric Anomaly: High connection rate" in hit_str:
            orig = s.get("orig_h")
            if orig: attackers.add(orig)
        if "Volumetric Anomaly: Targeted" in hit_str:
            resp = s.get("resp_h")
            if resp: victims.add(resp)

    # --- Phase D: Assign roles to all internal hosts in host_profiles ---
    roles = {}
    internal_hosts = [
        (ip, p) for ip, p in host_profiles.items()
        if is_internal(ip) and not _is_ipv6_artifact(ip)
    ]

    for ip, profile in internal_hosts:
        if ip in attackers:
            role = "ATTACKER"
        elif ip in victims:
            role = "VICTIM"
        elif ip in c2_nodes:
            role = "C2_NODE"
        elif ip in lateral_map and ip not in receives_lateral:
            role = "INFECTOR"  # spreads to others, not receiving lateral
        elif ip in receives_lateral:
            role = "INFECTED"  # receives from another internal host
        else:
            role = "SUSPECTED_PATIENT_ZERO"

        roles[ip] = {
            "role": role,
            "infection_score": profile["infection_score"],
            "first_seen": profile.get("first_seen", float('inf')),
            "lateral_movements": [(dst, port, proto) for dst, port, proto in lateral_map.get(ip, set())],
            "infected_by": list(receives_lateral.get(ip, set()))
        }

    # --- Phase E: Determine Patient Zero(s) ---
    # Pick earliest first_seen among all infected internal hosts
    all_candidates = [(ip, r) for ip, r in roles.items() if r["infection_score"] > 0 and r["role"] not in ("ATTACKER", "VICTIM", "C2_NODE")]

    if all_candidates:
        all_candidates.sort(key=lambda x: (x[1]["first_seen"], -x[1]["infection_score"]))
        earliest_ts = all_candidates[0][1]["first_seen"]
        pz_ips = [
            ip for ip, r in all_candidates
            if abs(r["first_seen"] - earliest_ts) <= 1.0  # co-primary window: 1 second
        ]
        if len(pz_ips) == 1:
            roles[pz_ips[0]]["role"] = "PATIENT_ZERO"
        else:
            for ip in pz_ips:
                roles[ip]["role"] = "CO_PRIMARY"

    return roles


def generate_attack_story(sessions: Dict[str, Dict], timeline_events: List[Dict], host_profiles: Dict[str, Dict], phase2_dir: Path):
    story_lines = []
    story_lines.append("🧾 ATTACK STORY (AUTO-GENERATED)")
    story_lines.append("=" * 50)
    
    global_flags = {"ransomware": False, "volumetric": False, "c2": False, "malware": False, "exfiltration": False}
    dos_sessions = []
    malware_sessions = []

    # Classify roles FIRST — this is used to build the narrative correctly
    host_roles = classify_host_roles(sessions, host_profiles)
    
    for s in sessions.values():
        if s["score"] == 0: continue
        hit_str = " ".join(s.get("intel_hits", []))
        
        is_vol = "Volumetric" in hit_str
        is_rans = "Ransomware" in hit_str
        is_c2 = "C2" in hit_str or "Backdoor" in hit_str
        is_exfil = "Data Exfiltration" in hit_str
        is_mal = "Malicious" in hit_str or s.get("files") or is_rans or is_c2 or "Exploit" in hit_str or "Web Attack" in hit_str or "Downloader" in hit_str or "Injection" in hit_str or is_exfil
        
        if is_vol:
            global_flags["volumetric"] = True
            dos_sessions.append(s)
            
        if not is_vol or (is_vol and is_mal): # if hybrid, it goes to both
            malware_sessions.append(s)
            if is_rans: global_flags["ransomware"] = True
            if is_c2: global_flags["c2"] = True
            if is_mal: global_flags["malware"] = True
            if is_exfil: global_flags["exfiltration"] = True

    # 1. Output DoS Summary if exists
    if global_flags["volumetric"]:
        story_lines.append("\n🚨 VERDICT: Denial of Service (DoS) Attack")
        story_lines.append("Confidence: HIGH")
        
        attackers = set()
        targets = set()
        total_connections = 0
        min_ts = float('inf')
        max_ts = 0
        
        for s in dos_sessions:
            if s.get("orig_h"): attackers.add(s["orig_h"])
            if s.get("resp_h"): targets.add(f"{s['resp_h']}:{s['resp_p']}")
            total_connections += 1
            ts = s.get("ts", 0)
            if ts:
                if ts < min_ts: min_ts = ts
                if ts > max_ts: max_ts = ts
                
        duration = max_ts - min_ts if max_ts > min_ts else 1.0
        
        story_lines.append("\n🎯 ATTACK TYPE: Volumetric Flood")
        
        story_lines.append("\n🟥 ATTACKER(S):")
        for a in attackers: story_lines.append(f"- {a}")
        
        story_lines.append("\n🎯 TARGET(S):")
        for t in targets: story_lines.append(f"- {t}")
        
        story_lines.append("\n📊 CHARACTERISTICS:")
        story_lines.append(f"- Total Connections: {total_connections}")
        story_lines.append(f"- Time Window: ~{duration:.2f} seconds burst")
        story_lines.append("- Pattern: Rapid, repeated requests")
        story_lines.append("- Payload: None")
        story_lines.append("- C2: None")
        story_lines.append("- Persistence: None")
        
        story_lines.append("\n📌 INTERPRETATION:")
        story_lines.append("High-rate connection flood targeting host(s), consistent with DoS behavior.")
        story_lines.append("\n⚠ IMPACT:")
        story_lines.append("Target service likely degraded or unavailable")
        story_lines.append("\n" + "-" * 50)

    # 2. Output Malware / Role-Aware Summary if malware detected
    if global_flags["malware"] or (not global_flags["volumetric"] and malware_sessions):
        affected_hosts = []
        max_score = 0
        pz_story_lines = []
        global_stages = set()
        global_seen_stage2_hashes = set()

        # Build role-ordered host list: PZ/CO-PRIMARY first, then INFECTED
        ROLE_ORDER = {"PATIENT_ZERO": 0, "CO_PRIMARY": 1, "INFECTOR": 2, "INFECTED": 3, "SUSPECTED_PATIENT_ZERO": 4}
        ordered_ips = sorted(
            [ip for ip, r in host_roles.items() if r["role"] not in ("ATTACKER", "VICTIM", "C2_NODE")],
            key=lambda ip: (ROLE_ORDER.get(host_roles[ip]["role"], 99), -host_roles[ip]["infection_score"])
        )

        # C2 infrastructure block
        c2_nodes = [ip for ip, r in host_roles.items() if r["role"] == "C2_NODE"]
        if c2_nodes:
            pz_story_lines.append("\n🌐 C2 INFRASTRUCTURE IDENTIFIED:")
            for node in c2_nodes:
                pz_story_lines.append(f"  - {node} (receives beaconing from internal hosts)")

        # Lateral movement summary block
        lateral_events = []
        for ip, r in host_roles.items():
            for (dst, port, proto) in r.get("lateral_movements", []):
                lateral_events.append((ip, dst, port, proto))
        if lateral_events:
            pz_story_lines.append("\n🔴 LATERAL MOVEMENT DETECTED:")
            for src, dst, port, proto in lateral_events:
                pz_story_lines.append(f"  {src} → {dst} via {proto} (Port {port})")

        for pz_ip in ordered_ips:
            role_info = host_roles.get(pz_ip, {})
            role = role_info.get("role", "UNKNOWN")
            pz = host_profiles.get(pz_ip)
            if not pz: continue

            pz_sessions = [s for s in malware_sessions if (s["orig_h"] == pz_ip or s["resp_h"] == pz_ip)]
            if not pz_sessions and role not in ("PATIENT_ZERO", "CO_PRIMARY"): continue

            # Role-aware header
            role_emoji = {
                "PATIENT_ZERO": "🎯 LIKELY PATIENT ZERO",
                "CO_PRIMARY": "🎯 LIKELY CO-PRIMARY PATIENT ZERO",
                "INFECTOR": "☣ INFECTOR",
                "INFECTED": "💀 INFECTED HOST",
                "SUSPECTED_PATIENT_ZERO": "🎯 SUSPECTED PATIENT ZERO"
            }.get(role, f"💻 HOST")

            hostname_str = f" ({pz.get('hostname', 'Unknown')})"
            pz_story_lines.append(f"\n{role_emoji}: {pz_ip}{hostname_str}")
            
            if role in ("PATIENT_ZERO", "CO_PRIMARY", "SUSPECTED_PATIENT_ZERO"):
                confidence = "HIGH" if len(role_info.get("lateral_movements", [])) > 0 else "MEDIUM"
                if role == "SUSPECTED_PATIENT_ZERO": confidence = "LOW"
                
                pz_story_lines.append(f"  Confidence: {confidence}")
                pz_story_lines.append(f"  Reason:")
                
                if role == "PATIENT_ZERO":
                    pz_story_lines.append(f"  - Earliest confirmed infection time")
                elif role == "CO_PRIMARY":
                    pz_story_lines.append(f"  - Simultaneous compromise detected with another host")
                elif role == "SUSPECTED_PATIENT_ZERO":
                    pz_story_lines.append(f"  - Shows signs of compromise but lacks clear lateral movement initiation")
                    
                lat_moves = role_info.get("lateral_movements", [])
                if lat_moves:
                    protocols = list(set([p for _, _, p in lat_moves]))
                    pz_story_lines.append(f"  - Initiated {', '.join(protocols)}-based lateral movement")
                    
                if pz["infection_score"] > 100:
                    pz_story_lines.append(f"  - High malicious activity score ({pz['infection_score']} pts)")

            if role_info.get("infected_by"):
                pz_story_lines.append(f"  ↳ Infected by: {', '.join(role_info['infected_by'])}")
            pz_story_lines.append("-" * 50)
            
            pz_sessions.sort(key=lambda x: x["ts"] or 0)
            stages = {1: [], 2: [], 3: [], 4: [], 5: [], 6: [], 7: []}
            
            connections_to_target = {}
            for s in pz_sessions:
                if s["orig_h"] == pz_ip: 
                    target = (s["resp_h"], s["resp_p"])
                    connections_to_target.setdefault(target, []).append(s)
                    
            beaconing_targets = {}
            for target, conns in connections_to_target.items():
                if len(conns) < 2: continue
                
                score = 0
                if len(conns) >= 5: score += 20
                if len(conns) >= 10: score += 40
                
                intervals = []
                for i in range(1, len(conns)):
                    intervals.append(conns[i]["ts"] - conns[i-1]["ts"])
                
                if len(intervals) > 1:
                    std_dev = statistics.stdev(intervals)
                    if std_dev < 2.0: score += 40
                        
                avg_duration = sum(c.get("duration", 0) for c in conns) / len(conns)
                if avg_duration < 5.0: score += 20
                    
                avg_bytes = sum(c.get("orig_bytes", 0) + c.get("resp_bytes", 0) for c in conns) / len(conns)
                if avg_bytes < 50000: score += 20
                    
                dns_lookup = False
                for c in conns:
                    if c.get("dns"): dns_lookup = True
                if dns_lookup: score += 10
                    
                known_bad = False
                for c in conns:
                    hit_str = " ".join(c.get("intel_hits", []))
                    if "C2" in hit_str or "Backdoor" in hit_str or c.get("files"): known_bad = True
                if known_bad: score += 50
                    
                beaconing_targets[target] = score
    
            for s in pz_sessions:
                hit_str = " ".join(s.get("intel_hits", []))
                
                stage = None
                if "Web Attack" in hit_str or "Exploit" in hit_str: stage = 1
                elif "Downloader" in hit_str or s.get("files"): stage = 2
                elif s.get("dns") and ("C2" in hit_str or "VT" in hit_str): stage = 3
                elif "C2" in hit_str or "Backdoor" in hit_str: stage = 4
                elif "Fileless" in hit_str or "Injection" in hit_str or "Lateral Movement" in hit_str: stage = 6
                elif "Ransomware" in hit_str: stage = 7
                    
                if s["orig_h"] == pz_ip:
                    target = (s["resp_h"], s["resp_p"])
                    b_score = beaconing_targets.get(target, 0)
                    if b_score >= 80:
                        stage = 5
                        s["beaconing_score"] = b_score
                        
                if stage: stages[stage].append(s)
                    
            has_story = False
            last_stage_printed = False
            
            stage_names = {
                1: "[STAGE 1] Initial Access",
                2: "[STAGE 2] Payload Execution",
                3: "[STAGE 3] Command & Control Setup",
                4: "[STAGE 4] C2 Communication Established",
                5: "[STAGE 5] Beaconing / Persistence",
                6: "[STAGE 6] Possible Lateral Movement",
                7: "[STAGE 7] Impact (Potential)"
            }
            
            for stg_num in range(1, 8):
                stg_sessions = stages[stg_num]
                if not stg_sessions: continue
                
                global_stages.add(stg_num)
                if last_stage_printed: pz_story_lines.append("\n        ↓\n")
                
                pz_story_lines.append(stage_names[stg_num])
                has_story = True
                last_stage_printed = True
                
                if stg_num == 1:
                    pz_story_lines.append(f"Host {pz_ip} likely compromised via attack.")
                    pz_story_lines.append(f"Indicators:")
                    for s in stg_sessions[:3]: pz_story_lines.append(f"- {s.get('intel_hits', ['Exploitation Attempt'])[0]}")
                elif stg_num == 2:
                    files = list(set([f for s in stg_sessions for f in s.get("files", [])]))
                    new_files = [f for f in files if f not in global_seen_stage2_hashes]
                    
                    if not new_files and files:
                        pz_story_lines.append(f"Malicious payload executed on host (Previously seen hash: {files[0][:8]}...)")
                    else:
                        pz_story_lines.append(f"Malicious payload executed on host.")
                        if new_files: 
                            pz_story_lines.append(f"Hash: {new_files[0][:8]}...")
                            global_seen_stage2_hashes.update(new_files)
                            
                    pz_story_lines.append(f"Indicators:")
                    for s in stg_sessions[:3]: pz_story_lines.append(f"- {s.get('intel_hits', ['Malicious File Transfer'])[0]}")
                elif stg_num == 3:
                    domains = list(set([d.get("query") for s in stg_sessions for d in s.get("dns", []) if d.get("query")]))
                    pz_story_lines.append(f"Host begins DNS queries resolving attacker infrastructure.")
                    for d in domains[:3]: pz_story_lines.append(f"→ {d}")
                elif stg_num == 4:
                    ips = list(set([s["resp_h"] for s in stg_sessions]))
                    pz_story_lines.append(f"Host communicates with external server:")
                    for ip in ips[:3]: pz_story_lines.append(f"- {ip} (known malicious)")
                elif stg_num == 5:
                    unique_targets = set([(s["resp_h"], s["resp_p"], s.get("beaconing_score", 0)) for s in stg_sessions])
                    pz_story_lines.append(f"Repeated outbound connections observed:")
                    for target in list(unique_targets)[:3]: pz_story_lines.append(f"{pz_ip} → {target[0]}:{target[1]} (Beaconing Score: {target[2]})")
                elif stg_num == 6:
                    internal_targets = set([s["resp_h"] for s in stg_sessions])
                    pz_story_lines.append(f"Secondary host(s) involved:")
                    for ip in list(internal_targets)[:3]: pz_story_lines.append(f"- {ip} shows similar suspicious behavior")
                elif stg_num == 7:
                    pz_story_lines.append(f"Indicators of:")
                    for s in stg_sessions[:3]: pz_story_lines.append(f"- {s.get('intel_hits', ['Impact Activity'])[0]}")
    
            if not has_story:
                pz_story_lines.append("No clear stage progression detected for this host, but suspicious activity logged.")
            else:
                affected_hosts.append(pz_ip)
                if pz["infection_score"] > max_score: max_score = pz["infection_score"]
                
        verdict = "Suspicious network activity detected."
        if global_flags["exfiltration"] and (global_flags["ransomware"] or global_flags["c2"]):
            verdict = "Internal compromise with active data exfiltration"
        elif global_flags["ransomware"] and (global_flags["c2"] or 5 in global_stages):
            verdict = "Ransomware infection with active C2 communication"
        elif global_flags["ransomware"]:
            verdict = "Ransomware activity detected"
        elif global_flags["exfiltration"]:
            verdict = "Suspected data exfiltration detected"
        elif 6 in global_stages or any(r["lateral_movements"] for r in host_roles.values()):
            verdict = "Internal network compromise and lateral movement"
        elif 5 in global_stages or global_flags["c2"]:
            verdict = "Active C2 beaconing and persistence established"
        elif 4 in global_stages:
            verdict = "C2 communication established"
        elif 2 in global_stages:
            verdict = "Malicious payload execution"
        elif 1 in global_stages:
            verdict = "Initial access / Exploitation attempt"
    
        confidence = "LOW"
        if max_score > 200: confidence = "HIGH"
        elif max_score > 100: confidence = "MEDIUM"
        
        story_lines.append("\n🚨 VERDICT: " + verdict)
        story_lines.append(f"Confidence: {confidence}")
        story_lines.append(f"Affected Hosts: {', '.join(affected_hosts) if affected_hosts else 'None'}\n")
        story_lines.extend(pz_story_lines)

    story_lines.append("\n============================================================")
    story_lines.append(" 🕒 GLOBAL ATTACK TIMELINE")
    story_lines.append("============================================================")
    for evt in timeline_events:
        dt = datetime.datetime.fromtimestamp(evt['timestamp'], tz=datetime.timezone.utc)
        if dt.year == 1970:
            iso_ts = f"T+{evt['timestamp']:.2f}s"
        else:
            iso_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        story_lines.append(f"{iso_ts} | {evt['action']:<30} | {evt['source']} -> {evt['destination']} (Score: {evt['score']})")
        
    out_story = "\n".join(story_lines)
    
    with open(phase2_dir / "attack_story.txt", "w", encoding="utf-8") as f:
        f.write(out_story)
        
    print("\n" + out_story)

def build_attack_chains(
    base_dir: Path,
    phase2_dir: Path
) -> None:
    print(f"[Correlation] Loading data from {base_dir}")
    
    # 1. Load Mappings
    linker_data = _load_json(base_dir / "flow_linker.json")
    zeek_to_suri = linker_data.get("zeek_uid_to_suricata_flow_id", {})
    
    file_linker_data = _load_json(base_dir / "file_linker.json")
    hash_to_uid = file_linker_data.get("file_hash_to_zeek_uid", {})
    uid_to_hashes: Dict[str, List[str]] = {}
    for fhash, info in hash_to_uid.items():
        uid = info.get("uid")
        if uid:
            uid_to_hashes.setdefault(uid, []).append(fhash)

    # 2. Load Phase 2 Intelligence
    iocs_data = _load_json(phase2_dir / "unified_iocs.json")
    # Build fast lookups
    intel_by_ip = {}
    intel_by_domain = {}
    intel_by_hash = {}
    for ioc in iocs_data:
        if ioc.get("ip"):
            intel_by_ip[ioc["ip"]] = ioc
        if ioc.get("domain"):
            intel_by_domain[ioc["domain"]] = ioc
        if ioc.get("file_hash"):
            intel_by_hash[ioc["file_hash"]] = ioc

    # 3. Load Raw Network Sessions
    zeek_dir = base_dir / "zeek"
    conns = _load_json_lines(zeek_dir / "conn.json")
    http = _load_json_lines(zeek_dir / "http.json")
    dns = _load_json_lines(zeek_dir / "dns.json")
    
    # 3.5. Hostname Identity Extraction
    ip_to_hostname = {}
    
    dhcp = _load_json_lines(zeek_dir / "dhcp.json")
    for d in dhcp:
        ip = d.get("client_addr") or d.get("assigned_ip")
        name = d.get("host_name") or d.get("client_fqdn")
        if ip and name:
            ip_to_hostname[ip] = name
            
    ntlm = _load_json_lines(zeek_dir / "ntlm.json")
    for n in ntlm:
        ip = n.get("id.orig_h")
        name = n.get("hostname")
        if ip and name:
            ip_to_hostname[ip] = name
            
    kerberos = _load_json_lines(zeek_dir / "kerberos.json")
    for k in kerberos:
        ip = k.get("id.orig_h")
        name = k.get("client")
        if ip and name and "/" not in name:
            ip_to_hostname[ip] = name
    
    # Organize zeek events by UID
    sessions: Dict[str, Dict] = {}
    
    for c in conns:
        uid = c.get("uid")
        if uid:
            sessions[uid] = {
                "uid": uid,
                "ts": c.get("ts"),
                "orig_h": c.get("id.orig_h"),
                "resp_h": c.get("id.resp_h"),
                "orig_hostname": ip_to_hostname.get(c.get("id.orig_h")),
                "resp_hostname": ip_to_hostname.get(c.get("id.resp_h")),
                "proto": c.get("proto"),
                "service": c.get("service"),
                "orig_p": c.get("id.orig_p"),
                "resp_p": c.get("id.resp_p"),
                "duration": c.get("duration", 0.0),
                "orig_bytes": c.get("orig_bytes", 0),
                "resp_bytes": c.get("resp_bytes", 0),
                "http": [],
                "dns": [],
                "files": [],
                "suricata_alerts": [],
                "score": 0,
                "severity": "LOW",
                "intel_hits": []
            }

    for h in http:
        uid = h.get("uid")
        if uid and uid in sessions:
            sessions[uid]["http"].append({
                "host": h.get("host"),
                "uri": h.get("uri"),
                "method": h.get("method")
            })
            
    for d in dns:
        uid = d.get("uid")
        if uid and uid in sessions:
            sessions[uid]["dns"].append({
                "query": d.get("query"),
                "qtype_name": d.get("qtype_name")
            })

    # Attach file hashes
    for uid, sess in sessions.items():
        if uid in uid_to_hashes:
            sess["files"].extend(uid_to_hashes[uid])

    # 4. Attach Suricata Alerts using flow_id
    suri_dir = base_dir / "suricata"
    eve = _load_json_lines(suri_dir / "eve.json")
    
    flow_to_alerts = {}
    for e in eve:
        if e.get("event_type") == "alert":
            fid = e.get("flow_id")
            if fid:
                alert = e.get("alert", {})
                flow_to_alerts.setdefault(fid, []).append({
                    "signature": alert.get("signature"),
                    "severity": alert.get("severity")
                })
                
    for uid, sess in sessions.items():
        fid = zeek_to_suri.get(uid)
        if fid and fid in flow_to_alerts:
            sess["suricata_alerts"].extend(flow_to_alerts[fid])

    # 4.5. Volumetric Analysis Pre-Processing
    src_conn_counts = {}
    target_conn_counts = {}
    for uid, sess in sessions.items():
        src = sess.get("orig_h")
        target = (sess.get("orig_h"), sess.get("resp_h"), sess.get("resp_p"))
        if src:
            src_conn_counts[src] = src_conn_counts.get(src, 0) + 1
        if target[0] and target[1]:
            target_conn_counts[target] = target_conn_counts.get(target, 0) + 1

    # 5. Calculate Severity Score per Session
    for uid, sess in sessions.items():
        score = 0
        hits = []
        
        # 5e. Volumetric Anomaly Detection
        src = sess.get("orig_h")
        target = (sess.get("orig_h"), sess.get("resp_h"), sess.get("resp_p"))
        
        if src and src_conn_counts.get(src, 0) > VOLUMETRIC_THRESHOLD_DOS:
            score += 80
            hits.append(f"Volumetric Anomaly: High connection rate from {src} ({src_conn_counts[src]} Conns)")
        elif target[0] and target[1] and target_conn_counts.get(target, 0) > VOLUMETRIC_THRESHOLD_PORT_SCAN:
            score += 80
            hits.append(f"Volumetric Anomaly: Targeted attack on {target[1]}:{target[2]} ({target_conn_counts[target]} Conns)")
            
        # 5a. Suricata Alerts
        if sess["suricata_alerts"]:
            score += 50
            hits.append(f"Suricata Alerts ({len(sess['suricata_alerts'])})")
            
        # 5b. IP Intelligence
        for ip in [sess["orig_h"], sess["resp_h"]]:
            if not ip: continue
            intel = intel_by_ip.get(ip, {})
            
            vt_score = intel.get("vt_malicious_count", 0) or 0
            if vt_score >= 5:
                score += 30
                hits.append(f"VT Malicious IP ({ip})")
                
            if intel.get("is_malicious_ip"):
                score += 20
            vt_score = intel.get("vt_malicious_count", 0) or 0
            if vt_score >= 5: 
                score += 80
                hits.append(f"VT ({vt_score} engines) on {ip}")
            if intel.get("is_malicious_ip"): 
                score += 50
                hits.append(f"AbuseIPDB (Malicious) on {ip}")
            if intel.get("high_pulse_rate"): 
                score += 50
                hits.append(f"OTX (High Pulse) on {ip}")

        # 5c. Domain Intelligence
        for d in sess["dns"]:
            query = d.get("query")
            if not query: continue
            intel = intel_by_domain.get(query, {})
            vt_score = intel.get("vt_malicious_count", 0) or 0
            if vt_score >= 5:
                score += 80
                hits.append(f"VT ({vt_score} engines) on {query}")
            if intel.get("high_pulse_rate"):
                score += 50
                hits.append(f"OTX (High Pulse) on {query}")
                
        for h in sess["http"]:
            host = h.get("host")
            if not host: continue
            intel = intel_by_domain.get(host, {})
            vt_score = intel.get("vt_malicious_count", 0) or 0
            if vt_score >= 5:
                score += 80
                hits.append(f"VT ({vt_score} engines) on {host}")
            if intel.get("high_pulse_rate"):
                score += 50
                hits.append(f"OTX (High Pulse) on {host}")
                
        # 5d. YARA Intelligence
        for fhash in sess["files"]:
            intel = intel_by_hash.get(fhash, {})
            yara_score = intel.get("yara_score", 0)
            if yara_score > 0:
                score += yara_score
                clusters = intel.get("yara_clusters", [])
                cluster_str = "/".join(clusters) if clusters else "Unknown"
                hits.append(f"YARA Cluster [{cluster_str}] ({yara_score} pts on {fhash[:8]})")
            elif intel.get("yara_match"):
                score += 40
                hits.append(f"YARA Match ({intel.get('yara_match')} on {fhash[:8]})")
            if intel.get("vt_malicious_count", 0) >= 5:
                score += 30
                hits.append(f"VT Malicious File ({fhash[:8]})")

        # 5e. Data Exfiltration Detection (multi-factor scoring)
        orig_bytes = sess.get("orig_bytes", 0) or 0
        if orig_bytes >= DATA_EXFIL_THRESHOLD_BYTES:
            orig_ip = sess.get("orig_h")
            resp_ip = sess.get("resp_h")
            resp_port = sess.get("resp_p")
            
            def _is_int(ip):
                if not ip: return False
                try: return ipaddress.ip_address(ip).is_private
                except ValueError: return False

            if _is_int(orig_ip) and not _is_int(resp_ip):
                exfil_score = 0
                mb_sent = orig_bytes / (1024 * 1024)

                # Factor 1: Transfer size
                if orig_bytes > DATA_EXFIL_THRESHOLD_BYTES: exfil_score += 10
                if orig_bytes > 10 * DATA_EXFIL_THRESHOLD_BYTES: exfil_score += 20  # > 500MB

                # Factor 2: Unknown / unverified external destination
                dest_intel = intel_by_ip.get(resp_ip, {})
                no_known_good = not dest_intel.get("hostname") and not sess.get("dns")
                if no_known_good: exfil_score += 20

                # Factor 3: Destination flagged as malicious
                if dest_intel.get("vt_malicious_count", 0) >= 5 or dest_intel.get("is_malicious_ip"):
                    exfil_score += 60

                # Factor 4: Unusual port (not common upload ports)
                common_ports = {80, 443, 21, 22, 25, 8080, 8443, 2222}
                if resp_port and resp_port not in common_ports:
                    exfil_score += 20

                # Factor 5: Source host already known infected (score > 80)
                if score > 80:
                    exfil_score += 50

                if exfil_score >= 60:
                    score += 80
                    hits.append(f"Data Exfiltration: {mb_sent:.1f} MB transferred to {resp_ip}:{resp_port} (Exfil Score: {exfil_score})")

        sess["score"] = score
        sess["intel_hits"] = list(set(hits))
        
        if score >= 80:
            sess["severity"] = "HIGH"
        elif score >= 40:
            sess["severity"] = "MEDIUM"

    # 5.5. Host-Centric Profiling
    host_profiles = {}
    
    def is_internal(ip_str):
        if not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return False

    for uid, sess in sessions.items():
        if sess["score"] == 0:
            continue
            
        orig_ip = sess.get("orig_h")
        resp_ip = sess.get("resp_h")
        
        internal_ips = []
        external_ips = []
        
        if orig_ip and is_internal(orig_ip):
            internal_ips.append((orig_ip, sess.get("orig_hostname")))
        elif orig_ip:
            external_ips.append(orig_ip)
            
        if resp_ip and is_internal(resp_ip):
            internal_ips.append((resp_ip, sess.get("resp_hostname")))
        elif resp_ip:
            external_ips.append(resp_ip)
            
        for ip, hostname in internal_ips:
            if ip not in host_profiles:
                host_profiles[ip] = {
                    "ip": ip,
                    "hostname": hostname,
                    "infection_score": 0,
                    "intel_hits": set(),
                    "suricata_alerts": set(),
                    "files": set(),
                    "contacted_domains": set(),
                    "contacted_ips": set(),
                    "first_seen": sess.get("ts", float('inf'))
                }
            
            profile = host_profiles[ip]
            
            ts = sess.get("ts")
            if ts and ts < profile.get("first_seen", float('inf')):
                profile["first_seen"] = ts
                
            if "Volumetric" in " ".join(sess.get("intel_hits", [])):
                if not profile.get("dos_counted"):
                    profile["infection_score"] += 80
                    profile["dos_counted"] = True
                profile["dos_connections"] = profile.get("dos_connections", 0) + 1
            else:
                profile["infection_score"] += sess["score"]
            profile["intel_hits"].update(sess.get("intel_hits", []))
            
            for alert in sess.get("suricata_alerts", []):
                profile["suricata_alerts"].add(alert.get("signature"))
                
            profile["files"].update(sess.get("files", []))
            
            for d in sess.get("dns", []):
                if d.get("query"):
                    profile["contacted_domains"].add(d["query"])
            for h in sess.get("http", []):
                if h.get("host"):
                    profile["contacted_domains"].add(h["host"])
                    
            profile["contacted_ips"].update(external_ips)

    # Convert sets to lists for JSON serialization
    for ip, profile in host_profiles.items():
        profile["intel_hits"] = list(profile["intel_hits"])
        profile["suricata_alerts"] = list(profile["suricata_alerts"])
        profile["files"] = list(profile["files"])
        profile["contacted_domains"] = list(profile["contacted_domains"])
        profile["contacted_ips"] = list(profile["contacted_ips"])

    out_host_file = phase2_dir / "host_profiles.json"
    with open(out_host_file, "w", encoding="utf-8") as f:
        json.dump(host_profiles, f, indent=2)

    # 6. Output Generation
    high_sev = [s for s in sessions.values() if s["severity"] == "HIGH"]
    med_sev = [s for s in sessions.values() if s["severity"] == "MEDIUM"]
    
    dos_aggregated = {}
    non_dos_high_sev = []
    
    for s in high_sev:
        hit_str = " ".join(s.get("intel_hits", []))
        if "Volumetric" in hit_str:
            key = (s["orig_h"], s["resp_h"], s["resp_p"])
            if key not in dos_aggregated:
                dos_aggregated[key] = {
                    "uid": "AGGREGATED_DOS",
                    "ts": s.get("ts"),
                    "orig_h": s["orig_h"],
                    "orig_p": "Multiple",
                    "orig_hostname": s.get("orig_hostname", ""),
                    "resp_h": s["resp_h"],
                    "resp_p": s["resp_p"],
                    "resp_hostname": s.get("resp_hostname", ""),
                    "proto": s.get("proto"),
                    "service": s.get("service"),
                    "score": s["score"],
                    "severity": "HIGH",
                    "intel_hits": ["Volumetric DoS Attack (Aggregated)"],
                    "total_connections": 1,
                    "min_ts": s.get("ts", 0),
                    "max_ts": s.get("ts", 0),
                    "files": [],
                    "http": [],
                    "dns": [],
                    "suricata_alerts": []
                }
            else:
                dos_aggregated[key]["total_connections"] += 1
                if s.get("ts", 0) < dos_aggregated[key]["min_ts"]: dos_aggregated[key]["min_ts"] = s.get("ts", 0)
                if s.get("ts", 0) > dos_aggregated[key]["max_ts"]: dos_aggregated[key]["max_ts"] = s.get("ts", 0)
        else:
            non_dos_high_sev.append(s)
            
    final_high_sev = non_dos_high_sev + list(dos_aggregated.values())
    
    # Calculate pie chart distributions for the frontend
    protocol_distribution = {}
    service_distribution = {}
    src_port_distribution = {}
    
    for s in final_high_sev + med_sev:
        proto = s.get("proto") or "unknown"
        service = s.get("service") or "unknown"
        port = s.get("orig_p")
        
        protocol_distribution[proto] = protocol_distribution.get(proto, 0) + 1
        service_distribution[service] = service_distribution.get(service, 0) + 1
        
        if port:
            port_str = f"Port {port}"
            src_port_distribution[port_str] = src_port_distribution.get(port_str, 0) + 1
    
    out_file = phase2_dir / "incidents_correlated.json"
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "high_severity": high_sev,
            "medium_severity": med_sev,
            "total_high": len(high_sev),
            "total_medium": len(med_sev),
            "protocol_distribution": protocol_distribution,
            "service_distribution": service_distribution,
            "src_port_distribution": src_port_distribution
        }, f, indent=2)
        
    # 7. Timeline Generation
    timeline_events = []
    story_sessions = [s for s in sessions.values() if s["score"] > 0]
    
    for s in story_sessions:
        ts = s.get("ts")
        if not ts: continue
        
        action = "Suspicious Network Activity"
        hit_str = " ".join(s.get("intel_hits", []))
        
        if "Ransomware" in hit_str:
            action = "Ransomware Activity"
        elif "C2" in hit_str or "Backdoor" in hit_str:
            action = "C2 Communication"
        elif "Fileless" in hit_str or "Injection" in hit_str or "Lateral Movement" in hit_str:
            action = "Lateral Movement / Injection"
        elif "Web Attack" in hit_str or "Exploit" in hit_str:
            action = "Exploitation Attempt"
        elif "Downloader" in hit_str or s.get("files"):
            action = "Malicious Payload Transfer"
        elif s.get("suricata_alerts"):
            action = f"IDS Alert: {s['suricata_alerts'][0]['signature']}"
        elif "Volumetric" in hit_str:
            action = "Volumetric Anomaly"
            
        domain_str = s["http"][0].get("host") if s["http"] else (s["dns"][0].get("query") if s["dns"] else "Unknown Domain")
        
        timeline_events.append({
            "timestamp": ts,
            "action": action,
            "source": f"{s['orig_h']}:{s['orig_p']}",
            "destination": f"{s['resp_h']}:{s['resp_p']}",
            "domain": domain_str,
            "protocol": s.get("service") or s.get("proto"),
            "score": s["score"],
            "session_id": s["uid"],
            "details": s.get("intel_hits", [])[:3]
        })
        
    timeline_events.sort(key=lambda x: x["timestamp"])
    
    out_timeline_file = phase2_dir / "attack_timeline.json"
    with open(out_timeline_file, "w", encoding="utf-8") as f:
        json.dump(timeline_events, f, indent=2)

    print(f"\n============================================================")
    print(f" [Phase 3] CORRELATION COMPLETE")
    print(f"============================================================")
    
    stats_file = phase2_dir / "run_stats.json"
    pcap_hash = "Unknown (Run from Phase 3 manually)"
    if stats_file.exists():
        stats = _load_json(stats_file)
        pcap_hash = stats.get("forensic_integrity", {}).get("pcap_sha256", pcap_hash)
        
    print(f" Input PCAP Hash: {pcap_hash}")
    print(f" Analyzed {len(sessions)} unique Zeek sessions.")
    print(f" Profiled {len(host_profiles)} internal hosts.")
    print(f" Extracted {len(final_high_sev)} HIGH severity incidents (Aggregated from {len(high_sev)} raw).")
    print(f" Extracted {len(med_sev)} MEDIUM severity incidents.")
    print(f" Output saved to: {out_file}")
    print(f" Host profiles saved to: {out_host_file}")
    print(f" Attack timeline saved to: {out_timeline_file}\n")
    
    if timeline_events:
        print(" [ATTACK TIMELINE]")
        for evt in timeline_events[:10]:
            dt = datetime.datetime.fromtimestamp(evt['timestamp'], tz=datetime.timezone.utc)
            if dt.year == 1970:
                iso_ts = f"T+{evt['timestamp']:.2f}s"
            else:
                iso_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            print(f" ⏳ {iso_ts} | {evt['action']:<30} | {evt['source']} -> {evt['destination']} (Score: {evt['score']})")
        if len(timeline_events) > 10:
            print(f"   ... and {len(timeline_events) - 10} more events in attack_timeline.json")
        print("\n" + "="*60)
    
    top_hosts = sorted(host_profiles.values(), key=lambda x: x["infection_score"], reverse=True)[:5]
    if top_hosts:
        print(" [HOST-CENTRIC VIEW (TOP INFECTED HOSTS)]")
        for i, h in enumerate(top_hosts, 1):
            hostname_str = f" ({h['hostname']})" if h.get('hostname') else ""
            print(f"\n 💻 HOST {i}: {h['ip']}{hostname_str} (Score: {h['infection_score']})")
            if h["intel_hits"]:
                print(f"   - Intel Hits: {len(h['intel_hits'])}")
            if h["suricata_alerts"]:
                print(f"   - Alerts: {len(h['suricata_alerts'])}")
            if h["files"]:
                print(f"   - Extracted Files: {len(h['files'])}")
            if h["contacted_domains"]:
                print(f"   - External Domains: {len(h['contacted_domains'])}")
        print("\n" + "="*60)
        
    top_incidents = sorted(final_high_sev + med_sev, key=lambda x: x['score'], reverse=True)[:5]
    if top_incidents:
        print(" [ATTACK CHAINS (TOP DETECTIONS)]")
        for i, s in enumerate(top_incidents, 1):
            domain_str = s["http"][0].get("host") if s["http"] else (s["dns"][0].get("query") if s["dns"] else "Unknown Domain")
            file_str = s["files"][0][:8] if s["files"] else "No File"
            
            orig_host_str = f" ({s['orig_hostname']})" if s.get('orig_hostname') else ""
            resp_host_str = f" ({s['resp_hostname']})" if s.get('resp_hostname') else ""
            
            print(f"\n 💥 INCIDENT {i} (Score: {s['score']})")
            print(f" ├── Source IP: {s['orig_h']}{orig_host_str}:{s['orig_p']}")
            print(f" ├── Dest IP:   {s['resp_h']}{resp_host_str}:{s['resp_p']}")
            print(f" ├── Service:   {s['service'] or s['proto']}")
            print(f" ├── Domain:    {domain_str}")
            print(f" ├── Session:   {s['uid']}")
            print(f" └── File Hash: {file_str}")
            
            if s["intel_hits"]:
                print(f"\n 🔍 INTELLIGENCE HITS:")
                for hit in s["intel_hits"][:5]:
                    print(f"   - {hit}")
                if len(s["intel_hits"]) > 5:
                    print(f"   - ... and {len(s['intel_hits']) - 5} more hits.")
                    
            if s["suricata_alerts"]:
                print(f"\n 🚨 SURICATA ALERTS:")
                # Use a set to unique the alerts for display
                unique_alerts = list(set([a["signature"] for a in s["suricata_alerts"]]))
                for alert in unique_alerts[:5]:
                    print(f"   - {alert}")
                if len(unique_alerts) > 5:
                    print(f"   - ... and {len(unique_alerts) - 5} more alerts.")
            print("\n" + "-"*60)
            
        if len(final_high_sev) > 5:
            print(f"\n   ... and {len(final_high_sev) - 5} more High Severity incidents in the JSON report.")

    # Generate Narrative Story
    generate_attack_story(sessions, timeline_events, host_profiles, phase2_dir)

def main():
    parser = argparse.ArgumentParser(description="Phase 3 Correlation Engine")
    parser.add_argument("data_lake", type=Path, help="Path to processed data lake (e.g. processed/Hive_06...)")
    parser.add_argument("phase2_dir", type=Path, help="Path to Phase 2 output dir (e.g. phase2_output/Hive_...)")
    
    args = parser.parse_args()
    
    data_lake = args.data_lake.resolve()
    phase2_dir = args.phase2_dir.resolve()
    
    if not data_lake.exists() or not phase2_dir.exists():
        print("Error: Invalid paths provided.")
        return
        
    build_attack_chains(data_lake, phase2_dir)

if __name__ == "__main__":
    main()
