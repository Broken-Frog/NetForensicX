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
    
    # Organize zeek events by UID
    sessions: Dict[str, Dict] = {}
    
    for c in conns:
        uid = c.get("uid")
        if uid:
            sessions[uid] = {
                "uid": uid,
                "orig_h": c.get("id.orig_h"),
                "resp_h": c.get("id.resp_h"),
                "proto": c.get("proto"),
                "service": c.get("service"),
                "orig_p": c.get("id.orig_p"),
                "resp_p": c.get("id.resp_p"),
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

    # 5. Calculate Severity Score per Session
    for uid, sess in sessions.items():
        score = 0
        hits = []
        
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
                hits.append(f"AbuseIPDB Malicious ({ip})")
                
            if intel.get("high_pulse_rate"):
                score += 20
                hits.append(f"OTX High Pulse Rate ({ip})")
                
        # 5c. Domain Intelligence
        for d in sess["dns"]:
            query = d.get("query")
            if not query: continue
            intel = intel_by_domain.get(query, {})
            if intel.get("vt_malicious_count", 0) >= 5 or intel.get("high_pulse_rate"):
                score += 20
                hits.append(f"Suspicious DNS ({query})")
                
        for h in sess["http"]:
            host = h.get("host")
            if not host: continue
            intel = intel_by_domain.get(host, {})
            if intel.get("vt_malicious_count", 0) >= 5 or intel.get("high_pulse_rate"):
                score += 20
                hits.append(f"Suspicious HTTP Host ({host})")
                
        # 5d. YARA Intelligence
        for fhash in sess["files"]:
            intel = intel_by_hash.get(fhash, {})
            if intel.get("yara_match"):
                score += 40
                hits.append(f"YARA Match ({intel.get('yara_match')} on {fhash[:8]})")
            if intel.get("vt_malicious_count", 0) >= 5:
                score += 30
                hits.append(f"VT Malicious File ({fhash[:8]})")

        sess["score"] = score
        sess["intel_hits"] = list(set(hits))
        
        if score >= 80:
            sess["severity"] = "HIGH"
        elif score >= 40:
            sess["severity"] = "MEDIUM"

    # 6. Output Generation
    high_sev = [s for s in sessions.values() if s["severity"] == "HIGH"]
    med_sev = [s for s in sessions.values() if s["severity"] == "MEDIUM"]
    
    # Calculate pie chart distributions for the frontend
    protocol_distribution = {}
    service_distribution = {}
    
    for s in high_sev + med_sev:
        proto = s.get("proto") or "unknown"
        service = s.get("service") or "unknown"
        
        protocol_distribution[proto] = protocol_distribution.get(proto, 0) + 1
        service_distribution[service] = service_distribution.get(service, 0) + 1
    
    out_file = phase2_dir / "incidents_correlated.json"
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "high_severity": high_sev,
            "medium_severity": med_sev,
            "total_high": len(high_sev),
            "total_medium": len(med_sev),
            "protocol_distribution": protocol_distribution,
            "service_distribution": service_distribution
        }, f, indent=2)
        
    print(f"\n============================================================")
    print(f" [Phase 3] CORRELATION COMPLETE")
    print(f"============================================================")
    print(f" Analyzed {len(sessions)} unique Zeek sessions.")
    print(f" Extracted {len(high_sev)} HIGH severity incidents.")
    print(f" Extracted {len(med_sev)} MEDIUM severity incidents.")
    print(f" Output saved to: {out_file}\n")
    
    if high_sev:
        print(" [ATTACK CHAINS (HIGH SEVERITY)]")
        for i, s in enumerate(high_sev[:5], 1):
            domain_str = s["http"][0].get("host") if s["http"] else (s["dns"][0].get("query") if s["dns"] else "Unknown Domain")
            file_str = s["files"][0][:8] if s["files"] else "No File"
            
            print(f"\n 💥 INCIDENT {i} (Score: {s['score']})")
            print(f" ├── Source IP: {s['orig_h']}:{s['orig_p']}")
            print(f" ├── Dest IP:   {s['resp_h']}:{s['resp_p']}")
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
            
        if len(high_sev) > 5:
            print(f"\n   ... and {len(high_sev) - 5} more High Severity incidents in the JSON report.")

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
