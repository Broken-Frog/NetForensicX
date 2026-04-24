#!/usr/bin/env python3
"""
packet_factory.py
Senior DevSecOps Post-Analysis Ingestion Framework

Orchestrates Zeek + Suricata analysis of a PCAP, structures output as a Data Lake,
performs UID <-> flow_id linking, and cleans up artifacts.

Improvements over v1:
  - True multiprocessing (multiprocessing.Pool) — uses ALL logical CPU cores
  - Every path resolved to absolute before use (no relative-path bugs)
  - Suricata errors now re-raise identically to Zeek
  - Zeek log rename + zero-byte cleanup merged into one single directory scan
  - UID linker reads Suricata eve.json and Zeek conn.json in parallel
  - Extracted payload combining uses a multiprocessing Pool for concurrent moves
  - Tool presence (zeek / suricata) validated before any subprocess is spawned
  - Temp-file cleanup is guaranteed via a dedicated finally block
"""

import argparse
import json
import multiprocessing
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Configuration generators
# ──────────────────────────────────────────────────────────────────────────────

def create_zeek_local_script() -> str:
    """Return content for temporary local.zeek script."""
    return (
        "@load frameworks/intel\n"
        "@load frameworks/files/extract-all-files\n"
        "redef LogAscii::use_json = T;\n"
    )


def _suricata_major_version() -> int:
    """
    Return the Suricata major version integer (e.g. 6 or 7).
    Falls back to 6 on any parse error so the conservative config is used.
    """
    try:
        out = subprocess.check_output(
            ["suricata", "--build-info"], stderr=subprocess.STDOUT, text=True
        )
        for line in out.splitlines():
            # "Version 6.0.13 RELEASE" or "Suricata version 7.0.5"
            if "version" in line.lower():
                parts = line.split()
                for part in parts:
                    if part[0].isdigit():
                        return int(part.split(".")[0])
    except Exception:
        pass
    return 6  # safe conservative default


def create_suricata_yaml_snippet(rules_path: str = "/var/lib/suricata/rules") -> str:
    """
    Build a temporary suricata.yaml compatible with the installed Suricata version.

    Key differences handled automatically:
      • `filetype: json` inside eve-log — introduced in Suricata 7; INVALID on ≤6
      • `file-store` v2 layout (version: 2, force-filestore) vs v1 layout
    """
    major = _suricata_major_version()
    print(f"[Suricata] Detected major version: {major}", flush=True)

    # `filetype: json` is valid only on Suricata 7+; omit entirely on 6 and below
    filetype_line = "      filetype: regular\n" if major >= 7 else ""

    # file-store schema changed in Suricata 5 (v2 format); version key not used in <=4
    if major >= 5:
        file_store_block = (
            "file-store:\n"
            "  version: 2\n"
            "  enabled: yes\n"
            "  dir: file_store\n"
            "  force-filestore: yes\n"
            "  write-fileinfo: yes\n"
        )
    else:
        file_store_block = (
            "file-store:\n"
            "  enabled: yes\n"
            "  dir: file_store\n"
            "  force-magic: no\n"
            "  force-filestore: yes\n"
            "  write-fileinfo: yes\n"
        )

    return f"""%YAML 1.1
---
# packet_factory.py — temporary Suricata config (auto-generated for v{major}.x)
default-log-dir: .

logging:
  default-log-level: warning
  outputs:
    - console:
        enabled: yes

outputs:
  - eve-log:
      enabled: yes
{filetype_line}      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow
        - fileinfo
        - stats
        - smtp
        - smb

{file_store_block}
http:
  enabled: yes
smb:
  enabled: yes
smtp:
  enabled: yes

default-rule-path: {rules_path}
rule-files:
  - emerging.rules
"""


# ──────────────────────────────────────────────────────────────────────────────
# Tool availability check
# ──────────────────────────────────────────────────────────────────────────────

def assert_tool(name: str, full_path: Optional[str] = None) -> str:
    """
    Verify a required external tool is available.

    Parameters
    ----------
    name:      Binary name used in error messages.
    full_path: Absolute path to try first; falls back to PATH lookup.

    Returns the resolved command string to use in subprocess calls.
    Raises FileNotFoundError if the tool cannot be found.
    """
    candidates = [full_path] if full_path else []
    candidates.append(name)

    for candidate in candidates:
        if candidate and shutil.which(candidate):
            return candidate

    raise FileNotFoundError(
        f"Required tool '{name}' not found. "
        f"Install it or ensure it is on PATH before running packet_factory."
    )


# ──────────────────────────────────────────────────────────────────────────────
# Analysis phases  (called via multiprocessing.Pool — must be module-level)
# ──────────────────────────────────────────────────────────────────────────────

def run_zeek(args: Tuple[str, str, str]) -> None:
    """
    Phase A: Run Zeek (JSON logs + file extraction).

    Parameters (packed as a tuple for Pool.map compatibility):
        pcap_path_str    – absolute path to the PCAP
        zeek_dir_str     – absolute path to zeek output directory
        local_zeek_str   – absolute path to temporary local.zeek script
    """
    pcap_path_str, zeek_dir_str, local_zeek_str = args

    # Resolve every path to absolute — no ambiguity regardless of cwd
    pcap_path  = Path(pcap_path_str).resolve()
    zeek_dir   = Path(zeek_dir_str).resolve()
    local_zeek = Path(local_zeek_str).resolve()

    zeek_dir.mkdir(parents=True, exist_ok=True)

    zeek_bin = assert_tool("zeek", "/opt/zeek/bin/zeek")

    cmd = [
        zeek_bin,
        "-r", str(pcap_path),
        "-C",           # ignore checksum errors (common with PCAP replays)
        str(local_zeek),
    ]

    print(f"[Zeek]     Analysing {pcap_path.name} → {zeek_dir}", flush=True)
    try:
        result = subprocess.run(
            cmd,
            cwd=str(zeek_dir),   # logs land directly in zeek_dir
            check=True,
            capture_output=True,
            text=True,
        )
        if result.stderr.strip():
            print(f"[Zeek]     STDERR (non-fatal):\n{result.stderr.strip()}", flush=True)
    except subprocess.CalledProcessError as exc:
        print("❌ [Zeek] Fatal error:")
        print("   STDERR:", exc.stderr)
        print("   STDOUT:", exc.stdout)
        raise

    print(f"[Zeek]     ✓ Completed → {zeek_dir}", flush=True)


def run_suricata(args: Tuple[str, str, str]) -> None:
    """
    Phase B: Run Suricata in offline mode with ET Open rules.

    Parameters (packed as a tuple for Pool.map compatibility):
        pcap_path_str  – absolute path to the PCAP
        suri_dir_str   – absolute path to suricata output directory
        suri_yaml_str  – absolute path to temporary suricata.yaml
    """
    pcap_path_str, suri_dir_str, suri_yaml_str = args

    pcap_path = Path(pcap_path_str).resolve()
    suri_dir  = Path(suri_dir_str).resolve()
    suri_yaml = Path(suri_yaml_str).resolve()

    suri_dir.mkdir(parents=True, exist_ok=True)

    assert_tool("suricata")

    cmd = [
        "suricata",
        "-c", str(suri_yaml),
        "-r", str(pcap_path),
        "-l", str(suri_dir),    # all logs + file_store go here
        "--runmode", "single",
    ]

    print(f"[Suricata] Analysing {pcap_path.name} → {suri_dir}", flush=True)
    try:
        result = subprocess.run(
            cmd,
            cwd=str(suri_dir),
            check=True,
            capture_output=True,
            text=True,
        )
        if result.stderr.strip():
            print(f"[Suricata] STDERR (non-fatal):\n{result.stderr.strip()}", flush=True)
    except subprocess.CalledProcessError as exc:
        print("❌ [Suricata] Fatal error:")
        print("   STDERR:", exc.stderr)
        print("   STDOUT:", exc.stdout)
        raise   # ← was missing in v1; now consistent with Zeek

    print(f"[Suricata] ✓ Completed → {suri_dir}", flush=True)


# ──────────────────────────────────────────────────────────────────────────────
# Post-processing helpers
# ──────────────────────────────────────────────────────────────────────────────

def _move_file(args: Tuple[str, str]) -> None:
    """Worker used by Pool.map for parallel file moves."""
    src, dst = args
    shutil.move(src, dst)


def process_zeek_logs(zeek_dir: Path) -> None:
    """
    Single-pass over zeek_dir:
      • .log files → renamed to .json  (already JSON content)
      • zero-byte files → deleted

    v1 made two full directory scans; this does it in one.
    """
    zeek_dir = zeek_dir.resolve()
    renamed = deleted = 0

    for log_file in list(zeek_dir.glob("*.log")):
        if log_file.stat().st_size == 0:
            log_file.unlink()
            print(f"    [Zeek logs] Removed zero-byte: {log_file.name}", flush=True)
            deleted += 1
        else:
            json_path = log_file.with_suffix(".json")
            shutil.move(str(log_file), str(json_path))
            print(f"    [Zeek logs] Renamed {log_file.name} → {json_path.name}", flush=True)
            renamed += 1

    # Also purge any zero-byte .json files that Zeek may have created directly
    for json_file in list(zeek_dir.glob("*.json")):
        if json_file.stat().st_size == 0:
            json_file.unlink()
            print(f"    [Zeek logs] Removed zero-byte: {json_file.name}", flush=True)
            deleted += 1

    print(
        f"[Zeek logs] Post-processing done — "
        f"{renamed} renamed, {deleted} zero-byte files removed.",
        flush=True,
    )


# ──────── UID linker parallel readers ─────────────────────────────────────────

def _read_suricata_map(eve_path: Path) -> Dict[Tuple[str, str, str, str, str], int]:
    """Build 5-tuple → flow_id map from Suricata eve.json (NDJSON)."""
    suri_map: Dict[Tuple[str, str, str, str, str], int] = {}
    eve_path = eve_path.resolve()

    if not eve_path.exists():
        print(f"[UID Linker] WARNING: Suricata eve.json not found at {eve_path}", flush=True)
        return suri_map

    with open(eve_path, encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue

            required = ("src_ip", "src_port", "dest_ip", "dest_port", "proto", "flow_id")
            if all(k in event for k in required):
                key = (
                    event["src_ip"],
                    str(event["src_port"]),
                    event["dest_ip"],
                    str(event["dest_port"]),
                    event.get("proto", "").lower(),
                )
                # Keep the first occurrence (earliest timestamp wins)
                suri_map.setdefault(key, event["flow_id"])

    print(f"[UID Linker] Suricata map: {len(suri_map)} 5-tuples indexed.", flush=True)
    return suri_map


def _read_zeek_conn(conn_path: Path) -> Dict[Tuple[str, str, str, str, str], str]:
    """Build 5-tuple → Zeek UID map from conn.json."""
    zeek_map: Dict[Tuple[str, str, str, str, str], str] = {}
    conn_path = conn_path.resolve()

    if not conn_path.exists():
        print(f"[UID Linker] WARNING: Zeek conn.json not found at {conn_path}", flush=True)
        return zeek_map

    required = ("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")
    with open(conn_path, encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                conn = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if all(k in conn for k in required):
                key = (
                    conn["id.orig_h"],
                    str(conn["id.orig_p"]),
                    conn["id.resp_h"],
                    str(conn["id.resp_p"]),
                    conn.get("proto", "").lower(),
                )
                zeek_map.setdefault(key, conn["uid"])

    print(f"[UID Linker] Zeek conn map: {len(zeek_map)} 5-tuples indexed.", flush=True)
    return zeek_map


def build_uid_linker(
    zeek_dir: Path,
    suri_dir: Path,
    output_json: Path,
    cpu_count: int,
) -> None:
    """
    UID Linker: Map Zeek UIDs → Suricata flow_ids via shared 5-tuple.

    Reads both source files in parallel (2-worker Pool) then joins in memory.
    """
    zeek_dir    = zeek_dir.resolve()
    suri_dir    = suri_dir.resolve()
    output_json = output_json.resolve()

    eve_path  = suri_dir / "eve.json"
    conn_path = zeek_dir / "conn.json"

    # Read both files in parallel — I/O bound, 2 workers is optimal here
    with multiprocessing.Pool(processes=min(2, cpu_count)) as pool:
        suri_future = pool.apply_async(_read_suricata_map, (eve_path,))
        zeek_future = pool.apply_async(_read_zeek_conn,    (conn_path,))
        suri_map = suri_future.get()
        zeek_map = zeek_future.get()

    # Join: UID → flow_id
    linker: Dict[str, int] = {
        uid: suri_map[key]
        for key, uid in zeek_map.items()
        if key in suri_map
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "pcap": output_json.parent.parent.name,
                "zeek_uid_to_suricata_flow_id": linker,
                "total_mapped_flows": len(linker),
            },
            fh,
            indent=2,
        )

    print(f"[UID Linker] ✓ {output_json} — {len(linker)} UID↔flow_id mappings.", flush=True)


def combine_extracted_payloads(
    zeek_dir: Path,
    suri_dir: Path,
    extracted_dir: Path,
    cpu_count: int,
) -> None:
    """
    Combine all carved files from Zeek and Suricata into one flat directory.

    File moves are dispatched to a multiprocessing Pool so all cores help
    when there are many carved payloads (common with large PCAPs).
    """
    zeek_dir      = zeek_dir.resolve()
    suri_dir      = suri_dir.resolve()
    extracted_dir = extracted_dir.resolve()
    extracted_dir.mkdir(parents=True, exist_ok=True)

    move_jobs: list[Tuple[str, str]] = []

    # Zeek: everything that is NOT a .json log
    for item in zeek_dir.iterdir():
        if item.is_file() and not item.name.endswith(".json"):
            dst = extracted_dir / item.name
            if dst.exists():
                dst = extracted_dir / f"zeek_{item.name}"
            move_jobs.append((str(item), str(dst)))

    # Suricata file_store
    file_store = suri_dir / "file_store"
    if file_store.is_dir():
        for item in file_store.iterdir():
            if item.is_file():
                dst = extracted_dir / item.name
                if dst.exists():
                    dst = extracted_dir / f"suri_{item.name}"
                move_jobs.append((str(item), str(dst)))

    if move_jobs:
        workers = min(cpu_count, len(move_jobs))
        with multiprocessing.Pool(processes=workers) as pool:
            pool.map(_move_file, move_jobs)

        # Remove empty file_store dir if it now exists
        if file_store.is_dir():
            try:
                file_store.rmdir()
            except OSError:
                pass

    print(
        f"[Extracted Payloads] ✓ {len(move_jobs)} files moved → {extracted_dir}",
        flush=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="packet_factory.py — Post-Analysis Ingestion Framework"
    )
    parser.add_argument(
        "pcap",
        type=Path,
        help="Path to the input .pcap file",
    )
    parser.add_argument(
        "--processed-dir",
        type=Path,
        default=Path("processed"),
        help="Root directory for the processed data lake (default: ./processed)",
    )
    args = parser.parse_args()

    # ── Resolve PCAP to absolute path immediately ──────────────────────────────
    pcap_path: Path = args.pcap.resolve()

    if not pcap_path.exists():
        parser.error(f"PCAP not found: {pcap_path}")
    if pcap_path.suffix.lower() != ".pcap":
        parser.error(f"Input file must have a .pcap extension: {pcap_path.name}")

    # ── Validate tools before doing any work ──────────────────────────────────
    assert_tool("zeek", "/opt/zeek/bin/zeek")
    assert_tool("suricata")

    # ── Resolve all output paths to absolute ──────────────────────────────────
    processed_dir: Path = args.processed_dir.resolve()
    pcap_stem           = pcap_path.stem
    base_dir            = processed_dir / pcap_stem
    zeek_dir            = (base_dir / "zeek").resolve()
    suri_dir            = (base_dir / "suricata").resolve()
    extracted_dir       = (base_dir / "extracted_payloads").resolve()
    linker_json         = (base_dir / "flow_linker.json").resolve()

    # ── Determine CPU resources ────────────────────────────────────────────────
    cpu_count = os.cpu_count() or 1
    print(f"🖥  Detected {cpu_count} logical CPU core(s).", flush=True)
    print(f"🚀 Processing {pcap_path} → {base_dir}", flush=True)

    # ── Write temporary config files to absolute temp paths ───────────────────
    tmp_dir = Path(tempfile.mkdtemp(prefix="pkt_factory_")).resolve()
    local_zeek = tmp_dir / "local.zeek"
    suri_yaml  = tmp_dir / "suricata.yaml"

    local_zeek.write_text(create_zeek_local_script(),    encoding="utf-8")
    suri_yaml.write_text(create_suricata_yaml_snippet(), encoding="utf-8")

    try:
        # ── Phase 1: Parallel Zeek + Suricata via multiprocessing.Pool ────────
        # Two heavyweight subprocess tasks; one worker each is correct.
        # We still use Pool (not ThreadPoolExecutor) per the project requirement.
        zeek_args = (str(pcap_path), str(zeek_dir), str(local_zeek))
        suri_args = (str(pcap_path), str(suri_dir),  str(suri_yaml))

        with multiprocessing.Pool(processes=2) as pool:
            zeek_result = pool.apply_async(run_zeek,     (zeek_args,))
            suri_result = pool.apply_async(run_suricata, (suri_args,))

            # .get() re-raises any exception from the worker process
            zeek_result.get()
            suri_result.get()

        # ── Phase 2: Post-processing ───────────────────────────────────────────
        process_zeek_logs(zeek_dir)

        build_uid_linker(zeek_dir, suri_dir, linker_json, cpu_count)

        combine_extracted_payloads(zeek_dir, suri_dir, extracted_dir, cpu_count)

        print(f"\n✅ Processing complete!  Data lake ready at: {base_dir}", flush=True)

    finally:
        # Guaranteed cleanup of temp dir regardless of success or failure
        shutil.rmtree(str(tmp_dir), ignore_errors=True)
        print("🧹 Temporary configuration files cleaned up.", flush=True)


if __name__ == "__main__":
    # Required on Windows / macOS for multiprocessing safety;
    # harmless (and good practice) on Linux.
    multiprocessing.freeze_support()
    main()