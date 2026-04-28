"""
extraction.py
Phase 2 — Step 1: IOC extraction from Zeek logs, Suricata eve.json, extracted files.

All extractors return a list of raw IOC dicts conforming to the canonical schema.
Now supports port and protocol/application extraction, and gracefully handles
IPs masquerading as domains (e.g. from Host headers).
"""

import hashlib
import ipaddress
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from config import EXTRACTED_DIR, SURICATA_DIR, ZEEK_DIR

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Helper: Parse Host/IP and Port
# ──────────────────────────────────────────────────────────────────────────────

def _parse_host_port(host_str: str) -> Tuple[bool, str, Optional[str]]:
    """
    Given a host string (e.g., '192.168.1.1', 'example.com:8080', '[::1]:443'),
    returns (is_ip: bool, clean_host: str, port: str|None).
    """
    if not host_str:
        return False, "", None

    host_str = host_str.strip()
    port = None

    if host_str.startswith("[") and "]" in host_str:
        # IPv6 with brackets, e.g., [fe80::1]:80
        parts = host_str.split("]", 1)
        host_part = parts[0][1:]
        if parts[1].startswith(":"):
            port = parts[1][1:]
    else:
        if ":" in host_str:
            # Check if it's a raw IPv6 address without port
            try:
                ipaddress.IPv6Address(host_str)
                host_part = host_str
            except ValueError:
                # Likely IPv4:port or domain:port
                parts = host_str.rsplit(":", 1)
                host_part = parts[0]
                port = parts[1] if parts[1].isdigit() else None
                if not port:
                    host_part = host_str # Port parsing failed, keep as is
        else:
            host_part = host_str

    try:
        ipaddress.ip_address(host_part)
        return True, host_part, port
    except ValueError:
        return False, host_part, port


# ──────────────────────────────────────────────────────────────────────────────
# Canonical IOC factory
# ──────────────────────────────────────────────────────────────────────────────

def _ioc(
    source_type: str,
    *,
    timestamp: Optional[str] = None,
    ip: Optional[str] = None,
    domain: Optional[str] = None,
    url: Optional[str] = None,
    file_hash: Optional[str] = None,
    suricata_alert: Optional[str] = None,
    port: Optional[str] = None,
    protocol: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "timestamp":      timestamp,
        "ip":             ip or None,
        "domain":         domain or None,
        "url":            url or None,
        "file_hash":      file_hash or None,
        "yara_match":     None,
        "suricata_alert": suricata_alert or None,
        "source_type":    source_type,
        "port":           port or None,
        "protocol":       protocol or None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Low-level NDJSON reader (handles both .json and .log Zeek files)
# ──────────────────────────────────────────────────────────────────────────────

def _iter_ndjson(path: Path) -> Generator[Dict, None, None]:
    """Yield parsed JSON objects from a newline-delimited JSON file."""
    if not path.exists():
        log.warning("File not found, skipping: %s", path)
        return
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError as exc:
                log.debug("JSON parse error at %s:%d — %s", path.name, lineno, exc)


# ──────────────────────────────────────────────────────────────────────────────
# Zeek extractors
# ──────────────────────────────────────────────────────────────────────────────

def _extract_zeek_conn(zeek_dir: Path) -> List[Dict]:
    """conn.json → src/dst IP pairs + ports + service."""
    iocs: List[Dict] = []
    for rec in _iter_ndjson(zeek_dir / "conn.json"):
        ts = str(rec.get("ts", ""))
        proto = rec.get("proto", "")
        service = rec.get("service", "")
        
        # Combine proto/service if available (e.g. "tcp/http")
        protocol = service if service and service != "-" else proto
        if not protocol or protocol == "-":
            protocol = None

        orig_ip = rec.get("id.orig_h", "").strip()
        orig_p = str(rec.get("id.orig_p", "")).strip()
        
        resp_ip = rec.get("id.resp_h", "").strip()
        resp_p = str(rec.get("id.resp_p", "")).strip()

        if orig_ip:
            iocs.append(_ioc("zeek_conn", timestamp=ts, ip=orig_ip, port=orig_p, protocol=protocol))
        if resp_ip:
            iocs.append(_ioc("zeek_conn", timestamp=ts, ip=resp_ip, port=resp_p, protocol=protocol))

    log.debug("zeek_conn: %d raw IOCs", len(iocs))
    return iocs


def _extract_zeek_dns(zeek_dir: Path) -> List[Dict]:
    """dns.json → queried domains + answer IPs."""
    iocs: List[Dict] = []
    for rec in _iter_ndjson(zeek_dir / "dns.json"):
        ts = str(rec.get("ts", ""))

        query = rec.get("query", "").strip()
        if query:
            # Check if query is actually an IP
            is_ip, clean_host, _ = _parse_host_port(query)
            if is_ip:
                iocs.append(_ioc("zeek_dns", timestamp=ts, ip=clean_host, protocol="dns"))
            else:
                iocs.append(_ioc("zeek_dns", timestamp=ts, domain=clean_host, protocol="dns"))

        # Inline answers (Zeek encodes as list or "-")
        answers = rec.get("answers", [])
        if isinstance(answers, list):
            for ans in answers:
                ans = ans.strip()
                if ans and ans != "-":
                    iocs.append(_ioc("zeek_dns_answer", timestamp=ts, ip=ans, protocol="dns"))
    log.debug("zeek_dns: %d raw IOCs", len(iocs))
    return iocs


def _extract_zeek_http(zeek_dir: Path) -> List[Dict]:
    """http.json → host (domain), URI (url), server IP."""
    iocs: List[Dict] = []
    for rec in _iter_ndjson(zeek_dir / "http.json"):
        ts = str(rec.get("ts", ""))

        host = rec.get("host", "").strip()
        uri  = rec.get("uri", "").strip()
        resp_ip = rec.get("id.resp_h", "").strip()
        resp_p = str(rec.get("id.resp_p", "")).strip()

        is_ip, clean_host, host_port = _parse_host_port(host)
        actual_port = host_port or resp_p

        ip_val = clean_host if is_ip else None
        domain_val = None if is_ip else clean_host

        if clean_host:
            iocs.append(_ioc("zeek_http", timestamp=ts, ip=ip_val, domain=domain_val, port=actual_port, protocol="http"))
        if clean_host and uri and uri != "-":
            url = f"http://{clean_host}{uri}"
            iocs.append(_ioc("zeek_http", timestamp=ts, url=url, ip=ip_val, domain=domain_val, port=actual_port, protocol="http"))
        if resp_ip:
            iocs.append(_ioc("zeek_http", timestamp=ts, ip=resp_ip, port=resp_p, protocol="http"))
            
    log.debug("zeek_http: %d raw IOCs", len(iocs))
    return iocs


# ──────────────────────────────────────────────────────────────────────────────
# Suricata extractor
# ──────────────────────────────────────────────────────────────────────────────

def _extract_suricata(suri_dir: Path) -> List[Dict]:
    """eve.json → src/dst IPs, alert signatures, HTTP host/url."""
    iocs: List[Dict] = []
    eve = suri_dir / "eve.json"

    for event in _iter_ndjson(eve):
        ts          = event.get("timestamp", "")
        src_ip      = event.get("src_ip", "").strip()
        src_port    = str(event.get("src_port", "")).strip()
        dst_ip      = event.get("dest_ip", "").strip()
        dst_port    = str(event.get("dest_port", "")).strip()
        event_type  = event.get("event_type", "")
        app_proto   = event.get("app_proto", "")

        # Alert events
        alert_sig: Optional[str] = None
        if event_type == "alert":
            alert_sig = event.get("alert", {}).get("signature", "").strip() or None

        if src_ip:
            iocs.append(_ioc("suricata", timestamp=ts, ip=src_ip, port=src_port, protocol=app_proto, suricata_alert=alert_sig))
        if dst_ip:
            iocs.append(_ioc("suricata", timestamp=ts, ip=dst_ip, port=dst_port, protocol=app_proto, suricata_alert=alert_sig))

        # HTTP metadata inside eve
        if event_type == "http":
            http = event.get("http", {})
            hostname = http.get("hostname", "").strip()
            url_str  = http.get("url", "").strip()
            
            is_ip, clean_host, host_port = _parse_host_port(hostname)
            ip_val = clean_host if is_ip else None
            domain_val = None if is_ip else clean_host
            
            if clean_host:
                iocs.append(_ioc("suricata_http", timestamp=ts, ip=ip_val, domain=domain_val, port=host_port, protocol="http"))
            if clean_host and url_str:
                iocs.append(_ioc("suricata_http", timestamp=ts,
                                 url=f"http://{clean_host}{url_str}", ip=ip_val, domain=domain_val, port=host_port, protocol="http"))

        # DNS metadata inside eve
        if event_type == "dns":
            rrname = event.get("dns", {}).get("rrname", "").strip()
            if rrname:
                is_ip, clean_host, _ = _parse_host_port(rrname)
                ip_val = clean_host if is_ip else None
                domain_val = None if is_ip else clean_host
                iocs.append(_ioc("suricata_dns", timestamp=ts, ip=ip_val, domain=domain_val, protocol="dns"))

    log.debug("suricata: %d raw IOCs", len(iocs))
    return iocs


# ──────────────────────────────────────────────────────────────────────────────
# Extracted file hasher
# ──────────────────────────────────────────────────────────────────────────────

def _hash_file_sha256(path: Path) -> str:
    """Stream-hash a file and return its SHA-256 hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_files(extracted_dir: Path) -> List[Dict]:
    """Hash every carved file and create a file_hash IOC."""
    iocs: List[Dict] = []
    if not extracted_dir.exists():
        log.warning("Extracted payloads directory not found: %s", extracted_dir)
        return iocs

    for fpath in extracted_dir.iterdir():
        if not fpath.is_file():
            continue
        try:
            sha256 = _hash_file_sha256(fpath)
            iocs.append(_ioc("extracted_file", file_hash=sha256))
            log.debug("Hashed %s → %s", fpath.name, sha256)
        except OSError as exc:
            log.warning("Could not hash %s: %s", fpath.name, exc)

    log.debug("extracted_files: %d raw IOCs", len(iocs))
    return iocs


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def extract_all_iocs(
    zeek_dir: Path = ZEEK_DIR,
    suri_dir: Path = SURICATA_DIR,
    extracted_dir: Path = EXTRACTED_DIR,
) -> List[Dict]:
    """
    Run all extractors and return a combined list of raw IOC dicts.
    No deduplication or filtering is performed here.
    """
    zeek_dir      = Path(zeek_dir).resolve()
    suri_dir      = Path(suri_dir).resolve()
    extracted_dir = Path(extracted_dir).resolve()

    all_iocs: List[Dict] = []

    log.info("Extracting Zeek conn log …")
    all_iocs.extend(_extract_zeek_conn(zeek_dir))

    log.info("Extracting Zeek DNS log …")
    all_iocs.extend(_extract_zeek_dns(zeek_dir))

    log.info("Extracting Zeek HTTP log …")
    all_iocs.extend(_extract_zeek_http(zeek_dir))

    log.info("Extracting Suricata eve.json …")
    all_iocs.extend(_extract_suricata(suri_dir))

    log.info("Hashing extracted payload files …")
    all_iocs.extend(_extract_files(extracted_dir))

    log.info("Extraction complete — %d raw IOCs collected.", len(all_iocs))
    return all_iocs
