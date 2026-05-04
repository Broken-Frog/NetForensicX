"""
cleaning.py
Phase 2 — Step 2: Clean and deduplicate raw IOC records.

Rules applied (in order):
  1. Drop records where ip, domain, url AND file_hash are all None/empty.
  2. Remove records whose `ip` field is a private / reserved address (RFC 1918 +).
  3. Deduplicate using a stable composite key: sha256(ip|domain|file_hash).
     The FIRST occurrence of each key is kept; later duplicates are discarded.
"""

import hashlib
import ipaddress
import logging
from typing import Any, Dict, List, Set, Tuple

from config import PRIVATE_IP_RANGES

log = logging.getLogger(__name__)

# Pre-build ipaddress network objects once at import time
_PRIVATE_NETS = [ipaddress.ip_network(r, strict=False) for r in PRIVATE_IP_RANGES]


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_private_ip(addr: str) -> bool:
    """
    Return True if *addr* is a private / loopback / link-local / reserved address.
    Returns False for invalid strings so those are handled by the empty-check pass.
    """
    addr = addr.strip()
    if not addr:
        return False
    try:
        ip_obj = ipaddress.ip_address(addr)
    except ValueError:
        # Not a valid IP — could be a hostname erroneously in the ip field
        return False
    return any(ip_obj in net for net in _PRIVATE_NETS)


def _is_noise_ip(addr: str) -> bool:
    # Deprecated: replaced by ipaddress classification
    return False


def _dedup_key(ioc: Dict[str, Any]) -> str:
    """
    Build a stable 64-char hex key that uniquely identifies the *content*
    of an IOC (ignoring timestamp, source_type, alert text, etc.).

    Key components:  ip | domain | file_hash | port (pipe-separated, None → "")
    """
    parts = "|".join([
        (ioc.get("ip")        or "").lower().strip(),
        (ioc.get("domain")    or "").lower().strip(),
        (ioc.get("file_hash") or "").lower().strip(),
        str(ioc.get("port")   or "").lower().strip(),
    ])
    return hashlib.sha256(parts.encode()).hexdigest()


def _is_empty(ioc: Dict[str, Any]) -> bool:
    """True if every meaningful indicator field is absent."""
    return not any([
        ioc.get("ip"),
        ioc.get("domain"),
        ioc.get("url"),
        ioc.get("file_hash"),
    ])


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def clean_and_deduplicate(raw_iocs: List[Dict]) -> Tuple[List[Dict], Dict[str, int]]:
    """
    Parameters
    ----------
    raw_iocs : raw list from extraction.extract_all_iocs()

    Returns
    -------
    cleaned   : deduplicated, filtered IOC list
    stats     : {
                    "input_count":     int,
                    "dropped_empty":   int,
                    "dropped_private": int,
                    "dropped_dedup":   int,
                    "output_count":    int,
                }
    """
    input_count     = len(raw_iocs)
    dropped_empty       = 0
    dropped_special_ips = 0
    dropped_dedup   = 0

    seen_keys: Set[str] = set()
    cleaned:   List[Dict] = []

    for ioc in raw_iocs:
        # Pass 1 — drop fully empty records
        if _is_empty(ioc):
            dropped_empty += 1
            continue

        # Pass 2 — categorize and drop special/unroutable IPs
        ip_str = ioc.get("ip", "") or ""
        if ip_str:
            ip_str = ip_str.strip()
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                
                if ip_obj.is_unspecified:
                    tag = "UNSPECIFIED"        # 0.0.0.0
                elif ip_obj.is_multicast:
                    tag = "MULTICAST"
                elif ip_obj.is_reserved:
                    tag = "RESERVED"
                elif ip_obj.is_loopback:
                    tag = "LOOPBACK"           # 127.0.0.1
                elif ip_obj.is_private:
                    tag = "INTERNAL"           # 192.168.x.x
                elif getattr(ip_obj, 'is_global', not ip_obj.is_private):
                    tag = "EXTERNAL"
                else:
                    tag = "UNKNOWN"
                    
                ioc["network_zone"] = tag
                
                if tag == "INTERNAL":
                    ioc["is_private"] = True
                    
                if tag in ("UNSPECIFIED", "MULTICAST", "RESERVED", "LOOPBACK"):
                    dropped_special_ips += 1
                    continue
                    
            except ValueError:
                pass
                
            if ip_str.lower().startswith("fe80:"):
                ioc["network_zone"] = "LOCAL_LINK"
                ioc["reduce_weight"] = True

        # Pass 3 — deduplicate
        key = _dedup_key(ioc)
        if key in seen_keys:
            dropped_dedup += 1
            continue

        seen_keys.add(key)
        # Attach the dedup key so downstream steps can use it without recomputing
        ioc["_dedup_key"] = key
        cleaned.append(ioc)

    stats = {
        "input_count":     input_count,
        "dropped_empty":       dropped_empty,
        "dropped_special_ips": dropped_special_ips,
        "dropped_dedup":   dropped_dedup,
        "output_count":    len(cleaned),
    }

    log.info(
        "Cleaning complete: %d in → %d out  "
        "(empty=%d  special_ips=%d  dedup=%d)",
        input_count, len(cleaned),
        dropped_empty, dropped_special_ips, dropped_dedup,
    )
    return cleaned, stats
