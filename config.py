"""
config.py
Central configuration for the Phase 2 IOC processing pipeline.
All paths, API keys, Redis settings, and tunable constants live here.
"""

import os
from pathlib import Path

import sys

# ── Input paths (produced by Phase 1 / packet_factory.py) ────────────────────
BASE_PROCESSED_DIR = Path(os.environ.get("PROCESSED_DIR", "processed"))

_pcap_stem_env = os.environ.get("PCAP_STEM")

# 1. Check CLI args first
if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    arg_path = Path(sys.argv[1])
    # If a full path like processed/Hive_06... is passed
    if len(arg_path.parts) > 1:
        BASE_PROCESSED_DIR = arg_path.parent
        PCAP_STEM = arg_path.name
    else:
        PCAP_STEM = str(arg_path)
# 2. Then check environment variables
elif _pcap_stem_env:
    PCAP_STEM = _pcap_stem_env
# 3. Finally auto-detect the most recently modified folder
else:
    if BASE_PROCESSED_DIR.exists() and BASE_PROCESSED_DIR.is_dir():
        subdirs = [d for d in BASE_PROCESSED_DIR.iterdir() if d.is_dir()]
        if subdirs:
            # Pick the most recently modified directory
            PCAP_STEM = max(subdirs, key=lambda d: d.stat().st_mtime).name
        else:
            PCAP_STEM = "Hive_06082021"
    else:
        PCAP_STEM = "Hive_06082021"

ZEEK_DIR           = BASE_PROCESSED_DIR / PCAP_STEM / "zeek"
SURICATA_DIR       = BASE_PROCESSED_DIR / PCAP_STEM / "suricata"
EXTRACTED_DIR      = BASE_PROCESSED_DIR / PCAP_STEM / "extracted_payloads"


import datetime

# ── Output paths ──────────────────────────────────────────────────────────────
_base_output_dir   = Path(os.environ.get("OUTPUT_DIR", "phase2_output"))
_timestamp_str     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR         = _base_output_dir / f"{PCAP_STEM}_{_timestamp_str}"

UNIFIED_IOCS_JSON  = OUTPUT_DIR / "unified_iocs.json"
STATS_JSON         = OUTPUT_DIR / "run_stats.json"

# ── YARA ──────────────────────────────────────────────────────────────────────
YARA_RULES_DIR     = Path(os.environ.get("YARA_RULES_DIR", "yara_rules"))

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_HOST         = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT         = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB           = int(os.environ.get("REDIS_DB", 0))
REDIS_PASSWORD     = os.environ.get("REDIS_PASSWORD", None)   # None = no auth
REDIS_CACHE_TTL    = int(os.environ.get("REDIS_CACHE_TTL", 86400))  # 24 h in seconds
REDIS_KEY_PREFIX   = "pf2:enrich:"   # namespace to avoid key collisions

# ── VirusTotal ────────────────────────────────────────────────────────────────
VT_API_KEY         = os.environ.get("VT_API_KEY", "")         # Optional if others are provided
VT_BASE_URL        = "https://www.virustotal.com/api/v3"
VT_IP_ENDPOINT     = VT_BASE_URL + "/ip_addresses/{ioc}"
VT_HASH_ENDPOINT   = VT_BASE_URL + "/files/{ioc}"

# Rate-limit settings (free tier = 4 req/min, 500 req/day)
VT_MAX_CONCURRENT  = int(os.environ.get("VT_MAX_CONCURRENT", 4))   # semaphore slots
VT_RATE_WINDOW     = float(os.environ.get("VT_RATE_WINDOW", 60))   # seconds per window
VT_MAX_PER_WINDOW  = int(os.environ.get("VT_MAX_PER_WINDOW", 4))   # requests per window
VT_MAX_RETRIES     = int(os.environ.get("VT_MAX_RETRIES", 3))
VT_RETRY_BACKOFF   = float(os.environ.get("VT_RETRY_BACKOFF", 5.0)) # seconds between retries
VT_REQUEST_TIMEOUT = float(os.environ.get("VT_REQUEST_TIMEOUT", 30.0))

# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_IP_ENDPOINT = ABUSEIPDB_BASE_URL + "/check"
ABUSEIPDB_MAX_CONCURRENT = int(os.environ.get("ABUSEIPDB_MAX_CONCURRENT", 5))
ABUSEIPDB_RATE_WINDOW    = float(os.environ.get("ABUSEIPDB_RATE_WINDOW", 86400)) # 1000 per day free
ABUSEIPDB_MAX_PER_WINDOW = int(os.environ.get("ABUSEIPDB_MAX_PER_WINDOW", 1000))

# ── OTX AlienVault ────────────────────────────────────────────────────────────
OTX_API_KEY        = os.environ.get("OTX_API_KEY", "")
OTX_BASE_URL       = "https://otx.alienvault.com/api/v1/indicators"
OTX_IP_ENDPOINT    = OTX_BASE_URL + "/IPv4/{ioc}/general"
OTX_DOMAIN_ENDPOINT = OTX_BASE_URL + "/domain/{ioc}/general"
OTX_HASH_ENDPOINT  = OTX_BASE_URL + "/file/{ioc}/general"
OTX_MAX_CONCURRENT = int(os.environ.get("OTX_MAX_CONCURRENT", 5))
OTX_RATE_WINDOW    = float(os.environ.get("OTX_RATE_WINDOW", 3600))
OTX_MAX_PER_WINDOW = int(os.environ.get("OTX_MAX_PER_WINDOW", 10000))

# ── Private IP ranges to exclude (RFC 1918 + loopback + link-local) ───────────
PRIVATE_IP_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

# ── Volumetric Analysis Thresholds ────────────────────────────────────────────
VOLUMETRIC_THRESHOLD_DOS = int(os.environ.get("VOLUMETRIC_THRESHOLD_DOS", 5000))
VOLUMETRIC_THRESHOLD_PORT_SCAN = int(os.environ.get("VOLUMETRIC_THRESHOLD_PORT_SCAN", 2000))

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL  = os.environ.get("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
LOG_FILE   = OUTPUT_DIR / "pipeline.log"
