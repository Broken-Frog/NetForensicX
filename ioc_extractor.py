#!/usr/bin/env python3
"""
main.py
Phase 2 + 2.5 — IOC Processing Pipeline Orchestrator

Run order:
  1. extraction.py     → raw IOC dicts from Zeek / Suricata / carved files
  2. cleaning.py       → remove private IPs, empty records, duplicates
  3. yara_scan.py      → YARA match each unique file_hash once
  4. enrichment_async.py → async VT enrichment with Redis cache + rate limiter
  5. output.py         → unified_iocs.json + run_stats.json

Usage
─────
  # Minimal (use defaults from config.py + env vars)
  python main.py

  # Override PCAP stem and output dir
  PCAP_STEM=Hive_06082021 OUTPUT_DIR=./results python main.py

  # With custom processed-data root and VT key
  PROCESSED_DIR=/data/processed VT_API_KEY=<key> python main.py

Required env vars
─────────────────
  VT_API_KEY   — VirusTotal API key (enrichment is skipped if absent)

Optional env vars (all have sensible defaults — see config.py)
─────────────────────────────────────────────────────────────
  PCAP_STEM        PROCESSED_DIR    OUTPUT_DIR
  YARA_RULES_DIR   REDIS_HOST       REDIS_PORT
  REDIS_DB         REDIS_PASSWORD   REDIS_CACHE_TTL
  VT_MAX_CONCURRENT VT_MAX_PER_WINDOW VT_RATE_WINDOW
  VT_MAX_RETRIES   LOG_LEVEL
"""

import logging
import sys
import time
from pathlib import Path

# ── Bootstrap logging BEFORE importing any project module so all loggers
#    (including those created at module import time) inherit the config.
import config  # noqa: E402  (config must come first)

config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format=config.LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(config.LOG_FILE), mode="a", encoding="utf-8"),
    ],
)

log = logging.getLogger("main")

# ── Project modules ────────────────────────────────────────────────────────────
from cache            import RedisCache
from cleaning         import clean_and_deduplicate
from enrichment_async import enrich_iocs
from extraction       import extract_all_iocs
from output           import save_results
from yara_scan        import run_yara_scan


def main() -> None:
    wall_start = time.perf_counter()
    log.info("=" * 60)
    log.info("Phase 2 IOC Pipeline starting")
    log.info("  PCAP stem      : %s", config.PCAP_STEM)
    log.info("  Zeek dir       : %s", config.ZEEK_DIR)
    log.info("  Suricata dir   : %s", config.SURICATA_DIR)
    log.info("  Extracted dir  : %s", config.EXTRACTED_DIR)
    log.info("  YARA rules     : %s", config.YARA_RULES_DIR)
    log.info("  Output dir     : %s", config.OUTPUT_DIR)
    log.info("  Redis          : %s:%d db=%d", config.REDIS_HOST, config.REDIS_PORT, config.REDIS_DB)
    log.info("=" * 60)

    # Accumulate all stats into one dict that gets written to run_stats.json
    pipeline_stats: dict = {}

    # ── Step 1: Extraction ────────────────────────────────────────────────────
    t0 = time.perf_counter()
    log.info("[Step 1/5] IOC Extraction …")

    raw_iocs = extract_all_iocs(
        zeek_dir=config.ZEEK_DIR,
        suri_dir=config.SURICATA_DIR,
        extracted_dir=config.EXTRACTED_DIR,
    )
    pipeline_stats["raw_ioc_count"] = len(raw_iocs)
    log.info("[Step 1/5] Done — %d raw IOCs  (%.2fs)", len(raw_iocs), time.perf_counter() - t0)

    if not raw_iocs:
        log.error("No IOCs extracted. Check that Phase 1 output dirs are correct.")
        sys.exit(1)

    # ── Step 2: Cleaning & Deduplication ─────────────────────────────────────
    t0 = time.perf_counter()
    log.info("[Step 2/5] Cleaning & deduplication …")

    clean_iocs, clean_stats = clean_and_deduplicate(raw_iocs)
    pipeline_stats.update(clean_stats)
    log.info(
        "[Step 2/5] Done — %d → %d IOCs  (%.2fs)",
        clean_stats["input_count"], clean_stats["output_count"],
        time.perf_counter() - t0,
    )

    if not clean_iocs:
        log.warning("All IOCs were filtered out during cleaning. Nothing to process.")
        save_results([], pipeline_stats)
        return

    # ── Step 3: YARA Scanning ─────────────────────────────────────────────────
    t0 = time.perf_counter()
    log.info("[Step 3/5] YARA scanning …")

    yara_stats = run_yara_scan(
        iocs=clean_iocs,
        rules_dir=config.YARA_RULES_DIR,
        extracted_dir=config.EXTRACTED_DIR,
    )
    pipeline_stats.update(yara_stats)
    log.info(
        "[Step 3/5] Done — %d files scanned, %d hits  (%.2fs)",
        yara_stats["scanned_files"], yara_stats["yara_hits"],
        time.perf_counter() - t0,
    )

    # ── Step 4: Async Threat Intel Enrichment ─────────────────────────────────
    t0 = time.perf_counter()
    log.info("[Step 4/5] Async Threat Intel (VT, AbuseIPDB, OTX) enrichment …")

    cache = RedisCache()
    enrich_stats = enrich_iocs(clean_iocs, cache)
    pipeline_stats.update(enrich_stats)
    log.info(
        "[Step 4/5] Done — enriched=%d  cache_hits=%d  api_calls=%d  (%.2fs)",
        enrich_stats.get("total_enriched", 0),
        enrich_stats.get("cache_hits",     0),
        enrich_stats.get("api_calls_made", 0),
        time.perf_counter() - t0,
    )

    # ── Step 5: Output ────────────────────────────────────────────────────────
    t0 = time.perf_counter()
    log.info("[Step 5/5] Writing output …")

    import os
    pipeline_stats["forensic_integrity"] = {
        "pcap_sha256": os.environ.get("FORENSIC_PCAP_HASH", "Unknown"),
        "operator": os.environ.get("FORENSIC_OPERATOR", "Unknown"),
        "hostname": os.environ.get("FORENSIC_HOSTNAME", "Unknown"),
        "timestamp_utc": os.environ.get("FORENSIC_START_TIME", "Unknown")
    }

    pipeline_stats["wall_time_seconds"] = round(time.perf_counter() - wall_start, 2)
    save_results(
        iocs=clean_iocs,
        pipeline_stats=pipeline_stats,
        output_dir=config.OUTPUT_DIR,
        iocs_path=config.UNIFIED_IOCS_JSON,
        stats_path=config.STATS_JSON,
    )
    log.info("[Step 5/5] Done  (%.2fs)", time.perf_counter() - t0)
    log.info("Total wall time: %.2fs", pipeline_stats["wall_time_seconds"])


if __name__ == "__main__":
    main()
