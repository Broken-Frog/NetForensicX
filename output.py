"""
output.py
Phase 2 — Step 6: Serialise the enriched IOC list and run statistics.

Responsibilities:
  • Strip internal bookkeeping fields (e.g. _dedup_key) before writing.
  • Write unified_iocs.json (one IOC per line for easy streaming / grep).
  • Write run_stats.json with all aggregated pipeline statistics.
  • Print a human-readable summary to stdout.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from config import OUTPUT_DIR, STATS_JSON, UNIFIED_IOCS_JSON

log = logging.getLogger(__name__)

# Fields that are internal implementation details and must NOT appear in output
_INTERNAL_FIELDS = {"_dedup_key"}


def _strip_internal(ioc: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in ioc.items() if k not in _INTERNAL_FIELDS}


def _compute_output_stats(iocs: List[Dict]) -> Dict[str, Any]:
    """Derive summary counts from the final IOC list."""
    total            = len(iocs)
    with_ip          = sum(1 for i in iocs if i.get("ip"))
    with_domain      = sum(1 for i in iocs if i.get("domain"))
    with_url         = sum(1 for i in iocs if i.get("url"))
    with_hash        = sum(1 for i in iocs if i.get("file_hash"))
    with_yara        = sum(1 for i in iocs if i.get("yara_match"))
    with_alert       = sum(1 for i in iocs if i.get("suricata_alert"))
    with_vt          = sum(1 for i in iocs if i.get("vt_score") is not None)
    with_abuseipdb   = sum(1 for i in iocs if i.get("abuseipdb_score") is not None)
    with_otx         = sum(1 for i in iocs if i.get("otx_pulse_count") is not None)
    high_confidence  = sum(1 for i in iocs if (
        (i.get("vt_malicious_count") or 0) >= 5 or
        i.get("is_malicious_ip") is True or
        i.get("high_pulse_rate") is True
    ))

    return {
        "total_output_iocs":     total,
        "iocs_with_ip":          with_ip,
        "iocs_with_domain":      with_domain,
        "iocs_with_url":         with_url,
        "iocs_with_file_hash":   with_hash,
        "iocs_with_yara_match":  with_yara,
        "iocs_with_suri_alert":  with_alert,
        "iocs_vt_enriched":      with_vt,
        "iocs_abuseipdb_enriched": with_abuseipdb,
        "iocs_otx_enriched":     with_otx,
        "high_confidence_hits":  high_confidence,  # Any source
    }


def save_results(
    iocs: List[Dict],
    pipeline_stats: Dict[str, Any],
    output_dir: Path = OUTPUT_DIR,
    iocs_path: Path = UNIFIED_IOCS_JSON,
    stats_path: Path = STATS_JSON,
) -> None:
    """
    Write unified_iocs.json and run_stats.json.

    unified_iocs.json is written as a pretty-printed JSON array for
    human readability.  Each IOC dict contains only public fields.

    run_stats.json merges pipeline_stats (passed in from main.py) with
    stats computed from the final IOC list.
    """
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    iocs_path  = Path(iocs_path).resolve()
    stats_path = Path(stats_path).resolve()

    # ── unified_iocs.json ────────────────────────────────────────────────────
    clean_iocs = [_strip_internal(i) for i in iocs]

    with open(iocs_path, "w", encoding="utf-8") as fh:
        json.dump(clean_iocs, fh, indent=2, default=str)

    log.info("IOC output written: %s (%d records)", iocs_path, len(clean_iocs))

    # ── run_stats.json ───────────────────────────────────────────────────────
    output_stats = _compute_output_stats(clean_iocs)
    merged_stats = {**pipeline_stats, **output_stats}

    with open(stats_path, "w", encoding="utf-8") as fh:
        json.dump(merged_stats, fh, indent=2)

    log.info("Stats written: %s", stats_path)

    # ── Human-readable summary ───────────────────────────────────────────────
    _print_summary(merged_stats, iocs_path, stats_path)


def _print_summary(stats: Dict[str, Any], iocs_path: Path, stats_path: Path) -> None:
    sep = "─" * 60
    print(f"\n{sep}")
    print("  Phase 2 Pipeline — Run Summary")
    print(sep)

    sections = [
        ("Extraction", [
            ("Raw IOCs collected",      stats.get("input_count",      "—")),
        ]),
        ("Cleaning", [
            ("Dropped (empty)",         stats.get("dropped_empty",    "—")),
            ("Dropped (private IP)",    stats.get("dropped_private",  "—")),
            ("Dropped (duplicate)",     stats.get("dropped_dedup",    "—")),
            ("Clean IOCs",              stats.get("output_count",     "—")),
        ]),
        ("YARA Scanning", [
            ("Files scanned",           stats.get("scanned_files",    "—")),
            ("YARA hits",               stats.get("yara_hits",        "—")),
        ]),
        ("Enrichment (API Integrations)", [
            ("Cache hits",              stats.get("cache_hits",       "—")),
            ("API calls made",          stats.get("api_calls_made",   "—")),
            ("API errors",              stats.get("api_errors",       "—")),
            ("Total enriched",          stats.get("total_enriched",   "—")),
        ]),
        ("Final Output", [
            ("Total IOCs written",      stats.get("total_output_iocs",    "—")),
            ("  with IP",               stats.get("iocs_with_ip",         "—")),
            ("  with domain",           stats.get("iocs_with_domain",     "—")),
            ("  with file hash",        stats.get("iocs_with_file_hash",  "—")),
            ("  with YARA match",       stats.get("iocs_with_yara_match", "—")),
            ("  with Suricata alert",   stats.get("iocs_with_suri_alert", "—")),
            ("  VT-enriched",           stats.get("iocs_vt_enriched",     "—")),
            ("  AbuseIPDB-enriched",    stats.get("iocs_abuseipdb_enriched", "—")),
            ("  OTX-enriched",          stats.get("iocs_otx_enriched",    "—")),
            ("  High-confidence hits",  stats.get("high_confidence_hits", "—")),
        ]),
    ]

    for title, rows in sections:
        print(f"\n  {title}")
        for label, value in rows:
            print(f"    {label:<30} {value}")

    print(f"\n  Output files:")
    print(f"    IOCs  → {iocs_path}")
    print(f"    Stats → {stats_path}")
    print(f"{sep}\n")
