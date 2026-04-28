"""
yara_scan.py
Phase 2 — Step 3: YARA scanning of extracted payload files.

Design decisions:
  • Rules are compiled ONCE at startup from YARA_RULES_DIR and reused for all scans.
  • Each unique file_hash is scanned AT MOST ONCE (cache: hash → match list).
  • The scanner walks EXTRACTED_DIR to build a path→hash map first, so it can
    locate the file on disk given a hash from the IOC list.
  • Results are written back into the IOC dicts in-place (yara_match field).
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from config import EXTRACTED_DIR, YARA_RULES_DIR

log = logging.getLogger(__name__)

try:
    import yara  # type: ignore
    _YARA_AVAILABLE = True
except ImportError:
    log.warning("yara-python not installed — YARA scanning disabled.")
    _YARA_AVAILABLE = False


# ──────────────────────────────────────────────────────────────────────────────
# Rule compilation
# ──────────────────────────────────────────────────────────────────────────────

def _compile_rules(rules_dir: Path) -> Optional[object]:
    """
    Compile all *.yar / *.yara files found in rules_dir into a single
    yara.Rules object.  Returns None if the directory is empty or yara
    is not available.
    """
    if not _YARA_AVAILABLE:
        return None

    rules_dir = rules_dir.resolve()
    if not rules_dir.is_dir():
        log.warning("YARA rules directory not found: %s", rules_dir)
        return None

    rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
    if not rule_files:
        log.warning("No .yar/.yara files found in: %s", rules_dir)
        return None

    # ── Strategy A: index file present (e.g. index.yar with `include` lines) ──
    # yara.compile(sources=...) feeds raw strings to the engine which has no
    # concept of a working directory, so `include "foo.yar"` fails with
    # "can't open include file".  Use yara.compile(filepath=...) instead —
    # YARA then resolves all includes relative to the index file's directory.
    index_candidates = [f for f in rule_files if f.stem.lower() == "index"]
    if index_candidates:
        index_path = index_candidates[0]
        log.info(
            "YARA: index file detected (%s) — compiling via filepath "
            "so includes are resolved relative to %s",
            index_path.name, rules_dir,
        )
        try:
            compiled = yara.compile(
                filepath=str(index_path),
                # includes=True is the default; stated explicitly for clarity
            )
            log.info(
                "YARA: compiled successfully from index %s", index_path.name
            )
            return compiled
        except yara.SyntaxError as exc:
            log.error("YARA index compilation failed: %s", exc)
            return None
        except Exception as exc:
            log.error("YARA unexpected error compiling index: %s", exc)
            return None

    # ── Strategy B: no index file — compile each standalone rule file into its
    #    own namespace so rule-name collisions across files don't cause errors.
    log.info(
        "YARA: no index.yar found — compiling %d standalone file(s) "
        "from %s", len(rule_files), rules_dir,
    )
    filepaths: Dict[str, str] = {}  # namespace → absolute path string
    for rpath in rule_files:
        filepaths[rpath.stem] = str(rpath)

    try:
        compiled = yara.compile(filepaths=filepaths)
        log.info(
            "YARA: compiled %d standalone rule file(s).", len(filepaths)
        )
        return compiled
    except yara.SyntaxError as exc:
        log.error("YARA rule compilation failed: %s", exc)
        return None
    except Exception as exc:
        log.error("YARA unexpected error: %s", exc)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# File → hash index builder
# ──────────────────────────────────────────────────────────────────────────────

def _build_hash_to_path(extracted_dir: Path) -> Dict[str, Path]:
    """
    Walk extracted_dir and build  sha256_hex → Path  mapping.
    Avoids re-hashing by importing the same hasher used in extraction.py.
    """
    import hashlib

    index: Dict[str, Path] = {}
    if not extracted_dir.is_dir():
        return index

    for fpath in extracted_dir.iterdir():
        if not fpath.is_file():
            continue
        h = hashlib.sha256()
        try:
            with open(fpath, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            index[h.hexdigest()] = fpath
        except OSError as exc:
            log.warning("Cannot hash %s for YARA index: %s", fpath.name, exc)

    log.debug("YARA file index: %d files indexed.", len(index))
    return index


# ──────────────────────────────────────────────────────────────────────────────
# Per-file scanner
# ──────────────────────────────────────────────────────────────────────────────

def _scan_file(rules: object, path: Path) -> Optional[str]:
    """
    Scan a single file with the compiled ruleset.

    Returns
    -------
    Comma-separated rule names if matches found, else None.
    """
    try:
        matches = rules.match(str(path))  # type: ignore[union-attr]
        if matches:
            return ",".join(m.rule for m in matches)
    except Exception as exc:  # yara.Error can wrap many things
        log.warning("YARA scan error on %s: %s", path.name, exc)
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_yara_scan(
    iocs: List[Dict],
    rules_dir: Path = YARA_RULES_DIR,
    extracted_dir: Path = EXTRACTED_DIR,
) -> Dict[str, int]:
    """
    Scan extracted files and populate the `yara_match` field on matching IOCs.

    Each unique file_hash is scanned at most once.  Results are stored in a
    local cache dict for the duration of this run; there is no cross-run
    persistence (YARA matches are deterministic, so re-scanning is cheap).

    Parameters
    ----------
    iocs         : cleaned IOC list (mutated in-place)
    rules_dir    : directory containing .yar/.yara rule files
    extracted_dir: directory produced by Phase 1 combine_extracted_payloads()

    Returns
    -------
    stats dict: {scanned_files, yara_hits, skipped_no_file, skipped_no_rules}
    """
    stats = {
        "scanned_files":   0,
        "yara_hits":       0,
        "skipped_no_file": 0,
        "skipped_no_rules": 0,
    }

    rules_dir     = Path(rules_dir).resolve()
    extracted_dir = Path(extracted_dir).resolve()

    compiled_rules = _compile_rules(rules_dir)
    if compiled_rules is None:
        log.warning("YARA scanning skipped — no compiled rules available.")
        stats["skipped_no_rules"] = sum(1 for i in iocs if i.get("file_hash"))
        return stats

    hash_to_path = _build_hash_to_path(extracted_dir)

    # Per-hash scan cache  →  hash: match_string | None
    scan_cache: Dict[str, Optional[str]] = {}

    for ioc in iocs:
        fhash = ioc.get("file_hash")
        if not fhash:
            continue

        if fhash not in scan_cache:
            fpath = hash_to_path.get(fhash)
            if fpath is None:
                log.debug("No file on disk for hash %s — skipping YARA.", fhash[:16])
                scan_cache[fhash] = None
                stats["skipped_no_file"] += 1
            else:
                result = _scan_file(compiled_rules, fpath)
                scan_cache[fhash] = result
                stats["scanned_files"] += 1
                if result:
                    log.info("YARA HIT  %s → %s", fhash[:16], result)
                    stats["yara_hits"] += 1

        match = scan_cache[fhash]
        if match:
            ioc["yara_match"] = match

    log.info(
        "YARA complete: scanned=%d  hits=%d  no_file=%d",
        stats["scanned_files"], stats["yara_hits"], stats["skipped_no_file"],
    )
    return stats