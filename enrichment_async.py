"""
enrichment_async.py
Phase 2.5 — Async enrichment engine supporting VirusTotal, AbuseIPDB, and OTX AlienVault.

Architecture
────────────
┌─────────────────────────────────────────────────────────┐
│                   enrich_iocs()   (entry point)         │
│  builds work queue → dispatches _enrich_one() tasks     │
│  via asyncio.gather with a semaphore-based concurrency  │
│  limiter                                                │
└─────────────────────────────────────────────────────────┘
           │
    ┌──────▼──────┐
    │ Redis cache │  HIT  → return cached payload immediately
    └──────┬──────┘
           │ MISS
    ┌──────▼──────────────────────────────────────────────┐
    │  _call_*_api() (Parallel calls for VT, Abuse, OTX)  │
    │  • aiohttp session (shared, keep-alive)             │
    │  • RateLimiters: token-bucket per provider          │
    │  • Retry: up to max retries with exponential backoff│
    └──────┬──────────────────────────────────────────────┘
           │
    ┌──────▼──────┐
    │  Redis SET  │  store combined response with TTL
    └─────────────┘
"""

import asyncio
import ipaddress
import json
import logging
import time
import sys
from typing import Any, Dict, List, Optional, Set

import aiohttp  # type: ignore

from cache import RedisCache
from config import (
    PRIVATE_IP_RANGES,
    OUTPUT_DIR,
    VT_API_KEY,
    VT_HASH_ENDPOINT,
    VT_IP_ENDPOINT,
    VT_MAX_CONCURRENT,
    VT_MAX_PER_WINDOW,
    VT_MAX_RETRIES,
    VT_RATE_WINDOW,
    VT_REQUEST_TIMEOUT,
    VT_RETRY_BACKOFF,
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_IP_ENDPOINT,
    ABUSEIPDB_MAX_CONCURRENT,
    ABUSEIPDB_RATE_WINDOW,
    ABUSEIPDB_MAX_PER_WINDOW,
    OTX_API_KEY,
    OTX_IP_ENDPOINT,
    OTX_DOMAIN_ENDPOINT,
    OTX_HASH_ENDPOINT,
    OTX_MAX_CONCURRENT,
    OTX_RATE_WINDOW,
    OTX_MAX_PER_WINDOW,
)

log = logging.getLogger(__name__)

_PRIVATE_NETS = [ipaddress.ip_network(r, strict=False) for r in PRIVATE_IP_RANGES]


# ──────────────────────────────────────────────────────────────────────────────
# Token-bucket rate limiter
# ──────────────────────────────────────────────────────────────────────────────

class _TokenBucket:
    def __init__(self, rate: int, window: float) -> None:
        self._rate      = rate          # tokens per window
        self._window    = window        # seconds
        self._tokens    = rate          # start full
        self._lock      = asyncio.Lock()
        self._last_refill: float = time.monotonic()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill

                if elapsed >= self._window:
                    self._tokens      = self._rate
                    self._last_refill = now

                if self._tokens > 0:
                    self._tokens -= 1
                    return

                wait_time = self._window - elapsed

            log.debug("Rate limit reached — waiting %.1fs for token refill.", wait_time)
            await asyncio.sleep(wait_time)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_private(addr: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(addr)
        return any(ip_obj in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _vt_url_for(ioc: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        return VT_IP_ENDPOINT.format(ioc=ioc)
    return VT_HASH_ENDPOINT.format(ioc=ioc)


def _parse_vt_response(data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious   = int(stats.get("malicious",   0))
        suspicious  = int(stats.get("suspicious",  0))
        undetected  = int(stats.get("undetected",  0))
        harmless    = int(stats.get("harmless",    0))
        total_scans = malicious + suspicious + undetected + harmless

        return {
            "vt_score":           malicious + suspicious,
            "vt_malicious_count": malicious,
            "vt_total_scans":     total_scans,
        }
    except (AttributeError, TypeError, KeyError) as exc:
        log.debug("Could not parse VT response: %s", exc)
        return {}


# ──────────────────────────────────────────────────────────────────────────────
# Core API callers
# ──────────────────────────────────────────────────────────────────────────────

async def _call_vt_api(
    session: aiohttp.ClientSession,
    ioc: str,
    ioc_type: str,
    bucket: _TokenBucket,
) -> Optional[Dict[str, Any]]:
    if not VT_API_KEY:
        return {}
    
    url = _vt_url_for(ioc, ioc_type)
    headers = {"x-apikey": VT_API_KEY}

    for attempt in range(1, VT_MAX_RETRIES + 1):
        await bucket.acquire()
        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=VT_REQUEST_TIMEOUT),
            ) as resp:
                if resp.status == 200:
                    raw = await resp.json(content_type=None)
                    return _parse_vt_response(raw)
                elif resp.status == 404:
                    return {}
                elif resp.status == 429:
                    retry_after = float(resp.headers.get("Retry-After", VT_RATE_WINDOW))
                    await asyncio.sleep(retry_after)
                    continue
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            pass
        
        if attempt < VT_MAX_RETRIES:
            await asyncio.sleep(VT_RETRY_BACKOFF * (2 ** (attempt - 1)))
            
    return {}


async def _call_abuseipdb_api(
    session: aiohttp.ClientSession,
    ioc: str,
    ioc_type: str,
    bucket: _TokenBucket,
) -> Optional[Dict[str, Any]]:
    if not ABUSEIPDB_API_KEY or ioc_type != "ip":
        return {}

    url = ABUSEIPDB_IP_ENDPOINT
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": "90"}

    for attempt in range(1, VT_MAX_RETRIES + 1):
        await bucket.acquire()
        try:
            async with session.get(
                url,
                headers=headers,
                params=params,
                timeout=aiohttp.ClientTimeout(total=VT_REQUEST_TIMEOUT),
            ) as resp:
                if resp.status == 200:
                    raw = await resp.json(content_type=None)
                    data = raw.get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                    return {
                        "abuseipdb_score": score,
                        "abuseipdb_reports": reports,
                        "is_malicious_ip": score >= 50 # Mark as malicious if score >= 50
                    }
                elif resp.status == 429:
                    await asyncio.sleep(VT_RATE_WINDOW)
                    continue
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            pass
            
        if attempt < VT_MAX_RETRIES:
            await asyncio.sleep(VT_RETRY_BACKOFF * (2 ** (attempt - 1)))
            
    return {}


async def _call_otx_api(
    session: aiohttp.ClientSession,
    ioc: str,
    ioc_type: str,
    bucket: _TokenBucket,
) -> Optional[Dict[str, Any]]:
    if not OTX_API_KEY:
        return {}

    if ioc_type == "ip":
        url = OTX_IP_ENDPOINT.format(ioc=ioc)
    elif ioc_type == "domain":
        url = OTX_DOMAIN_ENDPOINT.format(ioc=ioc)
    else:
        url = OTX_HASH_ENDPOINT.format(ioc=ioc)

    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    for attempt in range(1, VT_MAX_RETRIES + 1):
        await bucket.acquire()
        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=VT_REQUEST_TIMEOUT),
            ) as resp:
                if resp.status == 200:
                    raw = await resp.json(content_type=None)
                    pulse_info = raw.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)
                    return {
                        "otx_pulse_count": pulse_count,
                        "high_pulse_rate": pulse_count >= 5 # Mark as high pulse rate if >= 5
                    }
                elif resp.status == 404:
                    return {}
                elif resp.status == 429:
                    await asyncio.sleep(VT_RATE_WINDOW)
                    continue
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            pass

        if attempt < VT_MAX_RETRIES:
            await asyncio.sleep(VT_RETRY_BACKOFF * (2 ** (attempt - 1)))

    return {}


# ──────────────────────────────────────────────────────────────────────────────
# Per-IOC enrichment task
# ──────────────────────────────────────────────────────────────────────────────

async def _enrich_one(
    ioc_value: str,
    ioc_type: str,
    cache: RedisCache,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    vt_bucket: _TokenBucket,
    abuse_bucket: _TokenBucket,
    otx_bucket: _TokenBucket,
    results: Dict[str, Dict[str, Any]],
    stats: Dict[str, int],
    scanned_records: List[Dict[str, Any]],
) -> None:
    cached = cache.get(ioc_value)
    if cached is not None:
        results[ioc_value] = cached
        stats["cache_hits"] += 1
        return

    async with semaphore:
        cached = cache.get(ioc_value)
        if cached is not None:
            results[ioc_value] = cached
            stats["cache_hits"] += 1
            return

        stats["api_calls_made"] += 1
        
        vt_task = _call_vt_api(session, ioc_value, ioc_type, vt_bucket)
        abuse_task = _call_abuseipdb_api(session, ioc_value, ioc_type, abuse_bucket)
        otx_task = _call_otx_api(session, ioc_value, ioc_type, otx_bucket)
        
        vt_res, abuse_res, otx_res = await asyncio.gather(vt_task, abuse_task, otx_task)
        
        apis_used = []
        if VT_API_KEY: apis_used.append("VirusTotal")
        if ABUSEIPDB_API_KEY and ioc_type == "ip": apis_used.append("AbuseIPDB")
        if OTX_API_KEY: apis_used.append("OTX AlienVault")
        
        scanned_records.append({
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "apis_scanned": apis_used,
            "timestamp": time.time()
        })
        
        enrichment = {}
        if vt_res: enrichment.update(vt_res)
        if abuse_res: enrichment.update(abuse_res)
        if otx_res: enrichment.update(otx_res)

        if not enrichment:
            stats["api_errors"] += 1
            return

        cache.set(ioc_value, enrichment)
        results[ioc_value] = enrichment


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

async def enrich_iocs_async(
    iocs: List[Dict],
    cache: RedisCache,
) -> Dict[str, int]:
    stats: Dict[str, int] = {
        "cache_hits":       0,
        "api_calls_made":   0,
        "api_errors":       0,
        "total_enriched":   0,
        "skipped_no_key":   0,
    }

    if not VT_API_KEY and not ABUSEIPDB_API_KEY and not OTX_API_KEY:
        log.error("No API keys provided for enrichment.")
        stats["skipped_no_key"] = len(iocs)
        return stats

    work_items: Set[tuple] = set()
    for ioc in iocs:
        ip = ioc.get("ip")
        fhash = ioc.get("file_hash")
        domain = ioc.get("domain") # Assuming domains might be extracted
        
        if ip and not ioc.get("is_private", False):
            work_items.add((ip, "ip"))
        if fhash:
            work_items.add((fhash, "hash"))
        if domain:
            work_items.add((domain, "domain"))

    if not work_items:
        log.info("No enrichable IOCs found.")
        return stats

    log.info("Enrichment queue: %d unique IOCs to process.", len(work_items))

    results: Dict[str, Dict[str, Any]] = {}
    scanned_records: List[Dict[str, Any]] = []

    vt_bucket    = _TokenBucket(rate=VT_MAX_PER_WINDOW, window=VT_RATE_WINDOW)
    abuse_bucket = _TokenBucket(rate=ABUSEIPDB_MAX_PER_WINDOW, window=ABUSEIPDB_RATE_WINDOW)
    otx_bucket   = _TokenBucket(rate=OTX_MAX_PER_WINDOW, window=OTX_RATE_WINDOW)
    
    max_concurrency = max(VT_MAX_CONCURRENT, ABUSEIPDB_MAX_CONCURRENT, OTX_MAX_CONCURRENT)
    semaphore = asyncio.Semaphore(max_concurrency)
    connector = aiohttp.TCPConnector(limit=max_concurrency, ssl=True)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            _enrich_one(
                ioc_value=value,
                ioc_type=itype,
                cache=cache,
                session=session,
                semaphore=semaphore,
                vt_bucket=vt_bucket,
                abuse_bucket=abuse_bucket,
                otx_bucket=otx_bucket,
                results=results,
                stats=stats,
                scanned_records=scanned_records,
            )
            for value, itype in work_items
        ]
        
        total_tasks = len(tasks)
        completed = 0
        sys.stdout.write(f"\r[Enrichment] Progress: [0/{total_tasks}] 0% completed")
        sys.stdout.flush()
        
        for f in asyncio.as_completed(tasks):
            await f
            completed += 1
            pct = int((completed / total_tasks) * 100)
            sys.stdout.write(f"\r[Enrichment] Progress: [{completed}/{total_tasks}] {pct}% completed")
            sys.stdout.flush()
            
        print()
        
    if scanned_records:
        log_file = OUTPUT_DIR / "scanned_iocs_by_api.json"
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(scanned_records, f, indent=2)
        log.info("Saved scan log to %s", log_file)

    enriched_count = 0
    for ioc in iocs:
        ip = ioc.get("ip")
        fhash = ioc.get("file_hash")
        domain = ioc.get("domain")

        payload = {}
        if fhash and fhash in results:
            payload.update(results[fhash])
        if ip and ip in results:
            payload.update(results[ip])
        if domain and domain in results:
            payload.update(results[domain])

        if payload:
            ioc.update(payload)
            enriched_count += 1

    stats["total_enriched"] = enriched_count

    redis_stats = cache.stats
    stats["redis_writes"] = redis_stats.get("cache_writes", 0)
    stats["redis_errors"] = redis_stats.get("cache_errors", 0)

    log.info(
        "Enrichment complete: enriched=%d  cache_hits=%d  api_calls=%d  errors=%d",
        enriched_count, stats["cache_hits"], stats["api_calls_made"], stats["api_errors"],
    )
    return stats


def enrich_iocs(iocs: List[Dict], cache: RedisCache) -> Dict[str, int]:
    return asyncio.run(enrich_iocs_async(iocs, cache))
