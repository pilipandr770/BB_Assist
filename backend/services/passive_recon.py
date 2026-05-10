"""
Passive recon — free API integrations for intelligence gathering.

NO direct contact with target. All data from third-party databases.
Safe to run on any program without worrying about scope rules.

Sources (in priority order):
  1. crt.sh          — certificate transparency, no key needed
  2. Wayback CDX     — historical URLs, no key needed
  3. IPInfo.io       — ASN/geo info, 50k/month free
  4. VirusTotal      — passive DNS, subdomain, reputation (500/day)
  5. URLScan.io      — URL scan results, screenshots (100/day)
  6. AlienVault OTX  — threat intel, IP/domain info (unlimited free)
"""

import asyncio
import re
from typing import Optional

import httpx

from backend.config import settings

# Extensions to skip from Wayback — not useful for vuln hunting
_SKIP_EXTENSIONS = re.compile(
    r"\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|gz)(\?|$)",
    re.IGNORECASE,
)

_TIMEOUT = httpx.Timeout(30.0)


async def crt_sh_subdomains(domain: str) -> list[str]:
    """
    Query crt.sh for subdomains via certificate transparency.
    No API key required.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains: set[str] = set()

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            entries = resp.json()
        except Exception:
            return []

    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            # Strip leading wildcard
            if name.startswith("*."):
                name = name[2:]
            if name and domain in name and not name.startswith("@"):
                subdomains.add(name)

    return sorted(subdomains)


async def wayback_urls(domain: str) -> list[str]:
    """
    Query Wayback Machine CDX API for historical URLs.
    No API key required.
    """
    url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "10000",
    }

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

    # First row is the header ["original"]
    urls: set[str] = set()
    for row in data[1:]:
        if not row:
            continue
        original = row[0]
        if original and not _SKIP_EXTENSIONS.search(original):
            urls.add(original)

    return sorted(urls)


async def virustotal_subdomains(domain: str) -> list[str]:
    """
    Get subdomains from VirusTotal passive DNS.
    Requires VIRUSTOTAL_API_KEY. Returns [] if no key.
    """
    if not settings.virustotal_api_key:
        return []

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": settings.virustotal_api_key}
    subdomains: set[str] = set()

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

    for item in data.get("data", []):
        sub = item.get("id", "").strip().lower()
        if sub:
            subdomains.add(sub)

    return sorted(subdomains)


async def urlscan_lookup(domain: str) -> list[dict]:
    """
    Search URLScan.io for past scans of domain.
    Returns list of scan results with URL, IP, tech stack info.
    Requires URLSCAN_API_KEY. Returns [] if no key.
    """
    if not settings.urlscan_api_key:
        return []

    url = "https://urlscan.io/api/v1/search/"
    params = {"q": f"domain:{domain}", "size": "100"}
    headers = {"API-Key": settings.urlscan_api_key}

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

    results = []
    for result in data.get("results", []):
        page = result.get("page", {})
        results.append({
            "url": page.get("url", ""),
            "ip": page.get("ip", ""),
            "country": page.get("country", ""),
            "technologies": result.get("stats", {}).get("techs", []),
            "screenshot": result.get("screenshot", ""),
        })

    return results


async def otx_domain_info(domain: str) -> dict:
    """
    Get domain intelligence from AlienVault OTX.
    Returns IPs, subdomains, malware associations, related URLs.
    Requires OTX_API_KEY. Returns {} if no key.
    """
    if not settings.otx_api_key:
        return {}

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"X-OTX-API-KEY": settings.otx_api_key}

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return {}

    ips: set[str] = set()
    subdomains: set[str] = set()

    for record in data.get("passive_dns", []):
        hostname = record.get("hostname", "").lower()
        address = record.get("address", "")
        if hostname and domain in hostname:
            subdomains.add(hostname)
        if address and re.match(r"^\d+\.\d+\.\d+\.\d+$", address):
            ips.add(address)

    return {
        "subdomains": sorted(subdomains),
        "ips": sorted(ips),
        "raw": data,
    }


async def ipinfo_lookup(ip: str) -> dict:
    """
    Get IP info (ASN, org, country, hostname) from IPInfo.io.
    50,000 requests/month free. Optional token for higher limits.
    """
    url = f"https://ipinfo.io/{ip}/json"
    headers = {}
    if settings.ipinfo_token:
        headers["Authorization"] = f"Bearer {settings.ipinfo_token}"

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return {}


async def run_all_passive(domain: str) -> dict:
    """
    Run all passive recon sources for a domain in parallel.
    Returns merged results with deduplication.
    Gracefully handles individual failures.
    """
    results = await asyncio.gather(
        crt_sh_subdomains(domain),
        wayback_urls(domain),
        virustotal_subdomains(domain),
        urlscan_lookup(domain),
        otx_domain_info(domain),
        return_exceptions=True,
    )

    crt_subs = results[0] if not isinstance(results[0], Exception) else []
    wayback = results[1] if not isinstance(results[1], Exception) else []
    vt_subs = results[2] if not isinstance(results[2], Exception) else []
    urlscan = results[3] if not isinstance(results[3], Exception) else []
    otx = results[4] if not isinstance(results[4], Exception) else {}

    # Merge and deduplicate subdomains from all sources
    all_subdomains: set[str] = set()
    all_subdomains.update(crt_subs)
    all_subdomains.update(vt_subs)
    all_subdomains.update(otx.get("subdomains", []))

    return {
        "subdomains": sorted(all_subdomains),
        "urls": wayback,
        "scan_results": urlscan,
        "threat_intel": otx,
    }
