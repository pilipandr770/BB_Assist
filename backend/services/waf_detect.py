"""Early WAF/CDN detection from httpx results.

Behind Cloudflare, blind fuzzing (ffuf, arjun) and bulk nuclei runs mostly get
blocked or throttled, wasting many minutes with ~0 findings. This module measures
how much of the live surface is fronted by Cloudflare so the pipeline can adapt.
"""
from __future__ import annotations

from dataclasses import dataclass

# Share of live hosts behind Cloudflare at/above which the scan switches to
# "WAF-heavy" mode.
CF_HEAVY_RATIO = 0.7
# Nuclei target cap in WAF-heavy mode (default is 500).
CF_NUCLEI_MAX_URLS = 150


@dataclass(frozen=True)
class WafProfile:
    total_hosts: int
    cloudflare_hosts: int

    @property
    def ratio(self) -> float:
        return self.cloudflare_hosts / self.total_hosts if self.total_hosts else 0.0

    @property
    def cloudflare_heavy(self) -> bool:
        return self.total_hosts > 0 and self.ratio >= CF_HEAVY_RATIO


def _is_cloudflare(result: dict) -> bool:
    server = str(result.get("webserver") or "").lower()
    if "cloudflare" in server:
        return True

    for field in ("tech", "technologies", "technology"):
        value = result.get(field)
        items = value if isinstance(value, list) else [value] if value else []
        if any("cloudflare" in str(i).lower() for i in items):
            return True

    if "cloudflare" in str(result.get("cdn_name") or "").lower():
        return True

    headers = result.get("header") or result.get("headers") or {}
    if isinstance(headers, dict):
        lowered = {str(k).lower().replace("_", "-"): str(v).lower() for k, v in headers.items()}
        if "cf-ray" in lowered or "cloudflare" in lowered.get("server", ""):
            return True
    return False


def detect_waf_profile(http_results: list[dict] | None) -> WafProfile:
    """Count unique hosts and how many of them sit behind Cloudflare."""
    hosts: dict[str, bool] = {}
    for r in http_results or []:
        if not isinstance(r, dict):
            continue
        host = str(r.get("host") or r.get("input") or r.get("url") or "").lower()
        if not host:
            continue
        hosts[host] = hosts.get(host, False) or _is_cloudflare(r)
    return WafProfile(total_hosts=len(hosts), cloudflare_hosts=sum(hosts.values()))


# ── Origin-IP candidates ──────────────────────────────────────────────────────
# Subdomains of a Cloudflare-fronted program that resolve to non-Cloudflare IPs
# often point straight at the origin infrastructure (mail, dev, direct, legacy).
# This is purely passive: DNS resolution only, no requests to the target hosts.

import asyncio
import ipaddress
import socket

_CLOUDFLARE_V4 = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)]


def is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and any(addr in net for net in _CLOUDFLARE_V4)


def select_origin_candidates(host_ips: dict[str, list[str]]) -> dict[str, list[str]]:
    """Keep hosts whose public IPv4 addresses are all outside Cloudflare ranges."""
    out: dict[str, list[str]] = {}
    for host, ips in host_ips.items():
        public = [
            ip for ip in ips
            if not ipaddress.ip_address(ip).is_private
            and not ipaddress.ip_address(ip).is_loopback
        ]
        if public and not any(is_cloudflare_ip(ip) for ip in public):
            out[host] = sorted(set(public))
    return out


def cloudflare_confirmed_hosts(http_results: list[dict] | None) -> set[str]:
    """Hosts that httpx itself saw served by Cloudflare."""
    hosts: set[str] = set()
    for r in http_results or []:
        if isinstance(r, dict) and _is_cloudflare(r):
            h = str(r.get("host") or r.get("input") or "").lower()
            if h:
                hosts.add(h)
    return hosts


def resolver_looks_unreliable(host_ips: dict[str, list[str]], cf_hosts: set[str]) -> bool:
    """True if a host proven to be on Cloudflare resolves outside Cloudflare ranges.

    That means our DNS resolver returns altered answers (ISP block/sinkhole, split DNS),
    so 'non-Cloudflare IP' hits would be false positives.
    """
    for host in cf_hosts:
        ips = host_ips.get(host)
        if ips and not any(is_cloudflare_ip(ip) for ip in ips):
            return True
    return False


async def resolve_hosts(hosts: list[str], concurrency: int = 40, max_hosts: int = 400) -> dict[str, list[str]]:
    """Resolve IPv4 A records for hosts (bounded)."""
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    result: dict[str, list[str]] = {}

    async def _one(host: str) -> None:
        async with sem:
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
                    timeout=6,
                )
            except Exception:
                return
            ips = sorted({i[4][0] for i in infos})
            if ips:
                result[host] = ips

    await asyncio.gather(*(_one(h) for h in sorted(set(hosts))[:max_hosts]))
    return result


async def probe_cloudflare(domains: list[str], max_domains: int = 3) -> bool:
    """Quick live check used by the Program Scorer: is the first concrete domain on Cloudflare?"""
    import httpx

    candidates = [d.strip().lstrip("*.").lower() for d in domains if d and d.strip()]
    for domain in list(dict.fromkeys(candidates))[:max_domains]:
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
                resp = await client.get(f"https://{domain}")
        except Exception:
            continue
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        if "cf-ray" in headers or "cloudflare" in headers.get("server", ""):
            return True
        return False
    return False
