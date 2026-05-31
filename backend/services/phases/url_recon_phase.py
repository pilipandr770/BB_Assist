"""Phase helpers for URL-level reconnaissance after live host discovery."""

from collections.abc import Awaitable, Callable
import os
import re
from urllib.parse import urlparse

import aiofiles

from backend.models import Scope
from backend.services import tool_runner
from backend.services.scan_targets import (
    build_httpx_targets,
    generate_scope_domain_urls,
    select_passive_domains,
)
from backend.services.scope_parser import is_in_scope


EventEmitter = Callable[[str, dict], Awaitable[None]]

_CRED_IN_PATH_RE = re.compile(
    r"(?:^|/)"
    r":?"
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+"
    r":"
    r"[^/\s@]{6,}",
    re.IGNORECASE,
)


def _version_samples(service_versions: list[dict], limit: int = 12) -> list[dict]:
    samples: list[dict] = []
    for svc in service_versions:
        service = str(svc.get("service", "")).strip()
        version = str(svc.get("version", "")).strip()
        fingerprint = str(svc.get("fingerprint", "")).strip()
        display = fingerprint or " ".join(x for x in [service, version] if x).strip()
        if not display:
            continue
        samples.append(
            {
                "host": svc.get("host", ""),
                "port": svc.get("port", 0),
                "display": display,
            }
        )
        if len(samples) >= limit:
            break
    return samples


async def run_url_recon_phase(
    *,
    scope: Scope,
    recon_dir: str,
    live_hosts: list[str],
    nmap_endpoints: list[str],
    nmap_service_versions: list[dict],
    nmap_csv_cve_hits: list[dict],
    do_katana: bool,
    program_type: str,
    session_cookies: str,
    auth_header: str,
    emit: EventEmitter,
) -> dict:
    """
    Run URL-level recon: httpx/fallbacks, nmap retry, header version fallback, gau, katana.
    """
    explicit_scope_urls = [u for u in (scope.in_scope_urls or []) if u.startswith("http")]
    httpx_targets = build_httpx_targets(live_hosts, nmap_endpoints, explicit_scope_urls)

    await emit("tool_start", {"tool": "httpx", "detail": f"{len(httpx_targets)} hosts"})
    httpx_out = os.path.join(recon_dir, "httpx.jsonl")
    http_results = await tool_runner.run_httpx(
        httpx_targets,
        httpx_out,
        session_cookies=session_cookies,
        auth_header=auth_header,
    )
    live_urls = [r.get("url", "") for r in http_results if r.get("url")]
    await emit("tool_done", {"tool": "httpx", "count": len(live_urls)})

    detected_techs = tool_runner.extract_tech_stack(http_results)
    if detected_techs:
        await emit("tech_detected", {"techs": sorted(detected_techs)})

    if not live_urls and explicit_scope_urls:
        live_urls = explicit_scope_urls
        await emit(
            "tool_start",
            {
                "tool": "httpx-fallback",
                "detail": f"using {len(explicit_scope_urls)} explicit scope URLs",
            },
        )
        await emit("tool_done", {"tool": "httpx-fallback", "count": len(explicit_scope_urls)})

    if not live_urls:
        generated = generate_scope_domain_urls(scope.in_scope_domains, max_domains=3)
        gen_httpx_out = os.path.join(recon_dir, "httpx_gen.jsonl")
        await emit(
            "tool_start",
            {
                "tool": "httpx-gen-fallback",
                "detail": f"probing {len(generated)} generated domain URLs",
            },
        )
        gen_results = await tool_runner.run_httpx(
            generated,
            gen_httpx_out,
            session_cookies=session_cookies,
            auth_header=auth_header,
        )
        gen_live = [r.get("url", "") for r in gen_results if r.get("url")]
        live_urls = gen_live if gen_live else generated
        await emit("tool_done", {"tool": "httpx-gen-fallback", "count": len(live_urls)})

    if not nmap_service_versions and live_urls:
        nmap_retry_hosts: list[str] = []
        seen_retry_hosts: set[str] = set()
        for url in live_urls:
            host = (urlparse(url).hostname or "").strip()
            if host and host not in seen_retry_hosts:
                seen_retry_hosts.add(host)
                nmap_retry_hosts.append(host)
            if len(nmap_retry_hosts) >= 100:
                break

        if nmap_retry_hosts:
            await emit(
                "tool_start",
                {
                    "tool": "nmap_retry",
                    "detail": f"service versions on {len(nmap_retry_hosts)} confirmed live hosts",
                },
            )
            nmap_retry_out = os.path.join(recon_dir, "nmap_retry.gnmap")
            _, retry_service_versions = await tool_runner.run_nmap(nmap_retry_hosts, nmap_retry_out)
            retry_csv_hits = tool_runner.match_service_versions_to_cves(retry_service_versions)

            nmap_service_versions = retry_service_versions
            nmap_csv_cve_hits = retry_csv_hits

            await emit(
                "tool_done",
                {
                    "tool": "nmap_retry",
                    "count": 0,
                    "versioned_services": len(nmap_service_versions),
                    "csv_cve_hits": len(nmap_csv_cve_hits),
                },
            )
            await emit(
                "tool_done",
                {
                    "tool": "cve_csv_retry",
                    "count": len(nmap_csv_cve_hits),
                    "services_checked": len(nmap_service_versions),
                },
            )

            samples = _version_samples(nmap_service_versions)
            if samples:
                await emit("service_versions", {"count": len(nmap_service_versions), "samples": samples})
        else:
            await emit(
                "tool_skip",
                {
                    "tool": "nmap_retry",
                    "reason": "no valid hostnames extracted from live URLs",
                },
            )
    elif nmap_service_versions:
        await emit(
            "tool_skip",
            {
                "tool": "nmap_retry",
                "reason": f"initial nmap already fingerprinted {len(nmap_service_versions)} services",
            },
        )
    else:
        await emit(
            "tool_skip",
            {
                "tool": "nmap_retry",
                "reason": "no confirmed live URLs for retry",
            },
        )

    if not nmap_service_versions and http_results:
        httpx_service_versions = tool_runner.extract_service_versions_from_httpx(http_results)
        if httpx_service_versions:
            nmap_service_versions = httpx_service_versions
            nmap_csv_cve_hits = tool_runner.match_service_versions_to_cves(nmap_service_versions)

            await emit("tool_done", {"tool": "httpx_version_inventory", "count": len(nmap_service_versions)})
            await emit(
                "tool_done",
                {
                    "tool": "cve_csv_httpx",
                    "count": len(nmap_csv_cve_hits),
                    "services_checked": len(nmap_service_versions),
                },
            )

            samples = _version_samples(nmap_service_versions)
            if samples:
                await emit("service_versions", {"count": len(nmap_service_versions), "samples": samples})
        else:
            await emit(
                "tool_skip",
                {
                    "tool": "cve_csv_httpx",
                    "reason": "httpx headers/tech contained no parseable version tokens",
                },
            )

    gau_urls: set[str] = set()
    gau_domains_run = select_passive_domains(scope.in_scope_domains, max_domains=5)

    for gau_domain in gau_domains_run:
        await emit("tool_start", {"tool": "gau", "detail": gau_domain})
        gau_out = os.path.join(recon_dir, f"gau_{gau_domain.replace('.', '_')}.txt")
        gau_results = await tool_runner.run_gau(gau_domain, gau_out)
        gau_urls.update(gau_results)
        await emit("tool_done", {"tool": "gau", "count": len(gau_results)})

    if do_katana:
        katana_urls = live_urls[:50] if live_urls else []
        await emit("tool_start", {"tool": "katana", "detail": f"{len(katana_urls)} URLs"})
        katana_out = os.path.join(recon_dir, "katana.txt")
        crawled_urls = await tool_runner.run_katana(
            katana_urls,
            katana_out,
            session_cookies=session_cookies,
            auth_header=auth_header,
        )
        await emit("tool_done", {"tool": "katana", "count": len(crawled_urls)})
    else:
        crawled_urls = []
        await emit(
            "tool_skip",
            {
                "tool": "katana",
                "reason": f"program_type={program_type} — JS crawling not applicable",
            },
        )

    all_target_urls = list(set(live_urls) | gau_urls | set(crawled_urls))
    all_target_urls = [u for u in all_target_urls if is_in_scope(u, scope)]
    if len(all_target_urls) > 15_000:
        all_target_urls.sort(key=lambda u: len(u))
        all_target_urls = all_target_urls[:15_000]

    cred_urls: list[dict] = []
    seen_cred_hosts: set[str] = set()
    for raw_url in gau_urls:
        try:
            parsed = urlparse(raw_url)
            host = parsed.hostname or ""
            if not host or host in seen_cred_hosts:
                continue

            if parsed.password:
                seen_cred_hosts.add(host)
                cred_urls.append(
                    {
                        "url": raw_url,
                        "username": parsed.username or "",
                        "password": parsed.password,
                        "host": host,
                        "source": "userinfo",
                    }
                )
            elif _CRED_IN_PATH_RE.search(parsed.path):
                seen_cred_hosts.add(host)
                cred_urls.append(
                    {
                        "url": raw_url,
                        "username": "",
                        "password": "",
                        "host": host,
                        "source": "path_embedded",
                    }
                )
        except Exception:
            continue

    async with aiofiles.open(os.path.join(recon_dir, "all_urls.txt"), "w", encoding="utf-8") as f:
        await f.write("\n".join(sorted(all_target_urls)))

    return {
        "live_urls": live_urls,
        "http_results": http_results,
        "detected_techs": sorted(detected_techs),
        "nmap_service_versions": nmap_service_versions,
        "nmap_csv_cve_hits": nmap_csv_cve_hits,
        "gau_urls": gau_urls,
        "crawled_urls": crawled_urls,
        "all_target_urls": all_target_urls,
        "cred_urls": cred_urls,
    }
