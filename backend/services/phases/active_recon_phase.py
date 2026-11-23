"""Phase 2 helpers for active recon core discovery."""

import re
from collections.abc import Awaitable, Callable
import os

from backend.models import Scope
from backend.services import cve_enricher, tool_runner
from backend.services.scope_parser import is_in_scope


EventEmitter = Callable[[str, dict], Awaitable[None]]



_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def explicit_scope_hosts(scope) -> set[str]:
    """Concrete (non-wildcard) hostnames the program lists as in scope."""
    hosts: set[str] = set()
    for d in getattr(scope, "in_scope_domains", None) or []:
        d = (d or "").strip().lower().rstrip(".")
        if d and "*" not in d and _HOST_RE.match(d):
            hosts.add(d)
    return hosts

async def run_active_recon_core(
    *,
    scope: Scope,
    recon_dir: str,
    seed_subdomains: set[str],
    emit: EventEmitter,
    shodan_api_key: str = "",
) -> dict:
    """
    Run subfinder -> dnsx -> nmap and return structured outputs.
    """
    all_subdomains = set(seed_subdomains)
    # Programs often list exact hosts (api.example.com, console.example.com) rather than
    # wildcards. Discovery tools never "find" those, so probe them directly.
    all_subdomains.update(explicit_scope_hosts(scope))

    await emit("tool_start", {"tool": "subfinder", "detail": f"{len(scope.in_scope_domains)} domains"})
    subfinder_out = os.path.join(recon_dir, "subfinder.txt")
    active_subs = await tool_runner.run_subfinder(scope.in_scope_domains, subfinder_out)
    all_subdomains.update(active_subs)
    await emit("tool_done", {"tool": "subfinder", "count": len(active_subs)})

    scoped_subs = [s for s in all_subdomains if is_in_scope(s, scope)]

    await emit("tool_start", {"tool": "dnsx", "detail": f"{len(scoped_subs)} subdomains"})
    dnsx_out = os.path.join(recon_dir, "dnsx.txt")
    live_hosts = await tool_runner.run_dnsx(scoped_subs, dnsx_out)
    await emit("tool_done", {"tool": "dnsx", "count": len(live_hosts)})

    await emit(
        "tool_start",
        {
            "tool": "nmap",
            "detail": f"service versions on 80/443 + non-standard web ports for {min(len(live_hosts), 100)} hosts",
        },
    )
    nmap_out = os.path.join(recon_dir, "nmap.gnmap")
    nmap_endpoints, nmap_service_versions = await tool_runner.run_nmap(live_hosts, nmap_out)

    shodan_vuln_findings: list[dict] = []
    if shodan_api_key:
        await emit("tool_start", {"tool": "shodan", "detail": f"passive lookup on {min(len(live_hosts), 25)} hosts"})
        shodan_out = os.path.join(recon_dir, "shodan.json")
        shodan_result = await tool_runner.run_shodan_lookup(live_hosts, shodan_api_key, shodan_out)
        nmap_service_versions += shodan_result["service_versions"]
        shodan_vuln_findings, shodan_dropped = await cve_enricher.filter_actionable_cves(shodan_result["vuln_findings"])
        await emit(
            "tool_done",
            {
                "tool": "shodan",
                "count": len(shodan_result["service_versions"]),
                "shodan_vulns": len(shodan_vuln_findings),
                "shodan_vulns_dropped": shodan_dropped,
            },
        )

    nmap_csv_cve_hits = tool_runner.match_service_versions_to_cves(nmap_service_versions)
    nmap_csv_cve_hits, _csv_dropped = await cve_enricher.filter_actionable_cves(nmap_csv_cve_hits, key="cve")

    version_samples = []
    for svc in nmap_service_versions:
        service = str(svc.get("service", "")).strip()
        version = str(svc.get("version", "")).strip()
        fingerprint = str(svc.get("fingerprint", "")).strip()
        display = fingerprint or " ".join(x for x in [service, version] if x).strip()
        if not display:
            continue
        version_samples.append(
            {
                "host": svc.get("host", ""),
                "port": svc.get("port", 0),
                "display": display,
            }
        )
        if len(version_samples) >= 12:
            break

    await emit(
        "tool_done",
        {
            "tool": "nmap",
            "count": len(nmap_endpoints),
            "versioned_services": len(nmap_service_versions),
            "csv_cve_hits": len(nmap_csv_cve_hits),
        },
    )

    if version_samples:
        await emit(
            "service_versions",
            {
                "count": len(nmap_service_versions),
                "samples": version_samples,
            },
        )

    await emit(
        "tool_done",
        {
            "tool": "cve_csv",
            "count": len(nmap_csv_cve_hits),
            "services_checked": len(nmap_service_versions),
        },
    )

    return {
        "all_subdomains": all_subdomains,
        "live_hosts": live_hosts,
        "nmap_endpoints": nmap_endpoints,
        "nmap_service_versions": nmap_service_versions,
        "nmap_csv_cve_hits": nmap_csv_cve_hits,
        "version_samples": version_samples,
        "shodan_vuln_findings": shodan_vuln_findings,
    }
