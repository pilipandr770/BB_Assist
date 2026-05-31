"""Phase 2 helpers for active recon core discovery."""

from collections.abc import Awaitable, Callable
import os

from backend.models import Scope
from backend.services import tool_runner
from backend.services.scope_parser import is_in_scope


EventEmitter = Callable[[str, dict], Awaitable[None]]


async def run_active_recon_core(
    *,
    scope: Scope,
    recon_dir: str,
    seed_subdomains: set[str],
    emit: EventEmitter,
) -> dict:
    """
    Run subfinder -> dnsx -> nmap and return structured outputs.
    """
    all_subdomains = set(seed_subdomains)

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
    nmap_csv_cve_hits = tool_runner.match_service_versions_to_cves(nmap_service_versions)

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
    }
