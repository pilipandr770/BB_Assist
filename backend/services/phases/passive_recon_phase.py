"""Phase 1 orchestration helpers for passive recon."""

import asyncio

from backend.services import passive_recon
from backend.services.scan_targets import select_passive_domains


async def run_passive_recon_phase(scope_domains: list[str], max_domains: int = 5) -> dict:
    """
    Execute passive recon over deduplicated apex domains and return aggregated output.
    """
    passive_domains = select_passive_domains(scope_domains, max_domains=max_domains)

    all_subdomains: set[str] = set()
    all_urls: set[str] = set()

    passive_results = await asyncio.gather(
        *[passive_recon.run_all_passive(domain) for domain in passive_domains],
        return_exceptions=True,
    )

    for result in passive_results:
        if isinstance(result, Exception):
            continue
        all_subdomains.update(result.get("subdomains", []))
        all_urls.update(result.get("urls", []))

    return {
        "passive_domains": passive_domains,
        "subdomains": all_subdomains,
        "urls": all_urls,
    }
