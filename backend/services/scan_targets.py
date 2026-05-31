"""Target-selection helpers for scan phases."""


def _apex(domain: str) -> str:
    parts = domain.lstrip("*.").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lstrip("*.")


def select_passive_domains(scope_domains: list[str], max_domains: int = 5) -> list[str]:
    """
    Deduplicate by apex and cap passive recon domains.
    """
    seen_apexes: set[str] = set()
    passive_domains: list[str] = []

    for raw_domain in scope_domains or []:
        base = raw_domain.lstrip("*.")
        apex_domain = _apex(base)
        if apex_domain in seen_apexes:
            continue
        seen_apexes.add(apex_domain)
        passive_domains.append(base)
        if len(passive_domains) >= max_domains:
            break

    return passive_domains


def build_httpx_targets(
    live_hosts: list[str],
    nmap_endpoints: list[str],
    explicit_scope_urls: list[str],
) -> list[str]:
    """
    Merge and dedupe host targets for httpx probing.
    """
    out = list(live_hosts or [])
    for item in (nmap_endpoints or []):
        if item not in out:
            out.append(item)
    for item in (explicit_scope_urls or []):
        if item not in out:
            out.append(item)
    return out


def generate_scope_domain_urls(scope_domains: list[str], max_domains: int = 3) -> list[str]:
    """
    Generate fallback URL seeds from in-scope domains.
    """
    generated: list[str] = []
    prefixes = ("", "www.", "api.", "app.", "dashboard.", "portal.")
    for raw_domain in (scope_domains or [])[:max_domains]:
        base = raw_domain.lstrip("*.")
        for prefix in prefixes:
            generated.append(f"https://{prefix}{base}")
    return generated
