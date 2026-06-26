"""Phase helpers for content discovery and JS secret scanning."""

from collections.abc import Awaitable, Callable
import os

from backend.models import Scope
from backend.services import tool_runner
from backend.services.scope_parser import is_in_scope


EventEmitter = Callable[[str, dict], Awaitable[None]]

_JS_PUBLIC_CTX = (
    "algolia",
    "search-api-key",
    "searchapikey",
    "next_public_",
    "react_app_",
    "vite_public_",
    "gtm-",
    "googletagmanager",
    "ga-measurement",
)


async def run_content_and_js_phase(
    *,
    scan_dir: str,
    scope: Scope,
    live_urls: list[str],
    all_target_urls: list[str],
    gau_urls: set[str],
    crawled_urls: list[str],
    do_ffuf: bool,
    program_type: str,
    ffuf_target_selector,
    session_cookies: str,
    auth_header: str,
    emit: EventEmitter,
) -> dict:
    """
    Run content discovery (ffuf) and JS secret scanning.
    """
    await emit("phase_start", {"phase": "content_discovery"})

    ffuf_found_urls: list[str] = []
    ffuf_403_urls: list[str] = []

    if do_ffuf:
        ffuf_hosts = ffuf_target_selector(live_urls, max_hosts=5)
        if not ffuf_hosts and scope.in_scope_urls:
            ffuf_hosts = [u for u in scope.in_scope_urls if u.startswith("http")][:3]

        resolved_ffuf_wordlist = tool_runner.resolve_ffuf_wordlist("")
        ffuf_wordlist_missing = not bool(resolved_ffuf_wordlist)
        if ffuf_wordlist_missing:
            await emit(
                "pipeline_warning",
                {
                    "phase": "content_discovery",
                    "warning": "ffuf wordlist not found in container; skipping content discovery",
                },
            )

        for host_url in ffuf_hosts:
            await emit("tool_start", {"tool": "ffuf", "detail": host_url})
            ffuf_out = os.path.join(scan_dir, f"ffuf_{len(ffuf_found_urls)}.json")
            results = await tool_runner.run_ffuf(
                host_url,
                "",
                ffuf_out,
                session_cookies=session_cookies,
                auth_header=auth_header,
            )
            found = [f"{host_url.rstrip('/')}/{r['input']['FUZZ']}" for r in results if r.get("status") != 403]
            forbidden = [f"{host_url.rstrip('/')}/{r['input']['FUZZ']}" for r in results if r.get("status") == 403]
            ffuf_found_urls.extend(found)
            ffuf_403_urls.extend(forbidden)
            await emit(
                "tool_done",
                {
                    "tool": "ffuf",
                    "count": len(results),
                    "found": len(found),
                    "forbidden": len(forbidden),
                    **({"warning": "wordlist_missing"} if ffuf_wordlist_missing else {}),
                },
            )

        new_urls = [u for u in ffuf_found_urls if is_in_scope(u, scope)]
        all_target_urls = list(set(all_target_urls) | set(new_urls))

        await emit(
            "phase_done",
            {
                "phase": "content_discovery",
                "new_paths": len(new_urls),
                "forbidden": len(ffuf_403_urls),
                **({"skipped_reason": "wordlist_missing"} if ffuf_wordlist_missing else {}),
            },
        )
    else:
        await emit(
            "phase_done",
            {
                "phase": "content_discovery",
                "skipped": True,
                "reason": f"program_type={program_type}",
            },
        )

    await emit("phase_start", {"phase": "js_scan"})

    js_urls = [
        u
        for u in all_target_urls
        if u.endswith(".js") and not u.endswith(".min.js") and is_in_scope(u, scope)
    ]
    for u in list(gau_urls) + crawled_urls:
        if u.endswith(".js") and not u.endswith(".min.js") and is_in_scope(u, scope):
            if u not in js_urls:
                js_urls.append(u)

    await emit("tool_start", {"tool": "js_scanner", "detail": f"{len(js_urls)} JS files"})
    js_out = os.path.join(scan_dir, "js_secrets.jsonl")
    js_secrets = await tool_runner.run_js_scanner(js_urls, js_out)
    await emit("tool_done", {"tool": "js_scanner", "count": len(js_secrets)})

    js_pre_filtered = 0
    js_kept = []
    for secret in js_secrets:
        ctx_lower = (secret.get("context", "") + " " + secret.get("match", "")).lower()
        if any(pattern in ctx_lower for pattern in _JS_PUBLIC_CTX):
            js_pre_filtered += 1
        else:
            js_kept.append(secret)
    js_secrets = js_kept

    # trufflehog: verified secret detection on JS URLs (complements regex scanner)
    trufflehog_secrets: list[dict] = []
    if js_urls:
        await emit("tool_start", {"tool": "trufflehog", "detail": f"{len(js_urls)} JS URLs"})
        trufflehog_out = os.path.join(scan_dir, "trufflehog_web.jsonl")
        try:
            trufflehog_raw = await tool_runner.run_trufflehog(js_urls[:50], trufflehog_out)
            # Convert trufflehog format to js_secrets format for unified processing
            for th in trufflehog_raw:
                if not th.get("verified"):
                    continue  # skip unverified in web pipeline to reduce noise
                trufflehog_secrets.append({
                    "url": th.get("url", ""),
                    "secret_type": th.get("detector_type", "unknown"),
                    "match": th.get("raw", "")[:120],
                    "context": th.get("extra_data", {}).get("context", ""),
                    "severity": "high" if th.get("verified") else "medium",
                    "_source": "trufflehog",
                    "_verified": th.get("verified", False),
                })
        except Exception:
            pass
        await emit("tool_done", {"tool": "trufflehog", "count": len(trufflehog_secrets)})
        # Merge verified trufflehog finds into js_secrets (dedup by match prefix)
        existing_matches = {s.get("match", "")[:60] for s in js_secrets}
        for th_secret in trufflehog_secrets:
            if th_secret.get("match", "")[:60] not in existing_matches:
                js_secrets.append(th_secret)

    await emit(
        "phase_done",
        {
            "phase": "js_scan",
            "js_files": len(js_urls),
            "secrets_found": len(js_secrets),
            "trufflehog_verified": len(trufflehog_secrets),
            **({"pre_filtered_public_keys": js_pre_filtered} if js_pre_filtered else {}),
        },
    )

    return {
        "all_target_urls": all_target_urls,
        "ffuf_found_urls": ffuf_found_urls,
        "ffuf_403_urls": ffuf_403_urls,
        "js_secrets": js_secrets,
    }
