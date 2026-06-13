"""Phase helpers for 403 bypass, parameter discovery, and focused XSS probing."""

from collections.abc import Awaitable, Callable
import os
import re
from urllib.parse import urlparse

from urllib.parse import ParseResult

from backend.models import Scope
from backend.services import tool_runner
from backend.services.scope_parser import is_in_scope


def _try_parse(url: str) -> ParseResult | None:
    try:
        return urlparse(url)
    except Exception:
        return None


EventEmitter = Callable[[str, dict], Awaitable[None]]

_ARJUN_PATH_RE = re.compile(
    r"/(?:api|v[123456]|graphql|search|user|account|admin|auth|query|login|register|oauth|token|payment)"
    r"(?=/|$)",
    re.IGNORECASE,
)

_STATIC_EXTS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".txt", ".xml", ".yaml", ".yml", ".json", ".lock",
    ".pdf", ".zip", ".gz", ".tar", ".md", ".csv",
    ".html", ".htm", ".min.html", ".min.htm",
}

_STATIC_PATH_SEGS = frozenset(
    {
        "static", "assets", "vendor", "dist", "build", "public",
        "images", "img", "fonts", "media", "css", "views",
    }
)


async def run_appsec_probe_phase(
    *,
    scan_dir: str,
    scope: Scope,
    all_target_urls: list[str],
    ffuf_403_urls: list[str],
    do_arjun: bool,
    arjun_max: int,
    program_type: str,
    session_cookies: str,
    auth_header: str,
    emit: EventEmitter,
) -> dict:
    bypasses: list[dict] = []
    arjun_params: dict[str, list[str]] = {}
    dalfox_findings: list[dict] = []

    if ffuf_403_urls:
        await emit("phase_start", {"phase": "bypass_403"})
        await emit("tool_start", {"tool": "403_bypass", "detail": f"{len(ffuf_403_urls)} forbidden endpoints"})
        bypass_out = os.path.join(scan_dir, "bypasses.jsonl")
        bypasses = await tool_runner.run_403_bypass(ffuf_403_urls, bypass_out)
        await emit("tool_done", {"tool": "403_bypass", "count": len(bypasses)})
        await emit("phase_done", {"phase": "bypass_403", "bypasses": len(bypasses)})

    await emit("phase_start", {"phase": "param_discovery"})

    if do_arjun:
        param_targets: list[str] = []
        for target_url in all_target_urls:
            if "?" in target_url or not is_in_scope(target_url, scope):
                continue
            try:
                parsed = urlparse(target_url)
                path = parsed.path.lower()
            except Exception:
                continue
            if path.endswith("/") and path != "/":
                continue
            if any(path.endswith(ext) for ext in _STATIC_EXTS):
                continue

            raw_parts = [p for p in path.split("/") if p]
            if any(seg in _STATIC_PATH_SEGS for seg in raw_parts[:-1]):
                continue
            if len(raw_parts) != len(set(raw_parts)):
                continue
            if any("=" in part for part in raw_parts):
                continue

            path_prefix = "/" + "/".join(raw_parts[:2])
            if _ARJUN_PATH_RE.search(path_prefix):
                param_targets.append(target_url)
            if len(param_targets) >= arjun_max:
                break

        for pt_url in param_targets:
            await emit("tool_start", {"tool": "arjun", "detail": pt_url})
            arjun_out = os.path.join(scan_dir, f"arjun_{len(arjun_params)}.json")
            params = await tool_runner.run_arjun(pt_url, arjun_out)
            if params:
                arjun_params[pt_url] = params
                param_url = pt_url + "?" + "&".join(f"{p}=FUZZ" for p in params[:5])
                if is_in_scope(param_url, scope):
                    all_target_urls.append(param_url)
            await emit("tool_done", {"tool": "arjun", "count": len(params)})

        await emit(
            "phase_done",
            {
                "phase": "param_discovery",
                "endpoints_tested": len(param_targets),
                "params_found": sum(len(v) for v in arjun_params.values()),
            },
        )
    else:
        await emit(
            "phase_done",
            {
                "phase": "param_discovery",
                "skipped": True,
                "reason": f"program_type={program_type}",
            },
        )

    if arjun_params:
        await emit("phase_start", {"phase": "xss_scan"})
        for xss_base, xss_params in list(arjun_params.items())[:3]:
            xss_url = xss_base + "?" + "&".join(f"{p}=test" for p in xss_params[:5])
            await emit("tool_start", {"tool": "dalfox", "detail": f"{xss_base} ({len(xss_params)} params)"})
            dalfox_out = os.path.join(scan_dir, f"dalfox_{len(dalfox_findings)}.json")
            dalfox_results = await tool_runner.run_dalfox(xss_url, xss_params, dalfox_out)
            dalfox_findings.extend(dalfox_results)
            await emit("tool_done", {"tool": "dalfox", "count": len(dalfox_results)})
        await emit("phase_done", {"phase": "xss_scan", "findings": len(dalfox_findings)})

    # ── GraphQL probe ─────────────────────────────────────────────────────────
    graphql_findings: list[dict] = []
    base_hosts = list({
        f"{parsed.scheme}://{parsed.netloc}"
        for url in all_target_urls[:50]
        if (parsed := _try_parse(url)) and parsed.netloc
    })
    if base_hosts:
        await emit("phase_start", {"phase": "graphql_probe"})
        await emit("tool_start", {"tool": "graphql", "detail": f"{len(base_hosts)} hosts"})
        gql_out = os.path.join(scan_dir, "graphql_findings.jsonl")
        graphql_findings = await tool_runner.run_graphql_probe(base_hosts, scan_dir)
        await emit("tool_done", {"tool": "graphql", "count": len(graphql_findings)})
        await emit("phase_done", {"phase": "graphql_probe", "findings": len(graphql_findings)})

    # ── JWT probe ─────────────────────────────────────────────────────────────
    jwt_findings: list[dict] = []
    if session_cookies or auth_header:
        await emit("phase_start", {"phase": "jwt_probe"})
        await emit("tool_start", {"tool": "jwt_probe", "detail": "testing JWT tokens"})
        jwt_findings = await tool_runner.run_jwt_probe(
            urls=all_target_urls[:5],
            session_cookies=session_cookies,
            auth_header=auth_header,
            scan_dir=scan_dir,
        )
        await emit("tool_done", {"tool": "jwt_probe", "count": len(jwt_findings)})
        await emit("phase_done", {"phase": "jwt_probe", "findings": len(jwt_findings)})

    return {
        "all_target_urls": all_target_urls,
        "bypasses": bypasses,
        "arjun_params": arjun_params,
        "dalfox_findings": dalfox_findings,
        "graphql_findings": graphql_findings,
        "jwt_findings": jwt_findings,
    }
