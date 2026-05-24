"""
Tool runner — executes Go security tools via asyncio subprocess.

Critical rules:
  - ALWAYS pass scope constraints to every tool (never scan out-of-scope)
  - Stream output line by line to Redis so frontend shows live progress
  - Each tool returns structured output (parsed from JSON where possible)
  - Tools run in phases: passive → active recon → scan → validate

Scan pipeline:
  Phase 1:   Passive recon (subfinder passive, GAU) + GitHub dorking
  Phase 2:   Active recon (subfinder active, dnsx, httpx, gau, katana)
  Phase 2.5: Content discovery (ffuf on live hosts)
  Phase 2.6: JS secret scanning (regex on .js files from gau/katana)
  Phase 2.7: 403 bypass testing (header/path tricks)
  Phase 2.8: Parameter discovery (arjun on interesting endpoints)
  Phase 2.9: CORS misconfiguration checker (on live API URLs)
  Phase 2.10: Subdomain takeover checker (CNAME → fingerprint)
  Phase 3:   Nuclei scan (with interactsh for blind SSRF/XSS)
  Phase 4:   Filter & validate findings (AI + PoC)
  Phase 5:   Generate HackerOne reports with PoC commands
"""

import asyncio
import csv
import json
import os
import re
import tempfile
import urllib.request
import urllib.error
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import httpx as _httpx

import redis.asyncio as aioredis

from backend.config import settings
from backend.models import Scope

WORKSPACE = settings.workspace_dir

NUCLEI_TAGS_RUN = (
    "rce,sqli,xss,ssrf,lfi,idor,auth-bypass,exposed-panel,"
    "default-creds,exposed-api,token-disclosure,jwt,graphql,"
    "xxe,ssti,open-redirect,cve"
)

NUCLEI_SEVERITY = "low,medium,high,critical"

# Maps normalized tech names (from httpx output) to nuclei CVE tags.
# Used for a targeted second nuclei pass on http/cves when tech is detected.
_TECH_NUCLEI_TAGS: dict[str, str] = {
    "wordpress": "wordpress", "wp": "wordpress",
    "drupal": "drupal", "joomla": "joomla",
    "laravel": "laravel", "codeigniter": "codeigniter",
    "spring": "spring", "springboot": "springboot",
    "jenkins": "jenkins", "jira": "jira",
    "confluence": "confluence", "gitlab": "gitlab",
    "grafana": "grafana", "kibana": "kibana",
    "elasticsearch": "elasticsearch", "solr": "solr",
    "apache": "apache", "nginx": "nginx", "iis": "iis",
    "php": "php", "rails": "rails", "django": "django",
    "struts": "struts", "tomcat": "tomcat",
    "weblogic": "weblogic", "websphere": "websphere",
    "sharepoint": "sharepoint", "exchange": "exchange",
    "citrix": "citrix", "vmware": "vmware",
    "magento": "magento", "opencart": "opencart",
    "prestashop": "prestashop", "woocommerce": "woocommerce",
    "phpmyadmin": "phpmyadmin", "adminer": "adminer",
    "nextjs": "nextjs", "react": "react",
    "litespeed": "litespeed", "caddy": "caddy",
    "cloudflare": "cloudflare",
}


# Cookie name prefixes that reveal specific frameworks
_COOKIE_TECH_MAP = {
    "phpsessid":        "php",
    "jsessionid":       "java",
    "aspsessionid":     "asp",
    "asp.net_sessionid": "aspnet",
    "laravel_session":  "laravel",
    "ci_session":       "codeigniter",
    "symfony":          "symfony",
    "yii_csrf_token":   "yii",
    "rails_session":    "rails",
    "_rails":           "rails",
    "django_session":   "django",
    "csrftoken":        "django",
    "wp-settings":      "wordpress",
    "wordpress_":       "wordpress",
    "joomla":           "joomla",
    "drupal":           "drupal",
    "magento":          "magento",
    "prestashop":       "prestashop",
    "opencart":         "opencart",
}

# Response header values → technology
_HEADER_TECH_MAP = {
    "x-powered-by": {
        "php":          "php",
        "asp.net":      "aspnet",
        "express":      "nodejs",
        "next.js":      "nextjs",
        "ruby on rails": "rails",
        "django":       "django",
        "laravel":      "laravel",
        "wordpress":    "wordpress",
        "drupal":       "drupal",
    },
    "server": {
        "apache":       "apache",
        "nginx":        "nginx",
        "iis":          "iis",
        "caddy":        "caddy",
        "litespeed":    "litespeed",
        "gunicorn":     "gunicorn",
        "tomcat":       "tomcat",
        "cloudflare":   "cloudflare",
        "openresty":    "nginx",
        "pepyaka":      "wordpress",  # Wix
    },
}


_TECH_NOISE: frozenset[str] = frozenset({
    # HTTP protocol / feature labels — not technologies
    "http", "https", "http/1.1", "http/2", "http/3", "h2", "h3",
    # Security policy names
    "hsts", "basic", "digest", "bearer", "ntlm",
    # Generic CDN/infra that aren't useful for CVE targeting
    "cdn", "waf",
    # Single-letter leftovers from bad parsing
    "", "-", "_",
})


def extract_tech_stack(http_results: list[dict]) -> set[str]:
    """
    Parse httpx JSONL results to extract a normalized set of detected technologies.

    Detection layers (in priority order):
    1. httpx 'tech'/'technologies' field (populated in newer httpx builds)
    2. 'webserver' field from httpx
    3. Response headers: Server, X-Powered-By (always present)
    4. Cookie names (framework session cookies are highly reliable fingerprints)
    """
    techs: set[str] = set()
    for r in http_results:
        # Layer 1: httpx native tech detection
        for field in ("tech", "technologies", "technology"):
            for t in (r.get(field) or []):
                name = str(t).split(":")[0].split("/")[0].lower().strip()
                if name and len(name) > 1 and name not in _TECH_NOISE:
                    techs.add(name)

        # Layer 2: webserver banner
        ws = (r.get("webserver") or "").lower()
        for keyword, tech in _HEADER_TECH_MAP["server"].items():
            if keyword in ws:
                techs.add(tech)

        # Layer 3: response headers dict (httpx stores as {"header-name": "value"})
        headers: dict = r.get("headers") or {}
        for header_name, keyword_map in _HEADER_TECH_MAP.items():
            header_val = headers.get(header_name, headers.get(header_name.lower(), "")).lower()
            if header_val:
                for keyword, tech in keyword_map.items():
                    if keyword in header_val:
                        techs.add(tech)
                        break

        # Layer 4: Set-Cookie header — framework session cookie names are reliable
        set_cookie = headers.get("set-cookie", headers.get("Set-Cookie", "")).lower()
        for cookie_prefix, tech in _COOKIE_TECH_MAP.items():
            if cookie_prefix in set_cookie:
                techs.add(tech)

    # Final pass: strip protocol/policy noise regardless of which layer added it
    return techs - _TECH_NOISE


_HTTPX_VERSION_TOKEN_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9._-]{1,32})[/ ]v?(\d+(?:\.\d+){1,3}[A-Za-z0-9._-]*)",
    re.IGNORECASE,
)

_HTTPX_VERSION_STOPWORDS: frozenset[str] = frozenset({
    "http", "https", "tls", "ssl", "ubuntu", "debian", "linux", "windows",
    "alpine", "apache", "mozilla", "gecko", "chrome", "safari",
})


def extract_service_versions_from_httpx(http_results: list[dict]) -> list[dict]:
    """
    Best-effort service/version inventory from httpx metadata.

    This is a fallback path for CDN-heavy targets where nmap -sV often returns
    empty service banners. We parse version tokens from:
      - webserver / Server header
      - X-Powered-By header
      - httpx technology entries that include versions (e.g. nginx:1.24.0)
    """
    services: list[dict] = []
    seen: set[tuple[str, int, str, str]] = set()

    for r in http_results:
        raw_url = str(r.get("url", "")).strip()
        if not raw_url:
            continue

        parsed = urlparse(raw_url)
        host = (parsed.hostname or "").strip()
        if not host:
            continue

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        headers: dict = r.get("headers") or {}
        webserver = str(r.get("webserver", "") or headers.get("server", "") or headers.get("Server", ""))
        x_powered_by = str(headers.get("x-powered-by", "") or headers.get("X-Powered-By", ""))

        candidates: list[str] = []
        for candidate in (webserver, x_powered_by):
            if candidate:
                candidates.append(candidate)

        for field in ("tech", "technologies", "technology"):
            for tech in (r.get(field) or []):
                t = str(tech).strip()
                if t:
                    candidates.append(t)

        for candidate in candidates:
            for match in _HTTPX_VERSION_TOKEN_RE.finditer(candidate):
                service = match.group(1).lower().strip("._-")
                version = match.group(2).strip()
                if not service or not version:
                    continue
                if service in _HTTPX_VERSION_STOPWORDS:
                    continue

                key = (host, int(port), service, version)
                if key in seen:
                    continue
                seen.add(key)

                services.append({
                    "host": host,
                    "port": int(port),
                    "service": service,
                    "version": version,
                    "fingerprint": candidate.strip(),
                })

    return services


def _h1_header_args(h1_username: Optional[str] = None) -> list[str]:
    """
    Return command-line header arguments for the X-HackerOne-Researcher header.

    Many H1 programs (e.g. Coupang, Shopify) require all testing traffic to carry
    this header so their security team can identify researcher activity in logs.
    Without it, findings may be disqualified or traffic flagged as malicious.

    Returns e.g. ["-H", "X-HackerOne-Researcher: myusername"] if username is set,
    or [] if not configured.
    """
    username = h1_username or settings.h1_username
    if not username:
        return []
    return ["-H", f"X-HackerOne-Researcher: {username}"]


async def _get_redis() -> Optional[aioredis.Redis]:
    """Return async Redis client, or None if Redis is unavailable."""
    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        return r
    except Exception:
        return None


async def _run_command(
    cmd: list[str],
    cwd: str = None,
    stream_key: str = None,
    timeout_s: Optional[int] = None,
) -> tuple[int, str, str]:
    """
    Run command via asyncio subprocess.
    Reads stdout and stderr concurrently to prevent pipe-buffer deadlock.
    Streams stdout lines to Redis if stream_key is provided.
    If timeout_s is given and exceeded, the process is killed and partial output is returned.
    Returns (returncode, stdout, stderr).
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )

    redis_client = await _get_redis() if stream_key else None
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    async def _drain_stdout():
        async for raw in proc.stdout:
            decoded = raw.decode(errors="replace").rstrip()
            stdout_lines.append(decoded)
            if redis_client and stream_key:
                await redis_client.rpush(stream_key, decoded)

    async def _drain_stderr():
        async for raw in proc.stderr:
            stderr_lines.append(raw.decode(errors="replace").rstrip())

    # Read both streams concurrently — prevents deadlock when stderr fills pipe buffer
    try:
        await asyncio.wait_for(
            asyncio.gather(_drain_stdout(), _drain_stderr()),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        # Kill the subprocess and use whatever partial output was collected
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    await proc.wait()

    if redis_client:
        await redis_client.aclose()

    return proc.returncode or 0, "\n".join(stdout_lines), "\n".join(stderr_lines)


def _write_temp_list(items: list[str], suffix: str = ".txt") -> str:
    """Write a list of items to a temp file, one per line. Returns file path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(items) + "\n")
    return path


async def run_subfinder(domains: list[str], output_file: str) -> list[str]:
    """
    Discover subdomains with subfinder.
    Command: subfinder -dL {domains_file} -silent -o {output_file}
    Timeout: 180s — if subfinder can't finish in 3 min without API keys, something
    is hanging (rate-limited source, DNS timeout, slow passive feed). Use partial
    results rather than blocking the entire pipeline for 10 minutes.
    Uses -all flag when available for best coverage; falls back to defaults.
    """
    domains_file = _write_temp_list(domains)
    try:
        cmd = [
            "subfinder",
            "-dL", domains_file,
            "-silent",
            "-o", output_file,
            "-t", "50",         # threads
            "-timeout", "15",   # per-source request timeout (was 30 — cut in half)
        ]
        rc, stdout, _ = await _run_command(cmd, timeout_s=180)  # was 600 — 10x faster failure

        # Read output file if it exists
        if os.path.exists(output_file):
            with open(output_file) as f:
                return [line.strip() for line in f if line.strip()]

        # Fallback: parse stdout
        return [line.strip() for line in stdout.splitlines() if line.strip()]
    finally:
        os.unlink(domains_file)


async def run_dnsx(subdomains: list[str], output_file: str) -> list[str]:
    """
    Validate which subdomains have DNS records.
    Command: dnsx -silent -l {input_file} -o {output_file}
    Timeout: 120s — 600 subdomains at 100 threads resolves in seconds normally.
    """
    input_file = _write_temp_list(subdomains)
    try:
        cmd = [
            "dnsx",
            "-silent",
            "-l", input_file,
            "-o", output_file,
            "-t", "100",
        ]
        await _run_command(cmd, timeout_s=120)  # no stream_key — output read from file

        if os.path.exists(output_file):
            with open(output_file) as f:
                return [line.strip() for line in f if line.strip()]
        return []
    finally:
        os.unlink(input_file)


async def run_nmap(hosts: list[str], output_file: str) -> list[str]:
    """
    Scan dnsx-validated hosts for non-standard web service ports.
    Finds web apps running on 8080, 8443, 3000, 5000, etc. — often less hardened
    than the standard 80/443 services and frequently forgotten in scope reviews.

    CDN awareness: many targets share a CDN IP (e.g. Cloudflare 172.64.x.x).
    nmap deduplicates by IP, so if 50 hosts resolve to the same IP, only one
    hostname appears in the greppable output. We fix this by:
      1. Pre-resolving all input hostnames → build ip→[hostnames] map
      2. For each open port found, emit hostname:port for ALL hostnames on that IP
         (capped at 20 hostnames per IP to avoid probe explosion)

        Returns tuple:
            - list of "hostname:port" strings ready for httpx to probe
            - list of detected service/version banners per endpoint
    Always uses hostnames (never raw IPs) so CDN/SNI routing works correctly.
    Caps at 100 hosts input; 30 s per-host timeout keeps the scan under 5 min.
    """
    import logging
    import socket
    log = logging.getLogger("tool_runner")

    if not hosts:
        return [], []

    # Ports used for version inventory. Includes 80/443 so CVE lookup still works
    # when a target only exposes standard web ports.
    WEB_PORTS = "80,443,8080,8443,8000,8888,8008,3000,3001,4000,4443,5000,5443,9000,9090,9443,7080,7443"
    NON_STANDARD_PORTS: set[str] = {
        "8080", "8443", "8000", "8888", "8008", "3000", "3001", "4000",
        "4443", "5000", "5443", "9000", "9090", "9443", "7080", "7443",
    }

    targets = hosts[:100]
    targets_file = _write_temp_list(targets)

    # Pre-resolve input hostnames → ip→[hostnames] map so we can expand CDN IPs
    # back to all hostnames that share that IP (critical for Cloudflare/Fastly targets).
    ip_to_hosts: dict[str, list[str]] = {}
    for h in targets:
        try:
            ip = socket.gethostbyname(h)
            ip_to_hosts.setdefault(ip, []).append(h)
        except Exception:
            pass

    try:
        cmd = [
            "nmap",
            "-iL", targets_file,
            "-p", WEB_PORTS,
            "--open",               # show only open ports
            "-sC",                  # run default NSE scripts
            "-sV",                  # detect service versions
            "--version-light",      # faster version probing
            "-T4",                  # aggressive timing (fast)
            "--max-retries", "1",
            "--host-timeout", "45s",
            "-oG", output_file,     # greppable output — easy to parse
        ]
        await _run_command(cmd, timeout_s=600)

        # Parse greppable nmap output.
        # Line format: Host: IP (hostname)\tPorts: PORT/open/tcp//service///[,...]
        # Keep two maps:
        #   1) ip_to_nonstd_ports for endpoint expansion (httpx probes)
        #   2) ip_to_versioned_ports for CVE version matching inventory (includes 80/443)
        ip_to_nonstd_ports: dict[str, set] = {}
        ip_to_versioned_ports: dict[str, set] = {}
        ip_port_meta: dict[tuple[str, str], dict] = {}
        if os.path.exists(output_file):
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith("Host:") or "Ports:" not in line:
                        continue
                    parts = line.split("\t")
                    host_tokens = parts[0].split()
                    ip = host_tokens[1] if len(host_tokens) > 1 else ""
                    if not ip:
                        continue

                    # Extract open port numbers from "Ports:" section
                    ports_section = ""
                    for part in parts:
                        stripped = part.strip()
                        if stripped.startswith("Ports:"):
                            ports_section = stripped[len("Ports:"):].strip()
                            break

                    for entry in ports_section.split(","):
                        entry = entry.strip()
                        if "/open/" in entry:
                            fields = entry.split("/")
                            port = fields[0].strip() if fields else ""
                            if port.isdigit():
                                ip_to_versioned_ports.setdefault(ip, set()).add(port)
                                # Expand endpoints only for non-standard ports to avoid
                                # unnecessary duplication with live host list from dnsx/httpx.
                                if port in NON_STANDARD_PORTS:
                                    ip_to_nonstd_ports.setdefault(ip, set()).add(port)
                                service = fields[4].strip() if len(fields) > 4 else ""
                                banner_raw = fields[6].strip() if len(fields) > 6 else ""
                                # nmap often puts additional version details in extra fields.
                                if len(fields) > 7:
                                    extra = " ".join(x.strip() for x in fields[7:] if x.strip())
                                    if extra:
                                        banner_raw = f"{banner_raw} {extra}".strip()

                                fingerprint = " ".join(x for x in [service, banner_raw] if x).strip()
                                ip_port_meta[(ip, port)] = {
                                    "service": service,
                                    "version": banner_raw,
                                    "fingerprint": fingerprint,
                                }

        # Build final endpoint list: for each open port on each IP, emit hostname:port
        # for ALL hostnames that resolved to that IP. This ensures CDN-fronted hosts
        # are probed with the correct Host header (httpx uses the hostname, not the IP).
        seen: set[str] = set()
        endpoints: list[str] = []
        service_versions: list[dict] = []
        for ip, versioned_ports in ip_to_versioned_ports.items():
            # Find hostnames that resolve to this IP (from our pre-resolution map)
            matched_hosts = ip_to_hosts.get(ip, [])
            # If no match (nmap resolved to a different IP than we did), use nmap's hostname
            if not matched_hosts:
                # Try to find the hostname nmap put in parens — stored in parsing loop above
                # Fall back to the IP itself (less ideal but functional for non-CDN hosts)
                matched_hosts = [ip]
            # Cap per-IP to 20 hostnames to avoid probe explosion (e.g. 86 hosts on one Cloudflare IP)
            for hostname in matched_hosts[:20]:
                for port in sorted(versioned_ports):
                    if port in NON_STANDARD_PORTS:
                        ep = f"{hostname}:{port}"
                        if ep not in seen:
                            seen.add(ep)
                            endpoints.append(ep)
                        meta = ip_port_meta.get((ip, port), {})
                        service_versions.append({
                            "host": hostname,
                            "port": int(port),
                            "service": meta.get("service", ""),
                            "version": meta.get("version", ""),
                            "fingerprint": meta.get("fingerprint", ""),
                        })

        log.info(
            "nmap: %d open web ports on %d unique IPs → %d hostname:port probes, %d version banners",
            sum(len(v) for v in ip_to_versioned_ports.values()),
            len(ip_to_versioned_ports),
            len(endpoints),
            len(service_versions),
        )
        return endpoints, service_versions
    finally:
        if os.path.exists(targets_file):
            os.unlink(targets_file)


def match_service_versions_to_cves(
    service_versions: list[dict],
    csv_path: Optional[str] = None,
) -> list[dict]:
    """
    Metasploit-style version-based CVE matching.
    
    Matches nmap -sV banners against a local CSV database of product:version→CVE mappings.
    Works exactly like Metasploit: find service+version, look up in database, return matching CVEs.
    No exploitation, no probing — just version fingerprint lookup.
    
    CSV columns: product,version_regex,cve,severity,title,reference
    """
    import logging
    log = logging.getLogger("tool_runner")
    
    if not service_versions:
        return []

    if not csv_path:
        csv_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data",
            "cve_service_versions.csv",
        )

    if not os.path.exists(csv_path):
        log.warning(f"CVE version database not found: {csv_path}")
        return []

    # Load and compile CVE rules from CSV
    rules: list[dict] = []
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pattern = (row.get("version_regex") or "").strip()
                product = (row.get("product") or "").strip().lower()
                if not pattern or not product:
                    continue
                try:
                    row["_compiled"] = re.compile(pattern, re.IGNORECASE)
                    row["_product_lower"] = product
                    rules.append(row)
                except re.error as e:
                    log.warning(f"Invalid regex in CVE rule {row.get('product')}: {e}")
                    continue
        log.info(f"cve_matcher: loaded {len(rules)} CVE version rules from {csv_path}")
    except Exception as e:
        log.error(f"Failed to load CVE database: {e}")
        return []

    matches: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    
    for svc in service_versions:
        host = str(svc.get("host", "")).strip()
        port = int(svc.get("port", 0) or 0)
        service = str(svc.get("service", "")).strip().lower()
        version = str(svc.get("version", "")).strip()
        fingerprint = str(svc.get("fingerprint", "")).strip()
        
        # Build comprehensive search string: service, version, and full fingerprint
        haystack = " ".join(x for x in [service, version, fingerprint] if x).lower()
        if not haystack or not service:
            continue

        # Try matching against each CVE rule
        for rule in rules:
            product = rule.get("_product_lower", "")
            compiled = rule.get("_compiled")
            
            # First: product name must appear in service/fingerprint
            if product not in service and product not in fingerprint:
                continue
            
            # Second: version pattern must match the full haystack
            if not compiled or not compiled.search(haystack):
                continue

            cve = (rule.get("cve") or "CVE-UNKNOWN").strip()
            key = (host, port, cve)
            if key in seen:
                continue
            seen.add(key)

            sev = (rule.get("severity") or "medium").strip().lower()
            if sev not in {"critical", "high", "medium", "low", "info", "informative"}:
                sev = "medium"
            if sev == "info":
                sev = "informative"

            matches.append({
                "host": host,
                "port": port,
                "service": service,
                "version": version,
                "fingerprint": fingerprint,
                "product": product,
                "cve": cve,
                "severity": sev,
                "title": (rule.get("title") or "Version-based CVE").strip(),
                "reference": (rule.get("reference") or "").strip(),
                "pattern": (rule.get("version_regex") or "").strip(),
            })

    if matches:
        log.info(f"cve_matcher: found {len(matches)} version-based CVE candidates across {len(service_versions)} services")
    
    return matches


async def run_httpx(hosts: list[str], output_file: str) -> list[dict]:
    """
    Probe live HTTP hosts and gather info.

    Design notes:
    - dnsx outputs bare hostnames (no scheme). We prepend https:// so httpx
      probes HTTPS by default instead of trying both HTTP+HTTPS.
    - We try TWO flag sets: modern short flags first, then legacy long flags.
      This handles all httpx versions installed via @latest.
    - Always log stderr + result count to help diagnose zero-result issues.
    """
    import logging
    log = logging.getLogger("tool_runner")

    # Normalise entries: strip any extra tokens from dnsx output
    # (dnsx may add ' [A 1.2.3.4]' suffix on some versions).
    # IMPORTANT: do NOT prepend a scheme to bare hostnames.
    # When httpx receives a bare hostname (no http:// / https://) it probes
    # BOTH http and https automatically, which doubles discovery coverage.
    # Only keep an explicit scheme if the caller already provided one
    # (e.g. entries from scope.in_scope_urls like https://app.example.com).
    normed: list[str] = []
    for h in hosts:
        h = h.strip().split()[0]   # take first token only
        if not h:
            continue
        normed.append(h)  # no scheme → httpx probes both HTTP + HTTPS

    if not normed:
        return []

    input_file = _write_temp_list(normed)
    try:
        # IMPORTANT: use the full path to ProjectDiscovery httpx.
        # pip installs a Python httpx CLI at /usr/local/bin/httpx which shadows
        # the Go binary at /root/go/bin/httpx because /usr/local/bin is first in PATH.
        # Using the full path guarantees we always call the right tool.
        _HTTPX_BIN = "/root/go/bin/httpx"

        # Two flag sets to try in order — handles @latest version differences.
        # Set A: modern short aliases (httpx ≥ 1.3)
        # Set B: legacy long flags (httpx ≤ 1.2) — fallback if A gives 0 results
        _hdr = _h1_header_args()
        cmd_sets = [
            [  # Set A — modern short flags (v1.3+)
                _HTTPX_BIN, "-l", input_file, "-json", "-o", output_file,
                "-sc", "-cl", "-fr",
                "-threads", "20", "-timeout", "10", "-rl", "30", "-retries", "1",
            ] + _hdr,
            [  # Set B — legacy long flags (v1.2 and below)
                _HTTPX_BIN, "-l", input_file, "-json", "-o", output_file,
                "-status-code", "-content-length", "-follow-redirects", "-no-color",
                "-threads", "20", "-timeout", "10", "-rate-limit", "30", "-retries", "1",
            ] + _hdr,
        ]

        results = []
        seen_urls: set[str] = set()

        def _parse_jsonl(text: str):
            for line in text.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    url = obj.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        results.append(obj)
                except json.JSONDecodeError:
                    continue

        for i, cmd in enumerate(cmd_sets):
            # Clear output file before each attempt
            if os.path.exists(output_file):
                os.remove(output_file)

            rc, stdout, stderr = await _run_command(
                cmd,
                stream_key=f"tool:httpx:{output_file}",
                timeout_s=300,
            )

            # Always log so Docker logs show what happened
            log.info(
                "httpx attempt %d/%d: rc=%d hosts=%d stderr_head=%s",
                i + 1, len(cmd_sets), rc, len(normed), stderr[:200] if stderr else "",
            )

            results.clear()
            seen_urls.clear()

            if os.path.exists(output_file):
                with open(output_file) as f:
                    _parse_jsonl(f.read())
            if not results and stdout:
                _parse_jsonl(stdout)

            log.info("httpx attempt %d: parsed %d results", i + 1, len(results))

            if results:
                break   # first flag set that works wins; skip the other

        log.info("httpx: %d live hosts from %d probed", len(results), len(normed))
        return results
    finally:
        if os.path.exists(input_file):
            os.unlink(input_file)


async def run_gau(domain: str, output_file: str) -> list[str]:
    """
    Fetch known URLs from various sources (Wayback, Common Crawl, etc).
    Command: gau {domain} --blacklist png,jpg,gif,css,woff --o {output_file}
    Timeout: 120s per domain — some domains return 50k+ URLs and we cap them anyway.
    """
    cmd = [
        "gau",
        domain,
        "--blacklist", "png,jpg,gif,jpeg,svg,ico,css,woff,woff2,ttf,mp4,mp3",
        "--o", output_file,
        "--threads", "5",
        "--timeout", "30",
    ]
    # No stream_key: gau returns 10k-50k URLs per domain; pushing every line to
    # Redis causes multi-hundred-MB RDB snapshots with zero benefit (output is
    # read from the file, not the Redis stream).
    await _run_command(cmd, timeout_s=120)

    if os.path.exists(output_file):
        with open(output_file) as f:
            urls = [line.strip() for line in f if line.strip()]
        # Cap per-domain to avoid www.example.com → 50k URLs overwhelming the pool.
        # The global all_target_urls cap (15k) is a backstop, but capping early
        # reduces memory and Redis write pressure during the scan.
        return urls[:10_000]
    return []


async def run_katana(urls: list[str], output_file: str) -> list[str]:
    """
    Web crawl target URLs for endpoint discovery.
    Hard caps: 10 min wall time (-crawl-duration), 50k results (post-filter).
    Depth 2 keeps JS-heavy SPAs from exploding to millions of routes.
    """
    input_file = _write_temp_list(urls)
    try:
        cmd = [
            "katana",
            "-list", input_file,
            "-silent",
            "-jc",                   # JS crawling
            "-o", output_file,
            "-depth", "2",           # was 3 — depth 3 on SPAs = millions of URLs
            "-concurrency", "10",
            "-rate-limit", "50",
            "-timeout", "10",
            "-crawl-duration", "8m", # hard stop at 8 min regardless of depth
        ] + _h1_header_args()
        await _run_command(cmd, timeout_s=510)  # no stream_key — output read from file

        if os.path.exists(output_file):
            urls_out = [line.strip() for line in open(output_file) if line.strip()]
            # Cap at 50k — beyond that the signal/noise ratio collapses
            return urls_out[:50_000]
        return []
    finally:
        os.unlink(input_file)


async def run_nuclei(
    urls: list[str],
    output_file: str,
    scope: Scope,
    tags: str = NUCLEI_TAGS_RUN,
    detected_techs: set[str] | None = None,
) -> list[dict]:
    """
    Run nuclei vulnerability scanner with curated templates.
    Filters URLs against scope before scanning.
    Hard limit: 900 seconds (15 min) — partial results are used if timeout is hit.

    Template strategy: use specific high-value subdirectories from the templates
    root rather than broad tag matching, which can pull in thousands of CVE
    templates and run for hours.
    """
    import logging
    log = logging.getLogger("tool_runner")

    from backend.services.scope_parser import is_in_scope

    # Never scan out-of-scope URLs
    scoped_urls = [u for u in urls if is_in_scope(u, scope)]
    if not scoped_urls:
        return []

    input_file = _write_temp_list(scoped_urls)
    try:
        # nuclei v3 stores templates at ~/.local/nuclei-templates/ (root → /root/.local/...)
        template_roots = [
            "/root/.local/nuclei-templates",   # nuclei v3 default
            "/root/nuclei-templates",           # nuclei v2 / explicit clone
            "/home/nuclei-templates",
            "/nuclei-templates",
        ]
        templates_dir = next((p for p in template_roots if os.path.isdir(p)), None)

        if templates_dir:
            yaml_count = sum(1 for _ in Path(templates_dir).rglob("*.yaml"))
            log.info("nuclei templates: %s (%d yaml files)", templates_dir, yaml_count)
        else:
            log.warning("nuclei: no templates directory found, letting nuclei auto-discover")

        # Use specific high-signal subdirs instead of broad tag match.
        # Broad tags (especially "cve") pull in 5000+ templates → hours of scanning.
        # These subdirs cover the most impactful finding classes for bug bounty.
        HIGH_VALUE_SUBDIRS = [
            "http/exposures",
            "http/misconfiguration",
            "http/vulnerabilities",
            "http/takeovers",
            "http/default-logins",
            "http/exposed-panels",
        ]
        template_args: list[str] = []
        if templates_dir:
            for subdir in HIGH_VALUE_SUBDIRS:
                full = os.path.join(templates_dir, subdir)
                if os.path.isdir(full):
                    template_args += ["-t", full]
            if not template_args:
                # Fallback: use the root with tag filtering (old behaviour)
                template_args = ["-t", templates_dir, "-tags", tags]
        else:
            # No local templates: let nuclei auto-discover + tag-filter
            template_args = ["-tags", tags]

        template_count = sum(
            sum(1 for _ in Path(os.path.join(templates_dir, s)).rglob("*.yaml"))
            for s in HIGH_VALUE_SUBDIRS
            if templates_dir and os.path.isdir(os.path.join(templates_dir, s))
        ) if templates_dir else 0
        log.info("nuclei: using %d templates across %d subdirs",
                 template_count, len([a for a in template_args if a != "-t"]))

        # Cloudflare targets block nuclei's default "Go-http-client" UA and throttle
        # high-rate scans. Use browser UA always; lower rate when CF is detected.
        behind_cloudflare = detected_techs and "cloudflare" in detected_techs
        nuclei_rate = "20" if behind_cloudflare else "100"
        nuclei_bulk = "20" if behind_cloudflare else "50"
        nuclei_conc = "10" if behind_cloudflare else "25"
        nuclei_ua   = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )

        cmd = [
            "nuclei",
            "-l", input_file,
            "-severity", NUCLEI_SEVERITY,
            "-jsonl-export", output_file,   # nuclei v3: JSONL file export
            "-j",                            # nuclei v3: JSONL to stdout too
            "-silent",
            "-rate-limit", nuclei_rate,
            "-bulk-size", nuclei_bulk,
            "-concurrency", nuclei_conc,
            "-timeout", "10",
            "-retries", "1",
            "-nc",                           # no color codes in output
            "-H", f"User-Agent: {nuclei_ua}",
            # Note: interactsh ENABLED intentionally — needed for blind SSRF/XSS/XXE detection
        ] + template_args + _h1_header_args()

        MAX_NUCLEI_RUNTIME = 900  # 15 minutes hard cap — use partial results after
        rc, stdout, stderr = await _run_command(
            cmd,
            stream_key=f"tool:nuclei:{output_file}",
            timeout_s=MAX_NUCLEI_RUNTIME,
        )

        if rc != 0 and stderr:
            log.warning("nuclei exit=%d stderr=%s", rc, stderr[:600])

        findings = []
        # Try the JSONL export file first, then fall back to stdout
        if os.path.exists(output_file):
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        if not findings and stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and line.startswith("{"):
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        log.info("nuclei: %d findings from %d scoped URLs", len(findings), len(scoped_urls))

        # ── Tech-stack targeted CVE second pass ───────────────────────────────
        # If httpx detected specific technologies, run a targeted nuclei pass
        # against http/cves with tech-specific tags (90s hard cap).
        # This is a SEPARATE invocation so -tags doesn't filter the main scan subdirs.
        if detected_techs and templates_dir:
            cve_dir = os.path.join(templates_dir, "http", "cves")
            if os.path.isdir(cve_dir):
                cve_tags = list(dict.fromkeys(
                    _TECH_NUCLEI_TAGS[t] for t in detected_techs if t in _TECH_NUCLEI_TAGS
                ))[:6]  # cap at 6 tags to keep template count manageable
                if cve_tags:
                    cve_out = output_file.replace(".jsonl", "_cve.jsonl")
                    cve_cmd = [
                        "nuclei",
                        "-l", input_file,
                        "-t", cve_dir,
                        "-tags", ",".join(cve_tags),
                        "-severity", NUCLEI_SEVERITY,
                        "-jsonl-export", cve_out,
                        "-j",
                        "-silent",
                        "-rate-limit", "15" if behind_cloudflare else "80",
                        "-bulk-size", "20" if behind_cloudflare else "30",
                        "-concurrency", "8"  if behind_cloudflare else "15",
                        "-timeout", "10",
                        "-retries", "1",
                        "-nc",
                        "-H", f"User-Agent: {nuclei_ua}",
                    ] + _h1_header_args()
                    log.info("nuclei-cve: running with tags=%s", ",".join(cve_tags))
                    await _run_command(cve_cmd, timeout_s=90)

                    cve_count_before = len(findings)
                    if os.path.exists(cve_out):
                        with open(cve_out) as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        obj = json.loads(line)
                                        obj["_cve_pass"] = True
                                        findings.append(obj)
                                    except json.JSONDecodeError:
                                        continue
                    log.info(
                        "nuclei-cve: %d additional findings (tags=%s)",
                        len(findings) - cve_count_before,
                        ",".join(cve_tags),
                    )

        return findings
    finally:
        os.unlink(input_file)


async def run_ffuf(url: str, wordlist: str, output_file: str) -> list[dict]:
    """
    Directory/endpoint fuzzing with ffuf.
    Returns all results (200/201/301/302/403) so callers can extract 403s
    for bypass testing and 200s for new attack surface.
    """
    # Try wordlist locations in priority order.
    # /wordlists/ is populated at Docker build time from SecLists.
    wordlist = resolve_ffuf_wordlist(wordlist)
    if not wordlist:
        return []  # No wordlist available — Docker image not rebuilt yet

    cmd = [
        "ffuf",
        "-u", f"{url.rstrip('/')}/FUZZ",
        "-w", wordlist,
        "-mc", "200,201,301,302,403",
        "-o", output_file,
        "-of", "json",
        "-t", "30",
        "-rate", "30",     # CDN-friendly
        "-timeout", "10",
        "-silent",
    ] + _h1_header_args()
    await _run_command(cmd, stream_key=f"tool:ffuf:{output_file}", timeout_s=180)

    if os.path.exists(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
                return data.get("results", [])
        except (json.JSONDecodeError, KeyError):
            return []
    return []


def resolve_ffuf_wordlist(wordlist: str) -> str:
    """Return an existing ffuf wordlist path or empty string if unavailable."""
    if wordlist and os.path.exists(wordlist):
        return wordlist

    for candidate in [
        "/wordlists/web-combined.txt",          # our curated merge (common + api endpoints)
        "/wordlists/common.txt",                 # SecLists common
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]:
        if os.path.exists(candidate):
            return candidate
    return ""


async def run_dalfox(url: str, params: list[str], output_file: str) -> list[dict]:
    """
    XSS scanner — only call if nuclei or manual review flagged XSS candidate.
    Command: dalfox url {url} --silence --format json -o {output_file}
    """
    # dalfox uses --header instead of -H
    _dalfox_hdrs = []
    if settings.h1_username:
        _dalfox_hdrs = ["--header", f"X-HackerOne-Researcher: {settings.h1_username}"]

    cmd = [
        "dalfox",
        "url", url,
        "--silence",
        "--format", "json",
        "-o", output_file,
        "--timeout", "10",
        "--delay", "100",
    ] + _dalfox_hdrs

    # Add specific params if provided
    if params:
        cmd += ["--param", ",".join(params)]

    await _run_command(cmd, stream_key=f"tool:dalfox:{output_file}")

    if os.path.exists(output_file):
        try:
            with open(output_file) as f:
                content = f.read().strip()
                if content.startswith("["):
                    return json.loads(content)
                # dalfox sometimes outputs one JSON object per line
                results = []
                for line in content.splitlines():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                return results
        except Exception:
            return []
    return []


async def run_sqlmap(url: str, scan_dir: str) -> list[dict]:
    """
    Test URL for SQL injection using time-based blind technique only.

    Safe mode constraints (won't upset program rules):
    - --technique=T  → time-based blind only (no UNION, no error-based, no data dump)
    - --level=1      → minimal parameter coverage
    - --risk=1       → no heavy/destructive payloads
    - --batch        → never interactive
    - --threads=1    → single-threaded, CDN-friendly

    Returns list of finding dicts if SQLi is confirmed, empty list otherwise.
    A full rebuild is required before sqlmap is available (it's not in the base image).
    """
    import logging
    log = logging.getLogger("tool_runner")

    output_dir = os.path.join(scan_dir, "sqlmap_output")
    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        "sqlmap",
        "-u", url,
        "--technique=T",        # time-based blind only
        "--level=1",
        "--risk=1",
        "--batch",              # no user prompts
        "--output-dir", output_dir,
        "--forms",              # also test HTML form fields
        "--timeout", "10",
        "--retries", "1",
        "--threads", "1",
        "-q",                   # quiet (less noise in logs)
    ]

    rc, stdout, stderr = await _run_command(cmd, timeout_s=300)

    combined = (stdout + "\n" + stderr).lower()
    findings = []

    # sqlmap prints "parameter X appears to be 'TIME-BASED BLIND' injectable"
    if "appears to be" in combined and ("injectable" in combined or "blind" in combined):
        findings.append({
            "url": url,
            "tool": "sqlmap",
            "technique": "time-based blind",
            "evidence": (stdout or stderr)[:1500],
        })
        log.info("sqlmap: CONFIRMED SQLi at %s", url)
    else:
        log.info("sqlmap: no SQLi confirmed at %s", url)

    return findings


async def run_arjun(url: str, output_file: str) -> list[str]:
    """
    Discover hidden HTTP parameters.
    Command: arjun -u {url} -oJ {output_file} --stable -q
    Timeout: 120s per URL — if arjun hasn't found params in 2 min, the endpoint
    likely doesn't have discoverable params. Prevents 30-min arjun blocks on
    large scopes (5 URLs × 360s = 30 min → now 5 × 120s = 10 min max).
    """
    cmd = [
        "arjun",
        "-u", url,
        "-oJ", output_file,
        "--stable",
        "-q",
        "-t", "10",
    ]
    await _run_command(cmd, stream_key=f"tool:arjun:{output_file}", timeout_s=120)

    if os.path.exists(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
                # arjun output: {"url": [...params...]} or list
                if isinstance(data, dict):
                    return data.get(url, data.get("params", []))
                if isinstance(data, list):
                    return data
        except Exception:
            return []
    return []


# ── JS Secret Scanner ─────────────────────────────────────────────────────────

# Regex patterns for secrets commonly found in JavaScript files.
# Each entry: (pattern, secret_type, severity)
_JS_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # Cloud credentials
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'critical'),
    (r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key["\':\s=]+([A-Za-z0-9/+=]{40})', 'AWS Secret Key', 'critical'),
    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Secret Key', 'critical'),
    (r'rk_live_[0-9a-zA-Z]{24,}', 'Stripe Restricted Key', 'high'),
    # GitHub tokens
    (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Token', 'high'),
    (r'ghs_[0-9a-zA-Z]{36}', 'GitHub Server Token', 'high'),
    # Slack
    (r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'Slack Bot Token', 'high'),
    (r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'Slack User Token', 'high'),
    # Firebase
    (r'AIza[0-9A-Za-z\-_]{35}', 'Firebase API Key', 'high'),
    # Generic API keys in variable assignments
    (r'(?i)["\']?api[_\-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'API Key', 'high'),
    (r'(?i)["\']?api[_\-]?secret["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'API Secret', 'high'),
    (r'(?i)["\']?auth[_\-]?token["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'Auth Token', 'high'),
    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', 'Private Key', 'critical'),
    # Generic passwords in config objects
    (r'(?i)["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'Password', 'medium'),
    (r'(?i)["\']?secret["\']?\s*[:=]\s*["\']([^"\']{12,})["\']', 'Secret', 'medium'),
]

# False-positive strings — skip matches that contain these
_JS_FP_STRINGS = {
    'example', 'placeholder', 'your_', 'xxxx', '0000', 'test',
    'sample', 'dummy', 'fake', 'changeme', 'replace', 'insert',
    'your-api', 'xxxxxxxx', 'aaaaaaa', '<api_key>', '{api_key}',
}


def _download_url(url: str, timeout: int = 10) -> Optional[str]:
    """Download URL content synchronously (runs in thread pool)."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityResearcher/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Only read up to 512 KB per file
            return resp.read(524288).decode("utf-8", errors="replace")
    except Exception:
        return None


async def run_js_scanner(js_urls: list[str], output_file: str) -> list[dict]:
    """
    Download JS files and scan for secrets using regex.
    Returns list of findings: {url, secret_type, match, context, severity}.
    Caps at 200 URLs, prioritising first-party JS (not CDN/analytics/third-party).
    Runs 10 downloads concurrently in a thread pool.
    """
    import logging
    log = logging.getLogger("tool_runner")

    if not js_urls:
        return []

    # De-prioritise known CDN / analytics / third-party domains — they're never
    # going to contain the target's secrets but make up the bulk of JS URLs.
    CDN_NOISE = (
        "cdn.", "static.", "assets.", "googletagmanager", "google-analytics",
        "googleapis", "gstatic", "cloudflare", "jsdelivr", "unpkg", "cdnjs",
        "jquery", "bootstrap", "fontawesome", "intercom", "segment",
        "analytics", "hotjar", "mixpanel", "amplitude", "sentry-cdn",
        "facebook", "twitter", "linkedin",
    )
    first_party = [u for u in js_urls if not any(n in u.lower() for n in CDN_NOISE)]
    third_party  = [u for u in js_urls if     any(n in u.lower() for n in CDN_NOISE)]
    ordered = first_party + third_party

    urls_to_scan = ordered[:200]
    findings: list[dict] = []
    compiled = [(re.compile(pat), stype, sev) for pat, stype, sev in _JS_SECRET_PATTERNS]
    loop = asyncio.get_event_loop()
    semaphore = asyncio.Semaphore(10)

    async def _scan_one(url: str):
        async with semaphore:
            content = await loop.run_in_executor(None, _download_url, url)
        if not content:
            return
        for regex, secret_type, severity in compiled:
            for m in regex.finditer(content):
                matched = m.group(0)[:120]
                matched_lower = matched.lower()
                if any(fp in matched_lower for fp in _JS_FP_STRINGS):
                    continue
                start = max(0, m.start() - 60)
                end = min(len(content), m.end() + 60)
                context = content[start:end].replace("\n", " ").strip()
                findings.append({
                    "url": url,
                    "secret_type": secret_type,
                    "match": matched,
                    "context": context,
                    "severity": severity,
                })
                break  # one finding per URL per pattern type is enough

    await asyncio.gather(*[_scan_one(u) for u in urls_to_scan])

    # Deduplicate by (secret_type, match prefix) — the same key embedded in 100s of
    # JS bundle files should be one finding, not 100 separate AI evaluations.
    seen_key_values: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for fnd in findings:
        key = (fnd["secret_type"], fnd["match"][:50])
        if key not in seen_key_values:
            seen_key_values.add(key)
            deduped.append(fnd)
    if len(deduped) < len(findings):
        log.info(
            "js_scanner: collapsed %d → %d unique findings after dedup",
            len(findings), len(deduped),
        )
    findings = deduped

    if findings:
        with open(output_file, "w") as f:
            for finding in findings:
                f.write(json.dumps(finding) + "\n")

    log.info("js_scanner: %d secrets found in %d JS files", len(findings), len(urls_to_scan))
    return findings


# ── 403 Bypass Tester ─────────────────────────────────────────────────────────

_BYPASS_HEADERS = [
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
]

_PATH_SUFFIXES = ["/%2f", "/./", "//", "?", " ", "%20", "%09", ";/"]


def _try_bypass_sync(url: str) -> Optional[dict]:
    """Try 403 bypass techniques synchronously. Returns bypass dict or None."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path or "/"

        # Try header bypasses
        for header_template in _BYPASS_HEADERS:
            headers = {
                k: v.replace("{path}", path)
                for k, v in header_template.items()
            }
            headers["User-Agent"] = "Mozilla/5.0"
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status in (200, 201, 202):
                        return {
                            "url": url,
                            "bypass_type": "header",
                            "payload": str(header_template),
                            "status": resp.status,
                            "severity": "medium",
                        }
            except Exception:
                pass

        # Try path suffix bypasses
        base = url.rstrip("/")
        for suffix in _PATH_SUFFIXES:
            bypass_url = base + suffix
            try:
                req = urllib.request.Request(
                    bypass_url, headers={"User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status in (200, 201, 202):
                        return {
                            "url": url,
                            "bypass_type": "path",
                            "payload": bypass_url,
                            "status": resp.status,
                            "severity": "medium",
                        }
            except Exception:
                pass
    except Exception:
        pass
    return None


async def run_403_bypass(urls_403: list[str], output_file: str) -> list[dict]:
    """
    Try common 403 bypass techniques on restricted endpoints.
    Returns list of successful bypasses.
    Caps at 30 URLs, runs 8 concurrently.
    """
    import logging
    log = logging.getLogger("tool_runner")

    if not urls_403:
        return []

    targets = urls_403[:30]
    bypasses: list[dict] = []
    semaphore = asyncio.Semaphore(8)
    loop = asyncio.get_event_loop()

    async def _try_one(url: str):
        async with semaphore:
            result = await loop.run_in_executor(None, _try_bypass_sync, url)
        if result:
            bypasses.append(result)

    await asyncio.gather(*[_try_one(u) for u in targets])

    if bypasses:
        with open(output_file, "w") as f:
            for b in bypasses:
                f.write(json.dumps(b) + "\n")

    log.info("403_bypass: %d bypasses found from %d tested URLs", len(bypasses), len(targets))
    return bypasses


# ── CORS Checker ──────────────────────────────────────────────────────────────

def _test_cors_sync(url: str) -> Optional[dict]:
    """
    Test a single URL for CORS misconfiguration.
    Tries 4 attack patterns; returns first exploitable finding or None.
    """
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        scheme = parsed.scheme

        # Ordered from most severe to least; stop on first hit
        test_cases = [
            (f"https://evil.com",                "arbitrary_origin",  "critical"),
            (f"https://{host}.evil.com",         "suffix_bypass",     "high"),
            (f"https://evil{host}",              "prefix_bypass",     "high"),
            ("null",                             "null_origin",       "high"),
        ]

        for origin, attack_type, severity in test_cases:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Origin": origin, "User-Agent": "Mozilla/5.0"},
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

                    if not acao:
                        continue

                    reflected = (acao == origin) or (attack_type == "arbitrary_origin" and acao not in ("", "*"))
                    if reflected and acac == "true":
                        return {
                            "url": url,
                            "attack_type": attack_type,
                            "origin_sent": origin,
                            "acao_header": acao,
                            "acac_header": acac,
                            "severity": severity,
                            "impact": (
                                "Attacker can make cross-origin authenticated requests "
                                f"from {origin} → exfiltrate session data / perform CSRF with credentials."
                            ),
                        }
            except Exception:
                continue
    except Exception:
        pass
    return None


async def run_cors_checker(urls: list[str], output_file: str) -> list[dict]:
    """
    Check live URLs for CORS misconfiguration.
    Focuses on API-like endpoints where credentials are likely present.
    Caps at 60 URLs, 10 concurrent.
    """
    import logging
    log = logging.getLogger("tool_runner")

    if not urls:
        return []

    # Prefer API/auth endpoints where CORS matters most
    API_PATTERNS = ["/api", "/v1", "/v2", "/v3", "/graphql", "/auth",
                    "/oauth", "/user", "/account", "/me", "/profile", "/data"]
    api_urls = [u for u in urls if any(p in u.lower() for p in API_PATTERNS)]
    # Fill remaining slots with other live URLs
    other_urls = [u for u in urls if u not in api_urls]
    targets = (api_urls + other_urls)[:120]  # was 60 — doubled to avoid missing URLs beyond cap

    findings: list[dict] = []
    semaphore = asyncio.Semaphore(10)
    loop = asyncio.get_event_loop()

    async def _check_one(url: str):
        async with semaphore:
            result = await loop.run_in_executor(None, _test_cors_sync, url)
        if result:
            findings.append(result)

    await asyncio.gather(*[_check_one(u) for u in targets])

    if findings:
        with open(output_file, "w") as f:
            for item in findings:
                f.write(json.dumps(item) + "\n")

    log.info("cors_checker: %d issues found from %d tested URLs", len(findings), len(targets))
    return findings


# ── Subdomain Takeover Checker ────────────────────────────────────────────────

# Provider CNAME suffix → HTTP body fingerprints for unclaimed instances
_TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "github.io":              ["There isn't a GitHub Pages site here"],
    "herokuapp.com":          ["No such app", "herokucdn.com/error-pages/no-such-app"],
    "s3.amazonaws.com":       ["NoSuchBucket", "The specified bucket does not exist"],
    "blob.core.windows.net":  ["BlobNotFound", "The specified resource does not exist"],
    "azurewebsites.net":      ["404 Web Site not found"],
    "cloudapp.net":           ["404 - Web app not found"],
    "fastly.net":             ["Fastly error: unknown domain"],
    "zendesk.com":            ["Help Center Closed"],
    "shopify.com":            ["Sorry, this shop is currently unavailable"],
    "surge.sh":               ["project not found"],
    "readme.io":              ["Project doesnt exist", "We couldn’t find that page"],
    "pantheon.io":            ["404 error unknown site"],
    "unbouncepages.com":      ["The requested URL was not found"],
    "ghost.io":               ["The thing you were looking for is no longer here"],
    "helpscoutdocs.com":      ["No settings were found for this company"],
    "bitbucket.io":           ["Repository not found"],
    "fly.dev":                ["404: Not Found"],
    "vercel.app":             ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
    "netlify.app":            ["Not Found", "page not found"],
    "pages.dev":              ["Not Found"],
    "web.app":                ["Site Not Found"],
    "firebaseapp.com":        ["Firebase App Not Found"],
    "statuspage.io":          ["You are being redirected"],
    "aftership.com":          ["Oops. We couldn’t find that page"],
    "cargocollective.com":    ["404 Not Found"],
    "freshdesk.com":          ["There is no helpdesk here"],
    "intercom.help":          ["This page is reserved for artistic agents"],
    "desk.com":               ["Please try again or try Desk.com free for 14 days"],
    "tictail.com":            ["to target URL"],
    "campaignmonitor.com":    ["Double check the URL"],
    "uservoice.com":          ["This UserVoice subdomain is currently available"],
    "wordpress.com":          ["Do you want to register"],
    "simplebooklet.com":      ["We can’t find this flipbook"],
}


def _check_takeover_sync(subdomain: str) -> Optional[dict]:
    """Check a single subdomain for takeover vulnerability."""
    # First get CNAME record using dnsx-style resolution via socket
    try:
        # We'll check HTTP response fingerprints directly
        # Try both http and https
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read(32768).decode("utf-8", errors="replace").lower()
                    effective_url = resp.url

                    # Check if the response came from a known provider
                    for provider_suffix, fingerprints in _TAKEOVER_FINGERPRINTS.items():
                        if provider_suffix in effective_url.lower():
                            for fp in fingerprints:
                                if fp.lower() in body:
                                    return {
                                        "subdomain": subdomain,
                                        "provider": provider_suffix,
                                        "fingerprint": fp,
                                        "evidence_url": effective_url,
                                        "severity": "high",
                                        "impact": (
                                            f"Subdomain {subdomain} points to unclaimed "
                                            f"{provider_suffix} instance. Attacker can register "
                                            "the resource and serve malicious content on the "
                                            "trusted domain (phishing, cookie theft, CSP bypass)."
                                        ),
                                    }
            except urllib.error.HTTPError as e:
                # 404 from a provider is also interesting
                effective_url = url
                body = ""
                try:
                    body = e.read(8192).decode("utf-8", errors="replace").lower()
                except Exception:
                    pass
                for provider_suffix, fingerprints in _TAKEOVER_FINGERPRINTS.items():
                    if provider_suffix in subdomain.lower():
                        for fp in fingerprints:
                            if fp.lower() in body:
                                return {
                                    "subdomain": subdomain,
                                    "provider": provider_suffix,
                                    "fingerprint": fp,
                                    "evidence_url": url,
                                    "severity": "high",
                                    "impact": (
                                        f"Subdomain {subdomain} CNAME → unclaimed {provider_suffix}."
                                    ),
                                }
            except Exception:
                continue
    except Exception:
        pass
    return None


async def run_subdomain_takeover(subdomains: list[str], output_file: str) -> list[dict]:
    """
    Check subdomains for potential takeover.
    Caps at 200 subdomains, 15 concurrent.
    """
    import logging
    log = logging.getLogger("tool_runner")

    if not subdomains:
        return []

    targets = subdomains[:200]
    findings: list[dict] = []
    semaphore = asyncio.Semaphore(15)
    loop = asyncio.get_event_loop()

    async def _check_one(sub: str):
        async with semaphore:
            result = await loop.run_in_executor(None, _check_takeover_sync, sub)
        if result:
            findings.append(result)

    await asyncio.gather(*[_check_one(s) for s in targets])

    if findings:
        with open(output_file, "w") as f:
            for item in findings:
                f.write(json.dumps(item) + "\n")

    log.info("subdomain_takeover: %d vulnerabilities found from %d subdomains",
             len(findings), len(targets))
    return findings


# ── Swagger / OpenAPI Discovery ──────────────────────────────────────────────

_SWAGGER_PATHS = [
    "/swagger.json", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json",
    "/v2/api-docs", "/v3/api-docs",
    "/api/swagger.json", "/api/openapi.json",
    "/docs", "/redoc",
    "/_api/swagger.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json",
]


def _probe_swagger_sync(base_url: str) -> Optional[dict]:
    """Probe a single base URL for an exposed Swagger/OpenAPI spec."""
    for path in _SWAGGER_PATHS:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json, text/yaml, */*"},
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status != 200:
                    continue
                raw = resp.read(524288).decode("utf-8", errors="replace")
                # Must contain swagger/openapi markers
                if not any(kw in raw[:1000] for kw in (
                    '"swagger"', '"openapi"', 'swagger:', 'openapi:', '"paths"',
                )):
                    continue
                # Parse paths from JSON spec
                api_paths: list[str] = []
                try:
                    spec = json.loads(raw)
                    api_paths = list(spec.get("paths", {}).keys())
                except json.JSONDecodeError:
                    pass  # YAML spec — paths not extracted but finding still reported
                return {
                    "base_url": base_url,
                    "spec_url": url,
                    "endpoints_count": len(api_paths),
                    "sample_paths": api_paths[:30],
                    "severity": "medium",
                    "impact": (
                        f"API specification exposed at {url} reveals {len(api_paths)} endpoint(s). "
                        "Attackers can enumerate all API routes, parameters, and authentication "
                        "requirements without any prior knowledge of the API surface."
                    ),
                }
        except Exception:
            continue
    return None


async def run_swagger_discovery(live_urls: list[str], output_file: str) -> list[dict]:
    """
    Probe live hosts for exposed Swagger/OpenAPI specifications.
    API-like subdomains (api.*, backend.*) are checked first.
    Caps at 30 unique base hosts.
    """
    import logging
    from urllib.parse import urlparse as _up
    log = logging.getLogger("tool_runner")

    if not live_urls:
        return []

    # Unique base URLs scored by API likelihood
    seen: dict[str, int] = {}
    for u in live_urls:
        try:
            p = _up(u)
            base = f"{p.scheme}://{p.netloc}"
        except Exception:
            continue
        if base not in seen:
            score = 10 if any(kw in (p.hostname or "") for kw in ("api", "backend", "service", "gateway")) else 0
            seen[base] = score

    base_urls = sorted(seen, key=lambda b: seen[b], reverse=True)[:30]

    findings: list[dict] = []
    semaphore = asyncio.Semaphore(10)
    loop = asyncio.get_event_loop()

    async def _check_one(base_url: str):
        async with semaphore:
            result = await loop.run_in_executor(None, _probe_swagger_sync, base_url)
        if result:
            findings.append(result)

    await asyncio.gather(*[_check_one(b) for b in base_urls])

    if findings:
        with open(output_file, "w") as f:
            for item in findings:
                f.write(json.dumps(item) + "\n")

    log.info("swagger_discovery: %d specs found from %d hosts", len(findings), len(base_urls))
    return findings


# ── S3 Bucket Enumeration ─────────────────────────────────────────────────────

_S3_BUCKET_SUFFIXES = [
    "", "-backup", "-backups", "-dev", "-development",
    "-staging", "-stage", "-prod", "-production",
    "-assets", "-asset", "-static", "-media", "-uploads",
    "-files", "-data", "-logs", "-log", "-archive",
    "-internal", "-private", "-public", "-storage",
    "-cdn", "-email", "-export", "-tmp", "-temp",
    "-test", "-images", "-img", "-docs", "-reports",
    "backup", "assets", "static", "media", "data", "logs",
]


def _check_s3_bucket_sync(bucket: str) -> Optional[dict]:
    """Check a single S3 bucket for public access."""
    for url in (
        f"https://{bucket}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket}/",
    ):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    raw = resp.read(4096).decode("utf-8", errors="replace")
                    is_listing = "<ListBucketResult" in raw
                    return {
                        "bucket": bucket,
                        "url": url,
                        "publicly_listed": is_listing,
                        "severity": "critical" if is_listing else "high",
                        "impact": (
                            f"S3 bucket '{bucket}' is publicly accessible. "
                            + ("Directory listing enabled — all objects are enumerable."
                               if is_listing else "Bucket contents may be readable.")
                        ),
                    }
        except urllib.error.HTTPError as e:
            if e.code == 403:
                pass  # Bucket exists but private — not a finding
        except Exception:
            pass
    return None


async def run_s3_enum(domains: list[str], output_file: str) -> list[dict]:
    """
    Enumerate S3 buckets by generating company name variants from target domains.
    Only reports actually public buckets (HTTP 200). Private (403) buckets are skipped.
    """
    import logging
    log = logging.getLogger("tool_runner")

    if not domains:
        return []

    # Extract company identifiers from apex domains
    company_names: set[str] = set()
    for d in domains:
        base = d.lstrip("*.")
        name = base.split(".")[0].lower()
        company_names.add(name)
        company_names.add(name.replace("-", ""))
        company_names.add(name.replace("_", ""))

    bucket_to_scope_url: dict[str, str] = {}
    for domain in domains:
        scope_url = f"https://{domain.lstrip('*.')}"
        base = domain.lstrip("*.")
        name = base.split(".")[0].lower()
        names = [name, name.replace("-", ""), name.replace("_", "")]
        for derived_name in names:
            if not derived_name:
                continue
            for suffix in _S3_BUCKET_SUFFIXES:
                candidate = f"{derived_name}{suffix}"
                if 3 <= len(candidate) <= 63 and candidate not in bucket_to_scope_url:
                    # Keep first seen scope URL for deterministic attribution.
                    bucket_to_scope_url[candidate] = scope_url

    bucket_names = list(bucket_to_scope_url.keys())

    findings: list[dict] = []
    semaphore = asyncio.Semaphore(20)
    loop = asyncio.get_event_loop()

    async def _check_one(bucket: str):
        async with semaphore:
            result = await loop.run_in_executor(None, _check_s3_bucket_sync, bucket)
        if result:
            result["scope_url"] = bucket_to_scope_url.get(bucket, "")
            findings.append(result)

    await asyncio.gather(*[_check_one(b) for b in bucket_names])

    if findings:
        with open(output_file, "w") as f:
            for item in findings:
                f.write(json.dumps(item) + "\n")

    log.info("s3_enum: %d public buckets found from %d candidates", len(findings), len(bucket_names))
    return findings


# ── Email Security Scanner ────────────────────────────────────────────────────

def _check_email_security_sync(domain: str) -> dict:
    """
    Check SPF, DMARC, and DKIM for a domain via DNS lookups.
    Returns a finding dict if misconfiguration is found, else empty dict.

    Common H1 findings:
    - Missing DMARC → attacker can send spoofed emails from domain (phishing)
    - DMARC p=none → policy exists but not enforced (useless)
    - Missing SPF → no sender restriction
    - SPF +all → allows any server to send (critical misconfiguration)
    """
    import dns.resolver
    import dns.exception

    issues: list[dict] = []

    def _query_txt(name: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=8)
            return [b.decode("utf-8", errors="replace") for rdata in answers for b in rdata.strings]
        except (dns.exception.DNSException, Exception):
            return []

    # ── SPF check ───────────────────────────────────────────────────────────
    spf_records = [r for r in _query_txt(domain) if r.lower().startswith("v=spf1")]
    if not spf_records:
        issues.append({
            "check": "SPF",
            "severity": "medium",
            "detail": f"No SPF record found for {domain}. Anyone can send email appearing to come from @{domain}.",
            "impact": "Email spoofing — attacker can send phishing emails from @{domain} with no SPF validation failure.".format(domain=domain),
        })
    else:
        spf = spf_records[0].lower()
        if "+all" in spf or spf.endswith(" all") and "~all" not in spf and "-all" not in spf and "?all" not in spf:
            # Plain 'all' without qualifier = +all (pass all)
            issues.append({
                "check": "SPF +all",
                "severity": "high",
                "detail": f"SPF record uses '+all' or unqualified 'all': {spf_records[0]}",
                "impact": f"Any mail server on the internet is permitted to send email as @{domain}.",
            })

    # ── DMARC check ─────────────────────────────────────────────────────────
    dmarc_records = _query_txt(f"_dmarc.{domain}")
    dmarc_txt = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)

    if not dmarc_txt:
        issues.append({
            "check": "DMARC missing",
            "severity": "medium",
            "detail": f"No DMARC record found at _dmarc.{domain}.",
            "impact": (
                f"Without DMARC, spoofed emails from @{domain} are not rejected by receiving mail servers. "
                "Attackers can impersonate the domain in phishing campaigns with no enforcement."
            ),
        })
    else:
        dmarc_lower = dmarc_txt.lower()
        # Extract p= policy
        import re as _re
        p_match = _re.search(r'\bp=(\w+)', dmarc_lower)
        policy = p_match.group(1) if p_match else "none"
        if policy == "none":
            issues.append({
                "check": "DMARC p=none",
                "severity": "medium",
                "detail": f"DMARC record exists but policy is p=none (monitor only): {dmarc_txt}",
                "impact": (
                    f"DMARC p=none does not prevent spoofed emails from being delivered. "
                    f"Attackers can still send phishing emails as @{domain} and they will be delivered."
                ),
            })
        # Check for missing rua (reporting address) — won't find violations
        if "rua=" not in dmarc_lower:
            issues.append({
                "check": "DMARC no reporting",
                "severity": "informational",
                "detail": f"DMARC record has no rua= reporting address: {dmarc_txt}",
                "impact": "No visibility into spoofing attempts against the domain.",
            })

    if not issues:
        return {}

    # Determine overall severity (highest among issues)
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    top_issue = max(issues, key=lambda i: sev_order.get(i["severity"], 0))
    checks_summary = ", ".join(i["check"] for i in issues)

    return {
        "domain": domain,
        "issues": issues,
        "severity": top_issue["severity"],
        "checks_failed": checks_summary,
        "impact": top_issue["impact"],
    }


async def run_email_security(domains: list[str], output_file: str) -> list[dict]:
    """
    Check SPF/DMARC email security for target domains.
    Pure DNS — no active scanning, no rate limit concerns.
    """
    import logging
    log = logging.getLogger("tool_runner")

    if not domains:
        return []

    # Deduplicate to apex domains only
    seen: set[str] = set()
    apex_domains: list[str] = []
    for d in domains:
        apex = d.lstrip("*.")
        # Strip subdomains to get the apex (last two labels)
        parts = apex.split(".")
        apex2 = ".".join(parts[-2:]) if len(parts) >= 2 else apex
        if apex2 not in seen:
            seen.add(apex2)
            apex_domains.append(apex2)

    loop = asyncio.get_event_loop()
    findings: list[dict] = []

    for domain in apex_domains[:10]:  # cap at 10 apex domains
        result = await loop.run_in_executor(None, _check_email_security_sync, domain)
        if result:
            findings.append(result)

    if findings:
        with open(output_file, "w") as f:
            for item in findings:
                f.write(json.dumps(item) + "\n")

    log.info("email_security: %d domains with issues from %d checked", len(findings), len(apex_domains))
    return findings


# ── GitHub Dorking ────────────────────────────────────────────────────────────

# Search queries — prioritised by signal quality.
# Queries require *assignment syntax* (=, :) near the domain to avoid
# false positives from library docs / exchange lists that merely mention the domain.
#
# IMPORTANT: GitHub Code Search API does NOT support wildcard filename qualifiers
# like NOT filename:*.md — those trigger a 422 (invalid query) that is silently
# swallowed, causing the entire query to return 0 results.
# Only use exact filename matches (NOT filename:README) or path exclusions
# (NOT path:docs NOT path:test) which are fully supported.
_GITHUB_DORK_QUERIES = [
    # Config file patterns — exclude README/docs pages that just mention the domain
    '"{domain}" password= NOT filename:README NOT path:docs NOT path:test',
    '"{domain}" api_key= NOT filename:README NOT path:docs NOT path:test',
    '"{domain}" secret= NOT filename:README NOT path:docs NOT path:test',
    '"{domain}" access_token= NOT filename:README',
    # YAML/JSON config patterns (common in CI config and docker-compose)
    '"{domain}" password: NOT filename:README NOT path:docs',
    '"{domain}" secret_key: NOT filename:README',
    # .env files — exact filename exclusions work; wildcards do not
    'filename:.env "{domain}" NOT filename:.env.example NOT filename:.env.sample',
    'filename:.pem "{domain}"',
]

# Org-specific high-value queries — run against the APEX domain's GitHub org.
# These find secrets in the company's OWN repositories (much higher signal).
# The {org} placeholder is replaced with the apex domain's subdomain-stripped name.
_GITHUB_ORG_QUERIES = [
    'org:{org} filename:.env password',
    'org:{org} filename:.env secret',
    'org:{org} filename:.env api_key',
    'org:{org} password= NOT filename:README NOT filename:*.md',
    'org:{org} secret= NOT filename:README NOT filename:*.md',
]

# Values that look like placeholder / template / example credentials — not real secrets.
# Applied to the captured secret value (group 1) of generic patterns like password=/api_key=.
_PLACEHOLDER_VALUE_RE = re.compile(
    r'(?i)(?:'
    r'your[-_]'                     # your_key, your-password, your_secret_id_here
    r'|[-_]here$'                   # _here suffix: secret_key_here
    r'|example'                     # example_key, example_secret
    r'|placeholder'                 # placeholder_value
    r'|dummy'                       # dummy_password
    r'|fake'                        # fake_token
    r'|making_validator'            # making_validator_happy (literal from findings)
    r'|<[^>]+>'                     # <your_key_here>
    r'|\{[^}]+\}'                   # {your_key}
    r'|#+[A-Z_]+#+'                 # ###DB_PASSWORD###
    r'|x{4,}'                       # xxxx, xxxxx (masked)
    r'|\*{3,}'                      # ***, ***** (redacted)
    r'|^(?:postgres|password|passwd|changeme|secret|admin|root|test|demo|sample|none|null|undefined|todo)$'
    r')'
)

# Regex patterns to detect actual secrets in the code snippets GitHub returns
_GH_SECRET_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID", "critical"),
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "Stripe Secret Key", "critical"),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "Private Key", "critical"),
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), "GitHub PAT", "high"),
    (re.compile(r'xoxb-[0-9]{10,13}-[0-9a-zA-Z]{24,}'), "Slack Bot Token", "high"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Firebase API Key", "high"),
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?'), "Password", "medium"),
    (re.compile(r'(?i)(?:api_?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?'), "API Key", "medium"),
]


def _github_search_sync(query: str, token: str) -> list[dict]:
    """Call GitHub Code Search API synchronously."""
    import urllib.parse
    results = []
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.text-match+json",
        "User-Agent": "BugBountyAssistant/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = urllib.parse.urlencode({"q": query, "per_page": "10", "sort": "indexed"})
    url = f"https://api.github.com/search/code?{params}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            for item in data.get("items", []):
                # Extract matched snippets from text_matches
                snippets = []
                for tm in item.get("text_matches", []):
                    snippets.append(tm.get("fragment", ""))
                combined = "\n".join(snippets)

                # Only keep results that actually contain a detectable secret pattern
                for regex, secret_type, severity in _GH_SECRET_PATTERNS:
                    m = regex.search(combined)
                    if not m:
                        continue
                    # For generic patterns (password=, api_key=) that capture the value,
                    # reject if the captured value looks like a placeholder/template.
                    # High-specificity patterns (AKIA*, sk_live_*, ghp_*, PEM headers)
                    # have no capture group and are inherently non-placeholder.
                    if m.lastindex:
                        secret_value = m.group(1) or ""
                        if _PLACEHOLDER_VALUE_RE.search(secret_value):
                            continue  # skip — it's a template/example value
                    results.append({
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "file_path": item.get("path", ""),
                        "html_url": item.get("html_url", ""),
                        "secret_type": secret_type,
                        "severity": severity,
                        "query": query,
                        "snippet": combined[:300],
                    })
                    break  # one finding per search result
    except urllib.error.HTTPError as e:
        if e.code == 403:
            pass  # Rate limited — skip silently
        elif e.code == 422:
            pass  # Query validation failed — skip
    except Exception:
        pass
    return results


async def run_github_dork(domains: list[str], output_file: str,
                          github_token: Optional[str]) -> list[dict]:
    """
    Search GitHub for exposed secrets related to target domains.
    Requires GITHUB_TOKEN env var (read:public_repo scope).
    Returns list of findings with repo URL, file path, secret type.
    """
    import logging
    log = logging.getLogger("tool_runner")

    if not github_token:
        log.info("github_dork: no GITHUB_TOKEN configured — skipping")
        return []

    if not domains:
        return []

    # Deduplicate domains and extract apex + org names
    apex_domains: list[str] = []
    seen: set[str] = set()
    for d in domains:
        apex = d.lstrip("*.")
        if apex not in seen:
            seen.add(apex)
            apex_domains.append(apex)

    # Derive GitHub org name from apex domain: "gocardless.com" → "gocardless"
    # Companies almost always use their domain name as their GitHub org.
    orgs = list({d.split(".")[0] for d in apex_domains})

    all_findings: list[dict] = []
    loop = asyncio.get_event_loop()

    # Phase A: broad domain queries (third-party repos, lower signal)
    for domain in apex_domains[:2]:  # Max 2 domains to avoid rate limit
        for query_template in _GITHUB_DORK_QUERIES:  # all 8 queries
            query = query_template.replace("{domain}", domain)
            results = await loop.run_in_executor(
                None, _github_search_sync, query, github_token
            )
            all_findings.extend(results)
            await asyncio.sleep(2.5)  # 30 req/min auth limit

    # Phase B: org-scoped queries (company's OWN repos — highest signal)
    # These find secrets the company accidentally committed — always in scope.
    for org in orgs[:2]:
        for query_template in _GITHUB_ORG_QUERIES:
            query = query_template.replace("{org}", org)
            results = await loop.run_in_executor(
                None, _github_search_sync, query, github_token
            )
            # Mark org findings so the LLM filter can apply appropriate context
            for r in results:
                r["_is_org_repo"] = True
            all_findings.extend(results)
            await asyncio.sleep(2.5)

    # Deduplicate by html_url
    seen_urls: set[str] = set()
    unique_findings = []
    for f in all_findings:
        if f["html_url"] not in seen_urls:
            seen_urls.add(f["html_url"])
            unique_findings.append(f)

    if unique_findings:
        with open(output_file, "w") as f_out:
            for item in unique_findings:
                f_out.write(json.dumps(item) + "\n")

    log.info("github_dork: %d secrets found across %d domains (%d org queries)",
             len(unique_findings), len(apex_domains), len(orgs))
    return unique_findings


# ── Evidence capture ─────────────────────────────────────────────────────────

# Known API key validators: maps secret_type (lowercase, normalized) → validation spec
_API_KEY_VALIDATORS: dict[str, dict] = {
    "google-maps-api-key": {
        "url": "https://maps.googleapis.com/maps/api/geocode/json",
        "method": "GET",
        "params": {"address": "London", "key": None},  # key injected at runtime
        "key_param": "key",
        "check": "json_field",
        "field": "status",
        "active_values": ["OK", "ZERO_RESULTS"],
        "inactive_values": ["REQUEST_DENIED"],
    },
    "google-api-key": {
        "url": "https://maps.googleapis.com/maps/api/geocode/json",
        "method": "GET",
        "params": {"address": "London", "key": None},
        "key_param": "key",
        "check": "json_field",
        "field": "status",
        "active_values": ["OK", "ZERO_RESULTS"],
        "inactive_values": ["REQUEST_DENIED"],
    },
    "firebase-api-key": {
        "url": "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig",
        "method": "GET",
        "params": {"key": None},
        "key_param": "key",
        "check": "status_code",
        "active_status": 200,
    },
    "github-token": {
        "url": "https://api.github.com/user",
        "method": "GET",
        "header_key": "Authorization",
        "header_value_tpl": "token {key}",
        "check": "status_code",
        "active_status": 200,
    },
    "github-access-token": {
        "url": "https://api.github.com/user",
        "method": "GET",
        "header_key": "Authorization",
        "header_value_tpl": "token {key}",
        "check": "status_code",
        "active_status": 200,
    },
    "stripe-secret-key": {
        "url": "https://api.stripe.com/v1/balance",
        "method": "GET",
        "header_key": "Authorization",
        "header_value_tpl": "Bearer {key}",
        "check": "status_code",
        "active_status": 200,
    },
    "slack-token": {
        "url": "https://slack.com/api/auth.test",
        "method": "GET",
        "params": {"token": None},
        "key_param": "token",
        "check": "json_field",
        "field": "ok",
        "active_values": [True],
    },
    "sendgrid-api-key": {
        "url": "https://api.sendgrid.com/v3/user/profile",
        "method": "GET",
        "header_key": "Authorization",
        "header_value_tpl": "Bearer {key}",
        "check": "status_code",
        "active_status": 200,
    },
    "mailchimp-api-key": {
        "url": "https://login.mailchimp.com/oauth2/metadata",
        "method": "GET",
        "header_key": "Authorization",
        "header_value_tpl": "OAuth {key}",
        "check": "status_code",
        "active_status": 200,
    },
    "twilio-account-sid": {
        "url": "https://api.twilio.com/2010-04-01/Accounts.json",
        "method": "GET",
        "check": "status_code",
        "active_status": 200,
    },
    "aws-access-key-id": {
        "url": "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        "method": "GET",
        "check": "status_code",
        "active_status": 200,
    },
}

# Normalize secret_type aliases to validator keys
_SECRET_TYPE_ALIASES: dict[str, str] = {
    "google maps api key": "google-maps-api-key",
    "google_maps_api_key": "google-maps-api-key",
    "googlemapsapikey": "google-maps-api-key",
    "google api key": "google-api-key",
    "google_api_key": "google-api-key",
    "github personal access token": "github-token",
    "github_pat": "github-token",
    "ghp_": "github-token",
    "gho_": "github-access-token",
    "stripe secret key": "stripe-secret-key",
    "stripe_secret_key": "stripe-secret-key",
    "sk_live_": "stripe-secret-key",
}


def _infer_secret_type_from_value(key_value: str) -> Optional[str]:
    """Infer validator key from the key/token shape when secret_type is generic."""
    if not key_value:
        return None

    key = key_value.strip()

    # Google API/Firebase keys (both start with AIza)
    if re.match(r"^AIza[0-9A-Za-z\-_]{35}$", key):
        return "google-api-key"

    # GitHub tokens
    if key.startswith("ghp_"):
        return "github-token"
    if key.startswith("gho_"):
        return "github-access-token"

    # Stripe secret keys
    if key.startswith("sk_live_") or key.startswith("sk_test_"):
        return "stripe-secret-key"

    return None


def _normalize_secret_type(secret_type: str) -> str:
    """Normalize secret_type string to a validator key."""
    normalized = secret_type.lower().strip().replace(" ", "-")
    # Check aliases
    alias = _SECRET_TYPE_ALIASES.get(secret_type.lower().strip())
    if alias:
        return alias
    return normalized


async def validate_api_key(secret_type: str, key_value: str) -> dict:
    """
    Validate a discovered API key against the respective service API.
    Returns dict: {validated, status, status_code, response_snippet, curl_cmd}
    Does NOT raise — always returns a result dict.
    """
    import logging
    log = logging.getLogger("tool_runner")

    result: dict = {
        "validated": False,
        "status": "unknown",
        "status_code": None,
        "response_snippet": None,
        "curl_cmd": None,
        "error": None,
    }

    norm = _normalize_secret_type(secret_type)
    validator = _API_KEY_VALIDATORS.get(norm)

    # If detector returned a generic label (e.g. "API Key"), infer type from key value.
    if not validator:
        inferred = _infer_secret_type_from_value(key_value)
        if inferred:
            validator = _API_KEY_VALIDATORS.get(inferred)
            norm = inferred

    if not validator:
        result["status"] = "no_validator"
        return result

    try:
        url = validator["url"]
        method = validator.get("method", "GET")
        headers = {"User-Agent": "Mozilla/5.0 (compatible; security-research)"}
        params: dict = {}

        # Inject API key into params
        if "params" in validator and "key_param" in validator:
            params = dict(validator["params"])
            params[validator["key_param"]] = key_value
            # Build curl for evidence
            param_str = "&".join(f"{k}={v}" for k, v in params.items())
            result["curl_cmd"] = f'curl -s "{url}?{param_str}" | python3 -m json.tool'
        elif "header_key" in validator:
            header_val = validator["header_value_tpl"].replace("{key}", key_value)
            headers[validator["header_key"]] = header_val
            # Build curl
            result["curl_cmd"] = f'curl -s -H "{validator["header_key"]}: {header_val}" "{url}"'
        else:
            result["curl_cmd"] = f'curl -s "{url}"'

        async with _httpx.AsyncClient(timeout=12, verify=False) as client:
            if method == "GET":
                resp = await client.get(url, params=params, headers=headers)
            else:
                resp = await client.post(url, params=params, headers=headers)

            result["status_code"] = resp.status_code

            check = validator.get("check", "status_code")
            if check == "status_code":
                active = resp.status_code == validator.get("active_status", 200)
                result["validated"] = active
                result["status"] = "active" if active else "inactive"
                result["response_snippet"] = resp.text[:400]

            elif check == "json_field":
                try:
                    data = resp.json()
                    field_val = data.get(validator["field"])
                    active_vals = validator.get("active_values", [])
                    inactive_vals = validator.get("inactive_values", [])
                    if field_val in active_vals:
                        result["validated"] = True
                        result["status"] = "active"
                    elif field_val in inactive_vals:
                        result["validated"] = False
                        result["status"] = "restricted"
                    else:
                        result["status"] = f"unknown_response:{field_val}"
                    result["response_snippet"] = json.dumps(data, indent=2)[:600]
                except Exception:
                    result["response_snippet"] = resp.text[:400]

    except Exception as e:
        result["error"] = str(e)[:120]
        log.debug("validate_api_key(%s): %s", secret_type, e)

    return result


async def capture_http_evidence(js_url: str, search_term: str) -> dict:
    """
    Fetch a JS/HTML URL and extract the lines containing the secret.
    Returns dict: {url, status_code, content_type, context_lines, request_line}
    Does NOT raise.
    """
    result: dict = {
        "url": js_url,
        "status_code": None,
        "content_type": None,
        "context_lines": [],
        "request_line": f"GET {js_url} HTTP/1.1",
        "error": None,
    }

    try:
        async with _httpx.AsyncClient(
            timeout=15,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-research)"},
        ) as client:
            resp = await client.get(js_url)
            result["status_code"] = resp.status_code
            result["content_type"] = resp.headers.get("content-type", "")

            # Find lines containing the secret (use first 20 chars of match)
            search = search_term[:20] if len(search_term) > 20 else search_term
            lines = resp.text.splitlines()
            for i, line in enumerate(lines):
                if search in line:
                    start = max(0, i - 1)
                    end = min(len(lines), i + 2)
                    result["context_lines"] = [ln[:300] for ln in lines[start:end]]
                    break

    except Exception as e:
        result["error"] = str(e)[:120]

    return result


async def capture_page_screenshot(url: str, screenshot_file: str) -> dict:
    """
    Best-effort full-page screenshot capture for evidence.
    Returns dict with path/status and never raises.
    """
    result: dict = {
        "saved": False,
        "path": screenshot_file,
        "error": None,
    }

    if not screenshot_file:
        result["error"] = "no_output_path"
        return result

    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        result["error"] = f"playwright_unavailable:{type(e).__name__}"
        return result

    try:
        Path(screenshot_file).parent.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            page = await browser.new_page(viewport={"width": 1440, "height": 1024})

            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
            except Exception:
                # Still attempt screenshot even if networkidle waits out.
                pass

            await page.screenshot(path=screenshot_file, full_page=True)
            await browser.close()

        result["saved"] = os.path.exists(screenshot_file)
        if not result["saved"]:
            result["error"] = "screenshot_not_created"

    except Exception as e:
        result["error"] = f"screenshot_failed:{type(e).__name__}:{str(e)[:120]}"

    return result


async def capture_finding_evidence(
    raw_output_dict: dict,
    output_file: str,
    screenshot_file: Optional[str] = None,
) -> dict:
    """
    Given a raw finding dict (from raw_findings), capture HTTP evidence and
    validate any API keys. Returns enriched evidence dict.
    Saves to output_file if provided.
    """
    source = raw_output_dict.get("_source", "")
    evidence: dict = {
        "source": source,
        "http_fetch": None,
        "key_validation": None,
        "screenshot": None,
    }

    if source == "js_scanner":
        js_url = raw_output_dict.get("matched-at", "")
        secret_type = raw_output_dict.get("_secret_type", "")
        extracted = raw_output_dict.get("extracted-results", [])
        match_val = extracted[0] if extracted else raw_output_dict.get("_match", "")

        # Capture the JS file content showing the secret in context
        if js_url and match_val:
            evidence["http_fetch"] = await capture_http_evidence(js_url, match_val)

        # Capture visual evidence as PNG (best-effort; never blocks finding flow).
        if js_url and screenshot_file:
            evidence["screenshot"] = await capture_page_screenshot(js_url, screenshot_file)

        # Validate the API key if we know how
        if secret_type and match_val:
            evidence["key_validation"] = await validate_api_key(secret_type, match_val)

    if output_file:
        try:
            import aiofiles
            async with aiofiles.open(output_file, "w", encoding="utf-8") as f:
                await f.write(json.dumps(evidence, indent=2))
        except Exception:
            pass

    return evidence
