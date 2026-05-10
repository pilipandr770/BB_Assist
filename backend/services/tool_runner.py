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
import json
import os
import re
import tempfile
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

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
    """
    domains_file = _write_temp_list(domains)
    try:
        cmd = [
            "subfinder",
            "-dL", domains_file,
            "-silent",
            "-o", output_file,
            "-t", "50",         # threads
            "-timeout", "30",   # per-domain timeout
        ]
        rc, stdout, _ = await _run_command(cmd, stream_key=f"tool:subfinder:{output_file}")

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
        await _run_command(cmd, stream_key=f"tool:dnsx:{output_file}")

        if os.path.exists(output_file):
            with open(output_file) as f:
                return [line.strip() for line in f if line.strip()]
        return []
    finally:
        os.unlink(input_file)


async def run_httpx(hosts: list[str], output_file: str) -> list[dict]:
    """
    Probe live HTTP hosts and gather info.
    Note: -silent is intentionally omitted — it suppresses JSON output in newer httpx versions.
    We parse both the output file and stdout to be safe.
    """
    input_file = _write_temp_list(hosts)
    try:
        cmd = [
            "httpx",
            "-l", input_file,
            "-json",
            "-o", output_file,
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-follow-redirects",
            "-threads", "20",
            "-timeout", "15",
            "-rate-limit", "30",   # 150 was getting CDN-blocked (Cloudflare 429)
            "-no-color",
            "-retries", "1",
        ]
        rc, stdout, stderr = await _run_command(cmd, stream_key=f"tool:httpx:{output_file}")

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

        # Try output file first, then fall back to stdout
        if os.path.exists(output_file):
            with open(output_file) as f:
                _parse_jsonl(f.read())
        if not results and stdout:
            _parse_jsonl(stdout)

        return results
    finally:
        os.unlink(input_file)


async def run_gau(domain: str, output_file: str) -> list[str]:
    """
    Fetch known URLs from various sources (Wayback, Common Crawl, etc).
    Command: gau {domain} --blacklist png,jpg,gif,css,woff --o {output_file}
    """
    cmd = [
        "gau",
        domain,
        "--blacklist", "png,jpg,gif,jpeg,svg,ico,css,woff,woff2,ttf,mp4,mp3",
        "--o", output_file,
        "--threads", "5",
        "--timeout", "30",
    ]
    await _run_command(cmd, stream_key=f"tool:gau:{output_file}")

    if os.path.exists(output_file):
        with open(output_file) as f:
            return [line.strip() for line in f if line.strip()]
    return []


async def run_katana(urls: list[str], output_file: str) -> list[str]:
    """
    Web crawl target URLs for endpoint discovery.
    Command: katana -list {input_file} -silent -jc -o {output_file} -depth 3
    """
    input_file = _write_temp_list(urls)
    try:
        cmd = [
            "katana",
            "-list", input_file,
            "-silent",
            "-jc",              # JS crawling
            "-o", output_file,
            "-depth", "3",
            "-concurrency", "10",
            "-rate-limit", "50",
            "-timeout", "10",
        ]
        await _run_command(cmd, stream_key=f"tool:katana:{output_file}")

        if os.path.exists(output_file):
            with open(output_file) as f:
                return [line.strip() for line in f if line.strip()]
        return []
    finally:
        os.unlink(input_file)


async def run_nuclei(
    urls: list[str],
    output_file: str,
    scope: Scope,
    tags: str = NUCLEI_TAGS_RUN,
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

        cmd = [
            "nuclei",
            "-l", input_file,
            "-severity", NUCLEI_SEVERITY,
            "-jsonl-export", output_file,   # nuclei v3: JSONL file export
            "-j",                            # nuclei v3: JSONL to stdout too
            "-silent",
            "-rate-limit", "150",
            "-bulk-size", "50",
            "-concurrency", "25",
            "-timeout", "10",
            "-retries", "1",
            "-nc",                           # no color codes in output
            # Note: interactsh ENABLED intentionally — needed for blind SSRF/XSS/XXE detection
        ] + template_args

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
        return findings
    finally:
        os.unlink(input_file)


async def run_ffuf(url: str, wordlist: str, output_file: str) -> list[dict]:
    """
    Directory/endpoint fuzzing with ffuf.
    Returns all results (200/201/301/302/403) so callers can extract 403s
    for bypass testing and 200s for new attack surface.
    """
    # Try common wordlist locations
    if not wordlist or not os.path.exists(wordlist):
        for candidate in [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/wordlists/common.txt",
        ]:
            if os.path.exists(candidate):
                wordlist = candidate
                break
        else:
            return []  # No wordlist available

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
    ]
    await _run_command(cmd, stream_key=f"tool:ffuf:{output_file}", timeout_s=180)

    if os.path.exists(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
                return data.get("results", [])
        except (json.JSONDecodeError, KeyError):
            return []
    return []


async def run_dalfox(url: str, params: list[str], output_file: str) -> list[dict]:
    """
    XSS scanner — only call if nuclei or manual review flagged XSS candidate.
    Command: dalfox url {url} --silence --format json -o {output_file}
    """
    cmd = [
        "dalfox",
        "url", url,
        "--silence",
        "--format", "json",
        "-o", output_file,
        "--timeout", "10",
        "--delay", "100",
    ]

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


async def run_arjun(url: str, output_file: str) -> list[str]:
    """
    Discover hidden HTTP parameters.
    Command: arjun -u {url} -oJ {output_file} --stable -q
    """
    cmd = [
        "arjun",
        "-u", url,
        "-oJ", output_file,
        "--stable",
        "-q",
        "-t", "10",
    ]
    await _run_command(cmd, stream_key=f"tool:arjun:{output_file}")

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
    Caps at 80 URLs, runs 10 downloads concurrently in a thread pool.
    """
    import logging
    log = logging.getLogger("tool_runner")

    if not js_urls:
        return []

    urls_to_scan = js_urls[:80]
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
    targets = (api_urls + other_urls)[:60]

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


# ── GitHub Dorking ────────────────────────────────────────────────────────────

# Search queries — prioritised by signal quality
_GITHUB_DORK_QUERIES = [
    '"{domain}" password',
    '"{domain}" api_key OR apikey',
    '"{domain}" secret',
    '"{domain}" token',
    '"{domain}" authorization',
    '"{domain}" access_key OR accesskey',
    '"{domain}" credentials',
    '"{domain}" private_key',
]

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
                    if regex.search(combined):
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

    # Deduplicate domains and pick the base apex domains
    apex_domains: list[str] = []
    seen: set[str] = set()
    for d in domains:
        apex = d.lstrip("*.")
        if apex not in seen:
            seen.add(apex)
            apex_domains.append(apex)

    all_findings: list[dict] = []
    loop = asyncio.get_event_loop()

    for domain in apex_domains[:3]:  # Max 3 domains to avoid rate limit
        for query_template in _GITHUB_DORK_QUERIES[:5]:  # 5 queries per domain
            query = query_template.replace("{domain}", domain)
            results = await loop.run_in_executor(
                None, _github_search_sync, query, github_token
            )
            all_findings.extend(results)
            await asyncio.sleep(2.5)  # 30 req/min auth limit = 2s min; add buffer

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

    log.info("github_dork: %d secrets found across %d domains",
             len(unique_findings), len(apex_domains))
    return unique_findings
