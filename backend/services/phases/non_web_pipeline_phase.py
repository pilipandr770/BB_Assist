"""Phase helper for non-web scan modes: ip, source_code, and api."""

from collections.abc import Awaitable, Callable
import json
import os
import re

from backend.models import ScanJob, Scope
from backend.services import tool_runner


EventEmitter = Callable[[str, dict], Awaitable[None]]
PersistRawFindings = Callable[..., Awaitable[None]]


async def run_non_web_pipeline_phase(
    *,
    scan_mode: str,
    job: ScanJob,
    scope: Scope,
    scan_id: str,
    program_id: str,
    redis,
    scan_dir: str,
    finding_dir: str,
    llm_usage_start: dict | None,
    emit: EventEmitter,
    persist_raw_findings: PersistRawFindings,
) -> bool:
    # IP/CIDR pipeline
    if scan_mode == "ip":
        cidr_targets = list(scope.in_scope_cidrs or []) + [
            d
            for d in (scope.in_scope_domains or [])
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", d)
        ]
        await emit(
            "phase_start",
            {
                "phase": "ip_scan",
                "targets": cidr_targets,
            },
        )
        ip_out_dir = os.path.join(scan_dir, "ip_scan")
        ip_results = await tool_runner.run_ip_scan(
            targets=cidr_targets,
            output_dir=ip_out_dir,
            session_cookies=job.session_cookies,
            auth_header=job.auth_header,
        )
        await emit(
            "phase_done",
            {
                "phase": "ip_scan",
                "open_ports": len(ip_results["open_ports"]),
                "http_urls": len(ip_results["http_urls"]),
                "nuclei_findings": len(ip_results["nuclei_findings"]),
            },
        )

        all_findings_raw: list[dict] = []
        for finding in ip_results["nuclei_findings"]:
            severity = finding.get("info", {}).get("severity", "informative").lower()
            all_findings_raw.append(
                {
                    "tool": "nuclei_ip",
                    "title": finding.get("info", {}).get("name", finding.get("template-id", "finding")),
                    "url": finding.get("matched-at", finding.get("host", "")),
                    "severity": severity,
                    "vuln_type": ",".join(finding.get("info", {}).get("tags", [])),
                    "raw_output": json.dumps(finding),
                }
            )

        for service_line in ip_results["services"]:
            all_findings_raw.append(
                {
                    "tool": "nmap_ip",
                    "title": f"Open service: {service_line[:120]}",
                    "url": service_line.split()[1] if len(service_line.split()) > 1 else service_line[:80],
                    "severity": "informative",
                    "vuln_type": "exposed-service",
                    "raw_output": service_line,
                }
            )

        await emit(
            "scan_done",
            {
                "total_findings": len(all_findings_raw),
                "pipeline": "ip",
            },
        )
        await persist_raw_findings(
            redis=redis,
            scan_id=scan_id,
            program_id=program_id,
            raw_findings=all_findings_raw,
            job=job,
            finding_dir=finding_dir,
            llm_usage_start=llm_usage_start,
        )
        return True

    # Source code pipeline
    if scan_mode == "source_code":
        repo = job.repo_url or ""
        if not repo:
            await emit(
                "scan_error",
                {
                    "error": "source_code scan requires repo_url",
                },
            )
            return True

        await emit(
            "phase_start",
            {
                "phase": "source_scan",
                "repo_url": repo,
            },
        )
        src_out_dir = os.path.join(scan_dir, "source_scan")
        src_results = await tool_runner.run_source_scan(
            repo_url=repo,
            output_dir=src_out_dir,
        )
        await emit(
            "phase_done",
            {
                "phase": "source_scan",
                "gitleaks": len(src_results["gitleaks_findings"]),
                "semgrep": len(src_results["semgrep_findings"]),
                "trufflehog": len(src_results["trufflehog_findings"]),
            },
        )

        all_findings_raw = []
        for finding in src_results["gitleaks_findings"]:
            all_findings_raw.append(
                {
                    "tool": "gitleaks",
                    "title": f"Secret exposed: {finding.get('RuleID', 'unknown')}",
                    "url": finding.get("File", repo),
                    "severity": "high",
                    "vuln_type": "secret-exposure",
                    "raw_output": json.dumps(finding),
                }
            )
        for finding in src_results["semgrep_findings"]:
            all_findings_raw.append(
                {
                    "tool": "semgrep",
                    "title": finding.get("check_id", "semgrep-finding"),
                    "url": finding.get("path", repo) + f":{finding.get('start', {}).get('line', '')}",
                    "severity": finding.get("extra", {}).get("severity", "medium").lower(),
                    "vuln_type": finding.get("check_id", "sast"),
                    "raw_output": json.dumps(finding),
                }
            )
        for finding in src_results["trufflehog_findings"]:
            all_findings_raw.append(
                {
                    "tool": "trufflehog",
                    "title": f"Secret: {finding.get('DetectorName', 'unknown')}",
                    "url": finding.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("file", repo),
                    "severity": "high",
                    "vuln_type": "secret-exposure",
                    "raw_output": json.dumps(finding),
                }
            )

        await emit(
            "scan_done",
            {
                "total_findings": len(all_findings_raw),
                "pipeline": "source_code",
            },
        )
        await persist_raw_findings(
            redis=redis,
            scan_id=scan_id,
            program_id=program_id,
            raw_findings=all_findings_raw,
            job=job,
            finding_dir=finding_dir,
            llm_usage_start=llm_usage_start,
        )
        return True

    # API pipeline
    if scan_mode == "api" and job.api_spec_url:
        await emit(
            "phase_start",
            {
                "phase": "api_scan",
                "spec_url": job.api_spec_url,
            },
        )
        api_out_dir = os.path.join(scan_dir, "api_scan")
        api_results = await tool_runner.run_api_scan(
            spec_url=job.api_spec_url,
            output_dir=api_out_dir,
            session_cookies=job.session_cookies,
            auth_header=job.auth_header,
        )
        await emit(
            "phase_done",
            {
                "phase": "api_scan",
                "endpoints": len(api_results["endpoints"]),
                "ffuf_findings": len(api_results["ffuf_findings"]),
                "nuclei_findings": len(api_results["nuclei_findings"]),
                "arjun_params": len(api_results["arjun_params"]),
            },
        )

        all_findings_raw = []
        for finding in api_results["nuclei_findings"]:
            severity = finding.get("info", {}).get("severity", "informative").lower()
            all_findings_raw.append(
                {
                    "tool": "nuclei_api",
                    "title": finding.get("info", {}).get("name", finding.get("template-id", "finding")),
                    "url": finding.get("matched-at", ""),
                    "severity": severity,
                    "vuln_type": ",".join(finding.get("info", {}).get("tags", [])),
                    "raw_output": json.dumps(finding),
                }
            )
        for finding in api_results["ffuf_findings"]:
            status = finding.get("status", 0)
            all_findings_raw.append(
                {
                    "tool": "ffuf_api",
                    "title": f"Accessible endpoint [{status}]: {finding.get('url', '')}",
                    "url": finding.get("url", ""),
                    "severity": "informative",
                    "vuln_type": "exposed-endpoint",
                    "raw_output": json.dumps(finding),
                }
            )

        await emit(
            "scan_done",
            {
                "total_findings": len(all_findings_raw),
                "pipeline": "api",
            },
        )
        await persist_raw_findings(
            redis=redis,
            scan_id=scan_id,
            program_id=program_id,
            raw_findings=all_findings_raw,
            job=job,
            finding_dir=finding_dir,
            llm_usage_start=llm_usage_start,
        )
        return True

    return False
