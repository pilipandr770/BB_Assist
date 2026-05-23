import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import re
import tarfile
import tempfile
from datetime import datetime, timezone
from typing import Optional

import httpx

from backend.config import settings


log = logging.getLogger("cve_updater")

CSV_HEADERS = ["product", "version_regex", "cve", "severity", "title", "reference"]


def _looks_like_cvelist_repo_url(url: str) -> bool:
    u = (url or "").lower().strip()
    return "github.com/cveproject/cvelistv5" in u or "codeload.github.com/cveproject/cvelistv5" in u


def _codeload_tar_url(repo_url: str) -> str:
    # Accept both GitHub repo URL and direct codeload URL.
    u = (repo_url or "").strip()
    if "codeload.github.com/CVEProject/cvelistV5/tar.gz" in u:
        return u
    return "https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main"


def _normalize_product_name(raw: str) -> str:
    p = (raw or "").strip().lower()
    if not p or p in {"n/a", "na", "unknown", "none"}:
        return ""
    p = re.sub(r"\s+", " ", p)
    return p[:120]


def _extract_primary_version_text(version_obj: dict) -> str:
    if not isinstance(version_obj, dict):
        return ""
    for key in ("version", "lessThanOrEqual", "lessThan", "changes"):
        val = version_obj.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _version_to_regex(version_text: str) -> str:
    v = (version_text or "").strip().lower()
    if not v:
        return ""

    v = v.replace("<=", "").replace("<", "").replace(">=", "").replace(">", "").strip()
    v = re.sub(r"\s+", "", v)

    if v in {"*", "all", "unspecified", "unknown", "n/a"}:
        return ".*"

    # Keep semver-like chunk only; avoid distro suffix noise where possible.
    match = re.search(r"[0-9]+(?:\.[0-9a-zA-Z]+){0,4}", v)
    token = match.group(0) if match else v

    escaped = re.escape(token)
    escaped = escaped.replace(r"\*", ".*").replace("x", "[0-9]+")
    return escaped


def _severity_from_record(cna: dict) -> str:
    metrics = cna.get("metrics") or []
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            cvss = metric.get(key)
            if isinstance(cvss, dict):
                sev = (cvss.get("baseSeverity") or "").strip().lower()
                if sev in {"critical", "high", "medium", "low"}:
                    return sev
                score = cvss.get("baseScore")
                if isinstance(score, (int, float)):
                    if score >= 9.0:
                        return "critical"
                    if score >= 7.0:
                        return "high"
                    if score >= 4.0:
                        return "medium"
                    return "low"
    return "medium"


def _title_from_record(cna: dict, cve_id: str) -> str:
    title = (cna.get("title") or "").strip()
    if title:
        return title[:180]
    for desc in cna.get("descriptions") or []:
        if isinstance(desc, dict) and (desc.get("lang") or "").lower() == "en":
            value = (desc.get("value") or "").strip()
            if value:
                return value.split("\n", 1)[0][:180]
    return f"Version-based match for {cve_id}"


def _iter_affected_sections(record: dict) -> list[dict]:
    containers = record.get("containers") or {}
    sections: list[dict] = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        sections.append(cna)
    for adp in containers.get("adp") or []:
        if isinstance(adp, dict):
            sections.append(adp)
    return sections


def _generate_csv_from_cvelist_tar_bytes(data: bytes) -> tuple[str, int]:
    now_year = datetime.now(timezone.utc).year
    min_year = max(now_year - max(int(settings.cve_cvelist_years_back or 8), 1), 1999)
    max_rows = max(int(settings.cve_cvelist_max_rows or 20000), 1000)

    rows: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf:
            name = member.name
            if not name.endswith(".json") or "/cves/" not in name:
                continue

            year_match = re.search(r"/cves/(\d{4})/", name)
            if year_match:
                year = int(year_match.group(1))
                if year < min_year:
                    continue

            fileobj = tf.extractfile(member)
            if not fileobj:
                continue
            try:
                record = json.loads(fileobj.read().decode("utf-8", errors="ignore"))
            except Exception:
                continue

            cve_id = ((record.get("cveMetadata") or {}).get("cveId") or "").strip()
            if not cve_id.startswith("CVE-"):
                continue

            for section in _iter_affected_sections(record):
                severity = _severity_from_record(section)
                title = _title_from_record(section, cve_id)
                reference = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                affected = section.get("affected") or []

                for aff in affected:
                    if not isinstance(aff, dict):
                        continue
                    product = _normalize_product_name(
                        (aff.get("product") or aff.get("packageName") or "")
                    )
                    if not product:
                        continue

                    default_status = (aff.get("defaultStatus") or "").strip().lower()
                    versions = aff.get("versions") or []
                    if not versions and default_status == "affected":
                        key = (product, ".*", cve_id)
                        if key not in seen:
                            seen.add(key)
                            rows.append({
                                "product": product,
                                "version_regex": ".*",
                                "cve": cve_id,
                                "severity": severity,
                                "title": title,
                                "reference": reference,
                            })
                        continue

                    for ver in versions[:8]:
                        if not isinstance(ver, dict):
                            continue
                        status = (ver.get("status") or default_status or "").strip().lower()
                        if status and status not in {"affected", "unknown"}:
                            continue

                        version_text = _extract_primary_version_text(ver)
                        version_regex = _version_to_regex(version_text)
                        if not version_regex:
                            continue

                        key = (product, version_regex, cve_id)
                        if key in seen:
                            continue
                        seen.add(key)
                        rows.append({
                            "product": product,
                            "version_regex": version_regex,
                            "cve": cve_id,
                            "severity": severity,
                            "title": title,
                            "reference": reference,
                        })

                        if len(rows) >= max_rows:
                            break
                    if len(rows) >= max_rows:
                        break
                if len(rows) >= max_rows:
                    break
            if len(rows) >= max_rows:
                break

    if not rows:
        return "", 0

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_HEADERS)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return output.getvalue(), len(rows)


def _default_csv_path() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data",
        "cve_service_versions.csv",
    )


def _meta_path(csv_path: str) -> str:
    return f"{csv_path}.meta.json"


def _load_meta(csv_path: str) -> dict:
    path = _meta_path(csv_path)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_meta(csv_path: str, meta: dict) -> None:
    path = _meta_path(csv_path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=True, indent=2)


def _csv_is_valid(csv_text: str) -> tuple[bool, int]:
    try:
        rows = list(csv.DictReader(csv_text.splitlines()))
    except Exception:
        return False, 0

    if not rows:
        return False, 0

    sample = rows[0]
    for h in CSV_HEADERS:
        if h not in sample:
            return False, 0
    return True, len(rows)


async def refresh_cve_csv_if_needed(force: bool = False, csv_path: Optional[str] = None) -> dict:
    """
    Refresh local CVE CSV from a remote curated CSV URL (if configured).
    Safe behavior:
      - Does nothing when CVE_CSV_REMOTE_URL is unset
      - Validates headers and row count before replacing local DB
      - Uses atomic replace to avoid partial files
    """
    remote_url = (settings.cve_csv_remote_url or "").strip()
    if not remote_url:
        return {"status": "skipped", "reason": "remote_url_not_configured"}

    local_csv = csv_path or _default_csv_path()
    os.makedirs(os.path.dirname(local_csv), exist_ok=True)

    interval_h = max(int(settings.cve_csv_refresh_hours or 24), 1)
    now = datetime.now(timezone.utc)
    meta = _load_meta(local_csv)

    if not force:
        last_ok = meta.get("last_success_utc")
        if last_ok:
            try:
                last_dt = datetime.fromisoformat(last_ok)
                age_h = (now - last_dt).total_seconds() / 3600.0
                if age_h < interval_h:
                    return {"status": "skipped", "reason": "interval_not_reached", "age_hours": round(age_h, 2)}
            except Exception:
                pass

    timeout = httpx.Timeout(20.0, connect=10.0)
    csv_text = ""
    row_count = 0
    source_kind = "remote_csv"

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            if _looks_like_cvelist_repo_url(remote_url):
                source_kind = "cvelistv5"
                tar_url = _codeload_tar_url(remote_url)
                resp = await client.get(tar_url, timeout=httpx.Timeout(180.0, connect=20.0))
                resp.raise_for_status()
                csv_text, row_count = _generate_csv_from_cvelist_tar_bytes(resp.content)
                if not csv_text or row_count <= 0:
                    return {"status": "error", "error": "cvelist_conversion_empty"}
            else:
                resp = await client.get(remote_url)
                resp.raise_for_status()
                csv_text = resp.text
                ok, row_count = _csv_is_valid(csv_text)
                if not ok:
                    return {"status": "error", "error": "remote_csv_invalid_format"}
    except Exception as e:
        log.warning("cve_csv refresh failed: %s", e)
        return {"status": "error", "error": str(e)}

    digest = hashlib.sha256(csv_text.encode("utf-8", errors="ignore")).hexdigest()
    if meta.get("sha256") == digest and os.path.exists(local_csv):
        new_meta = {
            **meta,
            "last_checked_utc": now.isoformat(),
            "last_success_utc": now.isoformat(),
            "rows": row_count,
        }
        _write_meta(local_csv, new_meta)
        return {"status": "unchanged", "rows": row_count}

    fd, tmp_path = tempfile.mkstemp(
        prefix="cve_csv_",
        suffix=".csv",
        dir=os.path.dirname(local_csv),
    )
    os.close(fd)
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_text)
        os.replace(tmp_path, local_csv)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    new_meta = {
        "source_url": remote_url,
        "source_kind": source_kind,
        "last_checked_utc": now.isoformat(),
        "last_success_utc": now.isoformat(),
        "rows": row_count,
        "sha256": digest,
    }
    _write_meta(local_csv, new_meta)
    log.info("cve_csv refreshed: rows=%d source=%s", row_count, remote_url)
    return {"status": "updated", "rows": row_count}


async def periodic_cve_csv_refresh_loop() -> None:
    """
    Background loop that keeps CVE CSV fresh on a fixed interval.
    Exits silently when remote URL is not configured.
    """
    remote_url = (settings.cve_csv_remote_url or "").strip()
    if not remote_url:
        return

    # Immediate startup check, then periodic refreshes.
    try:
        result = await refresh_cve_csv_if_needed(force=False)
        log.info("cve_csv startup refresh: %s", result)
    except Exception as e:
        log.warning("cve_csv startup refresh exception: %s", e)

    interval_s = max(int(settings.cve_csv_refresh_hours or 24), 1) * 3600
    while True:
        await asyncio.sleep(interval_s)
        try:
            result = await refresh_cve_csv_if_needed(force=False)
            if result.get("status") not in {"skipped", "unchanged"}:
                log.info("cve_csv periodic refresh: %s", result)
        except Exception as e:
            log.warning("cve_csv periodic refresh exception: %s", e)
