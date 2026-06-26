"""
BB_Assist — Impact Validator
=============================
Минимальный, неразрушающий валидатор для подтверждения уязвимости.

Принципы:
  - Только READ-операции или безопасные probe-запросы
  - Никакой записи, модификации, удаления данных
  - Никакого использования полученных данных за пределами PoC
  - Останавливается сразу после подтверждения факта уязвимости
  - Все результаты — для отчёта, не для эксплуатации

Поддерживаемые типы:
  - firebase_key       : проверка анонимной аутентификации
  - google_maps_key    : проверка работоспособности ключа
  - exposed_jwt        : декодирование и проверка claims
  - open_redirect      : проверка Location header без перехода
  - s3_bucket          : проверка публичного листинга
  - graphql_introspect : проверка открытой интроспекции
"""

import asyncio
import base64
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 10  # секунд


# ──────────────────────────────────────────────────────────
# Модели данных
# ──────────────────────────────────────────────────────────

class ProbeStatus(str, Enum):
    CONFIRMED   = "CONFIRMED"
    NOT_VULN    = "NOT_VULN"
    RESTRICTED  = "RESTRICTED"
    ERROR       = "ERROR"


@dataclass
class ProbeResult:
    status:      ProbeStatus
    vuln_type:   str
    evidence:    dict = field(default_factory=dict)
    poc_command: str = ""
    note:        str = ""

    def summary(self) -> str:
        lines = [
            f"━━━ Impact Validator: {self.vuln_type} ━━━",
            f"Status  : {self.status.value}",
            f"Note    : {self.note}",
        ]
        if self.evidence:
            lines.append("Evidence:")
            for k, v in self.evidence.items():
                lines.append(f"  {k}: {v}")
        if self.poc_command:
            lines.append(f"\nPoC command:\n  {self.poc_command}")
        lines.append("━" * 45)
        return "\n".join(lines)

    def to_report_block(self) -> str:
        """Готовый блок для вставки в H1-отчёт."""
        if self.status != ProbeStatus.CONFIRMED:
            return ""
        lines = ["**Proof of Exploitability (non-destructive):**\n"]
        lines.append(f"```bash\n{self.poc_command}\n```\n")
        lines.append("**Response confirms vulnerability:**\n```json")
        lines.append(json.dumps(self.evidence, indent=2, ensure_ascii=False))
        lines.append("```")
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────
# Валидаторы
# ──────────────────────────────────────────────────────────

class ImpactValidator:

    @staticmethod
    async def firebase_key(api_key: str) -> ProbeResult:
        """
        Проверяет, включена ли анонимная аутентификация в Firebase проекте.
        Что делает:  POST signUp без email/password
        Что НЕ делает: не читает Firestore, не трогает Storage, не использует idToken
        """
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
        poc_cmd = (
            f'curl -s -X POST \\\n'
            f'  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}" \\\n'
            f'  -H "Content-Type: application/json" \\\n'
            f'  -d \'{{"returnSecureToken":true}}\''
        )
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(url, json={"returnSecureToken": True})
                data = resp.json()

            if resp.status_code == 200 and "idToken" in data:
                return ProbeResult(
                    status=ProbeStatus.CONFIRMED,
                    vuln_type="firebase_key",
                    evidence={
                        "http_status":      resp.status_code,
                        "anonymous_auth":   "ENABLED",
                        "token_received":   True,
                        "local_id_present": "localId" in data,
                    },
                    poc_command=poc_cmd,
                    note="Anonymous authentication is enabled. "
                         "An unauthenticated attacker can obtain a valid Firebase token.",
                )

            error = data.get("error", {})
            if error.get("message") == "ADMIN_ONLY_OPERATION":
                return ProbeResult(
                    status=ProbeStatus.RESTRICTED,
                    vuln_type="firebase_key",
                    evidence={"error": error.get("message")},
                    note="Anonymous auth disabled. Key may still be misused for other APIs.",
                )

            return ProbeResult(
                status=ProbeStatus.NOT_VULN,
                vuln_type="firebase_key",
                evidence={"http_status": resp.status_code, "error": error.get("message")},
                note="Key appears restricted or invalid.",
            )
        except Exception as e:
            return ProbeResult(status=ProbeStatus.ERROR, vuln_type="firebase_key", note=str(e))

    @staticmethod
    async def google_maps_key(api_key: str) -> ProbeResult:
        """
        Проверяет, является ли Google Maps ключ неограниченным.
        Что делает:  GET Geocoding API с безобидным адресом
        Что НЕ делает: не сохраняет результаты, не делает массовые запросы
        """
        url = f"https://maps.googleapis.com/maps/api/geocode/json?address=London&key={api_key}"
        poc_cmd = (
            f'curl -s "https://maps.googleapis.com/maps/api/geocode/json'
            f'?address=London&key={api_key}"'
        )
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(url)
                data = resp.json()

            status = data.get("status")
            if status == "OK":
                return ProbeResult(
                    status=ProbeStatus.CONFIRMED,
                    vuln_type="google_maps_key",
                    evidence={
                        "http_status":   resp.status_code,
                        "api_status":    status,
                        "results_count": len(data.get("results", [])),
                        "unrestricted":  True,
                    },
                    poc_command=poc_cmd,
                    note="Key is valid and unrestricted. "
                         "Any third party can make billable Maps API calls.",
                )

            if status == "REQUEST_DENIED":
                return ProbeResult(
                    status=ProbeStatus.RESTRICTED,
                    vuln_type="google_maps_key",
                    evidence={"api_status": status, "error_message": data.get("error_message", "")},
                    note="Key has referrer/IP restrictions applied.",
                )

            return ProbeResult(
                status=ProbeStatus.NOT_VULN,
                vuln_type="google_maps_key",
                evidence={"api_status": status},
                note="Key is invalid or quota exhausted.",
            )
        except Exception as e:
            return ProbeResult(status=ProbeStatus.ERROR, vuln_type="google_maps_key", note=str(e))

    @staticmethod
    async def exposed_jwt(token: str) -> ProbeResult:
        """Декодирует JWT и проверяет claims. Только локальный анализ, без сети."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return ProbeResult(status=ProbeStatus.NOT_VULN, vuln_type="exposed_jwt",
                                   note="Not a valid JWT format.")

            def b64_decode(s: str) -> dict:
                s += "=" * (4 - len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s))

            header  = b64_decode(parts[0])
            payload = b64_decode(parts[1])

            import time
            now = int(time.time())
            exp = payload.get("exp", 0)
            is_expired = exp < now if exp else None

            safe_payload = {k: v for k, v in payload.items()
                            if k not in ("sub", "email", "phone_number", "uid")}

            evidence = {
                "algorithm":  header.get("alg"),
                "token_type": header.get("typ"),
                "issuer":     payload.get("iss"),
                "audience":   payload.get("aud"),
                "is_expired": is_expired,
                "has_exp":    "exp" in payload,
                "claims":     list(safe_payload.keys()),
            }

            note = "JWT successfully decoded without signature verification."
            if is_expired is False:
                note += " Token is still VALID (not expired)."
            elif is_expired:
                note += " Token is expired."

            return ProbeResult(
                status=ProbeStatus.CONFIRMED,
                vuln_type="exposed_jwt",
                evidence=evidence,
                poc_command=f'echo "{parts[1]}" | base64 -d | python3 -m json.tool',
                note=note,
            )
        except Exception as e:
            return ProbeResult(status=ProbeStatus.ERROR, vuln_type="exposed_jwt", note=str(e))

    @staticmethod
    async def open_redirect(url: str, param: str = "url") -> ProbeResult:
        """Проверяет open redirect через Location header. Не переходит по редиректу."""
        test_url = f"{url}?{param}=https://example.com"
        poc_cmd  = f'curl -s -I "{test_url}" | grep -i location'
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
                resp = await client.get(test_url)

            location = resp.headers.get("location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and "example.com" in location:
                return ProbeResult(
                    status=ProbeStatus.CONFIRMED,
                    vuln_type="open_redirect",
                    evidence={"http_status": resp.status_code, "location": location,
                              "redirect_to": "attacker-controlled domain"},
                    poc_command=poc_cmd,
                    note="Server redirects to attacker-supplied URL without validation.",
                )
            return ProbeResult(
                status=ProbeStatus.NOT_VULN,
                vuln_type="open_redirect",
                evidence={"http_status": resp.status_code, "location": location or "none"},
                note="No open redirect detected.",
            )
        except Exception as e:
            return ProbeResult(status=ProbeStatus.ERROR, vuln_type="open_redirect", note=str(e))

    @staticmethod
    async def s3_bucket_listing(bucket_url: str) -> ProbeResult:
        """Проверяет публичный листинг S3. Только считает файлы, не скачивает."""
        poc_cmd = f'curl -s "{bucket_url}" | grep -o "<Key>[^<]*</Key>" | head -5'
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(bucket_url)

            if resp.status_code == 200 and "<ListBucketResult" in resp.text:
                keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
                return ProbeResult(
                    status=ProbeStatus.CONFIRMED,
                    vuln_type="s3_bucket_listing",
                    evidence={"http_status": resp.status_code, "public": True,
                              "files_count": len(keys)},
                    poc_command=poc_cmd,
                    note=f"S3 bucket is publicly listable. {len(keys)} objects visible.",
                )
            if resp.status_code == 403:
                return ProbeResult(status=ProbeStatus.RESTRICTED, vuln_type="s3_bucket_listing",
                                   evidence={"http_status": 403},
                                   note="Bucket exists but listing is denied.")
            return ProbeResult(status=ProbeStatus.NOT_VULN, vuln_type="s3_bucket_listing",
                               evidence={"http_status": resp.status_code},
                               note="Bucket not accessible.")
        except Exception as e:
            return ProbeResult(status=ProbeStatus.ERROR, vuln_type="s3_bucket_listing", note=str(e))

    @staticmethod
    async def graphql_introspection(endpoint: str) -> ProbeResult:
        """Проверяет открытую GraphQL интроспекцию. Стандартный безопасный запрос."""
        query   = {"query": "{ __schema { queryType { name } } }"}
        poc_cmd = (
            f'curl -s -X POST "{endpoint}" \\\n'
            f'  -H "Content-Type: application/json" \\\n'
            f'  -d \'{{"query":"{{ __schema {{ queryType {{ name }} }} }}"}}\''
        )
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(endpoint, json=query,
                                         headers={"Content-Type": "application/json"})
                data = resp.json()

            if "data" in data and "__schema" in data.get("data", {}):
                schema = data["data"]["__schema"]
                return ProbeResult(
                    status=ProbeStatus.CONFIRMED,
                    vuln_type="graphql_introspection",
                    evidence={"http_status": resp.status_code, "introspection": "ENABLED",
                              "query_type": schema.get("queryType", {}).get("name")},
                    poc_command=poc_cmd,
                    note="GraphQL introspection is enabled in production.",
                )
            return ProbeResult(status=ProbeStatus.NOT_VULN, vuln_type="graphql_introspection",
                               evidence={"http_status": resp.status_code},
                               note="Introspection disabled or endpoint not GraphQL.")
        except Exception as e:
            return ProbeResult(status=ProbeStatus.ERROR, vuln_type="graphql_introspection",
                               note=str(e))


# ──────────────────────────────────────────────────────────
# Фасад
# ──────────────────────────────────────────────────────────

VALIDATOR_MAP = {
    "firebase_key":          ImpactValidator.firebase_key,
    "google_maps_key":       ImpactValidator.google_maps_key,
    "exposed_jwt":           ImpactValidator.exposed_jwt,
    "open_redirect":         ImpactValidator.open_redirect,
    "s3_bucket_listing":     ImpactValidator.s3_bucket_listing,
    "graphql_introspection": ImpactValidator.graphql_introspection,
}


async def validate_impact(vuln_type: str, **kwargs) -> ProbeResult:
    validator = VALIDATOR_MAP.get(vuln_type)
    if not validator:
        return ProbeResult(
            status=ProbeStatus.ERROR,
            vuln_type=vuln_type,
            note=f"Unknown vuln_type: '{vuln_type}'. Available: {list(VALIDATOR_MAP.keys())}",
        )
    return await validator(**kwargs)


# ──────────────────────────────────────────────────────────
# Pipeline integration helper
# ──────────────────────────────────────────────────────────

# Маппинг BB_Assist vuln_type → тип валидатора + способ извлечения параметра
_PIPELINE_MAP: dict[str, tuple[str, str]] = {
    # (validator_type, param_name)
    "token-disclosure":    ("auto_key", "api_key"),   # определяем firebase/gmaps по контексту
    "firebase":            ("firebase_key", "api_key"),
    "google-maps":         ("google_maps_key", "api_key"),
    "open-redirect":       ("open_redirect", "url"),
    "s3-bucket":           ("s3_bucket_listing", "bucket_url"),
    "graphql":             ("graphql_introspection", "endpoint"),
    "graphql_introspection":("graphql_introspection", "endpoint"),
    "exposed_jwt":         ("exposed_jwt", "token"),
}

# Regex для извлечения ключей из raw_output
_KEY_PATTERNS = [
    re.compile(r'apiKey["\s:=]+["\']?(AIza[A-Za-z0-9_\-]{35})["\']?'),
    re.compile(r'"key"\s*:\s*"(AIza[A-Za-z0-9_\-]{35})"'),
    re.compile(r'(AIza[A-Za-z0-9_\-]{35})'),
]


def _extract_api_key(raw_output: str) -> Optional[str]:
    """Extract Google/Firebase API key from raw tool output."""
    for pattern in _KEY_PATTERNS:
        m = pattern.search(raw_output)
        if m:
            return m.group(1)
    return None


def _is_firebase_context(raw_output: str) -> bool:
    """Distinguish Firebase key from plain Google Maps key by context."""
    lower = raw_output.lower()
    return any(word in lower for word in
               ("firebase", "firebaseapp", "identitytoolkit", "firestore", "authDomain"))


async def run_for_finding(finding) -> Optional[ProbeResult]:
    """
    Pipeline entry point: determines validator type from a Finding object,
    extracts parameters from raw_output, and runs the appropriate probe.

    Returns None if no validator applies to this finding type.
    """
    vuln_type = (finding.vuln_type or "").lower()
    raw       = finding.raw_output or ""

    # token-disclosure: distinguish Firebase vs Google Maps
    if vuln_type == "token-disclosure" or "api key" in (finding.title or "").lower():
        api_key = _extract_api_key(raw)
        if not api_key:
            return None
        if _is_firebase_context(raw):
            logger.info("[ImpactValidator] firebase_key → %s", api_key[:12] + "...")
            return await ImpactValidator.firebase_key(api_key)
        else:
            logger.info("[ImpactValidator] google_maps_key → %s", api_key[:12] + "...")
            return await ImpactValidator.google_maps_key(api_key)

    # open redirect
    if "redirect" in vuln_type:
        return await ImpactValidator.open_redirect(url=finding.url)

    # graphql
    if "graphql" in vuln_type:
        return await ImpactValidator.graphql_introspection(endpoint=finding.url)

    # s3
    if "s3" in vuln_type or "bucket" in vuln_type:
        return await ImpactValidator.s3_bucket_listing(bucket_url=finding.url)

    # jwt
    if "jwt" in vuln_type or "token" in vuln_type:
        jwt_match = re.search(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', raw)
        if jwt_match:
            return await ImpactValidator.exposed_jwt(token=jwt_match.group(0))

    return None


# ──────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────

async def _main():
    import sys
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if len(sys.argv) < 3:
        print("Usage: python impact_validator.py <vuln_type> <value>")
        print("Examples:")
        print("  python impact_validator.py firebase_key    AIzaSy...")
        print("  python impact_validator.py google_maps_key AIzaSy...")
        print("  python impact_validator.py open_redirect   https://target.com/redir")
        print("  python impact_validator.py graphql_introspection https://target.com/graphql")
        return

    vuln_type = sys.argv[1]
    value     = sys.argv[2]

    kwarg_map = {
        "firebase_key":           {"api_key": value},
        "google_maps_key":        {"api_key": value},
        "exposed_jwt":            {"token": value},
        "open_redirect":          {"url": value},
        "s3_bucket_listing":      {"bucket_url": value},
        "graphql_introspection":  {"endpoint": value},
    }

    result = await validate_impact(vuln_type, **kwarg_map.get(vuln_type, {}))
    print(result.summary())

    if result.status == ProbeStatus.CONFIRMED:
        print("\n── Report Block (copy-paste to H1) ──")
        print(result.to_report_block())


if __name__ == "__main__":
    asyncio.run(_main())
