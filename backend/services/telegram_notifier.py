import httpx

from backend.config import settings


async def _send_message(text: str) -> None:
    token = settings.telegram_bot_token or ""
    chat_id = settings.telegram_chat_id or ""
    if not token or not chat_id:
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json=payload)
    except Exception:
        # Silent by design — notifications must never break scan flow.
        return


async def send_scan_done(program_name: str, findings: int, reports: int, duration_min: int):
    text = (
        f"*Scan complete*\n"
        f"Target: `{program_name}`\n"
        f"Duration: {duration_min} min\n"
        f"Findings: {findings}\n"
        f"Reports: {reports}"
    )
    await _send_message(text)


async def send_critical_finding(program_name: str, title: str, severity: str, target: str):
    text = (
        f"*High-priority finding*\n"
        f"Target: `{program_name}`\n"
        f"Severity: {severity}\n"
        f"Title: {title}\n"
        f"Asset: `{target}`"
    )
    await _send_message(text)
