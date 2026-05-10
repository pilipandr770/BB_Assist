import json
import os
import signal
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routers import programs, scans, reports


def _kill_child_processes():
    """Kill all child subprocesses (e.g. orphaned nuclei) on shutdown."""
    try:
        import subprocess
        result = subprocess.run(
            ["find", "/proc", "-maxdepth", "2", "-name", "comm"],
            capture_output=True, text=True, timeout=5,
        )
        our_pid = os.getpid()
        for comm_path in result.stdout.strip().split("\n"):
            try:
                with open(comm_path) as f:
                    name = f.read().strip()
                if name in ("nuclei", "subfinder", "httpx", "dnsx", "katana", "gau", "ffuf"):
                    pid = int(comm_path.split("/")[2])
                    if pid != our_pid:
                        os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
    except Exception:
        pass


async def _mark_zombie_scans():
    """
    On startup, push scan_error to any scan whose Redis event list ends without
    a scan_done/scan_error event. This handles scans interrupted by server
    restart or crash — the frontend will show an error instead of spinning forever.
    """
    try:
        import redis.asyncio as aioredis
        from backend.config import settings

        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()

        keys = await r.keys("scan:*:events")
        now = datetime.now(timezone.utc)
        for key in keys:
            try:
                last_raw = await r.lindex(key, -1)
                if not last_raw:
                    continue
                last = json.loads(last_raw)
                if last.get("type") in ("scan_done", "scan_error"):
                    continue  # already terminated

                # Check if last event is old enough to be a zombie (>2 min)
                ts_str = last.get("ts", "")
                if not ts_str:
                    continue
                last_ts = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)
                age_s = (now - last_ts).total_seconds()
                if age_s < 120:
                    continue  # might still be running

                # This is a zombie — push a scan_error so the frontend terminates
                scan_id = key.split(":")[1]
                event = json.dumps({
                    "type": "scan_error",
                    "data": {"error": "Scan was interrupted (server restart). Please start a new scan."},
                    "ts": now.isoformat(),
                })
                await r.rpush(key, event)
            except Exception:
                pass

        await r.aclose()
    except Exception:
        pass  # Redis unavailable — skip zombie cleanup


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: kill orphan tool processes and mark zombie scans as error
    _kill_child_processes()
    await _mark_zombie_scans()
    yield
    # Shutdown: kill all child tool processes
    _kill_child_processes()


app = FastAPI(
    title="Bug Bounty Assistant",
    description="AI-powered H1 bug bounty research tool",
    version="0.1.0",
    redirect_slashes=False,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(programs.router, prefix="/api/programs", tags=["programs"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])


@app.get("/")
async def root():
    return {"name": "Bug Bounty Assistant", "docs": "/docs", "status": "ok"}


@app.get("/health")
async def health():
    return {"status": "ok"}
