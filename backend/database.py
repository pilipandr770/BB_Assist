import aiosqlite

DB_PATH = "/workspace/bb_assist.db"


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS programs (
              id TEXT PRIMARY KEY,
              name TEXT,
              scope_text TEXT,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
              id TEXT PRIMARY KEY,
              program_id TEXT,
              status TEXT,
              started_at TIMESTAMP,
              finished_at TIMESTAMP,
              findings_count INTEGER DEFAULT 0,
                            reports_count INTEGER DEFAULT 0,
                            llm_cost_usd REAL DEFAULT 0,
              FOREIGN KEY (program_id) REFERENCES programs(id)
            )
            """
        )
                # Backward-compatible migration for existing DBs created before llm_cost_usd.
                cur = await db.execute("PRAGMA table_info(scans)")
                cols = [r[1] for r in await cur.fetchall()]
                if "llm_cost_usd" not in cols:
                        await db.execute("ALTER TABLE scans ADD COLUMN llm_cost_usd REAL DEFAULT 0")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
              id TEXT PRIMARY KEY,
              scan_id TEXT,
              title TEXT,
              severity TEXT,
              vuln_type TEXT,
              target TEXT,
              passed_filter INTEGER DEFAULT 0,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_scans_program_id ON scans(program_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
        await db.commit()


async def save_program(program_id: str, name: str, scope_text: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO programs(id, name, scope_text)
            VALUES(?, ?, ?)
            """,
            (program_id, name, scope_text),
        )
        await db.commit()


async def save_scan(
    scan_id: str,
    program_id: str,
    status: str,
    started_at: str | None = None,
    finished_at: str | None = None,
    findings_count: int = 0,
    reports_count: int = 0,
    llm_cost_usd: float = 0.0,
) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO scans(
              id, program_id, status, started_at, finished_at, findings_count, reports_count, llm_cost_usd
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                program_id,
                status,
                started_at,
                finished_at,
                findings_count,
                reports_count,
                llm_cost_usd,
            ),
        )
        await db.commit()


async def update_scan_status(
    scan_id: str,
    status: str,
    started_at: str | None = None,
    finished_at: str | None = None,
    findings_count: int | None = None,
    reports_count: int | None = None,
    llm_cost_usd: float | None = None,
) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            UPDATE scans
            SET status = ?,
                started_at = COALESCE(?, started_at),
                finished_at = COALESCE(?, finished_at),
                findings_count = COALESCE(?, findings_count),
                reports_count = COALESCE(?, reports_count),
                llm_cost_usd = COALESCE(?, llm_cost_usd)
            WHERE id = ?
            """,
            (status, started_at, finished_at, findings_count, reports_count, llm_cost_usd, scan_id),
        )
        await db.commit()


async def save_finding(
    finding_id: str,
    scan_id: str,
    title: str,
    severity: str,
    vuln_type: str,
    target: str,
    passed_filter: int = 0,
) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO findings(
              id, scan_id, title, severity, vuln_type, target, passed_filter
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (finding_id, scan_id, title, severity, vuln_type, target, passed_filter),
        )
        await db.commit()


async def get_program_history() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """
            SELECT
              p.id,
              p.name,
              p.created_at,
              COUNT(s.id) AS scan_count,
              COALESCE(SUM(s.findings_count), 0) AS total_findings,
              COALESCE(SUM(s.reports_count), 0) AS total_reports,
                            COALESCE(SUM(s.llm_cost_usd), 0) AS total_llm_cost_usd,
              MAX(COALESCE(s.finished_at, s.started_at)) AS last_scan_at
            FROM programs p
            LEFT JOIN scans s ON s.program_id = p.id
            GROUP BY p.id, p.name, p.created_at
            ORDER BY COALESCE(last_scan_at, p.created_at) DESC
            """
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_program_detail(program_id: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        pcur = await db.execute(
            "SELECT id, name, scope_text, created_at FROM programs WHERE id = ?",
            (program_id,),
        )
        prow = await pcur.fetchone()
        if not prow:
            return None

        scur = await db.execute(
            """
            SELECT id, program_id, status, started_at, finished_at, findings_count, reports_count, llm_cost_usd
            FROM scans
            WHERE program_id = ?
            ORDER BY COALESCE(finished_at, started_at) DESC
            """,
            (program_id,),
        )
        scans = [dict(r) for r in await scur.fetchall()]

        out = dict(prow)
        out["scans"] = scans
        return out


async def get_scan_findings(scan_id: str) -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        scan_cur = await db.execute(
            """
            SELECT id, program_id, status, started_at, finished_at, findings_count, reports_count, llm_cost_usd
            FROM scans WHERE id = ?
            """,
            (scan_id,),
        )
        scan = await scan_cur.fetchone()

        fcur = await db.execute(
            """
            SELECT id, scan_id, title, severity, vuln_type, target, passed_filter, created_at
            FROM findings
            WHERE scan_id = ?
            ORDER BY created_at DESC
            """,
            (scan_id,),
        )
        findings = [dict(r) for r in await fcur.fetchall()]

        return {
            "scan": dict(scan) if scan else None,
            "findings": findings,
        }


async def delete_scan(scan_id: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
