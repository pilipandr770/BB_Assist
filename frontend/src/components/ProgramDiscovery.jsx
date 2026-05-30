import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'

const G = {
  bg: '#0d1117', surface: '#161b22', border: '#30363d',
  text: '#c9d1d9', muted: '#8b949e', accent: '#f0883e',
  blue: '#58a6ff', green: '#3fb950', red: '#f85149', yellow: '#d29922',
}

const cellStyle = { padding: '8px 12px', borderBottom: `1px solid ${G.border}`, fontSize: 13 }

export default function ProgramDiscovery() {
  const [programs, setPrograms] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [page, setPage] = useState(1)
  const [hasMore, setHasMore] = useState(false)
  const [expanded, setExpanded] = useState({})   // handle → bool
  const [state, setState] = useState({})          // handle → status

  const fetchPrograms = useCallback(async (p = page) => {
    setLoading(true)
    setError('')
    try {
      const r = await fetch(`/api/discover/programs?page=${p}&size=50`)
      const j = await r.json()
      if (!r.ok) throw new Error(j.detail || r.statusText)
      if (p === 1) setPrograms(j.programs || [])
      else setPrograms(prev => [...prev, ...(j.programs || [])])
      setHasMore((j.programs || []).length === 50)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => { fetchPrograms(1) }, [])  // eslint-disable-line

  function loadMore() {
    const next = page + 1
    setPage(next)
    fetchPrograms(next)
  }

  async function doImport(p) {
    setState(s => ({ ...s, [p.handle]: 'importing' }))
    try {
      const r = await fetch(
        `/api/discover/import/${encodeURIComponent(p.handle)}?name=${encodeURIComponent(p.name)}`,
        { method: 'POST' },
      )
      const j = await r.json()
      if (!r.ok) throw new Error(j.detail || r.statusText)
      setState(s => ({ ...s, [p.handle]: { program_id: j.program_id } }))
    } catch (e) {
      setState(s => ({ ...s, [p.handle]: { error: e.message } }))
    }
  }

  async function doImportScan(p) {
    setState(s => ({ ...s, [p.handle]: 'planning' }))
    try {
      const r = await fetch(
        `/api/discover/import-scan/${encodeURIComponent(p.handle)}?name=${encodeURIComponent(p.name)}`,
        { method: 'POST' },
      )
      const j = await r.json()
      if (!r.ok) throw new Error(j.detail || r.statusText)
      setState(s => ({ ...s, [p.handle]: {
        program_id: j.program_id,
        scan_id: j.scan_id || null,
        scan_skip_reason: j.scan_skip_reason || null,
      } }))
    } catch (e) {
      setState(s => ({ ...s, [p.handle]: { error: e.message } }))
    }
  }

  const isMissingCreds = error?.includes('H1_API_TOKEN') || error?.includes('H1_USERNAME')

  return (
    <div>
      <h2 style={{ color: G.text, marginBottom: 6, fontSize: 18 }}>Discover H1 Programs</h2>
      <p style={{ color: G.muted, fontSize: 13, marginBottom: 20 }}>
        Open bug bounty programs on HackerOne. Import scope and launch scans — critical findings
        trigger Telegram notifications automatically.
      </p>

      {isMissingCreds && (
        <div style={{ background: '#2d1f1f', border: `1px solid ${G.red}`, borderRadius: 6,
          padding: '12px 16px', marginBottom: 16, fontSize: 13, color: G.red }}>
          <strong>H1 credentials not configured.</strong> Add to <code>.env</code>:<br />
          <code style={{ display: 'block', marginTop: 6, color: G.muted }}>
            H1_USERNAME=your-handle<br />
            H1_API_TOKEN=your-token
          </code>
          Generate a token at{' '}
          <a href="https://hackerone.com/settings/api_token/edit" target="_blank" rel="noreferrer"
            style={{ color: G.blue }}>
            hackerone.com/settings/api_token/edit
          </a>
          , then run <code>docker compose up -d --force-recreate backend</code>.
        </div>
      )}
      {error && !isMissingCreds && (
        <div style={{ color: G.red, marginBottom: 16, fontSize: 13 }}>{error}</div>
      )}

      {programs.length > 0 && (
        <>
          <p style={{ color: G.muted, fontSize: 12, marginBottom: 10 }}>
            {programs.length} programs loaded · open · offers bounties
          </p>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ color: G.muted, textAlign: 'left', borderBottom: `1px solid ${G.border}` }}>
                  <th style={cellStyle}>Program</th>
                  <th style={cellStyle}>Tags</th>
                  <th style={cellStyle}>Policy preview</th>
                  <th style={{ ...cellStyle, minWidth: 210 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {programs.map(p => {
                  const s = state[p.handle]
                  return (
                    <tr key={p.handle}>
                      <td style={cellStyle}>
                        <a href={`https://hackerone.com/${p.handle}`} target="_blank" rel="noreferrer"
                          style={{ color: G.blue }}>
                          {p.name}
                        </a>
                        <br />
                        <span style={{ color: G.muted, fontSize: 11 }}>@{p.handle}</span>
                      </td>
                      <td style={{ ...cellStyle, whiteSpace: 'nowrap' }}>
                        {p.fast_payments && (
                          <span style={{ background: '#1a2f1a', color: G.green, fontSize: 11,
                            padding: '2px 6px', borderRadius: 3, marginRight: 4 }}>⚡fast pay</span>
                        )}
                        {p.open_scope && (
                          <span style={{ background: '#1a1f2f', color: G.blue, fontSize: 11,
                            padding: '2px 6px', borderRadius: 3, marginRight: 4 }}>open scope</span>
                        )}
                        {p.gold_standard && (
                          <span style={{ background: '#2f2a1a', color: G.yellow, fontSize: 11,
                            padding: '2px 6px', borderRadius: 3 }}>★ gold</span>
                        )}
                      </td>
                      <td style={{ ...cellStyle, maxWidth: 300 }}>
                        <button
                          onClick={() => setExpanded(e => ({ ...e, [p.handle]: !e[p.handle] }))}
                          style={{ background: 'none', border: 'none', color: G.muted,
                            fontSize: 11, cursor: 'pointer', padding: 0 }}
                        >
                          {expanded[p.handle] ? '▲ hide' : '▼ preview'}
                        </button>
                        {expanded[p.handle] && (
                          <pre style={{ marginTop: 6, color: G.muted, fontSize: 11,
                            whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                            background: G.bg, padding: 8, borderRadius: 4, maxHeight: 200,
                            overflow: 'auto' }}>
                            {p.policy_preview || '(no policy text)'}
                          </pre>
                        )}
                      </td>
                      <td style={cellStyle}>
                        <ActionCell p={p} s={s} onImport={doImport} onImportScan={doImportScan} />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          {hasMore && (
            <button
              onClick={loadMore}
              disabled={loading}
              style={{ marginTop: 16, background: G.surface, color: G.muted,
                border: `1px solid ${G.border}`, padding: '6px 18px',
                borderRadius: 4, fontSize: 13 }}
            >
              {loading ? 'Loading…' : 'Load more'}
            </button>
          )}
        </>
      )}

      {!loading && !error && programs.length === 0 && (
        <p style={{ color: G.muted }}>No programs found.</p>
      )}
      {loading && programs.length === 0 && (
        <p style={{ color: G.muted }}>Loading programs from HackerOne…</p>
      )}
    </div>
  )
}

function ActionCell({ p, s, onImport, onImportScan }) {
  if (!s) {
    return (
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button
          onClick={() => onImport(p)}
          title="Import scope only — review plan before scanning"
          style={{ background: G.surface, color: G.muted, border: `1px solid ${G.border}`,
            padding: '4px 10px', borderRadius: 4, fontSize: 12 }}
        >
          Import
        </button>
        <button
          onClick={() => onImportScan(p)}
          title="Import scope, generate plan, start scan + Telegram alerts on findings"
          style={{ background: '#1a2f1a', color: G.green, border: `1px solid ${G.green}`,
            padding: '4px 10px', borderRadius: 4, fontSize: 12, fontWeight: 600 }}
        >
          Import &amp; Scan ▶
        </button>
      </div>
    )
  }

  if (s === 'importing') return <Spinner label="Importing + parsing scope…" />
  if (s === 'planning')  return <Spinner label="Generating plan + starting scan…" />

  if (s?.error) {
    return (
      <span style={{ color: G.red, fontSize: 11 }} title={s.error}>
        ✗ {s.error.slice(0, 80)}
      </span>
    )
  }

  if (s?.scan_id) {
    return (
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <Link to={`/programs/${s.program_id}/scans/${s.scan_id}`}
          style={{ color: G.green, fontSize: 12, fontWeight: 600 }}>
          ▶ Watch Scan
        </Link>
        <Link to={`/programs/${s.program_id}/plan`} style={{ color: G.muted, fontSize: 12 }}>
          Plan
        </Link>
      </div>
    )
  }

  if (s?.program_id) {
    return (
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <Link to={`/programs/${s.program_id}/plan`} style={{ color: G.blue, fontSize: 12 }}>
          → Open Plan
        </Link>
        {s.scan_skip_reason && (
          <span style={{ color: G.yellow, fontSize: 11 }} title={s.scan_skip_reason}>
            ⚠ scan skipped
          </span>
        )}
      </div>
    )
  }

  return null
}

function Spinner({ label }) {
  return (
    <span style={{ color: G.muted, fontSize: 12 }}>
      <span style={{ marginRight: 4, display: 'inline-block' }}>⟳</span>
      {label}
    </span>
  )
}
