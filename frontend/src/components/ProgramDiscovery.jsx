import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'

const G = {
  bg: '#0d1117', surface: '#161b22', border: '#30363d',
  text: '#c9d1d9', muted: '#8b949e', accent: '#f0883e',
  blue: '#58a6ff', green: '#3fb950', red: '#f85149', yellow: '#d29922',
}

const cellStyle = { padding: '8px 12px', borderBottom: `1px solid ${G.border}`, fontSize: 13 }

function fmtDate(s) {
  if (!s) return null
  try {
    return new Date(s).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
  } catch { return null }
}

export default function ProgramDiscovery() {
  const [activeTab, setActiveTab] = useState('new')

  // All Programs tab
  const [allPrograms, setAllPrograms] = useState([])
  const [allLoading, setAllLoading] = useState(false)
  const [allError, setAllError] = useState('')
  const [page, setPage] = useState(1)
  const [hasMore, setHasMore] = useState(false)

  // New Programs tab
  const [newPrograms, setNewPrograms] = useState([])
  const [newLoading, setNewLoading] = useState(false)
  const [newError, setNewError] = useState('')
  const [newScanned, setNewScanned] = useState(0)
  const [newChecked, setNewChecked] = useState(false)
  const [markingDone, setMarkingDone] = useState(false)

  // Shared
  const [expanded, setExpanded] = useState({})
  const [actionState, setActionState] = useState({})

  const fetchAll = useCallback(async (p) => {
    setAllLoading(true)
    setAllError('')
    try {
      const r = await fetch(`/api/discover/programs?page=${p}&size=50`)
      const j = await r.json()
      if (!r.ok) throw new Error(j.detail || r.statusText)
      if (p === 1) setAllPrograms(j.programs || [])
      else setAllPrograms(prev => [...prev, ...(j.programs || [])])
      setHasMore((j.programs || []).length === 50)
    } catch (e) {
      setAllError(e.message)
    } finally {
      setAllLoading(false)
    }
  }, [])

  const fetchNew = useCallback(async () => {
    setNewLoading(true)
    setNewError('')
    setNewChecked(false)
    setMarkingDone(false)
    try {
      const r = await fetch('/api/discover/new-programs?max_pages=10')
      const j = await r.json()
      if (!r.ok) throw new Error(j.detail || r.statusText)
      setNewPrograms(j.programs || [])
      setNewScanned(j.total_scanned || 0)
      setNewChecked(true)
    } catch (e) {
      setNewError(e.message)
    } finally {
      setNewLoading(false)
    }
  }, [])

  const markAllSeen = async () => {
    const handles = newPrograms.map(p => p.handle)
    if (!handles.length) return
    await fetch('/api/discover/mark-seen', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(handles),
    })
    setNewPrograms([])
    setMarkingDone(true)
  }

  useEffect(() => {
    fetchNew()
  }, []) // eslint-disable-line

  useEffect(() => {
    if (activeTab === 'all' && allPrograms.length === 0) fetchAll(1)
  }, [activeTab]) // eslint-disable-line

  async function doImport(p) {
    setActionState(s => ({ ...s, [p.handle]: 'importing' }))
    try {
      const r = await fetch(
        `/api/discover/import/${encodeURIComponent(p.handle)}?name=${encodeURIComponent(p.name)}`,
        { method: 'POST' },
      )
      const j = await r.json()
      if (!r.ok) throw new Error(j.detail || r.statusText)
      setActionState(s => ({ ...s, [p.handle]: { program_id: j.program_id } }))
    } catch (e) {
      setActionState(s => ({ ...s, [p.handle]: { error: e.message } }))
    }
  }

  async function doImportScan(p) {
    setActionState(s => ({ ...s, [p.handle]: 'planning' }))
    try {
      const r = await fetch(
        `/api/discover/import-scan/${encodeURIComponent(p.handle)}?name=${encodeURIComponent(p.name)}`,
        { method: 'POST' },
      )
      const j = await r.json()
      if (!r.ok) throw new Error(j.detail || r.statusText)
      setActionState(s => ({ ...s, [p.handle]: {
        program_id: j.program_id,
        scan_id: j.scan_id || null,
        scan_skip_reason: j.scan_skip_reason || null,
      } }))
    } catch (e) {
      setActionState(s => ({ ...s, [p.handle]: { error: e.message } }))
    }
  }

  const TabBtn = ({ id, label }) => (
    <button
      onClick={() => setActiveTab(id)}
      style={{
        padding: '6px 18px',
        borderRadius: '4px 4px 0 0',
        border: `1px solid ${activeTab === id ? G.border : 'transparent'}`,
        borderBottom: activeTab === id ? `1px solid ${G.surface}` : `1px solid ${G.border}`,
        background: activeTab === id ? G.surface : 'transparent',
        color: activeTab === id ? G.text : G.muted,
        fontSize: 13, cursor: 'pointer', fontWeight: activeTab === id ? 600 : 400,
      }}
    >{label}</button>
  )

  return (
    <div>
      <h2 style={{ color: G.text, marginBottom: 6, fontSize: 18 }}>Discover H1 Programs</h2>
      <p style={{ color: G.muted, fontSize: 13, marginBottom: 16 }}>
        Open bug bounty programs on HackerOne. Import scope and launch scans — critical findings
        trigger Telegram notifications automatically.
      </p>

      <div style={{ display: 'flex', gap: 0, borderBottom: `1px solid ${G.border}`, marginBottom: 20 }}>
        <TabBtn
          id="new"
          label={`🔔 New Programs${newPrograms.length ? ` (${newPrograms.length})` : ''}`}
        />
        <TabBtn id="all" label="All Programs" />
      </div>

      {/* ── New Programs Tab ── */}
      {activeTab === 'new' && (
        <div>
          {newLoading && (
            <p style={{ color: G.muted, fontSize: 13 }}>
              ⟳ Scanning HackerOne for new programs… (checking up to 1 000 entries)
            </p>
          )}

          {newError && <CredError error={newError} />}

          {!newLoading && newChecked && !newError && (
            <div style={{ marginBottom: 14, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <span style={{ color: G.muted, fontSize: 12 }}>
                {newPrograms.length > 0
                  ? `${newPrograms.length} new program${newPrograms.length !== 1 ? 's' : ''} found · ${newScanned} total scanned`
                  : markingDone
                    ? '✓ All caught up — check back later'
                    : `No new programs · ${newScanned} scanned`
                }
              </span>
              <button
                onClick={fetchNew}
                style={{ background: 'none', border: `1px solid ${G.border}`,
                  color: G.muted, fontSize: 12, padding: '3px 10px', borderRadius: 4, cursor: 'pointer' }}
              >
                ↻ Refresh
              </button>
              {newPrograms.length > 0 && (
                <button
                  onClick={markAllSeen}
                  style={{ background: 'none', border: `1px solid ${G.border}`,
                    color: G.muted, fontSize: 12, padding: '3px 10px', borderRadius: 4, cursor: 'pointer' }}
                >
                  ✓ Mark all seen
                </button>
              )}
            </div>
          )}

          {newPrograms.length > 0 && (
            <ProgramTable
              programs={newPrograms}
              actionState={actionState}
              expanded={expanded}
              setExpanded={setExpanded}
              onImport={doImport}
              onImportScan={doImportScan}
              showDate
            />
          )}
        </div>
      )}

      {/* ── All Programs Tab ── */}
      {activeTab === 'all' && (
        <div>
          {allError && <CredError error={allError} />}

          {allPrograms.length > 0 && (
            <>
              <p style={{ color: G.muted, fontSize: 12, marginBottom: 10 }}>
                {allPrograms.length} programs loaded · open · offers bounties
              </p>
              <ProgramTable
                programs={allPrograms}
                actionState={actionState}
                expanded={expanded}
                setExpanded={setExpanded}
                onImport={doImport}
                onImportScan={doImportScan}
              />
              {hasMore && (
                <button
                  onClick={() => { const next = page + 1; setPage(next); fetchAll(next) }}
                  disabled={allLoading}
                  style={{ marginTop: 16, background: G.surface, color: G.muted,
                    border: `1px solid ${G.border}`, padding: '6px 18px',
                    borderRadius: 4, fontSize: 13, cursor: 'pointer' }}
                >
                  {allLoading ? 'Loading…' : 'Load more'}
                </button>
              )}
            </>
          )}

          {!allLoading && !allError && allPrograms.length === 0 && (
            <p style={{ color: G.muted }}>No programs found.</p>
          )}
          {allLoading && allPrograms.length === 0 && (
            <p style={{ color: G.muted }}>Loading programs from HackerOne…</p>
          )}
        </div>
      )}
    </div>
  )
}

function ProgramTable({ programs, actionState, expanded, setExpanded, onImport, onImportScan, showDate }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ color: G.muted, textAlign: 'left', borderBottom: `1px solid ${G.border}` }}>
            <th style={cellStyle}>Program</th>
            <th style={cellStyle}>Tags</th>
            {showDate && <th style={{ ...cellStyle, whiteSpace: 'nowrap' }}>Accepting since</th>}
            <th style={cellStyle}>Policy preview</th>
            <th style={{ ...cellStyle, minWidth: 210 }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {programs.map(p => {
            const s = actionState[p.handle]
            const date = fmtDate(p.started_accepting_at)
            return (
              <tr key={p.handle}>
                <td style={cellStyle}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                    {p.is_new && (
                      <span style={{
                        background: '#0d2b1a', color: G.green, fontSize: 10,
                        padding: '1px 5px', borderRadius: 3, fontWeight: 700,
                        border: `1px solid ${G.green}`, flexShrink: 0,
                      }}>NEW</span>
                    )}
                    <a href={`https://hackerone.com/${p.handle}`} target="_blank" rel="noreferrer"
                      style={{ color: G.blue }}>
                      {p.name}
                    </a>
                  </div>
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
                {showDate && (
                  <td style={{ ...cellStyle, whiteSpace: 'nowrap', fontSize: 11, color: G.muted }}>
                    {date || '—'}
                  </td>
                )}
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
                  <ActionCell p={p} s={s} onImport={onImport} onImportScan={onImportScan} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function CredError({ error }) {
  const isMissingCreds = error?.includes('H1_API_TOKEN') || error?.includes('H1_USERNAME')
  if (isMissingCreds) {
    return (
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
    )
  }
  return <div style={{ color: G.red, marginBottom: 16, fontSize: 13 }}>{error}</div>
}

function ActionCell({ p, s, onImport, onImportScan }) {
  if (!s) {
    return (
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button
          onClick={() => onImport(p)}
          title="Import scope only — review plan before scanning"
          style={{ background: G.surface, color: G.muted, border: `1px solid ${G.border}`,
            padding: '4px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer' }}
        >
          Import
        </button>
        <button
          onClick={() => onImportScan(p)}
          title="Import scope, generate plan, start scan + Telegram alerts on findings"
          style={{ background: '#1a2f1a', color: G.green, border: `1px solid ${G.green}`,
            padding: '4px 10px', borderRadius: 4, fontSize: 12, fontWeight: 600, cursor: 'pointer' }}
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
      <span style={{ marginRight: 4 }}>⟳</span>
      {label}
    </span>
  )
}
