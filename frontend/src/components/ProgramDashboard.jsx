import { useState, useEffect, useCallback } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import axios from 'axios'

const G = {
  bg: '#0d1117', surface: '#161b22', border: '#30363d',
  text: '#c9d1d9', muted: '#8b949e', accent: '#f0883e',
  blue: '#58a6ff', green: '#3fb950', red: '#f85149', yellow: '#d29922',
}

const SEV = {
  critical: { color: '#f85149', bg: '#f8514922' },
  high:     { color: '#f0883e', bg: '#f0883e22' },
  medium:   { color: '#d29922', bg: '#d2992222' },
  low:      { color: '#3fb950', bg: '#3fb95022' },
  informative: { color: '#8b949e', bg: '#8b949e22' },
}

const STATUS = {
  done:    { color: G.green,  label: 'Done' },
  running: { color: G.blue,   label: 'Running' },
  pending: { color: G.yellow, label: 'Pending' },
  failed:  { color: G.red,    label: 'Failed' },
}

export default function ProgramDashboard() {
  const { programId } = useParams()
  const navigate = useNavigate()

  const [program, setProgram] = useState(null)
  const [history, setHistory] = useState(null)
  const [reports, setReports] = useState([])
  const [ctSnapshot, setCtSnapshot] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [h1Handle, setH1Handle] = useState('')
  const [savingHandle, setSavingHandle] = useState(false)
  const [handleSaved, setHandleSaved] = useState(false)

  const [ctChecking, setCtChecking] = useState(false)
  const [ctResult, setCtResult] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [progRes, histRes, repRes, ctRes] = await Promise.all([
        axios.get(`/api/programs/${programId}`),
        axios.get(`/api/history/programs/${programId}`).catch(() => ({ data: { data: null } })),
        axios.get(`/api/reports/${programId}`).catch(() => ({ data: { data: { reports: [] } } })),
        axios.get(`/api/ct/${programId}/snapshot`).catch(() => ({ data: { data: null } })),
      ])
      const prog = progRes.data?.data
      setProgram(prog)
      setH1Handle(prog?.h1_program_handle || '')
      setHistory(histRes.data?.data)
      setReports(repRes.data?.data?.reports || [])
      setCtSnapshot(ctRes.data?.data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load program')
    } finally {
      setLoading(false)
    }
  }, [programId])

  useEffect(() => { load() }, [load])

  async function saveHandle() {
    setSavingHandle(true)
    try {
      await axios.patch(`/api/programs/${programId}`, { h1_program_handle: h1Handle })
      setHandleSaved(true)
      setTimeout(() => setHandleSaved(false), 2000)
    } catch (e) {
      alert(e.response?.data?.detail || 'Save failed')
    } finally {
      setSavingHandle(false)
    }
  }

  async function startRescan() {
    try {
      const res = await axios.post('/api/scans/start', {
        program_id: programId,
        approved_plan: program?.plan || 'Rescan',
      })
      navigate(`/programs/${programId}/scans/${res.data.data.id}`)
    } catch (e) {
      alert(e.response?.data?.detail || 'Failed to start scan')
    }
  }

  async function checkCtLogs() {
    setCtChecking(true)
    setCtResult(null)
    try {
      const res = await axios.post(`/api/ct/${programId}/check`)
      setCtResult(res.data?.data)
      setCtSnapshot(res.data?.data)
    } catch (e) {
      setCtResult({ error: e.response?.data?.detail || 'Check failed' })
    } finally {
      setCtChecking(false)
    }
  }

  if (loading) return <p style={{ color: G.muted }}>Loading...</p>
  if (error) return <p style={{ color: G.red }}>{error}</p>
  if (!program) return <p style={{ color: G.muted }}>Program not found</p>

  const scope = program.scope || {}
  const domains = scope.in_scope_domains || []
  const scans = history?.scans || []
  const totalFindings = history?.total_findings || 0
  const totalCost = history?.total_llm_cost_usd || 0

  // Severity breakdown from reports
  const sevCounts = reports.reduce((acc, r) => {
    const s = r.severity || 'medium'
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {})

  return (
    <div style={{ maxWidth: 900 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
        <Link to="/programs" style={{ color: G.muted, fontSize: 13 }}>← Programs</Link>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: G.accent, flex: 1 }}>{program.name}</h1>
        <button
          onClick={startRescan}
          style={{
            padding: '8px 18px', background: '#238636',
            color: '#fff', border: 'none', borderRadius: 6,
            fontSize: 13, fontWeight: 600,
          }}
        >
          ▶ New Scan
        </button>
      </div>

      {/* Domains */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 20 }}>
        <span style={{
          background: '#58a6ff22', color: G.blue,
          border: '1px solid #58a6ff44', padding: '2px 8px',
          borderRadius: 4, fontSize: 11, fontWeight: 600,
        }}>
          {scope.program_type || 'web'}
        </span>
        {domains.slice(0, 8).map(d => (
          <code key={d} style={{
            background: '#0d1117', border: `1px solid ${G.border}`,
            borderRadius: 4, padding: '2px 8px', fontSize: 11, color: '#79c0ff',
          }}>
            {d}
          </code>
        ))}
        {domains.length > 8 && <span style={{ color: G.muted, fontSize: 11 }}>+{domains.length - 8} more</span>}
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Scans', value: scans.length },
          { label: 'Findings', value: totalFindings },
          { label: 'Reports', value: reports.length },
          { label: 'LLM Cost', value: `$${Number(totalCost).toFixed(3)}` },
        ].map(({ label, value }) => (
          <div key={label} style={{
            background: G.surface, border: `1px solid ${G.border}`,
            borderRadius: 6, padding: '14px 16px', textAlign: 'center',
          }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: G.text }}>{value}</div>
            <div style={{ fontSize: 12, color: G.muted, marginTop: 2 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Severity breakdown */}
      {reports.length > 0 && (
        <div style={{
          background: G.surface, border: `1px solid ${G.border}`,
          borderRadius: 6, padding: '12px 16px', marginBottom: 16,
          display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center',
        }}>
          <span style={{ color: G.muted, fontSize: 12, fontWeight: 600, marginRight: 4 }}>Reports by severity:</span>
          {['critical', 'high', 'medium', 'low', 'informative'].map(s => (
            sevCounts[s] ? (
              <span key={s} style={{
                background: SEV[s].bg, color: SEV[s].color,
                border: `1px solid ${SEV[s].color}44`,
                padding: '3px 10px', borderRadius: 4, fontSize: 12, fontWeight: 700,
              }}>
                {s.toUpperCase()} {sevCounts[s]}
              </span>
            ) : null
          ))}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        {/* H1 Handle */}
        <div style={{
          background: G.surface, border: `1px solid ${G.border}`,
          borderRadius: 6, padding: '14px 16px',
        }}>
          <div style={{ color: G.text, fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
            🚀 HackerOne Program Handle
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input
              value={h1Handle}
              onChange={e => setH1Handle(e.target.value)}
              placeholder="program-handle"
              style={{
                flex: 1, background: G.bg, border: `1px solid ${G.border}`,
                borderRadius: 4, color: G.text, fontSize: 13, padding: '6px 10px',
              }}
            />
            <button
              onClick={saveHandle}
              disabled={savingHandle}
              style={{
                padding: '6px 14px',
                background: handleSaved ? '#238636' : '#21262d',
                color: handleSaved ? '#fff' : G.blue,
                border: `1px solid ${G.border}`, borderRadius: 6,
                fontSize: 13, fontWeight: 600,
              }}
            >
              {handleSaved ? '✓ Saved' : 'Save'}
            </button>
          </div>
          <div style={{ color: G.muted, fontSize: 11, marginTop: 6 }}>
            Used for auto-submit reports via H1 API
          </div>
        </div>

        {/* CT-Log Monitor */}
        <div style={{
          background: G.surface, border: `1px solid ${G.border}`,
          borderRadius: 6, padding: '14px 16px',
        }}>
          <div style={{ color: G.text, fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
            🔍 CT-Log Monitor
          </div>
          <button
            onClick={checkCtLogs}
            disabled={ctChecking}
            style={{
              padding: '6px 14px', background: ctChecking ? '#21262d' : '#1f6feb',
              color: '#fff', border: 'none', borderRadius: 6,
              fontSize: 13, fontWeight: 600, cursor: ctChecking ? 'wait' : 'pointer',
            }}
          >
            {ctChecking ? 'Checking crt.sh…' : 'Check for new subdomains'}
          </button>
          {ctSnapshot?.checked_at && (
            <div style={{ color: G.muted, fontSize: 11, marginTop: 6 }}>
              Last checked: {new Date(ctSnapshot.checked_at).toLocaleString()}
              {ctSnapshot.total_count != null && ` · ${ctSnapshot.total_count} total`}
            </div>
          )}
          {ctResult?.new_subdomains?.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={{ color: G.green, fontSize: 12, fontWeight: 600 }}>
                ✓ {ctResult.new_subdomains.length} new subdomains!
              </div>
              {ctResult.new_subdomains.slice(0, 5).map(s => (
                <code key={s} style={{ display: 'block', color: '#79c0ff', fontSize: 11, marginTop: 2 }}>{s}</code>
              ))}
              {ctResult.new_subdomains.length > 5 && (
                <div style={{ color: G.muted, fontSize: 11 }}>+{ctResult.new_subdomains.length - 5} more</div>
              )}
            </div>
          )}
          {ctResult?.new_subdomains?.length === 0 && (
            <div style={{ color: G.muted, fontSize: 12, marginTop: 6 }}>No new subdomains found.</div>
          )}
          {ctResult?.error && (
            <div style={{ color: G.red, fontSize: 12, marginTop: 6 }}>{ctResult.error}</div>
          )}
        </div>
      </div>

      {/* Quick Actions */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 24 }}>
        <Link to={`/programs/${programId}/reports`} style={actionBtn('#21262d', G.blue)}>
          📄 Reports ({reports.length})
        </Link>
        <Link to={`/programs/${programId}/plan`} style={actionBtn('#21262d', G.muted)}>
          📋 View Plan
        </Link>
        <Link to={`/programs/${programId}/manual-finding`} style={actionBtn('#21262d', G.muted)}>
          ✍ Manual Finding
        </Link>
      </div>

      {/* Scan History */}
      <div style={{
        background: G.surface, border: `1px solid ${G.border}`,
        borderRadius: 6, overflow: 'hidden',
      }}>
        <div style={{
          padding: '10px 16px', borderBottom: `1px solid ${G.border}`,
          color: G.text, fontSize: 13, fontWeight: 600,
        }}>
          Scan History
        </div>
        {scans.length === 0 ? (
          <div style={{ padding: '24px', textAlign: 'center', color: G.muted, fontSize: 13 }}>
            No scans yet.{' '}
            <button onClick={startRescan} style={{ color: G.blue, background: 'none', border: 'none', cursor: 'pointer', fontSize: 13 }}>
              Start first scan →
            </button>
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#0d1117' }}>
                {['Started', 'Status', 'Findings', 'Reports', 'LLM Cost', ''].map(h => (
                  <th key={h} style={{ padding: '8px 14px', textAlign: 'left', color: G.muted, fontSize: 11, fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.map((s, i) => {
                const st = STATUS[s.status] || STATUS.pending
                return (
                  <tr key={s.id} style={{ borderTop: `1px solid ${G.border}` }}>
                    <td style={{ padding: '10px 14px', color: G.text, fontSize: 12 }}>
                      {s.started_at ? new Date(s.started_at).toLocaleString() : '—'}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{
                        color: st.color, background: st.color + '22',
                        border: `1px solid ${st.color}44`,
                        padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                      }}>
                        {st.label}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', color: G.text, fontSize: 12 }}>{s.findings_count || 0}</td>
                    <td style={{ padding: '10px 14px', color: G.text, fontSize: 12 }}>{s.reports_count || 0}</td>
                    <td style={{ padding: '10px 14px', color: G.muted, fontSize: 12 }}>${Number(s.llm_cost_usd || 0).toFixed(4)}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <Link
                          to={`/programs/${programId}/scans/${s.id}`}
                          style={smallBtn(G.blue)}
                        >
                          Scan
                        </Link>
                        {s.findings_count > 0 && (
                          <Link
                            to={`/programs/${programId}/scans/${s.id}/findings`}
                            style={smallBtn(G.muted)}
                          >
                            Findings
                          </Link>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Recent Reports */}
      {reports.length > 0 && (
        <div style={{
          background: G.surface, border: `1px solid ${G.border}`,
          borderRadius: 6, overflow: 'hidden', marginTop: 16,
        }}>
          <div style={{
            padding: '10px 16px', borderBottom: `1px solid ${G.border}`,
            display: 'flex', alignItems: 'center',
          }}>
            <span style={{ color: G.text, fontSize: 13, fontWeight: 600, flex: 1 }}>Recent Reports</span>
            <Link to={`/programs/${programId}/reports`} style={{ color: G.blue, fontSize: 12 }}>All reports →</Link>
          </div>
          {reports.slice(0, 5).map(r => {
            const sev = SEV[r.severity] || SEV.medium
            return (
              <div key={r.id} style={{
                padding: '10px 16px', borderTop: `1px solid ${G.border}`,
                display: 'flex', alignItems: 'center', gap: 12,
              }}>
                <span style={{
                  color: sev.color, background: sev.bg,
                  border: `1px solid ${sev.color}44`,
                  padding: '1px 7px', borderRadius: 4, fontSize: 11, fontWeight: 700,
                  whiteSpace: 'nowrap',
                }}>
                  {(r.severity || 'medium').toUpperCase()}
                </span>
                <span style={{ color: G.text, fontSize: 13, flex: 1 }}>
                  {r.title || `Report ${r.id?.slice(0, 8)}`}
                </span>
                {r.h1_submitted && (
                  <a
                    href={r.h1_report_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: G.green, fontSize: 11, whiteSpace: 'nowrap' }}
                  >
                    ✓ H1 #{r.h1_report_id}
                  </a>
                )}
                <Link
                  to={`/programs/${programId}/reports/${r.id}`}
                  style={{ color: G.blue, fontSize: 12, whiteSpace: 'nowrap' }}
                >
                  View →
                </Link>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function actionBtn(bg, color) {
  return {
    display: 'inline-block',
    padding: '7px 16px', background: bg,
    color, border: `1px solid ${G.border}`, borderRadius: 6,
    fontSize: 13, fontWeight: 600,
  }
}

function smallBtn(color) {
  return {
    display: 'inline-block',
    padding: '4px 10px', background: 'transparent',
    color, border: `1px solid ${color}44`, borderRadius: 4,
    fontSize: 11, fontWeight: 600,
  }
}
