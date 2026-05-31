import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

export default function HistoryList() {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(null)
  const navigate = useNavigate()

  async function load() {
    setLoading(true)
    setError('')
    try {
      const res = await axios.get('/api/history/programs')
      setRows(res.data?.data?.programs || [])
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load history')
    } finally {
      setLoading(false)
    }
  }

  async function viewProgram(programId) {
    const res = await axios.get(`/api/history/programs/${programId}`)
    setSelected(res.data?.data || null)
  }

  async function rescan(programId) {
    const res = await axios.post('/api/scans/start', {
      program_id: programId,
      approved_plan: 'Rescan from history',
    })
    const scan = res.data?.data
    navigate(`/programs/${programId}/scans/${scan.id}`)
  }

  useEffect(() => {
    load()
  }, [])

  return (
    <div style={{ maxWidth: 980 }}>
      <h1 style={{ fontSize: 22, color: '#f0883e', marginBottom: 10 }}>History</h1>
      <p style={{ color: '#8b949e', marginBottom: 16 }}>
        Program name, last scan date, total scans/findings, and estimated LLM cost.
      </p>

      {loading && <div style={{ color: '#8b949e' }}>Loading history...</div>}
      {error && <div style={{ color: '#f85149' }}>{error}</div>}

      {!loading && !error && (
        <div style={{ border: '1px solid #30363d', borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead style={{ background: '#161b22' }}>
              <tr>
                <th style={th}>Program</th>
                <th style={th}>Last scan</th>
                <th style={th}>Total scans</th>
                <th style={th}>Total findings</th>
                <th style={th}>LLM cost</th>
                <th style={th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ borderTop: '1px solid #30363d' }}>
                  <td style={td}>{r.name}</td>
                  <td style={td}>{r.last_scan_at ? new Date(r.last_scan_at).toLocaleString() : '-'}</td>
                  <td style={td}>{r.scan_count}</td>
                  <td style={td}>{r.total_findings}</td>
                  <td style={td}>${Number(r.total_llm_cost_usd || 0).toFixed(4)}</td>
                  <td style={td}>
                    <button style={btn} onClick={() => viewProgram(r.id)}>View</button>
                    <button style={btn} onClick={() => rescan(r.id)}>Rescan</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <div style={{ marginTop: 16, border: '1px solid #30363d', borderRadius: 8, padding: 12, background: '#161b22' }}>
          <div style={{ color: '#e6edf3', fontWeight: 700, marginBottom: 8 }}>{selected.name}</div>
          <div style={{ color: '#8b949e', marginBottom: 8 }}>Scans: {(selected.scans || []).length}</div>
          <div style={{ display: 'grid', gap: 8 }}>
            {(selected.scans || []).map((s) => (
              <div key={s.id} style={{ border: '1px solid #30363d', borderRadius: 6, padding: 8 }}>
                <div style={{ color: '#c9d1d9', fontSize: 13 }}>
                  {s.id} · {s.status} · findings {s.findings_count} · reports {s.reports_count} · llm ${Number(s.llm_cost_usd || 0).toFixed(4)}
                </div>
                <div style={{ marginTop: 6 }}>
                  <button style={btn} onClick={() => navigate(`/programs/${selected.id}/scans/${s.id}`)}>Open scan</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

const th = {
  textAlign: 'left',
  padding: '10px 12px',
  color: '#8b949e',
  fontWeight: 600,
  fontSize: 12,
}

const td = {
  padding: '10px 12px',
  color: '#c9d1d9',
  fontSize: 13,
}

const btn = {
  marginRight: 8,
  padding: '6px 10px',
  borderRadius: 6,
  border: '1px solid #30363d',
  background: '#0d1117',
  color: '#58a6ff',
  fontWeight: 600,
}
