import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import axios from 'axios'

const SEVERITY_COLOR = {
  critical: '#f85149',
  high:     '#f0883e',
  medium:   '#d29922',
  low:      '#3fb950',
  informative: '#8b949e',
}

export default function FindingsList() {
  const { programId, scanId } = useParams()
  const navigate = useNavigate()

  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState({}) // findingId → bool
  const [reportsByFinding, setReportsByFinding] = useState({}) // findingId → reportId

  useEffect(() => {
    // Load findings and existing reports in parallel
    Promise.all([
      axios.get(`/api/scans/${programId}/${scanId}/findings`),
      axios.get(`/api/reports/${programId}`),
    ])
      .then(([findingsRes, reportsRes]) => {
        setFindings(findingsRes.data.data?.findings ?? [])
        // Build findingId → reportId map from existing reports
        const map = {}
        for (const r of (reportsRes.data.data?.reports ?? [])) {
          if (r.finding_id) map[r.finding_id] = r.id
        }
        setReportsByFinding(map)
      })
      .catch(() => setFindings([]))
      .finally(() => setLoading(false))
  }, [programId, scanId])

  async function handleGenerateReport(finding) {
    // If a report already exists, navigate directly to it
    if (reportsByFinding[finding.id]) {
      navigate(`/programs/${programId}/reports/${reportsByFinding[finding.id]}`)
      return
    }
    setGenerating(g => ({ ...g, [finding.id]: true }))
    try {
      const res = await axios.post(`/api/reports/${programId}/${finding.id}`)
      const reportId = res.data.data.id
      setReportsByFinding(m => ({ ...m, [finding.id]: reportId }))
      navigate(`/programs/${programId}/reports/${reportId}`)
    } catch (e) {
      alert('Failed to generate report: ' + (e.response?.data?.detail || 'server error'))
      setGenerating(g => ({ ...g, [finding.id]: false }))
    }
  }

  if (loading) {
    return <p style={{ color: '#8b949e' }}>Loading findings...</p>
  }

  // Sort by severity weight
  const weight = { critical: 0, high: 1, medium: 2, low: 3, informative: 4 }
  const sorted = [...findings].sort((a, b) =>
    (weight[a.severity] ?? 9) - (weight[b.severity] ?? 9)
  )

  return (
    <div style={{ maxWidth: 900 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0883e', marginBottom: 6 }}>
          Validated Findings
          <span style={{ color: '#8b949e', fontWeight: 400, fontSize: 16, marginLeft: 10 }}>
            {findings.length} passed all 3 filter layers
          </span>
        </h1>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 10 }}>
          {Object.entries(SEVERITY_COLOR).map(([sev, color]) => {
            const count = findings.filter(f => f.severity === sev).length
            if (!count) return null
            return (
              <span key={sev} style={{
                background: color + '22', color, border: `1px solid ${color}`,
                padding: '2px 10px', borderRadius: 12, fontSize: 12, fontWeight: 600,
              }}>
                {count} {sev}
              </span>
            )
          })}
        </div>
      </div>

      {/* Quick link to all reports if any exist */}
      {Object.keys(reportsByFinding).length > 0 && (
        <button
          onClick={() => navigate(`/programs/${programId}/reports`)}
          style={{
            marginTop: 8, padding: '7px 16px',
            background: '#f0883e22', color: '#f0883e',
            border: '1px solid #f0883e', borderRadius: 6,
            fontSize: 13, fontWeight: 600,
          }}
        >
          📄 View all {Object.keys(reportsByFinding).length} generated reports →
        </button>
      )}

      {findings.length === 0 ? (
        <div style={{
          background: '#161b22', border: '1px solid #30363d',
          borderRadius: 6, padding: '24px 20px', textAlign: 'center', color: '#8b949e',
        }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>🎯</div>
          <p style={{ marginBottom: 6 }}>No findings passed all 3 filter layers.</p>
          <p style={{ fontSize: 12 }}>
            Rejected findings are saved to <code>workspace/{programId}/findings/rejected/</code>
          </p>
        </div>
      ) : (
        sorted.map(f => (
          <FindingCard
            key={f.id}
            finding={f}
            generating={generating[f.id]}
            hasReport={!!reportsByFinding[f.id]}
            onGenerate={() => handleGenerateReport(f)}
          />
        ))
      )}

      <div style={{ marginTop: 20 }}>
        <Link to="/" style={{ color: '#8b949e', fontSize: 13 }}>← New program</Link>
      </div>
    </div>
  )
}

function FindingCard({ finding: f, generating, hasReport, onGenerate }) {
  const [expanded, setExpanded] = useState(false)
  const sev = f.severity ?? 'informative'
  const color = SEVERITY_COLOR[sev]

  return (
    <div style={{
      background: '#161b22', border: `1px solid #30363d`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 6, padding: '14px 16px', marginBottom: 10,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <span style={{
          background: color + '22', color, border: `1px solid ${color}`,
          padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
          flexShrink: 0, marginTop: 1,
        }}>
          {sev.toUpperCase()}
        </span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, color: '#e6edf3', marginBottom: 4 }}>{f.title}</div>
          <div style={{ color: '#8b949e', fontSize: 12 }}>
            <code style={{ color: '#58a6ff' }}>{f.url}</code>
            <span style={{ margin: '0 8px' }}>·</span>
            <span>Tool: {f.tool}</span>
            <span style={{ margin: '0 8px' }}>·</span>
            <span>Type: {f.vuln_type}</span>
          </div>
        </div>
      </div>

      {/* Attack chain */}
      {f.filter_result?.attack_chain && (
        <div style={{
          marginTop: 10, padding: '8px 12px',
          background: '#0d1117', borderRadius: 4,
          color: '#c9d1d9', fontSize: 12, lineHeight: 1.6,
        }}>
          <span style={{ color: '#8b949e' }}>Attack chain: </span>
          {f.filter_result.attack_chain}
        </div>
      )}

      {/* PoC evidence */}
      {f.poc_result?.evidence && (
        <div style={{ marginTop: 8, color: '#3fb950', fontSize: 12 }}>
          ✓ {f.poc_result.evidence}
        </div>
      )}

      {/* Expand raw output */}
      {f.raw_output && (
        <button
          onClick={() => setExpanded(e => !e)}
          style={{
            marginTop: 8, background: 'none', border: 'none',
            color: '#8b949e', fontSize: 12, cursor: 'pointer', padding: 0,
          }}
        >
          {expanded ? '▲ Hide raw output' : '▼ Show raw output'}
        </button>
      )}
      {expanded && (
        <pre style={{
          marginTop: 8, padding: '10px 12px', background: '#010409',
          borderRadius: 4, fontSize: 11, color: '#8b949e',
          overflow: 'auto', maxHeight: 200, whiteSpace: 'pre-wrap',
        }}>
          {f.raw_output}
        </pre>
      )}

      {/* Actions */}
      <div style={{ marginTop: 12 }}>
        <button
          onClick={onGenerate}
          disabled={generating}
          style={{
            padding: '6px 16px',
            background: generating ? 'transparent' : hasReport ? '#1f6feb' : '#238636',
            color: generating ? '#8b949e' : '#fff',
            border: generating ? '1px solid #30363d' : 'none',
            borderRadius: 6, fontSize: 13, fontWeight: 600,
            cursor: generating ? 'not-allowed' : 'pointer',
          }}
        >
          {generating
            ? '⏳ Generating report...'
            : hasReport
              ? '📄 View H1 Report →'
              : '📝 Generate H1 Report →'}
        </button>
      </div>
    </div>
  )
}
