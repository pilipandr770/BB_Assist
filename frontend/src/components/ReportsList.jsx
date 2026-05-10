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

export default function ReportsList() {
  const { programId } = useParams()
  const navigate = useNavigate()

  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    axios.get(`/api/reports/${programId}`)
      .then(r => setReports(r.data.data?.reports ?? []))
      .catch(e => setError(e.response?.data?.detail || 'Failed to load reports'))
      .finally(() => setLoading(false))
  }, [programId])

  if (loading) return <p style={{ color: '#8b949e' }}>Loading reports...</p>

  if (error) return (
    <div style={{
      background: '#f8514922', border: '1px solid #f85149',
      borderRadius: 6, padding: '12px 16px', color: '#f85149', fontSize: 13,
    }}>
      {error}
    </div>
  )

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, informative: 0 }
  reports.forEach(r => { bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1 })

  return (
    <div style={{ maxWidth: 900 }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0883e', marginBottom: 6 }}>
          Generated Reports
          <span style={{ color: '#8b949e', fontWeight: 400, fontSize: 16, marginLeft: 10 }}>
            {reports.length} report{reports.length !== 1 ? 's' : ''} ready to submit
          </span>
        </h1>

        {/* Severity badges */}
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 10 }}>
          {Object.entries(SEVERITY_COLOR).map(([sev, color]) => {
            const count = bySeverity[sev]
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

        {reports.length > 0 && (
          <p style={{ color: '#8b949e', fontSize: 12, marginTop: 10 }}>
            Click a report to view the HackerOne-ready markdown. Copy and paste it into the H1 submission form.
          </p>
        )}
      </div>

      {/* Reports list */}
      {reports.length === 0 ? (
        <div style={{
          background: '#161b22', border: '1px solid #30363d',
          borderRadius: 6, padding: '24px 20px', textAlign: 'center', color: '#8b949e',
        }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>📄</div>
          <p>No reports generated yet.</p>
          <p style={{ fontSize: 12, marginTop: 6 }}>Reports are auto-generated for every approved finding.</p>
        </div>
      ) : (
        reports.map(report => (
          <ReportCard
            key={report.id}
            report={report}
            programId={programId}
            onClick={() => navigate(`/programs/${programId}/reports/${report.id}`)}
          />
        ))
      )}

      <div style={{ marginTop: 20 }}>
        <Link to="/" style={{ color: '#8b949e', fontSize: 13 }}>← New program</Link>
      </div>
    </div>
  )
}

function ReportCard({ report, programId, onClick }) {
  const sev = report.severity ?? 'medium'
  const color = SEVERITY_COLOR[sev] ?? '#8b949e'

  const date = report.created_at
    ? new Date(typeof report.created_at === 'number'
        ? report.created_at * 1000
        : report.created_at
      ).toLocaleString()
    : ''

  return (
    <div
      onClick={onClick}
      style={{
        background: '#161b22', border: '1px solid #30363d',
        borderLeft: `3px solid ${color}`,
        borderRadius: 6, padding: '14px 16px', marginBottom: 10,
        cursor: 'pointer', transition: 'border-color 0.15s',
      }}
      onMouseEnter={e => e.currentTarget.style.borderColor = '#58a6ff'}
      onMouseLeave={e => e.currentTarget.style.borderColor = '#30363d'}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <span style={{
          background: color + '22', color, border: `1px solid ${color}`,
          padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
          flexShrink: 0, marginTop: 1,
        }}>
          {sev.toUpperCase()}
        </span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, color: '#e6edf3', marginBottom: 4 }}>
            {report.title}
          </div>
          <div style={{ color: '#8b949e', fontSize: 12 }}>
            {date && <span>Generated: {date}</span>}
            <span style={{ margin: '0 8px' }}>·</span>
            <span style={{ color: '#58a6ff' }}>Click to view & copy →</span>
          </div>
        </div>
        <span style={{ color: '#58a6ff', fontSize: 18, flexShrink: 0 }}>📄</span>
      </div>
    </div>
  )
}
