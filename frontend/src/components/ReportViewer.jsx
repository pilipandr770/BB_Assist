import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import axios from 'axios'
import ReactMarkdown from 'react-markdown'

const mdStyles = `
  .md-report h1 { font-size: 20px; color: #f0883e; margin: 0 0 16px; }
  .md-report h2 { font-size: 15px; color: #c9d1d9; margin: 20px 0 8px; border-bottom: 1px solid #21262d; padding-bottom: 6px; }
  .md-report h3 { font-size: 14px; color: #e6edf3; margin: 14px 0 6px; }
  .md-report p { color: #c9d1d9; line-height: 1.7; margin-bottom: 10px; }
  .md-report ul, .md-report ol { padding-left: 22px; margin-bottom: 10px; }
  .md-report li { color: #c9d1d9; line-height: 1.7; margin-bottom: 4px; }
  .md-report code { background: #161b22; border: 1px solid #30363d; border-radius: 3px; padding: 1px 5px; font-size: 12px; color: #79c0ff; }
  .md-report pre { background: #010409; border: 1px solid #30363d; border-radius: 6px; padding: 14px 16px; overflow: auto; margin-bottom: 12px; }
  .md-report pre code { background: none; border: none; padding: 0; color: #c9d1d9; font-size: 12px; }
  .md-report strong { color: #e6edf3; }
  .md-report blockquote { border-left: 3px solid #30363d; padding-left: 12px; color: #8b949e; margin: 10px 0; }
  .md-report a { color: #58a6ff; }
  .md-report hr { border: none; border-top: 1px solid #21262d; margin: 16px 0; }
`

export default function ReportViewer() {
  const { programId, reportId } = useParams()

  const [markdown, setMarkdown] = useState('')
  const [meta, setMeta] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [view, setView] = useState('rendered') // 'rendered' | 'raw'
  const [copied, setCopied] = useState(false)
  const [h1Handle, setH1Handle] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [submitResult, setSubmitResult] = useState(null) // {success, url, error}

  useEffect(() => {
    Promise.all([
      axios.get(`/api/reports/${programId}/${reportId}`, { responseType: 'text' }),
      axios.get(`/api/reports/${programId}/${reportId}/meta`).catch(() => null),
    ])
      .then(([reportResp, metaResp]) => {
        setMarkdown(reportResp.data)
        if (metaResp?.data?.data) {
          setMeta(metaResp.data.data)
        }
      })
      .catch(e => setError(e.response?.data?.detail || 'Failed to load report'))
      .finally(() => setLoading(false))
  }, [programId, reportId])

  function handleCopy() {
    navigator.clipboard.writeText(markdown).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  async function handleH1Submit() {
    if (!h1Handle.trim()) {
      alert('Enter the HackerOne program handle (e.g. "acme" for hackerone.com/acme)')
      return
    }
    setSubmitting(true)
    setSubmitResult(null)
    try {
      const resp = await axios.post(
        `/api/reports/${programId}/${reportId}/submit`,
        { h1_program_handle: h1Handle.trim() }
      )
      const data = resp.data?.data || {}
      if (data.success) {
        setSubmitResult({ success: true, url: data.h1_report_url })
      } else {
        setSubmitResult({ success: false, error: data.error || 'Submission failed' })
      }
    } catch (e) {
      setSubmitResult({ success: false, error: e.response?.data?.detail || 'Network error' })
    } finally {
      setSubmitting(false)
    }
  }

  function handleDownload() {
    const blob = new Blob([markdown], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `h1-report-${reportId?.slice(0, 8) ?? 'report'}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (loading) return <p style={{ color: '#8b949e' }}>Loading report...</p>

  if (error) return (
    <div style={{
      background: '#f8514922', border: '1px solid #f85149',
      borderRadius: 6, padding: '12px 16px', color: '#f85149', fontSize: 13,
    }}>
      {error}
    </div>
  )

  return (
    <div style={{ maxWidth: 860 }}>
      <style>{mdStyles}</style>

      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12,
        marginBottom: 20, flexWrap: 'wrap',
      }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0883e', flex: 1 }}>
          H1 Report
        </h1>

        {/* View toggle */}
        <div style={{ display: 'flex', border: '1px solid #30363d', borderRadius: 6, overflow: 'hidden' }}>
          <TabBtn label="Preview" active={view === 'rendered'} onClick={() => setView('rendered')} />
          <TabBtn label="Raw markdown" active={view === 'raw'} onClick={() => setView('raw')} />
        </div>

        {/* Download button */}
        <button onClick={handleDownload} style={{
          padding: '7px 16px',
          background: '#21262d',
          color: '#3fb950',
          border: '1px solid #30363d', borderRadius: 6,
          fontSize: 13, fontWeight: 600,
        }}>
          ⬇ Download .md
        </button>

        {/* Copy button */}
        <button onClick={handleCopy} style={{
          padding: '7px 16px',
          background: copied ? '#238636' : '#21262d',
          color: copied ? '#fff' : '#58a6ff',
          border: '1px solid #30363d', borderRadius: 6,
          fontSize: 13, fontWeight: 600,
        }}>
          {copied ? '✓ Copied!' : '📋 Copy'}
        </button>
      </div>

      {/* H1 Auto-Submit */}
      <div style={{
        background: '#161b22', border: '1px solid #30363d', borderRadius: 6,
        padding: '12px 14px', marginBottom: 14,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ color: '#c9d1d9', fontSize: 13, fontWeight: 600, whiteSpace: 'nowrap' }}>
            🚀 Submit to H1
          </span>
          <input
            value={h1Handle}
            onChange={e => setH1Handle(e.target.value)}
            placeholder="program-handle"
            style={{
              flex: 1, minWidth: 140, maxWidth: 220,
              background: '#0d1117', border: '1px solid #30363d', borderRadius: 4,
              color: '#c9d1d9', fontSize: 13, padding: '5px 10px',
            }}
          />
          <button
            onClick={handleH1Submit}
            disabled={submitting}
            style={{
              padding: '6px 16px',
              background: submitting ? '#21262d' : '#238636',
              color: '#fff', border: 'none', borderRadius: 6,
              fontSize: 13, fontWeight: 600, cursor: submitting ? 'wait' : 'pointer',
            }}
          >
            {submitting ? 'Submitting…' : 'Submit'}
          </button>
          {meta?.h1_submitted && meta?.h1_report_url && (
            <a
              href={meta.h1_report_url}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: '#3fb950', fontSize: 13 }}
            >
              ✓ Submitted → #{meta.h1_report_id}
            </a>
          )}
        </div>
        {submitResult && (
          <div style={{
            marginTop: 8, fontSize: 12,
            color: submitResult.success ? '#3fb950' : '#f85149',
          }}>
            {submitResult.success
              ? <>✓ Report submitted! <a href={submitResult.url} target="_blank" rel="noopener noreferrer" style={{ color: '#58a6ff' }}>{submitResult.url}</a></>
              : `✗ ${submitResult.error}`}
          </div>
        )}
      </div>

      <p style={{ color: '#8b949e', fontSize: 12, marginBottom: 16 }}>
        Enter your HackerOne program handle above to auto-submit, or copy the markdown below and paste manually.
      </p>

      {meta?.quality && (
        <div style={{
          background: '#161b22', border: '1px solid #30363d', borderRadius: 6,
          padding: '12px 14px', marginBottom: 14,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <strong style={{ color: '#c9d1d9', fontSize: 13 }}>Quality Gate</strong>
            <span style={{
              color: meta.quality.hard_blocked ? '#f85149' : meta.quality.gate_passed ? '#3fb950' : '#d29922',
              fontSize: 12,
              fontWeight: 700,
            }}>
              Score: {meta.quality.score ?? 'N/A'}/100
            </span>
            <span style={{ color: '#8b949e', fontSize: 12 }}>
              Status: {meta.quality.hard_blocked ? 'Hard-blocked' : meta.quality.gate_passed ? 'Passed' : 'Needs review'}
            </span>
          </div>
          {Array.isArray(meta.quality.issues) && meta.quality.issues.length > 0 && (
            <div style={{ marginTop: 8, color: '#d29922', fontSize: 12 }}>
              {meta.quality.issues.slice(0, 2).join(' | ')}
            </div>
          )}
        </div>
      )}

      {/* Report content */}
      {view === 'rendered' ? (
        <div className="md-report" style={{
          background: '#161b22', border: '1px solid #30363d',
          borderRadius: 6, padding: '24px 28px',
        }}>
          <ReactMarkdown>{markdown}</ReactMarkdown>
        </div>
      ) : (
        <pre style={{
          background: '#010409', border: '1px solid #30363d',
          borderRadius: 6, padding: '20px', overflow: 'auto',
          fontSize: 12.5, lineHeight: 1.7, whiteSpace: 'pre-wrap',
          color: '#c9d1d9',
        }}>
          {markdown}
        </pre>
      )}

      <div style={{ marginTop: 20, display: 'flex', gap: 20 }}>
        <Link to={`/programs/${programId}/reports`} style={{ color: '#8b949e', fontSize: 13 }}>
          ← All reports
        </Link>
        <Link to="/" style={{ color: '#8b949e', fontSize: 13 }}>
          New program
        </Link>
      </div>
    </div>
  )
}

function TabBtn({ label, active, onClick }) {
  return (
    <button onClick={onClick} style={{
      padding: '6px 14px', border: 'none',
      background: active ? '#21262d' : 'transparent',
      color: active ? '#c9d1d9' : '#8b949e',
      fontSize: 13, cursor: 'pointer',
      borderRight: '1px solid #30363d',
    }}>
      {label}
    </button>
  )
}
