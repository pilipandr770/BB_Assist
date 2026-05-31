import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'

const EVENT_COLORS = {
  phase_start: '#58a6ff',
  phase_done: '#3fb950',
  tool_start: '#8b949e',
  tool_done: '#58a6ff',
  tool_skip: '#6e7681',
  nuclei_progress: '#8b949e',
  pipeline_config: '#8b949e',
  tech_detected: '#a371f7',
  service_versions: '#79c0ff',
  llm_usage: '#79c0ff',
  finding_approved: '#f0883e',
  finding_rejected: '#6e7681',
  finding_evaluating: '#d29922',
  finding_error: '#f85149',
  report_generated: '#3fb950',
  report_error: '#f85149',
  scan_done: '#3fb950',
  scan_error: '#f85149',
  heartbeat: null,
}

const PHASE_LABELS = {
  passive_recon:         '🔍 Passive Recon',
  passive_recon_detail:  '🔍 Passive Recon',
  github_dork:           '🐙 GitHub Dorking',
  active_recon:          '📡 Active Recon',
  content_discovery:     '📂 Content Discovery',
  js_scan:               '🔑 JS Secret Scan',
  bypass_403:            '🔓 403 Bypass Test',
  param_discovery:       '🎯 Parameter Discovery',
  cors_check:            '🌐 CORS Check',
  subdomain_takeover:    '💀 Subdomain Takeover',
  nuclei_scan:           '⚡ Nuclei Scan',
  sqli_validation:       '💉 SQLi Validation',
  filtering:             '🤖 AI Filtering',
  complete:              '✅ Complete',
  failed:                '❌ Failed',
}

const SEVERITY_COLOR = {
  critical: '#f85149',
  high: '#f0883e',
  medium: '#d29922',
  low: '#3fb950',
  informative: '#8b949e',
}

export default function ScanProgress() {
  const { programId, scanId } = useParams()
  const navigate = useNavigate()

  const [lines, setLines] = useState([])
  const [stats, setStats] = useState({ approved: 0, rejected: 0, reports: 0, llmCost: 0 })
  const [phase, setPhase] = useState('Initializing...')
  const [done, setDone] = useState(false)
  const [failed, setFailed] = useState(false)
  const [reportIds, setReportIds] = useState([]) // track generated report IDs for navigation
  const [rerunPhase, setRerunPhase] = useState('nuclei')
  const [rerunning, setRerunning] = useState(false)
  const bottomRef = useRef(null)
  const esRef = useRef(null)

  useEffect(() => {
    const url = `/api/scans/${programId}/${scanId}/stream`
    const es = new EventSource(url)
    esRef.current = es

    // Use a ref so onerror can read the current done state without stale closure
    const completedRef = { current: false }

    const addLine = (text, color) => {
      if (!color) return
      setLines(prev => [...prev, { text, color, ts: new Date().toLocaleTimeString() }])
    }

    const EVENTS = Object.keys(EVENT_COLORS)
    EVENTS.forEach(evType => {
      es.addEventListener(evType, (e) => {
        if (evType === 'heartbeat' || evType === 'pipeline_config') return
        try {
          const data = JSON.parse(e.data)
          if (evType === 'scan_done' || evType === 'scan_error') {
            completedRef.current = true
          }
          handleEvent(evType, data, addLine, es, setReportIds)
        } catch {}
      })
    })

    es.onerror = () => {
      // Ignore connection close that happens naturally after scan_done
      if (completedRef.current) {
        es.close()
        return
      }
      addLine('⚠ Connection lost — scan may still be running in background', '#f85149')
      setFailed(true)
      es.close()
    }

    return () => es.close()
  }, [programId, scanId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  async function handleRerunPhase() {
    setRerunning(true)
    try {
      await fetch(`/api/scans/${scanId}/rerun-phase`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phase: rerunPhase }),
      })
      window.location.reload()
    } finally {
      setRerunning(false)
    }
  }

  function handleEvent(type, data, addLine, es, setReportIds) {
    const color = EVENT_COLORS[type]

    switch (type) {
      case 'phase_start': {
        const label = PHASE_LABELS[data.phase] ?? data.phase?.replace(/_/g, ' ').toUpperCase()
        setPhase(label)
        addLine(`\n▶ Phase: ${label}`, color)
        break
      }

      case 'phase_done': {
        const extras = Object.entries(data)
          .filter(([k]) => k !== 'phase')
          .map(([k, v]) => `${v} ${k}`)
          .join(', ')
        addLine(`  ✓ Done${extras ? ` — ${extras}` : ''}`, color)
        break
      }

      case 'tool_start':
        addLine(`    ⟳ ${data.tool}  ${data.detail ? `(${data.detail})` : ''}`, color)
        break

      case 'tool_skip':
        addLine(`    ⊘ ${data.tool} skipped${data.reason ? ` — ${data.reason}` : ''}`, color)
        break

      case 'tech_detected': {
        const techList = (data.techs || []).join(', ')
        addLine(`  🔬 Tech detected: ${techList || 'none'}`, color)
        break
      }

      case 'service_versions': {
        const samples = (data.samples || [])
          .map(s => `${s.host}:${s.port} -> ${s.display}`)
          .join('; ')
        addLine(
          `  🧾 Service versions: ${samples || 'none'}${data.count > (data.samples || []).length ? ` … +${data.count - (data.samples || []).length} more` : ''}`,
          color,
        )
        break
      }

      case 'tool_done': {
        const extras = []
        if (data.tool === 'nmap' || data.tool === 'nmap_retry') {
          if (data.count != null) extras.push(`${data.count} new endpoints`)
          if (data.versioned_services != null) extras.push(`${data.versioned_services} services fingerprinted`)
          if (data.csv_cve_hits != null) extras.push(`${data.csv_cve_hits} CVE matches`)
        } else if (data.tool === 'cve_csv' || data.tool === 'cve_csv_retry' || data.tool === 'cve_csv_httpx') {
          if (data.count != null) extras.push(`${data.count} matches`)
          if (data.services_checked != null) extras.push(`${data.services_checked} services checked`)
        } else {
          if (data.count != null) extras.push(`${data.count} results`)
        }
        if (data.found != null) extras.push(`${data.found} found`)
        if (data.forbidden != null) extras.push(`${data.forbidden} forbidden`)
        addLine(`    ✓ ${data.tool} → ${extras.join(', ') || '0 results'}`, color)
        break
      }

      case 'nuclei_progress': {
        const mins = Math.floor(data.elapsed_s / 60)
        const secs = data.elapsed_s % 60
        addLine(`    ⟳ nuclei scanning ${data.targets} targets … ${mins}m${secs}s elapsed`, color)
        break
      }

      case 'finding_evaluating':
        addLine(`  ⟳ Evaluating: ${data.title} (${data.vuln_type})`, color)
        break

      case 'finding_approved':
        setStats(s => ({ ...s, approved: s.approved + 1 }))
        addLine(
          `  ★ APPROVED [${data.severity?.toUpperCase()}] ${data.title}`,
          SEVERITY_COLOR[data.severity] ?? color,
        )
        break

      case 'finding_rejected':
        setStats(s => ({ ...s, rejected: s.rejected + 1 }))
        addLine(`  ✗ Rejected: ${data.title} — ${data.reason}`, color)
        break

      case 'report_generated':
        setStats(s => ({ ...s, reports: s.reports + 1 }))
        if (data.report_id) setReportIds(ids => [...ids, data.report_id])
        addLine(`  📄 Report ready: ${data.title}`, color)
        break

      case 'finding_error':
        addLine(`  ✗ Finding error: ${data.raw_title || ''} — ${data.error}`, color)
        break

      case 'report_error':
        addLine(`  ✗ Report failed for finding ${data.finding_id}: ${data.error}`, color)
        break

      case 'llm_usage': {
        const cost = Number(data.estimated_cost_usd || 0)
        setStats(s => ({ ...s, llmCost: cost }))
        addLine(
          `  🤖 LLM usage: ${data.calls || 0} calls, in=${data.input_tokens || 0}, out=${data.output_tokens || 0}, cost=$${cost.toFixed(4)}`,
          color,
        )
        break
      }

      case 'scan_done':
        setStats(s => ({ ...s, approved: data.approved, rejected: data.rejected, reports: data.reports }))
        addLine(
          `\n✓ SCAN COMPLETE — ${data.approved} approved, ${data.rejected} rejected, ${data.reports} reports`,
          color,
        )
        setPhase('complete')
        setDone(true)
        es?.close()
        break

      case 'scan_error':
        addLine(`\n✗ SCAN FAILED: ${data.error}`, color)
        setFailed(true)
        setPhase('failed')
        es?.close()
        break

      default:
        break // unknown events — silently ignore
    }
  }

  return (
    <div style={{ maxWidth: 900 }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0883e', marginBottom: 8 }}>
          Scan in Progress
        </h1>

        {/* Status bar */}
        <div style={{
          display: 'flex', gap: 24, flexWrap: 'wrap',
          background: '#161b22', border: '1px solid #30363d',
          borderRadius: 6, padding: '12px 18px',
        }}>
          <StatusItem label="Phase" value={phase} color="#58a6ff" />
          <StatusItem label="Approved" value={stats.approved} color="#f0883e" />
          <StatusItem label="Rejected" value={stats.rejected} color="#6e7681" />
          <StatusItem label="Reports" value={stats.reports} color="#3fb950" />
          <StatusItem label="LLM Cost" value={`$${Number(stats.llmCost || 0).toFixed(4)}`} color="#79c0ff" />
        </div>
      </div>

      {/* Terminal output */}
      <div style={{
        background: '#010409', border: '1px solid #30363d',
        borderRadius: 6, padding: '14px 16px', height: '55vh',
        overflow: 'auto', fontSize: 12.5, lineHeight: 1.6,
      }}>
        {lines.length === 0 && (
          <span style={{ color: '#6e7681' }}>Waiting for scan events...</span>
        )}
        {lines.map((line, i) => (
          <div key={i} style={{ display: 'flex', gap: 10 }}>
            <span style={{ color: '#6e7681', flexShrink: 0, fontSize: 11 }}>{line.ts}</span>
            <span style={{ color: line.color, whiteSpace: 'pre-wrap' }}>{line.text}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Action buttons */}
      {(done || failed) && (
        <div style={{ marginTop: 16 }}>
          {done && stats.approved > 0 && (
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
              {/* Primary CTA: jump straight to reports if any were generated */}
              {stats.reports > 0 && (
                <button
                  onClick={() => navigate(`/programs/${programId}/reports`)}
                  style={{
                    padding: '9px 20px', background: '#f0883e',
                    color: '#fff', border: 'none', borderRadius: 6,
                    fontSize: 14, fontWeight: 700,
                  }}
                >
                  📄 View {stats.reports} Report{stats.reports !== 1 ? 's' : ''} →
                </button>
              )}
              <button
                onClick={() => navigate(`/programs/${programId}/scans/${scanId}/findings`)}
                style={{
                  padding: '9px 20px', background: '#238636',
                  color: '#fff', border: 'none', borderRadius: 6,
                  fontSize: 14, fontWeight: 600,
                }}
              >
                🎯 View {stats.approved} Finding{stats.approved !== 1 ? 's' : ''} →
              </button>
            </div>
          )}
          {done && stats.approved === 0 && (
            <p style={{ color: '#8b949e', fontSize: 13, marginBottom: 12 }}>
              No findings passed the filter. Check workspace/findings/rejected/ for details.
            </p>
          )}
          <button
            onClick={() => navigate('/')}
            style={{
              padding: '9px 16px', background: 'transparent',
              color: '#8b949e', border: '1px solid #30363d',
              borderRadius: 6, fontSize: 14,
            }}
          >
            ← New program
          </button>

          {done && (
            <div style={{ marginTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              <select
                value={rerunPhase}
                onChange={(e) => setRerunPhase(e.target.value)}
                style={{
                  background: '#161b22',
                  color: '#c9d1d9',
                  border: '1px solid #30363d',
                  borderRadius: 6,
                  padding: '8px 10px',
                }}
              >
                <option value="nuclei">Re-run nuclei</option>
                <option value="js_scan">Re-run JS scan</option>
                <option value="ffuf">Re-run FFUF</option>
                <option value="cors">Re-run CORS check</option>
                <option value="takeover">Re-run subdomain takeover</option>
                <option value="sqli">Re-run SQLi validation</option>
                <option value="passive_recon">Re-run passive recon</option>
              </select>
              <button
                onClick={handleRerunPhase}
                disabled={rerunning}
                style={{
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid #30363d',
                  background: '#0d1117',
                  color: '#58a6ff',
                  fontWeight: 600,
                  opacity: rerunning ? 0.7 : 1,
                }}
              >
                {rerunning ? 'Starting phase...' : 'Re-run phase'}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatusItem({ label, value, color }) {
  return (
    <div>
      <div style={{ color: '#8b949e', fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5 }}>
        {label}
      </div>
      <div style={{ color, fontWeight: 600, fontSize: 15, marginTop: 2 }}>
        {value}
      </div>
    </div>
  )
}
