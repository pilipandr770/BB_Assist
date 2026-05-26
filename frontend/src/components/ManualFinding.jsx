import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import axios from 'axios'

const S = {
  h1: { fontSize: 22, fontWeight: 700, color: '#f0883e', marginBottom: 6 },
  label: { display: 'block', color: '#c9d1d9', fontSize: 13, fontWeight: 600, marginBottom: 4 },
  input: {
    width: '100%', padding: '9px 12px',
    background: '#0d1117', border: '1px solid #30363d',
    borderRadius: 6, color: '#c9d1d9', fontSize: 13, outline: 'none',
  },
  card: {
    background: '#161b22', border: '1px solid #30363d',
    borderRadius: 8, padding: '16px 20px',
  },
  btnPrimary: {
    padding: '9px 20px', background: '#238636',
    color: '#fff', border: 'none', borderRadius: 6,
    fontSize: 14, fontWeight: 600,
  },
  btnSecondary: {
    padding: '9px 16px', background: 'transparent',
    color: '#8b949e', border: '1px solid #30363d',
    borderRadius: 6, fontSize: 14,
  },
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informative']

export default function ManualFinding() {
  const { programId } = useParams()
  const navigate = useNavigate()

  const [form, setForm] = useState({
    title: '',
    url: '',
    severity: 'medium',
    vuln_type: 'manual',
    description: '',
    steps_to_reproduce: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  function set(key, val) {
    setForm(f => ({ ...f, [key]: val }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (!form.title.trim() || !form.url.trim()) {
      setError('Title and URL are required.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const res = await axios.post('/api/scans/findings/manual', {
        program_id: programId,
        ...form,
      })
      setResult(res.data.data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to submit finding.')
    } finally {
      setSubmitting(false)
    }
  }

  if (result) {
    return (
      <div style={{ maxWidth: 700 }}>
        <h1 style={S.h1}>Finding Submitted</h1>
        <div style={{
          ...S.card, background: '#23863622', border: '1px solid #238636',
          color: '#3fb950', marginBottom: 20,
        }}>
          ✓ Finding saved (ID: {result.finding_id})
          {result.report?.report_id && (
            <span style={{ marginLeft: 12, color: '#58a6ff' }}>
              · Report generated: {result.report.title}
            </span>
          )}
          {result.report?.error && (
            <span style={{ marginLeft: 12, color: '#f0883e' }}>
              · Report error: {result.report.error}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <button
            onClick={() => { setResult(null); setForm({ title: '', url: '', severity: 'medium', vuln_type: 'manual', description: '', steps_to_reproduce: '' }) }}
            style={S.btnPrimary}
          >
            Add Another Finding
          </button>
          <button onClick={() => navigate(`/programs/${programId}/reports`)} style={S.btnSecondary}>
            View Reports →
          </button>
        </div>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: 700 }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={S.h1}>Add Manual Finding</h1>
        <p style={{ color: '#8b949e', fontSize: 13 }}>
          Record a vulnerability you found during manual testing. It will be processed by AI and a HackerOne report will be generated.
        </p>
      </div>

      {error && (
        <div style={{
          background: '#f8514922', border: '1px solid #f85149',
          borderRadius: 6, padding: '10px 14px', color: '#f85149',
          fontSize: 13, marginBottom: 16,
        }}>
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div style={{ ...S.card, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={S.label}>Title *</label>
            <input
              value={form.title}
              onChange={e => set('title', e.target.value)}
              placeholder="e.g. Stored XSS in profile bio field"
              style={S.input}
              required
            />
          </div>

          <div>
            <label style={S.label}>Target URL *</label>
            <input
              value={form.url}
              onChange={e => set('url', e.target.value)}
              placeholder="https://app.example.com/profile"
              style={S.input}
              required
            />
          </div>

          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <label style={S.label}>Severity</label>
              <select
                value={form.severity}
                onChange={e => set('severity', e.target.value)}
                style={S.input}
              >
                {SEVERITIES.map(s => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </div>
            <div style={{ flex: 1 }}>
              <label style={S.label}>Vulnerability Type</label>
              <input
                value={form.vuln_type}
                onChange={e => set('vuln_type', e.target.value)}
                placeholder="e.g. xss, sqli, idor, ssrf"
                style={S.input}
              />
            </div>
          </div>

          <div>
            <label style={S.label}>Description</label>
            <textarea
              value={form.description}
              onChange={e => set('description', e.target.value)}
              placeholder="Describe the vulnerability, its impact, and any relevant context..."
              rows={4}
              style={{ ...S.input, resize: 'vertical', lineHeight: 1.6 }}
            />
          </div>

          <div>
            <label style={S.label}>Steps to Reproduce</label>
            <textarea
              value={form.steps_to_reproduce}
              onChange={e => set('steps_to_reproduce', e.target.value)}
              placeholder={"1. Navigate to /profile\n2. Enter <script>alert(1)</script> in bio\n3. Save and visit the profile page\n4. Observe alert fires"}
              rows={5}
              style={{ ...S.input, resize: 'vertical', lineHeight: 1.6 }}
            />
          </div>

          <div style={{ display: 'flex', gap: 12, marginTop: 4 }}>
            <button
              type="submit"
              disabled={submitting}
              style={{ ...S.btnPrimary, opacity: submitting ? 0.5 : 1 }}
            >
              {submitting ? '⏳ Submitting...' : '✓ Submit Finding'}
            </button>
            <button type="button" onClick={() => navigate(-1)} style={S.btnSecondary}>
              ← Cancel
            </button>
          </div>
        </div>
      </form>
    </div>
  )
}
