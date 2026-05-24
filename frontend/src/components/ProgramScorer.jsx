import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

function splitPrograms(text) {
  return text
    .split(/^---\s*$/m)
    .map((x) => x.trim())
    .filter(Boolean)
}

function scoreColor(score) {
  if (score >= 70) return '#3fb950'
  if (score >= 40) return '#d29922'
  return '#f85149'
}

export default function ProgramScorer() {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [results, setResults] = useState([])
  const navigate = useNavigate()

  const count = useMemo(() => splitPrograms(input).length, [input])

  async function onAnalyze() {
    const programs = splitPrograms(input)
    if (!programs.length) {
      setError('Paste at least one program scope.')
      return
    }

    setLoading(true)
    setError('')
    try {
      const res = await axios.post('/api/scorer/analyze', { programs })
      setResults(res.data?.data?.results || [])
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to analyze program scopes')
    } finally {
      setLoading(false)
    }
  }

  function startScanWithProgram(result) {
    localStorage.setItem('bb_prefill_program_name', result.program_name || '')
    localStorage.setItem('bb_prefill_program_scope', result.program_text || '')
    navigate('/')
  }

  return (
    <div style={{ maxWidth: 980 }}>
      <h1 style={{ fontSize: 22, color: '#f0883e', marginBottom: 8 }}>Program Scorer</h1>
      <p style={{ color: '#8b949e', marginBottom: 16 }}>
        Paste program scopes. Separate multiple programs with --- on its own line.
      </p>

      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        rows={16}
        placeholder={'Program scope text #1\n---\nProgram scope text #2'}
        style={{
          width: '100%',
          background: '#161b22',
          color: '#c9d1d9',
          border: '1px solid #30363d',
          borderRadius: 8,
          padding: 12,
          lineHeight: 1.5,
          resize: 'vertical',
          marginBottom: 12,
        }}
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <button
          onClick={onAnalyze}
          disabled={loading}
          style={{
            padding: '9px 16px',
            border: 'none',
            borderRadius: 6,
            background: '#238636',
            color: '#fff',
            fontWeight: 600,
            cursor: loading ? 'not-allowed' : 'pointer',
            opacity: loading ? 0.7 : 1,
          }}
        >
          {loading ? 'Analyzing...' : 'Analyze programs'}
        </button>
        <span style={{ color: '#8b949e', fontSize: 13 }}>Detected blocks: {count}</span>
      </div>

      {error && (
        <div style={{
          border: '1px solid #f85149',
          background: '#f8514922',
          color: '#f85149',
          borderRadius: 6,
          padding: 10,
          marginBottom: 16,
        }}>
          {error}
        </div>
      )}

      <div style={{ display: 'grid', gap: 10 }}>
        {results.map((r, idx) => (
          <div key={`${r.program_name}-${idx}`} style={{
            border: '1px solid #30363d',
            borderRadius: 8,
            background: '#161b22',
            padding: 14,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ color: '#e6edf3', fontWeight: 700 }}>{r.program_name}</div>
                <div style={{ color: '#8b949e', fontSize: 12 }}>scope: {r.scope_type}</div>
              </div>
              <div style={{
                border: `1px solid ${scoreColor(r.score)}`,
                color: scoreColor(r.score),
                padding: '4px 10px',
                borderRadius: 999,
                fontWeight: 700,
              }}>
                {r.score}
              </div>
            </div>

            <div style={{ marginTop: 10, color: '#c9d1d9', fontSize: 13 }}>
              <strong>Our tool covers:</strong> {(r.our_tool_fit || []).join(', ') || 'n/a'}
            </div>
            <div style={{ marginTop: 6, color: '#c9d1d9', fontSize: 13 }}>
              <strong>Missing:</strong> {(r.missing_coverage || []).join(', ') || 'none'}
            </div>
            <div style={{ marginTop: 6, color: '#8b949e', fontSize: 13 }}>
              {r.recommendation}
            </div>

            {r.red_flags?.length > 0 && (
              <div style={{ marginTop: 8, color: '#f85149', fontSize: 13 }}>
                Red flags: {r.red_flags.join(', ')}
              </div>
            )}

            <div style={{ marginTop: 10 }}>
              <button
                onClick={() => startScanWithProgram(r)}
                style={{
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid #30363d',
                  background: '#0d1117',
                  color: '#58a6ff',
                  fontWeight: 600,
                }}
              >
                Start scan with this program
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
