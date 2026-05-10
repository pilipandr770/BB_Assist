import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

const S = {
  label: { display: 'block', marginBottom: 6, color: '#8b949e', fontSize: 13 },
  input: {
    width: '100%', padding: '9px 12px',
    background: '#161b22', border: '1px solid #30363d',
    borderRadius: 6, color: '#c9d1d9', fontSize: 14,
    outline: 'none', transition: 'border-color .15s',
  },
  btnPrimary: {
    padding: '9px 20px', background: '#238636',
    color: '#fff', border: 'none', borderRadius: 6,
    fontSize: 14, fontWeight: 600,
    opacity: 1, transition: 'opacity .15s',
  },
}

export default function ProgramInput() {
  const [name, setName] = useState('')
  const [rawText, setRawText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  async function handleSubmit(e) {
    e.preventDefault()
    if (!name.trim() || !rawText.trim()) {
      setError('Program name and scope text are required.')
      return
    }
    setLoading(true)
    setError(null)
    try {
      const res = await axios.post('/api/programs', {
        name: name.trim(),
        raw_text: rawText.trim(),
      })
      navigate(`/programs/${res.data.data.id}/plan`)
    } catch (e) {
      setError(e.response?.data?.detail || 'Backend error — is the server running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: 740 }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0883e', marginBottom: 6 }}>
          New Bug Bounty Program
        </h1>
        <p style={{ color: '#8b949e', fontSize: 13 }}>
          Paste the full HackerOne program page — scope, rules, out-of-scope, everything.
          Claude will parse it and generate a targeted testing plan.
        </p>
      </div>

      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 16 }}>
          <label style={S.label}>Program name</label>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="e.g. Circle BBP — Arc testnet"
            style={S.input}
            autoFocus
          />
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={S.label}>
            H1 program text
            <span style={{ marginLeft: 8, color: '#3fb950' }}>
              (scope + out-of-scope + rules)
            </span>
          </label>
          <textarea
            value={rawText}
            onChange={e => setRawText(e.target.value)}
            placeholder={'Paste the complete HackerOne program page here...\n\nInclude:\n- In scope targets\n- Out of scope targets\n- Out of scope vulnerabilities\n- Program rules / disclosure policy\n- Any special instructions'}
            rows={22}
            style={{ ...S.input, resize: 'vertical', lineHeight: 1.6, fontSize: 13 }}
          />
        </div>

        {error && (
          <div style={{
            background: '#f8514933', border: '1px solid #f85149',
            borderRadius: 6, padding: '10px 14px',
            color: '#f85149', fontSize: 13, marginBottom: 14,
          }}>
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          style={{ ...S.btnPrimary, opacity: loading ? 0.6 : 1, cursor: loading ? 'not-allowed' : 'pointer' }}
        >
          {loading ? '⏳ Parsing scope with Claude...' : 'Parse scope & generate plan →'}
        </button>
      </form>
    </div>
  )
}
