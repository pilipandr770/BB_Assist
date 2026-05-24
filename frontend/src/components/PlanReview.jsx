import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import axios from 'axios'

export default function PlanReview() {
  const { programId } = useParams()
  const navigate = useNavigate()

  const [plan, setPlan] = useState('')
  const [scope, setScope] = useState(null)
  const [phase, setPhase] = useState('generating') // generating | review | starting
  const [error, setError] = useState(null)
  const [sessionCookies, setSessionCookies] = useState('')
  const [authHeader, setAuthHeader] = useState('')
  const [showAuth, setShowAuth] = useState(false)
  const calledRef = useRef(false)

  // On mount: generate plan (POST), then fetch it (GET)
  useEffect(() => {
    // Guard against React StrictMode double-invoke
    if (calledRef.current) return
    calledRef.current = true

    let cancelled = false

    async function init() {
      try {
        // Generate plan via Claude
        await axios.post(`/api/programs/${programId}/plan`)
        if (cancelled) return

        // Load the generated plan (required)
        const planRes = await axios.get(`/api/programs/${programId}/plan`)
        if (cancelled) return
        setPlan(planRes.data.data.plan)

        // Load scope for display (optional — failure is non-fatal)
        axios.get(`/api/programs/${programId}`)
          .then(r => { if (!cancelled) setScope(r.data.data.scope) })
          .catch(() => {})

        setPhase('review')
      } catch (e) {
        if (!cancelled) setError(e.response?.data?.detail || 'Failed to generate plan')
      }
    }

    init()
    return () => { cancelled = true }
  }, [programId])

  async function handleApprove() {
    setPhase('starting')
    try {
      const res = await axios.post('/api/scans/start', {
        program_id: programId,
        approved_plan: plan,
        session_cookies: sessionCookies,
        auth_header: authHeader,
      })
      navigate(`/programs/${programId}/scans/${res.data.data.id}`)
    } catch (e) {
      setError('Failed to start scan: ' + (e.response?.data?.detail || 'server error'))
      setPhase('review')
    }
  }

  if (error) {
    return (
      <div style={{ maxWidth: 740 }}>
        <ErrorBox message={error} />
        <button onClick={() => navigate('/')} style={S.btnSecondary}>
          ← Start over
        </button>
      </div>
    )
  }

  if (phase === 'generating') {
    return (
      <div style={{ maxWidth: 740 }}>
        <h1 style={S.h1}>Generating Testing Plan</h1>
        <Spinner label="Claude is analyzing scope and generating a targeted testing plan..." />
      </div>
    )
  }

  return (
    <div style={{ maxWidth: 900 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={S.h1}>Review Testing Plan</h1>
        <p style={{ color: '#8b949e', fontSize: 13 }}>
          Claude generated this plan based on the program scope. Review it, then approve to start scanning.
        </p>
      </div>

      {/* Scope summary */}
      {scope && (
        <div style={{ ...S.card, marginBottom: 20 }}>
          <div style={{ display: 'flex', gap: 32, flexWrap: 'wrap' }}>
            <ScopeItem label="Program type" value={scope.program_type} color="#58a6ff" />
            <ScopeItem
              label="In scope"
              value={`${scope.in_scope_domains?.length ?? 0} domains`}
              color={(scope.in_scope_domains?.length ?? 0) > 0 ? '#3fb950' : '#f85149'}
            />
            <ScopeItem label="Excluded vuln types" value={`${scope.excluded_vuln_types?.length ?? 0} types`} color="#f0883e" />
          </div>
          {(scope.in_scope_domains?.length ?? 0) === 0 && (
            <div style={{
              marginTop: 12, padding: '10px 14px',
              background: '#f8514922', border: '1px solid #f85149',
              borderRadius: 6, color: '#f85149', fontSize: 12,
            }}>
              ⚠ Claude could not extract any in-scope domains from the program text.
              The scan will be blocked. Go back and re-create the program — paste the full HackerOne
              scope section including the "In scope" table or list with specific domains like
              <code style={{ marginLeft: 4 }}>*.example.com</code>.
            </div>
          )}
        </div>
      )}

      {/* Plan text — editable so user can tweak */}
      <label style={{ ...S.label, marginBottom: 8 }}>
        Testing plan
        <span style={{ color: '#8b949e', fontWeight: 400, marginLeft: 8 }}>(you can edit before approving)</span>
      </label>
      <textarea
        value={plan}
        onChange={e => setPlan(e.target.value)}
        style={{
          width: '100%', minHeight: 480, padding: '14px 16px',
          background: '#0d1117', border: '1px solid #30363d',
          borderRadius: 6, color: '#c9d1d9', fontSize: 13,
          lineHeight: 1.7, resize: 'vertical', outline: 'none',
        }}
      />

      <div style={{ ...S.card, marginTop: 14 }}>
        <button
          type="button"
          onClick={() => setShowAuth(v => !v)}
          style={{
            background: 'transparent',
            border: 'none',
            color: '#58a6ff',
            fontWeight: 600,
            padding: 0,
          }}
        >
          {showAuth ? '▼' : '▶'} Authentication (optional)
        </button>

        {showAuth && (
          <div style={{ marginTop: 12 }}>
            <label style={S.label}>Session Cookie</label>
            <input
              value={sessionCookies}
              onChange={e => setSessionCookies(e.target.value)}
              placeholder="sessionid=abc123; csrftoken=xyz"
              style={S.input}
            />

            <label style={{ ...S.label, marginTop: 12 }}>Authorization Header</label>
            <input
              value={authHeader}
              onChange={e => setAuthHeader(e.target.value)}
              placeholder="Bearer eyJhbGci..."
              style={S.input}
            />

            <div style={{
              marginTop: 10,
              fontSize: 12,
              color: '#f0883e',
              background: '#f0883e22',
              border: '1px solid #f0883e',
              borderRadius: 6,
              padding: '8px 10px',
            }}>
              These are passed directly to scanning tools. Never use real production credentials.
            </div>
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
        <button
          onClick={handleApprove}
          disabled={phase === 'starting' || (scope && (scope.in_scope_domains?.length ?? 0) === 0)}
          title={(scope && (scope.in_scope_domains?.length ?? 0) === 0) ? 'No in-scope domains — re-create the program' : ''}
          style={{
            ...S.btnPrimary,
            opacity: (phase === 'starting' || (scope && (scope.in_scope_domains?.length ?? 0) === 0)) ? 0.4 : 1,
            cursor: (scope && (scope.in_scope_domains?.length ?? 0) === 0) ? 'not-allowed' : 'pointer',
          }}
        >
          {phase === 'starting' ? '⏳ Starting scan...' : '✓ Approve & Start Scan'}
        </button>
        <button onClick={() => navigate('/')} style={S.btnSecondary}>
          ← Cancel
        </button>
      </div>
    </div>
  )
}

function ScopeItem({ label, value, color }) {
  return (
    <div>
      <div style={{ color: '#8b949e', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ color, fontWeight: 600 }}>{value}</div>
    </div>
  )
}

function Spinner({ label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, color: '#8b949e', fontSize: 13 }}>
      <div style={{
        width: 16, height: 16, border: '2px solid #30363d',
        borderTopColor: '#58a6ff', borderRadius: '50%',
        animation: 'spin 0.8s linear infinite',
      }} />
      {label}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}

function ErrorBox({ message }) {
  return (
    <div style={{
      background: '#f8514922', border: '1px solid #f85149',
      borderRadius: 6, padding: '12px 16px', color: '#f85149',
      fontSize: 13, marginBottom: 16,
    }}>
      {message}
    </div>
  )
}

const S = {
  h1: { fontSize: 22, fontWeight: 700, color: '#f0883e', marginBottom: 6 },
  label: { display: 'block', color: '#c9d1d9', fontSize: 13, fontWeight: 600 },
  card: {
    background: '#161b22', border: '1px solid #30363d',
    borderRadius: 6, padding: '14px 18px',
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
  input: {
    width: '100%',
    padding: '9px 12px',
    background: '#0d1117',
    border: '1px solid #30363d',
    borderRadius: 6,
    color: '#c9d1d9',
    fontSize: 13,
    outline: 'none',
  },
}
