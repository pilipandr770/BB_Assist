import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import axios from 'axios'

const SEV_COLOR = { critical: '#f85149', high: '#f0883e', medium: '#d29922', low: '#3fb950' }

const SEVERITY_COLOR = {
  critical: '#f85149',
  high: '#f0883e',
  medium: '#d29922',
  low: '#3fb950',
}

export default function ProgramsList() {
  const [programs, setPrograms] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    axios.get('/api/programs')
      .then(r => setPrograms(r.data.data?.programs ?? []))
      .catch(() => setPrograms([]))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <p style={{ color: '#8b949e' }}>Loading programs...</p>

  return (
    <div style={{ maxWidth: 860 }}>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0883e', flex: 1 }}>
          My Programs
        </h1>
        <button
          onClick={() => navigate('/')}
          style={{
            padding: '8px 16px', background: '#238636',
            color: '#fff', border: 'none', borderRadius: 6,
            fontSize: 13, fontWeight: 600,
          }}
        >
          + New Program
        </button>
      </div>

      {programs.length === 0 ? (
        <div style={{
          background: '#161b22', border: '1px solid #30363d',
          borderRadius: 6, padding: '40px 20px', textAlign: 'center',
        }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>🎯</div>
          <p style={{ color: '#c9d1d9', marginBottom: 8 }}>No programs yet.</p>
          <p style={{ color: '#8b949e', fontSize: 13, marginBottom: 20 }}>
            Paste an H1 program scope to get started.
          </p>
          <button
            onClick={() => navigate('/')}
            style={{
              padding: '8px 18px', background: '#238636',
              color: '#fff', border: 'none', borderRadius: 6, fontSize: 14,
            }}
          >
            Add first program →
          </button>
        </div>
      ) : (
        programs.map(p => <ProgramCard key={p.id} program={p} />)
      )}
    </div>
  )
}

function ProgramCard({ program: p }) {
  const navigate = useNavigate()
  const scope = p.scope ?? {}
  const domains = scope.in_scope_domains ?? []
  const programType = scope.program_type ?? 'web'

  const typeColor = {
    web: '#58a6ff', api: '#d29922', blockchain: '#a371f7',
    mobile: '#3fb950', source_code: '#f0883e',
  }

  return (
    <div
      onClick={() => navigate(`/programs/${p.id}`)}
      style={{
        background: '#161b22', border: '1px solid #30363d',
        borderRadius: 6, padding: '16px 18px', marginBottom: 10,
        cursor: 'pointer', transition: 'border-color .15s',
      }}
      onMouseEnter={e => e.currentTarget.style.borderColor = '#58a6ff'}
      onMouseLeave={e => e.currentTarget.style.borderColor = '#30363d'}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <span style={{ fontWeight: 700, color: '#e6edf3', fontSize: 15 }}>{p.name}</span>
            <span style={{
              background: (typeColor[programType] ?? '#8b949e') + '22',
              color: typeColor[programType] ?? '#8b949e',
              border: `1px solid ${typeColor[programType] ?? '#8b949e'}`,
              padding: '1px 7px', borderRadius: 4, fontSize: 11, fontWeight: 600,
            }}>
              {programType}
            </span>
            {p.h1_program_handle && (
              <span style={{ color: '#8b949e', fontSize: 11 }}>
                h1: {p.h1_program_handle}
              </span>
            )}
          </div>

          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
            {domains.slice(0, 5).map(d => (
              <code key={d} style={{
                background: '#0d1117', border: '1px solid #21262d',
                borderRadius: 4, padding: '1px 7px', fontSize: 11, color: '#79c0ff',
              }}>
                {d}
              </code>
            ))}
            {domains.length > 5 && (
              <span style={{ color: '#8b949e', fontSize: 11 }}>+{domains.length - 5} more</span>
            )}
          </div>

          <div style={{ color: '#8b949e', fontSize: 12 }}>
            <span>{domains.length} domains in scope</span>
            <span style={{ margin: '0 8px' }}>·</span>
            <span>{scope.excluded_vuln_types?.length ?? 0} excluded vuln types</span>
            {p.created_at && (
              <>
                <span style={{ margin: '0 8px' }}>·</span>
                <span>Added {new Date(p.created_at).toLocaleDateString()}</span>
              </>
            )}
          </div>
        </div>

        <div style={{ color: '#8b949e', fontSize: 12, flexShrink: 0 }}>
          View dashboard →
        </div>
      </div>
    </div>
  )
}
