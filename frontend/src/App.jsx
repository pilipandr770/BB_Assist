import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom'
import ProgramInput from './components/ProgramInput'
import PlanReview from './components/PlanReview'
import ScanProgress from './components/ScanProgress'
import FindingsList from './components/FindingsList'
import ReportViewer from './components/ReportViewer'
import ReportsList from './components/ReportsList'
import ProgramsList from './components/ProgramsList'
import ProgramScorer from './components/ProgramScorer'
import HistoryList from './components/HistoryList'

const G = {
  bg: '#0d1117',
  surface: '#161b22',
  border: '#30363d',
  text: '#c9d1d9',
  muted: '#8b949e',
  accent: '#f0883e',
  blue: '#58a6ff',
  green: '#3fb950',
}

const globalCss = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, monospace;
    background: ${G.bg};
    color: ${G.text};
    min-height: 100vh;
    font-size: 14px;
    line-height: 1.5;
  }
  a { color: ${G.blue}; text-decoration: none; }
  a:hover { text-decoration: underline; }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: ${G.bg}; }
  ::-webkit-scrollbar-thumb { background: ${G.border}; border-radius: 3px; }
  button { font-family: inherit; cursor: pointer; }
  input, textarea { font-family: inherit; }
`

function Nav() {
  const loc = useLocation()
  const active = (path) => loc.pathname === path
    ? { color: G.text, borderBottom: `2px solid ${G.accent}`, paddingBottom: 2 }
    : { color: G.muted }

  return (
    <nav style={{
      display: 'flex', alignItems: 'center', gap: 24,
      padding: '12px 24px', borderBottom: `1px solid ${G.border}`,
      background: G.surface, position: 'sticky', top: 0, zIndex: 100,
    }}>
      <Link to="/" style={{ color: G.accent, fontWeight: 700, fontSize: 15, letterSpacing: 0.5 }}>
        BB Assistant
      </Link>
      <div style={{ display: 'flex', gap: 20, marginLeft: 8 }}>
        <Link to="/" style={active('/')}>New Program</Link>
        <Link to="/scorer" style={active('/scorer')}>Program Scorer</Link>
        <Link to="/programs" style={active('/programs')}>My Programs</Link>
        <Link to="/history" style={active('/history')}>History</Link>
      </div>
    </nav>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <style>{globalCss}</style>
      <Nav />
      <div style={{ maxWidth: 960, margin: '0 auto', padding: '32px 24px' }}>
        <Routes>
          <Route path="/" element={<ProgramInput />} />
          <Route path="/scorer" element={<ProgramScorer />} />
          <Route path="/programs" element={<ProgramsList />} />
          <Route path="/history" element={<HistoryList />} />
          <Route path="/programs/:programId/plan" element={<PlanReview />} />
          <Route path="/programs/:programId/scans/:scanId" element={<ScanProgress />} />
          <Route path="/programs/:programId/scans/:scanId/findings" element={<FindingsList />} />
          <Route path="/programs/:programId/reports" element={<ReportsList />} />
          <Route path="/programs/:programId/reports/:reportId" element={<ReportViewer />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}
