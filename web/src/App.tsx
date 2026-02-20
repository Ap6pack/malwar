import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { ScanPage } from './pages/ScanPage'
import { ScanDetail } from './pages/ScanDetail'
import { ScansHistory } from './pages/ScansHistory'
import { SignaturesPage } from './pages/SignaturesPage'
import { CampaignsPage } from './pages/CampaignsPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<ScanPage />} />
          <Route path="/scan/:scanId" element={<ScanDetail />} />
          <Route path="/scans" element={<ScansHistory />} />
          <Route path="/signatures" element={<SignaturesPage />} />
          <Route path="/campaigns" element={<CampaignsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
