// Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { LoadingSpinner } from './components/LoadingSpinner'

const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })))
const ScanPage = lazy(() => import('./pages/ScanPage').then(m => ({ default: m.ScanPage })))
const ScanDetail = lazy(() => import('./pages/ScanDetail').then(m => ({ default: m.ScanDetail })))
const ScansHistory = lazy(() => import('./pages/ScansHistory').then(m => ({ default: m.ScansHistory })))
const SignaturesPage = lazy(() => import('./pages/SignaturesPage').then(m => ({ default: m.SignaturesPage })))
const CampaignsPage = lazy(() => import('./pages/CampaignsPage').then(m => ({ default: m.CampaignsPage })))

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Suspense fallback={<LoadingSpinner label="Loading..." />}><Dashboard /></Suspense>} />
          <Route path="/scan" element={<Suspense fallback={<LoadingSpinner label="Loading..." />}><ScanPage /></Suspense>} />
          <Route path="/scan/:scanId" element={<Suspense fallback={<LoadingSpinner label="Loading..." />}><ScanDetail /></Suspense>} />
          <Route path="/scans" element={<Suspense fallback={<LoadingSpinner label="Loading..." />}><ScansHistory /></Suspense>} />
          <Route path="/signatures" element={<Suspense fallback={<LoadingSpinner label="Loading..." />}><SignaturesPage /></Suspense>} />
          <Route path="/campaigns" element={<Suspense fallback={<LoadingSpinner label="Loading..." />}><CampaignsPage /></Suspense>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
