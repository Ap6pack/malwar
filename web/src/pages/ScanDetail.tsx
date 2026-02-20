// Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft,
  Download,
  Clock,
  Shield,
  ChevronRight,
  AlertTriangle,
  FileWarning,
  User,
  Hash,
  Layers,
  Tag,
  MapPin,
  Activity,
} from 'lucide-react'
import { api, type ScanResult, type Finding } from '../lib/api'
import {
  cn,
  verdictBg,
  verdictColor,
  severityColor,
  formatDate,
  formatDuration,
} from '../lib/utils'
import { Card } from '../components/Card'
import { Badge } from '../components/Badge'
import { LoadingSpinner } from '../components/LoadingSpinner'

// ── Badge variant helpers ────────────────────────────────────────────

function severityVariant(s: string): 'critical' | 'high' | 'medium' | 'low' | 'default' {
  switch (s?.toUpperCase()) {
    case 'CRITICAL': return 'critical'
    case 'HIGH':     return 'high'
    case 'MEDIUM':   return 'medium'
    case 'LOW':      return 'low'
    default:         return 'default'
  }
}

function verdictVariant(v: string): 'clean' | 'malicious' | 'suspicious' | 'default' {
  switch (v?.toUpperCase()) {
    case 'MALICIOUS':  return 'malicious'
    case 'SUSPICIOUS': return 'suspicious'
    case 'CAUTION':    return 'suspicious'
    case 'CLEAN':      return 'clean'
    default:           return 'default'
  }
}

// ── Risk Score Visual ────────────────────────────────────────────────

function RiskScoreGauge({ score }: { score: number }) {
  const circumference = 2 * Math.PI * 40
  const progress = (score / 100) * circumference
  const colorClass =
    score >= 80 ? 'text-severity-critical' :
    score >= 60 ? 'text-severity-high' :
    score >= 40 ? 'text-severity-medium' :
    score >= 20 ? 'text-severity-low' :
                  'text-severity-info'

  const strokeColor =
    score >= 80 ? '#ef4444' :
    score >= 60 ? '#f97316' :
    score >= 40 ? '#eab308' :
    score >= 20 ? '#22c55e' :
                  '#3b82f6'

  return (
    <div className="relative flex items-center justify-center">
      <svg width="100" height="100" viewBox="0 0 100 100" className="-rotate-90">
        <circle
          cx="50"
          cy="50"
          r="40"
          fill="none"
          stroke="#1e1e2e"
          strokeWidth="8"
        />
        <circle
          cx="50"
          cy="50"
          r="40"
          fill="none"
          stroke={strokeColor}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={cn('text-2xl font-bold', colorClass)}>{score}</span>
        <span className="text-[10px] text-text-muted">RISK</span>
      </div>
    </div>
  )
}

// ── Finding Detail Card ──────────────────────────────────────────────

function FindingDetailCard({ finding, index }: { finding: Finding; index: number }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <Card className={cn('transition-colors', expanded && 'border-border-hover')}>
      {/* Collapsed header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-3 px-5 py-4 text-left"
      >
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-bg-hover text-xs font-bold text-text-muted">
          {index + 1}
        </span>
        <Badge variant={severityVariant(finding.severity)} className="shrink-0">
          {finding.severity}
        </Badge>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-text">{finding.title}</p>
          <p className="truncate text-xs text-text-muted">{finding.rule_id}</p>
        </div>
        <span className="shrink-0 rounded-full bg-bg-hover px-2 py-0.5 text-xs font-medium text-text-muted">
          {finding.confidence}%
        </span>
        <ChevronRight
          className={cn(
            'h-4 w-4 shrink-0 text-text-muted transition-transform duration-200',
            expanded && 'rotate-90'
          )}
        />
      </button>

      {/* Expanded details */}
      {expanded && (
        <div className="border-t border-border">
          {/* Description */}
          <div className="px-5 py-4">
            <p className="text-sm leading-relaxed text-text-muted">
              {finding.description}
            </p>
          </div>

          {/* Evidence */}
          {finding.evidence && finding.evidence.length > 0 && (
            <div className="border-t border-border px-5 py-4">
              <p className="mb-2 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wider text-text-muted">
                <FileWarning className="h-3.5 w-3.5" />
                Evidence
              </p>
              <div className="space-y-2">
                {finding.evidence.map((e, i) => (
                  <div
                    key={i}
                    className="overflow-x-auto rounded-lg bg-bg px-4 py-2.5 font-mono text-xs leading-relaxed text-text-muted"
                  >
                    {e}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Metadata grid */}
          <div className="grid grid-cols-2 gap-px border-t border-border bg-border sm:grid-cols-4">
            <div className="flex items-center gap-2 bg-bg-card px-4 py-3">
              <MapPin className="h-3.5 w-3.5 text-text-muted" />
              <div>
                <p className="text-[10px] uppercase tracking-wider text-text-muted">Line</p>
                <p className="text-sm font-medium text-text">
                  {finding.line_start != null ? finding.line_start : '--'}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 bg-bg-card px-4 py-3">
              <Activity className="h-3.5 w-3.5 text-text-muted" />
              <div>
                <p className="text-[10px] uppercase tracking-wider text-text-muted">Confidence</p>
                <p className="text-sm font-medium text-text">{finding.confidence}%</p>
              </div>
            </div>
            <div className="flex items-center gap-2 bg-bg-card px-4 py-3">
              <Layers className="h-3.5 w-3.5 text-text-muted" />
              <div>
                <p className="text-[10px] uppercase tracking-wider text-text-muted">Detector</p>
                <p className="text-sm font-medium text-text">{finding.detector_layer}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 bg-bg-card px-4 py-3">
              <Tag className="h-3.5 w-3.5 text-text-muted" />
              <div>
                <p className="text-[10px] uppercase tracking-wider text-text-muted">Category</p>
                <p className="text-sm font-medium text-text">{finding.category}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </Card>
  )
}

// ── Severity breakdown bar ───────────────────────────────────────────

function SeverityBreakdown({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((sum, c) => sum + c, 0)
  if (total === 0) return null

  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
  const colors: Record<string, string> = {
    CRITICAL: 'bg-severity-critical',
    HIGH: 'bg-severity-high',
    MEDIUM: 'bg-severity-medium',
    LOW: 'bg-severity-low',
    INFO: 'bg-severity-info',
  }

  return (
    <div className="space-y-2">
      <div className="flex h-2 overflow-hidden rounded-full">
        {order.map((sev) => {
          const count = counts[sev] ?? counts[sev.toLowerCase()] ?? 0
          if (count === 0) return null
          const pct = (count / total) * 100
          return (
            <div
              key={sev}
              className={cn('transition-all', colors[sev])}
              style={{ width: `${pct}%` }}
              title={`${sev}: ${count}`}
            />
          )
        })}
      </div>
      <div className="flex flex-wrap gap-3">
        {order.map((sev) => {
          const count = counts[sev] ?? counts[sev.toLowerCase()] ?? 0
          if (count === 0) return null
          return (
            <span key={sev} className="flex items-center gap-1.5 text-xs text-text-muted">
              <span className={cn('h-2 w-2 rounded-full', colors[sev])} />
              {sev} ({count})
            </span>
          )
        })}
      </div>
    </div>
  )
}

// ── Main ScanDetail Component ────────────────────────────────────────

export function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!scanId) return
    let cancelled = false

    async function fetchScan() {
      try {
        setLoading(true)
        setError(null)
        const data = await api.getScan(scanId!)
        if (!cancelled) setScan(data)
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load scan')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchScan()
    return () => { cancelled = true }
  }, [scanId])

  const handleDownloadSarif = async () => {
    if (!scanId) return
    try {
      const sarif = await api.getScanSarif(scanId)
      const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${scanId}.sarif.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // SARIF may not be available
    }
  }

  // ── Loading state ──────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="py-20">
        <LoadingSpinner size="lg" label="Loading scan details..." />
      </div>
    )
  }

  // ── Error / 404 state ──────────────────────────────────────────────

  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-20">
        <AlertTriangle className="h-12 w-12 text-severity-high" />
        <p className="text-lg font-medium text-text">
          {error ?? 'Scan not found'}
        </p>
        <p className="text-sm text-text-muted">
          {error ? 'There was an error loading this scan.' : `No scan exists with ID "${scanId}".`}
        </p>
        <Link
          to="/scans"
          className="mt-2 flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to History
        </Link>
      </div>
    )
  }

  // ── Success state ──────────────────────────────────────────────────

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Back navigation */}
      <Link
        to="/scans"
        className="inline-flex items-center gap-1.5 text-sm text-text-muted transition-colors hover:text-text"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to History
      </Link>

      {/* Header Section */}
      <div className="flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1 space-y-3">
          {/* Verdict + Skill name */}
          <div className="flex flex-wrap items-center gap-3">
            <Badge
              variant={verdictVariant(scan.verdict)}
              className="px-3 py-1 text-sm font-semibold"
            >
              {scan.verdict}
            </Badge>
            <h1 className="text-2xl font-bold text-text">
              {scan.skill_name || 'Untitled Scan'}
            </h1>
          </div>

          {/* Metadata row */}
          <div className="flex flex-wrap items-center gap-4 text-sm text-text-muted">
            <span className="flex items-center gap-1.5" title="Scan ID">
              <Hash className="h-3.5 w-3.5" />
              <span className="font-mono text-xs">{scan.scan_id}</span>
            </span>
            {scan.skill_author && (
              <span className="flex items-center gap-1.5" title="Author">
                <User className="h-3.5 w-3.5" />
                {scan.skill_author}
              </span>
            )}
            <span className="flex items-center gap-1.5" title="Duration">
              <Clock className="h-3.5 w-3.5" />
              {formatDuration(scan.duration_ms)}
            </span>
            <span className="flex items-center gap-1.5" title="Date">
              <Shield className="h-3.5 w-3.5" />
              {formatDate(scan.created_at ?? null)}
            </span>
          </div>

          {/* Overall severity */}
          {scan.overall_severity && (
            <p className={cn('text-sm font-medium', severityColor(scan.overall_severity))}>
              Overall Severity: {scan.overall_severity}
            </p>
          )}
        </div>

        {/* Risk Score Gauge */}
        <div className="shrink-0">
          <RiskScoreGauge score={scan.risk_score} />
        </div>
      </div>

      {/* Verdict Banner */}
      <div className={cn('rounded-xl border p-5', verdictBg(scan.verdict))}>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium opacity-80">Scan Verdict</p>
            <p className={cn('text-2xl font-bold', verdictColor(scan.verdict))}>
              {scan.verdict}
            </p>
          </div>
          <div className="text-right">
            <p className="text-sm font-medium opacity-80">Risk Score</p>
            <p className="text-2xl font-bold">{scan.risk_score}/100</p>
          </div>
        </div>
      </div>

      {/* Severity Breakdown */}
      {scan.finding_count_by_severity &&
        Object.keys(scan.finding_count_by_severity).length > 0 && (
        <Card className="p-5">
          <h2 className="mb-3 text-sm font-semibold text-text">Severity Breakdown</h2>
          <SeverityBreakdown counts={scan.finding_count_by_severity} />
        </Card>
      )}

      {/* Actions bar */}
      <div className="flex flex-wrap gap-3">
        <button
          onClick={handleDownloadSarif}
          className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm font-medium text-text-muted transition-colors hover:border-border-hover hover:text-text"
        >
          <Download className="h-4 w-4" />
          Download SARIF
        </button>
        <button
          onClick={() => navigate('/scans')}
          className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm font-medium text-text-muted transition-colors hover:border-border-hover hover:text-text"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to History
        </button>
      </div>

      {/* Findings Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-text">
            Findings
            {scan.findings.length > 0 && (
              <span className="ml-2 text-sm font-normal text-text-muted">
                ({scan.findings.length})
              </span>
            )}
          </h2>
        </div>

        {scan.findings.length === 0 ? (
          <Card className="flex flex-col items-center gap-3 px-6 py-12">
            <Shield className="h-10 w-10 text-verdict-clean" />
            <p className="text-sm text-text-muted">No findings detected in this scan.</p>
          </Card>
        ) : (
          <div className="space-y-3">
            {scan.findings.map((finding, i) => (
              <FindingDetailCard
                key={finding.id || `${finding.rule_id}-${i}`}
                finding={finding}
                index={i}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
