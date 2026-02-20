// Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

import { useState, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Upload,
  FileText,
  ShieldCheck,
  AlertTriangle,
  Download,
  Loader2,
  Info,
  ChevronRight,
  X,
} from 'lucide-react'
import { api, type ScanResult, type Finding } from '../lib/api'
import {
  cn,
  verdictBg,
  verdictColor,
  severityColor,
  formatDuration,
} from '../lib/utils'
import { Card } from '../components/Card'
import { Badge } from '../components/Badge'

// ── Tab Types ────────────────────────────────────────────────────────

type InputMode = 'paste' | 'upload'

// ── Verdict banner ───────────────────────────────────────────────────

function VerdictBanner({ verdict, riskScore }: { verdict: string; riskScore: number }) {
  return (
    <div className={cn('rounded-xl border p-6', verdictBg(verdict))}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider opacity-70">Verdict</p>
          <p className={cn('mt-1 text-3xl font-bold', verdictColor(verdict))}>
            {verdict}
          </p>
        </div>
        <div className="text-right">
          <p className="text-xs font-medium uppercase tracking-wider opacity-70">Risk Score</p>
          <p className="mt-1 text-3xl font-bold">{riskScore}</p>
        </div>
      </div>
      {/* Risk score bar */}
      <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-black/20">
        <div
          className={cn(
            'h-full rounded-full transition-all duration-500',
            riskScore >= 80 ? 'bg-severity-critical' :
            riskScore >= 60 ? 'bg-severity-high' :
            riskScore >= 40 ? 'bg-severity-medium' :
            riskScore >= 20 ? 'bg-severity-low' :
                              'bg-severity-info'
          )}
          style={{ width: `${Math.min(riskScore, 100)}%` }}
        />
      </div>
    </div>
  )
}

// ── Finding card ─────────────────────────────────────────────────────

function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const [expanded, setExpanded] = useState(false)

  function badgeVariant(s: string): 'critical' | 'high' | 'medium' | 'low' | 'default' {
    switch (s?.toUpperCase()) {
      case 'CRITICAL': return 'critical'
      case 'HIGH':     return 'high'
      case 'MEDIUM':   return 'medium'
      case 'LOW':      return 'low'
      default:         return 'default'
    }
  }

  return (
    <Card
      className={cn('transition-colors', expanded && 'border-border-hover')}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-3 px-5 py-4 text-left"
      >
        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-bg-hover text-xs font-medium text-text-muted">
          {index + 1}
        </span>
        <Badge variant={badgeVariant(finding.severity)} className="shrink-0">
          {finding.severity}
        </Badge>
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-text">
          {finding.title}
        </span>
        <span className="shrink-0 text-xs text-text-muted">{finding.rule_id}</span>
        <ChevronRight
          className={cn(
            'h-4 w-4 shrink-0 text-text-muted transition-transform duration-200',
            expanded && 'rotate-90'
          )}
        />
      </button>

      {expanded && (
        <div className="border-t border-border px-5 py-4 space-y-3">
          <p className="text-sm text-text-muted">{finding.description}</p>

          {finding.evidence && finding.evidence.length > 0 && (
            <div>
              <p className="mb-1.5 text-xs font-medium uppercase tracking-wider text-text-muted">
                Evidence
              </p>
              <div className="space-y-1.5">
                {finding.evidence.map((e, i) => (
                  <div
                    key={i}
                    className="rounded-lg bg-bg px-3 py-2 font-mono text-xs text-text-muted"
                  >
                    {e}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex flex-wrap gap-4 text-xs text-text-muted">
            {finding.line_start != null && (
              <span>Line: <span className="text-text">{finding.line_start}</span></span>
            )}
            <span>Confidence: <span className="text-text">{finding.confidence}%</span></span>
            <span>Layer: <span className="text-text">{finding.detector_layer}</span></span>
            <span>Category: <span className="text-text">{finding.category}</span></span>
          </div>
        </div>
      )}
    </Card>
  )
}

// ── Main ScanPage Component ──────────────────────────────────────────

export function ScanPage() {
  const navigate = useNavigate()
  const fileInputRef = useRef<HTMLInputElement>(null)

  // ── State ──────────────────────────────────────────────────────────
  const [mode, setMode] = useState<InputMode>('paste')
  const [content, setContent] = useState('')
  const [fileName, setFileName] = useState('SKILL.md')
  const [useLlm, setUseLlm] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)

  // ── Handlers ───────────────────────────────────────────────────────

  const handleFileRead = useCallback((file: File) => {
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = (e) => {
      const text = e.target?.result
      if (typeof text === 'string') {
        setContent(text)
        setMode('paste') // switch to paste to show content
      }
    }
    reader.readAsText(file)
  }, [])

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragOver(false)
      const file = e.dataTransfer.files[0]
      if (file) handleFileRead(file)
    },
    [handleFileRead]
  )

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (file) handleFileRead(file)
    },
    [handleFileRead]
  )

  const handleSubmit = async () => {
    if (!content.trim()) return
    try {
      setScanning(true)
      setError(null)
      setResult(null)
      const scanResult = await api.submitScan(content, fileName, useLlm)
      setResult(scanResult)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
    } finally {
      setScanning(false)
    }
  }

  const handleDownloadSarif = async () => {
    if (!result) return
    try {
      const sarif = await api.getScanSarif(result.scan_id)
      const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${result.scan_id}.sarif.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // Silently handle - SARIF may not be available
    }
  }

  const clearResults = () => {
    setResult(null)
    setError(null)
  }

  // ── Render ─────────────────────────────────────────────────────────

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-text">New Scan</h1>
        <p className="mt-1 text-sm text-text-muted">
          Submit a SKILL.md file for threat analysis
        </p>
      </div>

      {/* Input Mode Tabs */}
      <div className="flex gap-1 rounded-lg bg-bg-card p-1 border border-border">
        <button
          onClick={() => setMode('paste')}
          className={cn(
            'flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors',
            mode === 'paste'
              ? 'bg-accent/15 text-accent'
              : 'text-text-muted hover:text-text'
          )}
        >
          <FileText className="mr-2 inline-block h-4 w-4" />
          Paste Content
        </button>
        <button
          onClick={() => setMode('upload')}
          className={cn(
            'flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors',
            mode === 'upload'
              ? 'bg-accent/15 text-accent'
              : 'text-text-muted hover:text-text'
          )}
        >
          <Upload className="mr-2 inline-block h-4 w-4" />
          Upload File
        </button>
      </div>

      {/* Input Area */}
      <Card className="overflow-hidden">
        {mode === 'paste' ? (
          <div className="relative">
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste your SKILL.md content here..."
              className="h-80 w-full resize-y bg-bg p-5 font-mono text-sm text-text placeholder:text-text-muted/50 focus:outline-none"
              spellCheck={false}
            />
            {content && (
              <button
                onClick={() => setContent('')}
                className="absolute right-3 top-3 rounded-md p-1 text-text-muted transition-colors hover:bg-bg-hover hover:text-text"
                title="Clear content"
              >
                <X className="h-4 w-4" />
              </button>
            )}
            <div className="border-t border-border bg-bg-card px-5 py-2 text-xs text-text-muted">
              {content.length > 0
                ? `${content.split('\n').length} lines, ${content.length} characters`
                : 'No content'}
            </div>
          </div>
        ) : (
          <div
            onDragOver={(e) => {
              e.preventDefault()
              setDragOver(true)
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={cn(
              'flex cursor-pointer flex-col items-center justify-center gap-4 px-6 py-16 transition-colors',
              dragOver ? 'bg-accent/5 border-accent' : 'hover:bg-bg-hover'
            )}
          >
            <div className={cn(
              'rounded-full p-4',
              dragOver ? 'bg-accent/15 text-accent' : 'bg-bg-hover text-text-muted'
            )}>
              <Upload className="h-8 w-8" />
            </div>
            <div className="text-center">
              <p className="text-sm font-medium text-text">
                {dragOver ? 'Drop file here' : 'Drop a .md file here, or click to browse'}
              </p>
              <p className="mt-1 text-xs text-text-muted">
                Supports .md and .txt files
              </p>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".md,.txt,.markdown"
              onChange={handleFileInput}
              className="hidden"
            />
          </div>
        )}
      </Card>

      {/* Options Panel */}
      <Card className="p-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
          {/* File name */}
          <div className="flex-1">
            <label className="mb-1.5 block text-xs font-medium text-text-muted">
              File Name
            </label>
            <input
              type="text"
              value={fileName}
              onChange={(e) => setFileName(e.target.value)}
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text transition-colors focus:border-accent focus:outline-none"
              placeholder="SKILL.md"
            />
          </div>

          {/* Use LLM toggle */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setUseLlm(!useLlm)}
                className={cn(
                  'relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200',
                  useLlm ? 'bg-accent' : 'bg-bg-hover'
                )}
                role="switch"
                aria-checked={useLlm}
              >
                <span
                  className={cn(
                    'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-lg transition-transform duration-200',
                    useLlm ? 'translate-x-5' : 'translate-x-0'
                  )}
                />
              </button>
              <span className="text-sm text-text">Use LLM</span>
              <div className="group relative">
                <Info className="h-3.5 w-3.5 cursor-help text-text-muted" />
                <div className="pointer-events-none absolute bottom-full left-1/2 z-10 mb-2 w-56 -translate-x-1/2 rounded-lg border border-border bg-bg-card p-3 text-xs text-text-muted opacity-0 shadow-lg transition-opacity group-hover:opacity-100">
                  Enables LLM-powered analysis for deeper threat detection. May incur additional API costs and increase scan time.
                </div>
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Submit Button */}
      <button
        onClick={handleSubmit}
        disabled={scanning || !content.trim()}
        className={cn(
          'flex w-full items-center justify-center gap-2 rounded-xl px-6 py-3.5 text-sm font-semibold transition-all',
          scanning || !content.trim()
            ? 'cursor-not-allowed bg-accent/30 text-accent/50'
            : 'bg-accent text-white shadow-lg shadow-accent/20 hover:bg-accent-hover hover:shadow-accent/30'
        )}
      >
        {scanning ? (
          <>
            <Loader2 className="h-5 w-5 animate-spin" />
            Scanning...
          </>
        ) : (
          <>
            <ShieldCheck className="h-5 w-5" />
            Scan for Threats
          </>
        )}
      </button>

      {/* Error State */}
      {error && (
        <Card className="border-severity-critical/30 bg-severity-critical/5 p-5">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 shrink-0 text-severity-critical" />
            <div>
              <p className="text-sm font-medium text-severity-critical">Scan Failed</p>
              <p className="mt-1 text-sm text-text-muted">{error}</p>
            </div>
            <button
              onClick={clearResults}
              className="ml-auto shrink-0 text-text-muted hover:text-text"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </Card>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-text">Scan Results</h2>
            <div className="flex gap-2">
              <button
                onClick={handleDownloadSarif}
                className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-text-muted transition-colors hover:border-border-hover hover:text-text"
              >
                <Download className="h-3.5 w-3.5" />
                Download SARIF
              </button>
              <button
                onClick={() => navigate(`/scan/${result.scan_id}`)}
                className="flex items-center gap-1.5 rounded-lg bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent transition-colors hover:bg-accent/20"
              >
                View Full Report
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Verdict Banner */}
          <VerdictBanner verdict={result.verdict} riskScore={result.risk_score} />

          {/* Summary stats */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Card className="p-4">
              <p className="text-xs text-text-muted">Findings</p>
              <p className="mt-1 text-xl font-bold text-text">{result.finding_count}</p>
            </Card>
            <Card className="p-4">
              <p className="text-xs text-text-muted">Severity</p>
              <p className={cn('mt-1 text-xl font-bold', severityColor(result.overall_severity))}>
                {result.overall_severity}
              </p>
            </Card>
            <Card className="p-4">
              <p className="text-xs text-text-muted">Duration</p>
              <p className="mt-1 text-xl font-bold text-text">
                {formatDuration(result.duration_ms)}
              </p>
            </Card>
            <Card className="p-4">
              <p className="text-xs text-text-muted">Skill</p>
              <p className="mt-1 truncate text-xl font-bold text-text">
                {result.skill_name || 'Unknown'}
              </p>
            </Card>
          </div>

          {/* Findings */}
          {result.findings.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-text">
                Findings ({result.findings.length})
              </h3>
              {result.findings.map((finding, i) => (
                <FindingCard key={finding.id || i} finding={finding} index={i} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
