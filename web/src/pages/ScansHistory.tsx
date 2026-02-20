// Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

import { useEffect, useState, useMemo, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search,
  Filter,
  ChevronDown,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  AlertTriangle,
  History,
  RefreshCw,
} from 'lucide-react'
import { api, type ScanListItem } from '../lib/api'
import { cn, formatDate, formatDuration } from '../lib/utils'
import { Card } from '../components/Card'
import { Badge } from '../components/Badge'
// LoadingSpinner available if needed for future enhancement

// ── Constants ────────────────────────────────────────────────────────

const VERDICT_OPTIONS = ['All', 'CLEAN', 'MALICIOUS', 'SUSPICIOUS', 'CAUTION'] as const
const PAGE_SIZE = 20

type SortField = 'created_at' | 'risk_score' | 'verdict' | 'skill_name'
type SortDir = 'asc' | 'desc'

// ── Badge variant mapping ────────────────────────────────────────────

function verdictVariant(v: string | null): 'clean' | 'malicious' | 'suspicious' | 'default' {
  switch (v?.toUpperCase()) {
    case 'MALICIOUS':  return 'malicious'
    case 'SUSPICIOUS': return 'suspicious'
    case 'CAUTION':    return 'suspicious'
    case 'CLEAN':      return 'clean'
    default:           return 'default'
  }
}

// ── Risk score bar ───────────────────────────────────────────────────

function RiskScoreBar({ score }: { score: number | null }) {
  const s = score ?? 0
  const color =
    s >= 80 ? 'bg-severity-critical' :
    s >= 60 ? 'bg-severity-high' :
    s >= 40 ? 'bg-severity-medium' :
    s >= 20 ? 'bg-severity-low' :
              'bg-severity-info'

  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-16 rounded-full bg-bg-hover">
        <div
          className={cn('h-2 rounded-full transition-all', color)}
          style={{ width: `${Math.min(s, 100)}%` }}
        />
      </div>
      <span className="text-xs tabular-nums text-text-muted">{s}</span>
    </div>
  )
}

// ── Sort header ──────────────────────────────────────────────────────

interface SortableHeaderProps {
  label: string
  field: SortField
  currentField: SortField
  currentDir: SortDir
  onSort: (field: SortField) => void
}

function SortableHeader({ label, field, currentField, currentDir, onSort }: SortableHeaderProps) {
  const isActive = currentField === field
  return (
    <th className="px-4 py-3 font-medium">
      <button
        onClick={() => onSort(field)}
        className="flex items-center gap-1 text-left transition-colors hover:text-text"
      >
        {label}
        {isActive ? (
          currentDir === 'asc' ? (
            <ArrowUp className="h-3 w-3" />
          ) : (
            <ArrowDown className="h-3 w-3" />
          )
        ) : (
          <ArrowUpDown className="h-3 w-3 opacity-40" />
        )}
      </button>
    </th>
  )
}

// ── Skeleton row ─────────────────────────────────────────────────────

function SkeletonRow() {
  return (
    <tr className="border-t border-border">
      {Array.from({ length: 7 }).map((_, i) => (
        <td key={i} className="px-4 py-3.5">
          <div className="h-4 w-full animate-pulse rounded bg-bg-hover" />
        </td>
      ))}
    </tr>
  )
}

// ── Main ScansHistory Component ──────────────────────────────────────

export function ScansHistory() {
  const navigate = useNavigate()

  // ── State ──────────────────────────────────────────────────────────
  const [scans, setScans] = useState<ScanListItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [verdictFilter, setVerdictFilter] = useState<string>('All')
  const [minScore, setMinScore] = useState<number>(0)
  const [searchQuery, setSearchQuery] = useState('')
  const [showFilters, setShowFilters] = useState(false)

  // Sorting
  const [sortField, setSortField] = useState<SortField>('created_at')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  // Pagination
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE)

  // ── Fetch data ─────────────────────────────────────────────────────

  const fetchScans = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await api.listScans(200)
      setScans(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load scans')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchScans()
  }, [fetchScans])

  // ── Filter + sort logic ────────────────────────────────────────────

  const filteredScans = useMemo(() => {
    let results = [...scans]

    // Verdict filter
    if (verdictFilter !== 'All') {
      results = results.filter(
        (s) => s.verdict?.toUpperCase() === verdictFilter.toUpperCase()
      )
    }

    // Min score filter
    if (minScore > 0) {
      results = results.filter((s) => (s.risk_score ?? 0) >= minScore)
    }

    // Search filter (client-side)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      results = results.filter(
        (s) =>
          (s.skill_name ?? '').toLowerCase().includes(q) ||
          (s.target ?? '').toLowerCase().includes(q) ||
          s.scan_id.toLowerCase().includes(q)
      )
    }

    // Sort
    results.sort((a, b) => {
      let cmp = 0
      switch (sortField) {
        case 'created_at': {
          const da = a.created_at ? new Date(a.created_at).getTime() : 0
          const db = b.created_at ? new Date(b.created_at).getTime() : 0
          cmp = da - db
          break
        }
        case 'risk_score':
          cmp = (a.risk_score ?? 0) - (b.risk_score ?? 0)
          break
        case 'verdict':
          cmp = (a.verdict ?? '').localeCompare(b.verdict ?? '')
          break
        case 'skill_name':
          cmp = (a.skill_name ?? a.target ?? '').localeCompare(b.skill_name ?? b.target ?? '')
          break
      }
      return sortDir === 'asc' ? cmp : -cmp
    })

    return results
  }, [scans, verdictFilter, minScore, searchQuery, sortField, sortDir])

  const visibleScans = filteredScans.slice(0, visibleCount)
  const hasMore = visibleCount < filteredScans.length

  // ── Sort handler ───────────────────────────────────────────────────

  const handleSort = (field: SortField) => {
    if (field === sortField) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir('desc')
    }
  }

  // ── Render ─────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text">Scan History</h1>
          <p className="mt-1 text-sm text-text-muted">
            Browse and filter all previous scans
          </p>
        </div>
        <button
          onClick={fetchScans}
          disabled={loading}
          className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-2 text-sm text-text-muted transition-colors hover:border-border-hover hover:text-text disabled:opacity-50"
        >
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Filter Bar */}
      <Card className="p-4">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
          {/* Search */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value)
                setVisibleCount(PAGE_SIZE)
              }}
              placeholder="Search by skill name or scan ID..."
              className="w-full rounded-lg border border-border bg-bg py-2 pl-9 pr-3 text-sm text-text placeholder:text-text-muted/50 transition-colors focus:border-accent focus:outline-none"
            />
          </div>

          {/* Verdict dropdown */}
          <div className="relative">
            <select
              value={verdictFilter}
              onChange={(e) => {
                setVerdictFilter(e.target.value)
                setVisibleCount(PAGE_SIZE)
              }}
              className="appearance-none rounded-lg border border-border bg-bg py-2 pl-3 pr-8 text-sm text-text transition-colors focus:border-accent focus:outline-none"
            >
              {VERDICT_OPTIONS.map((v) => (
                <option key={v} value={v}>
                  {v === 'All' ? 'All Verdicts' : v}
                </option>
              ))}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          </div>

          {/* Toggle advanced filters */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={cn(
              'flex items-center gap-1.5 rounded-lg border px-3 py-2 text-sm transition-colors',
              showFilters
                ? 'border-accent/30 bg-accent/10 text-accent'
                : 'border-border text-text-muted hover:border-border-hover hover:text-text'
            )}
          >
            <Filter className="h-4 w-4" />
            Filters
          </button>
        </div>

        {/* Advanced filters */}
        {showFilters && (
          <div className="mt-4 flex flex-col gap-4 border-t border-border pt-4 sm:flex-row sm:items-end">
            <div className="flex-1">
              <label className="mb-1.5 block text-xs font-medium text-text-muted">
                Minimum Risk Score: {minScore}
              </label>
              <input
                type="range"
                min={0}
                max={100}
                value={minScore}
                onChange={(e) => {
                  setMinScore(Number(e.target.value))
                  setVisibleCount(PAGE_SIZE)
                }}
                className="w-full accent-accent"
              />
              <div className="mt-1 flex justify-between text-[10px] text-text-muted">
                <span>0</span>
                <span>25</span>
                <span>50</span>
                <span>75</span>
                <span>100</span>
              </div>
            </div>
            <button
              onClick={() => {
                setVerdictFilter('All')
                setMinScore(0)
                setSearchQuery('')
                setVisibleCount(PAGE_SIZE)
              }}
              className="text-xs text-text-muted transition-colors hover:text-text"
            >
              Reset filters
            </button>
          </div>
        )}
      </Card>

      {/* Results count */}
      <div className="flex items-center justify-between text-sm text-text-muted">
        <span>
          Showing {visibleScans.length} of {filteredScans.length} scan{filteredScans.length !== 1 ? 's' : ''}
          {filteredScans.length !== scans.length && (
            <span> (filtered from {scans.length})</span>
          )}
        </span>
      </div>

      {/* Error state */}
      {error && (
        <Card className="border-severity-critical/30 bg-severity-critical/5 p-6">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-severity-critical" />
            <div>
              <p className="text-sm font-medium text-severity-critical">Failed to load scans</p>
              <p className="mt-0.5 text-xs text-text-muted">{error}</p>
            </div>
            <button
              onClick={fetchScans}
              className="ml-auto rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent-hover"
            >
              Retry
            </button>
          </div>
        </Card>
      )}

      {/* Table */}
      {!error && (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-text-muted">
                  <th className="px-4 py-3 font-medium">Scan ID</th>
                  <SortableHeader
                    label="Skill Name"
                    field="skill_name"
                    currentField={sortField}
                    currentDir={sortDir}
                    onSort={handleSort}
                  />
                  <SortableHeader
                    label="Verdict"
                    field="verdict"
                    currentField={sortField}
                    currentDir={sortDir}
                    onSort={handleSort}
                  />
                  <SortableHeader
                    label="Risk Score"
                    field="risk_score"
                    currentField={sortField}
                    currentDir={sortDir}
                    onSort={handleSort}
                  />
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Duration</th>
                  <SortableHeader
                    label="Date"
                    field="created_at"
                    currentField={sortField}
                    currentDir={sortDir}
                    onSort={handleSort}
                  />
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
                ) : visibleScans.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-16 text-center">
                      <div className="flex flex-col items-center gap-3">
                        <History className="h-10 w-10 text-text-muted/50" />
                        <p className="text-sm text-text-muted">
                          {scans.length === 0
                            ? 'No scans found. Submit your first scan to get started.'
                            : 'No scans match the current filters.'}
                        </p>
                        {scans.length > 0 && filteredScans.length === 0 && (
                          <button
                            onClick={() => {
                              setVerdictFilter('All')
                              setMinScore(0)
                              setSearchQuery('')
                            }}
                            className="text-xs text-accent hover:text-accent-hover"
                          >
                            Clear all filters
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ) : (
                  visibleScans.map((scan) => (
                    <tr
                      key={scan.scan_id}
                      onClick={() => navigate(`/scan/${scan.scan_id}`)}
                      className="cursor-pointer border-t border-border transition-colors hover:bg-bg-hover"
                    >
                      <td className="px-4 py-3.5">
                        <span className="font-mono text-xs text-text-muted">
                          {scan.scan_id.slice(0, 8)}...
                        </span>
                      </td>
                      <td className="px-4 py-3.5 font-medium text-text">
                        {scan.skill_name || scan.target || 'Untitled'}
                      </td>
                      <td className="px-4 py-3.5">
                        {scan.verdict ? (
                          <Badge variant={verdictVariant(scan.verdict)}>
                            {scan.verdict}
                          </Badge>
                        ) : (
                          <span className="text-text-muted">--</span>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        <RiskScoreBar score={scan.risk_score} />
                      </td>
                      <td className="px-4 py-3.5">
                        <span className={cn(
                          'text-xs font-medium',
                          scan.status === 'completed' ? 'text-verdict-clean' :
                          scan.status === 'failed'    ? 'text-verdict-malicious' :
                          scan.status === 'scanning'  ? 'text-accent' :
                                                        'text-text-muted'
                        )}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-text-muted">
                        {formatDuration(scan.duration_ms)}
                      </td>
                      <td className="px-4 py-3.5 text-text-muted">
                        {formatDate(scan.created_at)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Load More */}
          {hasMore && !loading && (
            <div className="border-t border-border px-4 py-4 text-center">
              <button
                onClick={() => setVisibleCount((c) => c + PAGE_SIZE)}
                className="rounded-lg bg-bg-hover px-6 py-2 text-sm font-medium text-text-muted transition-colors hover:text-text"
              >
                Load More ({filteredScans.length - visibleCount} remaining)
              </button>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
