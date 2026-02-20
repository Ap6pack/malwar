// Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FileSearch,
  ShieldAlert,
  Gauge,
  ShieldCheck,
  ArrowRight,
  AlertTriangle,
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import { api, type ScanListItem, type ScanResult } from '../lib/api'
import { cn, formatDate, formatDuration } from '../lib/utils'
import { Card } from '../components/Card'
import { Badge } from '../components/Badge'
import { LoadingSpinner } from '../components/LoadingSpinner'

// ── Severity chart color mapping ─────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  INFO: '#3b82f6',
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

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

// ── Stat Card ────────────────────────────────────────────────────────

interface StatCardProps {
  label: string
  value: string | number
  icon: React.ElementType
  iconColor?: string
  loading?: boolean
}

function StatCard({ label, value, icon: Icon, iconColor = 'text-accent', loading }: StatCardProps) {
  return (
    <Card className="relative overflow-hidden p-6">
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          {loading ? (
            <div className="h-9 w-24 animate-pulse rounded-lg bg-bg-hover" />
          ) : (
            <p className="text-3xl font-bold tracking-tight text-text">{value}</p>
          )}
          <p className="mt-1.5 text-sm text-text-muted">{label}</p>
        </div>
        <div className={cn('rounded-lg bg-bg-hover p-2.5', iconColor)}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </Card>
  )
}

// ── Skeleton row ─────────────────────────────────────────────────────

function SkeletonRow() {
  return (
    <tr className="border-t border-border">
      {Array.from({ length: 6 }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 w-full animate-pulse rounded bg-bg-hover" />
        </td>
      ))}
    </tr>
  )
}

// ── Custom recharts tooltip ──────────────────────────────────────────

interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{ value: number; payload: { severity: string; count: number } }>
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  const data = payload[0]
  return (
    <div className="rounded-lg border border-border bg-bg-card px-3 py-2 shadow-lg">
      <p className="text-sm font-medium text-text">{data.payload.severity}</p>
      <p className="text-xs text-text-muted">
        {data.value} finding{data.value !== 1 ? 's' : ''}
      </p>
    </div>
  )
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
      <span className="text-xs text-text-muted">{s}</span>
    </div>
  )
}

// ── Main Dashboard Component ─────────────────────────────────────────

export function Dashboard() {
  const navigate = useNavigate()
  const [scans, setScans] = useState<ScanListItem[]>([])
  const [scanDetails, setScanDetails] = useState<Map<string, ScanResult>>(new Map())
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function fetchData() {
      try {
        setLoading(true)
        setError(null)
        const scanList = await api.listScans(50)
        if (cancelled) return
        setScans(scanList)

        // Fetch detail for first 10 scans to get severity breakdown
        const top10 = scanList.slice(0, 10)
        const details = await Promise.allSettled(
          top10
            .filter((s) => s.status === 'completed')
            .map((s) => api.getScan(s.scan_id))
        )

        if (cancelled) return
        const detailMap = new Map<string, ScanResult>()
        for (const result of details) {
          if (result.status === 'fulfilled') {
            detailMap.set(result.value.scan_id, result.value)
          }
        }
        setScanDetails(detailMap)
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load dashboard data')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchData()
    return () => { cancelled = true }
  }, [])

  // ── Computed stats ───────────────────────────────────────────────

  const stats = useMemo(() => {
    const completed = scans.filter((s) => s.status === 'completed')
    const total = completed.length
    const malicious = completed.filter((s) => s.verdict?.toUpperCase() === 'MALICIOUS').length
    const clean = completed.filter((s) => s.verdict?.toUpperCase() === 'CLEAN').length
    const avgScore = total > 0
      ? Math.round(completed.reduce((sum, s) => sum + (s.risk_score ?? 0), 0) / total)
      : 0
    const cleanRate = total > 0 ? Math.round((clean / total) * 100) : 0

    return { total, malicious, avgScore, cleanRate }
  }, [scans])

  // ── Severity distribution data ───────────────────────────────────

  const severityData = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const severity of SEVERITY_ORDER) {
      counts[severity] = 0
    }

    for (const [, detail] of scanDetails) {
      if (detail.finding_count_by_severity) {
        for (const [sev, count] of Object.entries(detail.finding_count_by_severity)) {
          const key = sev.toUpperCase()
          counts[key] = (counts[key] ?? 0) + count
        }
      }
    }

    return SEVERITY_ORDER.map((severity) => ({
      severity,
      count: counts[severity] ?? 0,
    }))
  }, [scanDetails])

  // ── Render ───────────────────────────────────────────────────────

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-20">
        <AlertTriangle className="h-12 w-12 text-severity-high" />
        <p className="text-lg font-medium text-text">Failed to load dashboard</p>
        <p className="text-sm text-text-muted">{error}</p>
        <button
          onClick={() => window.location.reload()}
          className="mt-2 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
        >
          Retry
        </button>
      </div>
    )
  }

  const recentScans = scans.slice(0, 10)

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-text">Dashboard</h1>
        <p className="mt-1 text-sm text-text-muted">
          Threat scanning overview and recent activity
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Scans"
          value={stats.total}
          icon={FileSearch}
          iconColor="text-accent"
          loading={loading}
        />
        <StatCard
          label="Malicious Found"
          value={stats.malicious}
          icon={ShieldAlert}
          iconColor="text-severity-critical"
          loading={loading}
        />
        <StatCard
          label="Average Risk Score"
          value={stats.avgScore}
          icon={Gauge}
          iconColor="text-severity-high"
          loading={loading}
        />
        <StatCard
          label="Clean Rate"
          value={`${stats.cleanRate}%`}
          icon={ShieldCheck}
          iconColor="text-verdict-clean"
          loading={loading}
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Recent Scans Table */}
        <Card className="xl:col-span-2">
          <div className="flex items-center justify-between border-b border-border px-6 py-4">
            <h2 className="text-base font-semibold text-text">Recent Scans</h2>
            <button
              onClick={() => navigate('/scans')}
              className="flex items-center gap-1 text-xs font-medium text-accent transition-colors hover:text-accent-hover"
            >
              View All <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-text-muted">
                  <th className="px-4 py-3 font-medium">Skill Name</th>
                  <th className="px-4 py-3 font-medium">Verdict</th>
                  <th className="px-4 py-3 font-medium">Risk Score</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Duration</th>
                  <th className="px-4 py-3 font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)
                ) : recentScans.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-12 text-center text-text-muted">
                      No scans found. Submit your first scan to get started.
                    </td>
                  </tr>
                ) : (
                  recentScans.map((scan) => (
                    <tr
                      key={scan.scan_id}
                      onClick={() => navigate(`/scan/${scan.scan_id}`)}
                      className="cursor-pointer border-t border-border transition-colors hover:bg-bg-hover"
                    >
                      <td className="px-4 py-3 font-medium text-text">
                        {scan.skill_name || scan.target || 'Untitled'}
                      </td>
                      <td className="px-4 py-3">
                        {scan.verdict ? (
                          <Badge variant={verdictVariant(scan.verdict)}>
                            {scan.verdict}
                          </Badge>
                        ) : (
                          <span className="text-text-muted">--</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <RiskScoreBar score={scan.risk_score} />
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn(
                          'text-xs font-medium',
                          scan.status === 'completed' ? 'text-verdict-clean' :
                          scan.status === 'failed'    ? 'text-verdict-malicious' :
                                                        'text-text-muted'
                        )}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-text-muted">
                        {formatDuration(scan.duration_ms)}
                      </td>
                      <td className="px-4 py-3 text-text-muted">
                        {formatDate(scan.created_at)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Severity Distribution Chart */}
        <Card className="flex flex-col">
          <div className="border-b border-border px-6 py-4">
            <h2 className="text-base font-semibold text-text">Severity Distribution</h2>
            <p className="mt-0.5 text-xs text-text-muted">
              Findings across recent scans
            </p>
          </div>
          <div className="flex flex-1 items-center justify-center px-4 py-6">
            {loading ? (
              <LoadingSpinner size="md" label="Loading chart..." />
            ) : severityData.every((d) => d.count === 0) ? (
              <p className="text-sm text-text-muted">No finding data available</p>
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart
                  data={severityData}
                  margin={{ top: 8, right: 8, left: -12, bottom: 0 }}
                >
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#1e1e2e"
                    vertical={false}
                  />
                  <XAxis
                    dataKey="severity"
                    tick={{ fill: '#8888a0', fontSize: 11 }}
                    axisLine={{ stroke: '#1e1e2e' }}
                    tickLine={false}
                    tickFormatter={(v: string) => v.slice(0, 4)}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: '#8888a0', fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    content={<CustomTooltip />}
                    cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  />
                  <Bar
                    dataKey="count"
                    radius={[4, 4, 0, 0]}
                    maxBarSize={40}
                  >
                    {severityData.map((entry) => (
                      <Cell
                        key={entry.severity}
                        fill={SEVERITY_COLORS[entry.severity] ?? '#6366f1'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}
