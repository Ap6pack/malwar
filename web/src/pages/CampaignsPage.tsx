import { useCallback, useEffect, useState } from 'react'
import { Shield, AlertTriangle, Calendar, Users, ChevronDown, ChevronUp, X, AlertCircle, Hash } from 'lucide-react'
import { api, type Campaign } from '../lib/api'
import { cn, formatDate } from '../lib/utils'
import { Badge } from '../components/Badge'
import { Card } from '../components/Card'
import { LoadingSpinner } from '../components/LoadingSpinner'

/* ---------- Types ---------- */

interface CampaignDetail extends Campaign {
  signature_count: number
}

/* ---------- Helpers ---------- */

function parseIocs(iocs: string[] | string | null): string[] {
  if (!iocs) return []
  if (Array.isArray(iocs)) return iocs.map(String)
  try {
    const parsed = JSON.parse(iocs)
    if (Array.isArray(parsed)) return parsed.map(String)
    if (typeof parsed === 'object' && parsed !== null) {
      return Object.values(parsed).flat().map(String)
    }
    return [String(parsed)]
  } catch {
    return iocs
      .split(/[,\n]+/)
      .map((s: string) => s.trim())
      .filter(Boolean)
  }
}

function statusColor(status: string): string {
  return status?.toLowerCase() === 'active'
    ? 'bg-severity-low/15 text-severity-low'
    : 'bg-bg-hover text-text-muted'
}

/* ---------- Campaign Detail Panel ---------- */

function CampaignDetailPanel({
  campaign,
  onClose,
}: {
  campaign: Campaign
  onClose: () => void
}) {
  const [detail, setDetail] = useState<CampaignDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api
      .getCampaign(campaign.id)
      .then((data) => {
        if (!cancelled) setDetail(data)
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load campaign details')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [campaign.id])

  const iocs = parseIocs(detail?.iocs ?? campaign.iocs)

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Overlay */}
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />

      {/* Slide-over panel */}
      <div className="relative z-10 w-full max-w-lg bg-bg-card border-l border-border overflow-y-auto animate-slide-in">
        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-border bg-bg-card px-6 py-4">
          <h2 className="text-lg font-semibold text-text truncate pr-4">
            {campaign.name}
          </h2>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-bg-hover transition-colors text-text-muted hover:text-text shrink-0"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {loading && <LoadingSpinner label="Loading details..." />}

        {error && (
          <div className="mx-6 mt-4 flex items-center gap-2 rounded-lg border border-severity-critical/30 bg-severity-critical/10 px-4 py-3 text-sm text-severity-critical">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}

        {!loading && !error && (
          <div className="p-6 space-y-6">
            {/* Status + Attribution */}
            <div className="flex flex-wrap items-center gap-2">
              <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium', statusColor(campaign.status))}>
                {campaign.status}
              </span>
              {campaign.attributed_to && (
                <span className="inline-flex items-center gap-1.5 text-sm text-text-muted">
                  <Users className="h-3.5 w-3.5" />
                  {campaign.attributed_to}
                </span>
              )}
            </div>

            {/* Dates */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-text-muted mb-1">First seen</p>
                <p className="text-sm text-text">{formatDate(campaign.first_seen)}</p>
              </div>
              <div>
                <p className="text-xs text-text-muted mb-1">Last seen</p>
                <p className="text-sm text-text">{formatDate(campaign.last_seen)}</p>
              </div>
            </div>

            {/* Counts */}
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-bg rounded-lg border border-border p-3">
                <p className="text-xs text-text-muted mb-1">Skills affected</p>
                <p className="text-xl font-bold text-text">
                  {campaign.total_skills_affected ?? 0}
                </p>
              </div>
              <div className="bg-bg rounded-lg border border-border p-3">
                <p className="text-xs text-text-muted mb-1">Signatures</p>
                <p className="text-xl font-bold text-text">
                  {detail?.signature_count ?? '-'}
                </p>
              </div>
            </div>

            {/* Description */}
            {campaign.description && (
              <div>
                <p className="text-xs text-text-muted mb-2">Description</p>
                <p className="text-sm text-text leading-relaxed whitespace-pre-wrap">
                  {campaign.description}
                </p>
              </div>
            )}

            {/* IOCs */}
            {iocs.length > 0 && (
              <div>
                <p className="text-xs text-text-muted mb-2">
                  Indicators of Compromise ({iocs.length})
                </p>
                <div className="flex flex-wrap gap-2">
                  {iocs.map((ioc, i) => (
                    <span
                      key={i}
                      className="inline-flex items-center rounded-md bg-severity-high/10 text-severity-high px-2 py-1 text-xs font-mono break-all"
                    >
                      {ioc}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <style>{`
        @keyframes slideIn {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }
        .animate-slide-in {
          animation: slideIn 0.2s ease-out;
        }
      `}</style>
    </div>
  )
}

/* ---------- Campaign Card ---------- */

function CampaignCard({
  campaign,
  onSelect,
}: {
  campaign: Campaign
  onSelect: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const iocs = parseIocs(campaign.iocs)
  const isActive = campaign.status?.toLowerCase() === 'active'

  return (
    <Card
      className={cn(
        'p-5 space-y-4 transition-colors duration-150',
        isActive && 'border-severity-high/20',
      )}
      hover
      onClick={onSelect}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className={cn(
            'p-2 rounded-lg shrink-0',
            isActive ? 'bg-severity-high/10' : 'bg-bg-hover',
          )}>
            {isActive ? (
              <AlertTriangle className="h-5 w-5 text-severity-high" />
            ) : (
              <Shield className="h-5 w-5 text-text-muted" />
            )}
          </div>
          <div className="min-w-0">
            <h3 className="font-semibold text-text text-lg truncate">{campaign.name}</h3>
            {campaign.attributed_to && (
              <p className="flex items-center gap-1.5 text-sm text-text-muted mt-0.5">
                <Users className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{campaign.attributed_to}</span>
              </p>
            )}
          </div>
        </div>
        <span className={cn(
          'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium shrink-0',
          statusColor(campaign.status),
        )}>
          {campaign.status}
        </span>
      </div>

      {/* Meta row */}
      <div className="flex flex-wrap gap-x-5 gap-y-2 text-sm text-text-muted">
        <span className="inline-flex items-center gap-1.5">
          <Calendar className="h-3.5 w-3.5" />
          {formatDate(campaign.first_seen)}
          {campaign.last_seen && campaign.last_seen !== campaign.first_seen && (
            <> &mdash; {formatDate(campaign.last_seen)}</>
          )}
        </span>
        {campaign.total_skills_affected != null && (
          <span className="inline-flex items-center gap-1.5">
            <Hash className="h-3.5 w-3.5" />
            {campaign.total_skills_affected} skill{campaign.total_skills_affected !== 1 ? 's' : ''} affected
          </span>
        )}
      </div>

      {/* Description (truncated) */}
      {campaign.description && (
        <div
          onClick={(e) => {
            e.stopPropagation()
            setExpanded(!expanded)
          }}
          className="cursor-pointer group"
        >
          <p
            className={cn(
              'text-sm text-text-muted leading-relaxed',
              !expanded && 'line-clamp-2',
            )}
          >
            {campaign.description}
          </p>
          {campaign.description.length > 120 && (
            <button className="inline-flex items-center gap-1 text-xs text-accent mt-1 group-hover:text-accent-hover transition-colors">
              {expanded ? (
                <>
                  Show less <ChevronUp className="h-3 w-3" />
                </>
              ) : (
                <>
                  Show more <ChevronDown className="h-3 w-3" />
                </>
              )}
            </button>
          )}
        </div>
      )}

      {/* IOCs preview */}
      {iocs.length > 0 && (
        <div className="flex flex-wrap gap-1.5" onClick={(e) => e.stopPropagation()}>
          {iocs.slice(0, 5).map((ioc, i) => (
            <span
              key={i}
              className="inline-flex items-center rounded-md bg-severity-high/10 text-severity-high px-2 py-0.5 text-xs font-mono truncate max-w-[200px]"
            >
              {ioc}
            </span>
          ))}
          {iocs.length > 5 && (
            <Badge className="cursor-default">+{iocs.length - 5} more</Badge>
          )}
        </div>
      )}
    </Card>
  )
}

/* ---------- Main Page ---------- */

export function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null)

  const fetchCampaigns = useCallback(async () => {
    try {
      setError(null)
      const data = await api.listCampaigns()
      setCampaigns(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load campaigns')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchCampaigns()
  }, [fetchCampaigns])

  // Sort: active campaigns first, then by last_seen descending
  const sorted = [...campaigns].sort((a, b) => {
    const aActive = a.status?.toLowerCase() === 'active' ? 0 : 1
    const bActive = b.status?.toLowerCase() === 'active' ? 0 : 1
    if (aActive !== bActive) return aActive - bActive
    const aDate = a.last_seen ? new Date(a.last_seen).getTime() : 0
    const bDate = b.last_seen ? new Date(b.last_seen).getTime() : 0
    return bDate - aDate
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 bg-accent/10 rounded-lg">
          <Shield className="h-6 w-6 text-accent" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-text">Threat Campaigns</h1>
          <p className="text-sm text-text-muted">
            {campaigns.length} campaign{campaigns.length !== 1 ? 's' : ''} tracked
          </p>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-severity-critical/30 bg-severity-critical/10 px-4 py-3 text-sm text-severity-critical">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && <LoadingSpinner label="Loading campaigns..." />}

      {/* Campaign grid */}
      {!loading && sorted.length > 0 && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {sorted.map((c) => (
            <CampaignCard
              key={c.id}
              campaign={c}
              onSelect={() => setSelectedCampaign(c)}
            />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && campaigns.length === 0 && (
        <div className="bg-bg-card border border-border rounded-xl p-12 text-center">
          <Shield className="h-12 w-12 text-text-muted/30 mx-auto mb-4" />
          <p className="text-text-muted text-lg font-medium">No campaigns tracked yet.</p>
          <p className="text-text-muted/70 text-sm mt-1">
            Campaigns will appear here when threat intelligence data is available.
          </p>
        </div>
      )}

      {/* Detail slide-over */}
      {selectedCampaign && (
        <CampaignDetailPanel
          campaign={selectedCampaign}
          onClose={() => setSelectedCampaign(null)}
        />
      )}
    </div>
  )
}
