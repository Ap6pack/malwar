import { useCallback, useEffect, useMemo, useState } from 'react'
import { Plus, Trash2, Fingerprint, Search, X, AlertCircle } from 'lucide-react'
import { api, type Signature } from '../lib/api'
import { cn } from '../lib/utils'
import { Badge } from '../components/Badge'
import { LoadingSpinner } from '../components/LoadingSpinner'

/* ---------- Types ---------- */

type PatternType = 'regex' | 'exact' | 'fuzzy' | 'ioc'
type Severity = 'critical' | 'high' | 'medium' | 'low'

interface SignatureFormData {
  name: string
  pattern_type: PatternType
  pattern_value: string
  severity: Severity
  ioc_type: string
  source: string
  description: string
}

const EMPTY_FORM: SignatureFormData = {
  name: '',
  pattern_type: 'regex',
  pattern_value: '',
  severity: 'medium',
  ioc_type: '',
  source: '',
  description: '',
}

const PATTERN_TYPES: PatternType[] = ['regex', 'exact', 'fuzzy', 'ioc']
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']

/* ---------- Component ---------- */

export function SignaturesPage() {
  const [signatures, setSignatures] = useState<Signature[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState<SignatureFormData>(EMPTY_FORM)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  const [searchQuery, setSearchQuery] = useState('')

  /* ---- Data fetching ---- */

  const fetchSignatures = useCallback(async () => {
    try {
      setError(null)
      const data = await api.listSignatures()
      setSignatures(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load signatures')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSignatures()
  }, [fetchSignatures])

  /* ---- Filtered list ---- */

  const filtered = useMemo(() => {
    if (!searchQuery.trim()) return signatures
    const q = searchQuery.toLowerCase()
    return signatures.filter(
      (s) =>
        s.pattern_value.toLowerCase().includes(q) ||
        (s.name && s.name.toLowerCase().includes(q)),
    )
  }, [signatures, searchQuery])

  /* ---- Create ---- */

  const handleSave = async () => {
    if (!formData.pattern_value.trim()) {
      setSaveError('Pattern value is required')
      return
    }
    setSaving(true)
    setSaveError(null)
    try {
      await api.createSignature({
        name: formData.name || null,
        pattern_type: formData.pattern_type,
        pattern_value: formData.pattern_value,
        severity: formData.severity,
        ioc_type: formData.ioc_type || null,
        source: formData.source || null,
        description: formData.description || null,
        enabled: true,
      })
      setFormData(EMPTY_FORM)
      setShowForm(false)
      await fetchSignatures()
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to create signature')
    } finally {
      setSaving(false)
    }
  }

  /* ---- Delete ---- */

  const handleDelete = async (id: string) => {
    setDeleting(true)
    try {
      await api.deleteSignature(id)
      setDeleteId(null)
      await fetchSignatures()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete signature')
    } finally {
      setDeleting(false)
    }
  }

  /* ---- Helpers ---- */

  const severityVariant = (s: string): 'critical' | 'high' | 'medium' | 'low' | 'default' => {
    const v = s?.toLowerCase()
    if (v === 'critical' || v === 'high' || v === 'medium' || v === 'low') return v
    return 'default'
  }

  const updateField = <K extends keyof SignatureFormData>(key: K, value: SignatureFormData[K]) => {
    setFormData((prev) => ({ ...prev, [key]: value }))
  }

  /* ---- Render ---- */

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-accent/10 rounded-lg">
            <Fingerprint className="h-6 w-6 text-accent" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text">Threat Signatures</h1>
            <p className="text-sm text-text-muted">
              {signatures.length} signature{signatures.length !== 1 ? 's' : ''} registered
            </p>
          </div>
        </div>
        <button
          onClick={() => {
            setShowForm(true)
            setSaveError(null)
          }}
          className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-white hover:bg-accent-hover transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add Signature
        </button>
      </div>

      {/* Add signature panel */}
      {showForm && (
        <div className="bg-bg-card border border-border rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-text">New Signature</h2>
            <button
              onClick={() => {
                setShowForm(false)
                setFormData(EMPTY_FORM)
                setSaveError(null)
              }}
              className="p-1.5 rounded-lg hover:bg-bg-hover transition-colors text-text-muted hover:text-text"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Name */}
            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-text-muted">Name</label>
              <input
                type="text"
                placeholder="e.g. Suspicious PowerShell Download"
                value={formData.name}
                onChange={(e) => updateField('name', e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-text-muted/50 focus:outline-none focus:border-accent transition-colors"
              />
            </div>

            {/* Pattern Type */}
            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-text-muted">Pattern Type</label>
              <select
                value={formData.pattern_type}
                onChange={(e) => updateField('pattern_type', e.target.value as PatternType)}
                className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
              >
                {PATTERN_TYPES.map((pt) => (
                  <option key={pt} value={pt}>
                    {pt.charAt(0).toUpperCase() + pt.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            {/* Pattern Value */}
            <div className="space-y-1.5 md:col-span-2">
              <label className="block text-sm font-medium text-text-muted">
                Pattern Value <span className="text-severity-critical">*</span>
              </label>
              <input
                type="text"
                placeholder="e.g. Invoke-WebRequest.*-OutFile"
                value={formData.pattern_value}
                onChange={(e) => updateField('pattern_value', e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text font-mono placeholder:text-text-muted/50 focus:outline-none focus:border-accent transition-colors"
              />
            </div>

            {/* Severity */}
            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-text-muted">Severity</label>
              <select
                value={formData.severity}
                onChange={(e) => updateField('severity', e.target.value as Severity)}
                className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            {/* IOC Type */}
            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-text-muted">IOC Type</label>
              <input
                type="text"
                placeholder="e.g. url, ip, hash, domain"
                value={formData.ioc_type}
                onChange={(e) => updateField('ioc_type', e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-text-muted/50 focus:outline-none focus:border-accent transition-colors"
              />
            </div>

            {/* Source */}
            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-text-muted">Source</label>
              <input
                type="text"
                placeholder="e.g. MITRE ATT&CK, internal"
                value={formData.source}
                onChange={(e) => updateField('source', e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-text-muted/50 focus:outline-none focus:border-accent transition-colors"
              />
            </div>

            {/* Description */}
            <div className="space-y-1.5 md:col-span-2">
              <label className="block text-sm font-medium text-text-muted">Description</label>
              <textarea
                rows={3}
                placeholder="Describe what this signature detects..."
                value={formData.description}
                onChange={(e) => updateField('description', e.target.value)}
                className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-text-muted/50 focus:outline-none focus:border-accent transition-colors resize-none"
              />
            </div>
          </div>

          {/* Form error */}
          {saveError && (
            <div className="flex items-center gap-2 text-sm text-severity-critical">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {saveError}
            </div>
          )}

          {/* Form actions */}
          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              onClick={() => {
                setShowForm(false)
                setFormData(EMPTY_FORM)
                setSaveError(null)
              }}
              className="rounded-lg border border-border px-4 py-2 text-sm font-medium text-text-muted hover:bg-bg-hover transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? 'Saving...' : 'Save Signature'}
            </button>
          </div>
        </div>
      )}

      {/* Search / Filter */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
        <input
          type="text"
          placeholder="Filter by name or pattern value..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full rounded-lg border border-border bg-bg-card pl-10 pr-10 py-2.5 text-sm text-text placeholder:text-text-muted/50 focus:outline-none focus:border-accent transition-colors"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 p-0.5 rounded hover:bg-bg-hover transition-colors text-text-muted hover:text-text"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Error banner */}
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-severity-critical/30 bg-severity-critical/10 px-4 py-3 text-sm text-severity-critical">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && <LoadingSpinner label="Loading signatures..." />}

      {/* Table */}
      {!loading && filtered.length > 0 && (
        <div className="bg-bg-card border border-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="px-4 py-3 font-medium text-text-muted">Name / ID</th>
                  <th className="px-4 py-3 font-medium text-text-muted">Type</th>
                  <th className="px-4 py-3 font-medium text-text-muted">Pattern</th>
                  <th className="px-4 py-3 font-medium text-text-muted">Severity</th>
                  <th className="px-4 py-3 font-medium text-text-muted hidden lg:table-cell">IOC</th>
                  <th className="px-4 py-3 font-medium text-text-muted hidden lg:table-cell">Source</th>
                  <th className="px-4 py-3 font-medium text-text-muted">Status</th>
                  <th className="px-4 py-3 font-medium text-text-muted w-12" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((sig) => (
                  <tr
                    key={sig.id}
                    className="border-b border-border last:border-b-0 hover:bg-bg-hover/50 transition-colors"
                  >
                    {/* Name / ID */}
                    <td className="px-4 py-3">
                      <div className="flex flex-col">
                        <span className="font-medium text-text truncate max-w-[200px]">
                          {sig.name || 'Unnamed'}
                        </span>
                        <span className="text-xs text-text-muted font-mono truncate max-w-[200px]">
                          {sig.id.slice(0, 12)}...
                        </span>
                      </div>
                    </td>

                    {/* Pattern Type */}
                    <td className="px-4 py-3">
                      <Badge>{sig.pattern_type}</Badge>
                    </td>

                    {/* Pattern Value */}
                    <td className="px-4 py-3">
                      <code className="text-xs font-mono text-text bg-bg rounded px-1.5 py-0.5 truncate inline-block max-w-[240px]">
                        {sig.pattern_value}
                      </code>
                    </td>

                    {/* Severity */}
                    <td className="px-4 py-3">
                      <Badge variant={severityVariant(sig.severity)}>
                        {sig.severity}
                      </Badge>
                    </td>

                    {/* IOC Type */}
                    <td className="px-4 py-3 hidden lg:table-cell">
                      <span className="text-text-muted">{sig.ioc_type || '-'}</span>
                    </td>

                    {/* Source */}
                    <td className="px-4 py-3 hidden lg:table-cell">
                      <span className="text-text-muted truncate inline-block max-w-[120px]">
                        {sig.source || '-'}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'inline-flex items-center gap-1.5 text-xs font-medium',
                          sig.enabled ? 'text-severity-low' : 'text-text-muted',
                        )}
                      >
                        <span
                          className={cn(
                            'h-1.5 w-1.5 rounded-full',
                            sig.enabled ? 'bg-severity-low' : 'bg-text-muted',
                          )}
                        />
                        {sig.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>

                    {/* Delete */}
                    <td className="px-4 py-3">
                      {deleteId === sig.id ? (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleDelete(sig.id)}
                            disabled={deleting}
                            className="rounded px-2 py-1 text-xs font-medium bg-severity-critical/15 text-severity-critical hover:bg-severity-critical/25 transition-colors disabled:opacity-50"
                          >
                            {deleting ? '...' : 'Yes'}
                          </button>
                          <button
                            onClick={() => setDeleteId(null)}
                            className="rounded px-2 py-1 text-xs font-medium text-text-muted hover:bg-bg-hover transition-colors"
                          >
                            No
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setDeleteId(sig.id)}
                          className="p-1.5 rounded-lg hover:bg-severity-critical/10 text-text-muted hover:text-severity-critical transition-colors"
                          title="Delete signature"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && signatures.length === 0 && (
        <div className="bg-bg-card border border-border rounded-xl p-12 text-center">
          <Fingerprint className="h-12 w-12 text-text-muted/30 mx-auto mb-4" />
          <p className="text-text-muted text-lg font-medium">No signatures found.</p>
          <p className="text-text-muted/70 text-sm mt-1">Add one to get started.</p>
        </div>
      )}

      {/* Filtered empty state */}
      {!loading && signatures.length > 0 && filtered.length === 0 && (
        <div className="bg-bg-card border border-border rounded-xl p-12 text-center">
          <Search className="h-10 w-10 text-text-muted/30 mx-auto mb-3" />
          <p className="text-text-muted">No signatures match "{searchQuery}"</p>
        </div>
      )}
    </div>
  )
}
