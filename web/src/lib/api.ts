const BASE = '/api/v1'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const apiKey = localStorage.getItem('malwar_api_key') || ''
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(apiKey ? { 'X-API-Key': apiKey } : {}),
      ...options?.headers,
    },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

// Types
export interface Finding {
  id: string
  rule_id: string
  title: string
  description: string
  severity: string
  confidence: number
  category: string
  detector_layer: string
  evidence: string[]
  line_start: number | null
}

export interface ScanResult {
  scan_id: string
  status: string
  verdict: string
  risk_score: number
  overall_severity: string
  finding_count: number
  finding_count_by_severity: Record<string, number>
  findings: Finding[]
  skill_name: string | null
  skill_author: string | null
  duration_ms: number | null
  created_at: string | null
}

export interface ScanListItem {
  scan_id: string
  target: string
  verdict: string | null
  risk_score: number | null
  status: string
  skill_name: string | null
  created_at: string | null
  duration_ms: number | null
}

export interface Signature {
  id: string
  name: string | null
  pattern_type: string
  pattern_value: string
  severity: string
  category: string | null
  ioc_type: string | null
  campaign_id: string | null
  source: string | null
  description: string | null
  enabled: boolean
  created_at: string | null
  updated_at: string | null
}

export interface Campaign {
  id: string
  name: string
  description: string | null
  first_seen: string | null
  last_seen: string | null
  attributed_to: string | null
  iocs: string[] | string | null
  total_skills_affected: number | null
  status: string
}

export interface ReportListItem {
  scan_id: string
  target: string
  verdict: string | null
  risk_score: number | null
  status: string
  skill_name: string | null
  created_at: string | null
  duration_ms: number | null
  finding_count: number
}

export interface ReportDetail extends ScanResult {
  severity_breakdown: Record<string, number>
  category_breakdown: Record<string, number>
  detector_breakdown: Record<string, number>
}

export interface HealthStatus {
  status: string
  service: string
  version: string
}

// API functions
export const api = {
  health: () => request<HealthStatus>('/health'),

  submitScan: (content: string, fileName?: string, useLlm?: boolean) =>
    request<ScanResult>('/scan', {
      method: 'POST',
      body: JSON.stringify({
        content,
        file_name: fileName || 'SKILL.md',
        use_llm: useLlm ?? true,
      }),
    }),

  getScan: (scanId: string) => request<ScanResult>(`/scan/${scanId}`),
  getScanSarif: (scanId: string) => request<Record<string, unknown>>(`/scan/${scanId}/sarif`),
  listScans: (limit = 50) => request<ScanListItem[]>(`/scans?limit=${limit}`),

  listReports: (params?: { verdict?: string; min_risk_score?: number; limit?: number }) => {
    const qs = new URLSearchParams()
    if (params?.verdict) qs.set('verdict', params.verdict)
    if (params?.min_risk_score !== undefined) qs.set('min_risk_score', String(params.min_risk_score))
    if (params?.limit) qs.set('limit', String(params.limit))
    const q = qs.toString()
    return request<ReportListItem[]>(`/reports${q ? '?' + q : ''}`)
  },

  getReport: (scanId: string) => request<ReportDetail>(`/reports/${scanId}`),

  listSignatures: () => request<Signature[]>('/signatures'),
  createSignature: (data: Partial<Signature>) =>
    request<Signature>('/signatures', { method: 'POST', body: JSON.stringify(data) }),
  deleteSignature: (id: string) =>
    request<void>(`/signatures/${id}`, { method: 'DELETE' }),

  listCampaigns: () => request<Campaign[]>('/campaigns'),
  getCampaign: (id: string) => request<Campaign & { signature_count: number }>(`/campaigns/${id}`),
}
