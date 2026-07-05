import { clsx, type ClassValue } from 'clsx'

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs)
}

export function severityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'text-severity-critical'
    case 'high': return 'text-severity-high'
    case 'medium': return 'text-severity-medium'
    case 'low': return 'text-severity-low'
    default: return 'text-severity-info'
  }
}

export function severityBg(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'bg-severity-critical/15 text-severity-critical'
    case 'high': return 'bg-severity-high/15 text-severity-high'
    case 'medium': return 'bg-severity-medium/15 text-severity-medium'
    case 'low': return 'bg-severity-low/15 text-severity-low'
    default: return 'bg-severity-info/15 text-severity-info'
  }
}

export function verdictColor(verdict: string): string {
  switch (verdict?.toUpperCase()) {
    case 'MALICIOUS': return 'text-verdict-malicious'
    case 'SUSPICIOUS': return 'text-verdict-suspicious'
    case 'CAUTION': return 'text-verdict-caution'
    case 'CLEAN': return 'text-verdict-clean'
    default: return 'text-text-muted'
  }
}

export function verdictBg(verdict: string): string {
  switch (verdict?.toUpperCase()) {
    case 'MALICIOUS': return 'bg-verdict-malicious/15 text-verdict-malicious border-verdict-malicious/30'
    case 'SUSPICIOUS': return 'bg-verdict-suspicious/15 text-verdict-suspicious border-verdict-suspicious/30'
    case 'CAUTION': return 'bg-verdict-caution/15 text-verdict-caution border-verdict-caution/30'
    case 'CLEAN': return 'bg-verdict-clean/15 text-verdict-clean border-verdict-clean/30'
    default: return 'bg-bg-card text-text-muted border-border'
  }
}

export function formatDate(dateStr: string | null): string {
  if (!dateStr) return '-'
  try {
    return new Date(dateStr).toLocaleString()
  } catch {
    return dateStr
  }
}

export function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined) return '-'
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}
