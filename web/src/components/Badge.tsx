// Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
import { cn } from '../lib/utils'

interface BadgeProps {
  children: React.ReactNode
  variant?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'malicious' | 'suspicious'
  className?: string
}

const variantClasses: Record<NonNullable<BadgeProps['variant']>, string> = {
  default: 'bg-bg-hover text-text-muted',
  critical: 'bg-severity-critical/15 text-severity-critical',
  high: 'bg-severity-high/15 text-severity-high',
  medium: 'bg-severity-medium/15 text-severity-medium',
  low: 'bg-severity-low/15 text-severity-low',
  clean: 'bg-verdict-clean/15 text-verdict-clean',
  malicious: 'bg-verdict-malicious/15 text-verdict-malicious',
  suspicious: 'bg-verdict-suspicious/15 text-verdict-suspicious',
}

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium',
        variantClasses[variant],
        className,
      )}
    >
      {children}
    </span>
  )
}
