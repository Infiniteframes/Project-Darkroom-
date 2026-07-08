import type { Severity } from '../types'

export const severityStyles: Record<Severity, { text: string; bg: string }> = {
  Low: { text: 'text-dr-low', bg: 'bg-dr-low-bg' },
  Medium: { text: 'text-dr-medium', bg: 'bg-dr-medium-bg' },
  High: { text: 'text-dr-high', bg: 'bg-dr-high-bg' },
  Critical: { text: 'text-dr-critical', bg: 'bg-dr-critical-bg' },
}

export function getSeverityStyle(severity: string) {
  return severityStyles[severity as Severity] ?? severityStyles.Medium
}