interface StatsBarProps {
  received: number
  highCritical: number
  avgDurationMs: number | null
}

export default function StatsBar({ received, highCritical, avgDurationMs }: StatsBarProps) {
  const avgSeconds = avgDurationMs !== null ? (avgDurationMs / 1000).toFixed(1) : '—'

  return (
    <div className="flex items-baseline gap-6 pb-4 mb-4 border-b border-dr-border">
      <Stat value={received} label="received" />
      <Divider />
      <Stat value={highCritical} label="high / critical" color="text-dr-high" />
      <Divider />
      <Stat value={`${avgSeconds}s`} label="avg triage time" />
    </div>
  )
}

function Stat({
  value,
  label,
  color = 'text-dr-text',
}: {
  value: number | string
  label: string
  color?: string
}) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className={`text-xl font-medium ${color}`}>{value}</span>
      <span className="text-[11px] text-dr-text-faint">{label}</span>
    </div>
  )
}

function Divider() {
  return <div className="w-px h-4 bg-dr-border" />
}