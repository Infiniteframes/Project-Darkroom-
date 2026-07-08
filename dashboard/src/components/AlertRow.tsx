import type { FeedItem } from '../types'
import { getSeverityStyle } from '../lib/severity'
import ChevronIcon from './ChevronIcon'

interface AlertRowProps {
  item: FeedItem
  isExpanded: boolean
  onToggle: () => void
}

export default function AlertRow({ item, isExpanded, onToggle }: AlertRowProps) {
  if (item.status === 'analyzing') {
    return (
      <div className="flex items-center gap-2.5 py-2.5 opacity-55">
        <span className="font-mono text-[10px] text-dr-text-faint bg-dr-chip px-2.5 py-1 rounded">
          analyzing…
        </span>
        <span className="text-xs font-mono text-dr-text-faint flex-1 truncate">
          {item.alertText}
        </span>
      </div>
    )
  }

  if (item.status === 'error') {
    return (
      <div className="flex items-center gap-2.5 py-3 border-t border-dr-border-faint">
        <span className="font-mono text-[11px] text-dr-high bg-dr-high-bg px-2 py-0.5 rounded">
          error
        </span>
        <span className="text-sm text-dr-text-dim flex-1 truncate">
          {item.errorMessage ?? 'Triage failed'}
        </span>
      </div>
    )
  }

  const result = item.result!
  const severityStyle = getSeverityStyle(result.severity)

  return (
    <div className="py-3 border-t border-dr-border-faint">
      <button
        onClick={onToggle}
        className="flex items-center gap-2.5 w-full text-left"
        aria-expanded={isExpanded}
      >
        <span
          className={`font-mono text-[11px] ${severityStyle.text} ${severityStyle.bg} px-2 py-0.5 rounded shrink-0`}
        >
          {result.technique_id}
        </span>
        <span className="text-sm text-dr-text-dim flex-1 truncate">
          {result.summary}
        </span>
        <span className={`text-[11px] ${severityStyle.text} shrink-0`}>
          {result.severity}
        </span>
        <ChevronIcon open={isExpanded} />
      </button>

      {isExpanded && (
        <div className="mt-3 p-4 bg-dr-surface-2 rounded-lg border-l-2 border-dr-accent rounded-l-none">
          <p className="text-[13px] text-dr-text-dim leading-relaxed mb-3">
            {result.summary}
          </p>
          <p className="text-xs text-dr-text-muted mb-2.5">
            <span className="text-dr-text-faint">Recommended action — </span>
            {result.recommended_action}
          </p>
          <div className="flex gap-1.5 flex-wrap">
            {result.retrieved_context.attack_matches.slice(0, 3).map((m) => (
              <span
                key={m.technique_id}
                className="font-mono text-[10px] text-dr-text-muted bg-dr-chip px-2 py-0.5 rounded"
              >
                {m.technique_id} {m.name}
              </span>
            ))}
            {result.retrieved_context.cve_matches.slice(0, 2).map((m) => (
              <span
                key={m.cve_id}
                className="font-mono text-[10px] text-dr-text-muted bg-dr-chip px-2 py-0.5 rounded"
              >
                {m.cve_id}
              </span>
            ))}
          </div>
          {result.failed && (
            <p className="text-[11px] text-dr-high mt-2.5">
              Automated triage failed after {item.result?.attempts_needed} attempts - flagged for manual review.
            </p>
          )}
        </div>
      )}
    </div>
  )
}