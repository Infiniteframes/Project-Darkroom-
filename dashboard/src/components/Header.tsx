interface HeaderProps {
  isLive: boolean
}

export default function Header({ isLive }: HeaderProps) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div>
        <div className="text-[13px] font-medium tracking-[0.18em] text-dr-accent">
          DARKROOM
        </div>
        <div className="text-xs text-dr-text-faint mt-0.5">
          security alert triage
        </div>
      </div>
      <div className="flex items-center gap-2">
        <span
          className={`w-1.5 h-1.5 rounded-full ${
            isLive ? 'bg-dr-live' : 'bg-dr-text-fainter'
          }`}
        />
        <span className="text-xs font-mono text-dr-live-text">
          {isLive ? 'watching for alerts' : 'paused'}
        </span>
      </div>
    </div>
  )
}