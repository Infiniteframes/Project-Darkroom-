const STEPS = [
  {
    num: '01',
    title: 'Retrieve',
    detail: 'Embed the alert, search 1,000+ ATT&CK and CVE records',
  },
  {
    num: '02',
    title: 'Reason',
    detail: 'A local Llama 3.1 8B reads the alert alongside real matches',
  },
  {
    num: '03',
    title: 'Validate',
    detail: "Any technique the model didn't actually retrieve gets rejected",
  },
  {
    num: '04',
    title: 'Report',
    detail: 'A summary, severity score, and one concrete next step',
  },
]

const STATS = [
  { value: '697', label: 'ATT&CK techniques' },
  { value: '307', label: 'CVEs indexed' },
  { value: '$0', label: 'inference cost' },
  { value: '100%', label: 'runs locally' },
]

export default function AboutPanel() {
  return (
    <div>
      <SectionLabel>What this is</SectionLabel>
      <p className="text-sm sm:text-[15px] text-dr-text-dim leading-relaxed mb-7">
        An AI triage assistant for security alerts. Every alert is checked
        against real MITRE ATT&amp;CK and CVE data, then explained in plain
        English with a severity score and next step.
      </p>

      <SectionLabel>How it works</SectionLabel>
      <div className="flex flex-col gap-3.5 mb-7">
        {STEPS.map((step) => (
          <div key={step.num}>
            <div className="flex items-baseline gap-2.5">
              <span className="font-mono text-xs text-dr-high">{step.num}</span>
              <span className="text-sm sm:text-[15px] text-dr-text-dim font-medium">
                {step.title}
              </span>
            </div>
            <div className="text-xs sm:text-[13px] text-dr-text-faint ml-7">
              {step.detail}
            </div>
          </div>
        ))}
      </div>

      <SectionLabel>At a glance</SectionLabel>
      <div className="grid grid-cols-2 gap-2.5">
        {STATS.map((stat) => (
          <div key={stat.label} className="bg-dr-surface rounded-lg px-3.5 py-3">
            <div className="text-lg sm:text-xl font-medium">{stat.value}</div>
            <div className="text-[11px] sm:text-xs text-dr-text-faint">
              {stat.label}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function SectionLabel({ children }: { children: string }) {
  return (
    <div className="text-xs tracking-widest text-dr-text-faint mb-3 uppercase">
      {children}
    </div>
  )
}