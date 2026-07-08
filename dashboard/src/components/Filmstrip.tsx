import type { ReactNode } from 'react'

interface FilmstripProps {
  children: ReactNode
  holeCount?: number
}

export default function Filmstrip({ children, holeCount = 10 }: FilmstripProps) {
  return (
    <div className="flex">
      <div className="w-4 shrink-0 flex flex-col items-center gap-[19px] pt-2">
        {Array.from({ length: holeCount }).map((_, i) => (
          <div
            key={i}
            className="w-1.5 h-1.5 rounded-full bg-dr-bg shadow-[inset_0_0_0_0.5px_var(--color-dr-border)]"
          />
        ))}
      </div>
      <div className="flex-1 pl-4 border-l border-dr-border min-w-0">
        {children}
      </div>
    </div>
  )
}