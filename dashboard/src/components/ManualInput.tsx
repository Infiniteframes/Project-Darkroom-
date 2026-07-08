import { useState } from 'react'

interface ManualInputProps {
  onSubmit: (alertText: string) => void
  isSubmitting: boolean
}

export default function ManualInput({ onSubmit, isSubmitting }: ManualInputProps) {
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState('')

  function handleSubmit() {
    const trimmed = value.trim()
    if (!trimmed) return
    onSubmit(trimmed)
    setValue('')
    setOpen(false)
  }

  if (!open) {
    return (
      <div className="flex justify-end mt-4">
        <button
          onClick={() => setOpen(true)}
          className="text-[11px] text-dr-text-muted border border-dr-border-faint px-3 py-1.5 rounded-md hover:border-dr-border transition-colors"
        >
          Paste an alert manually
        </button>
      </div>
    )
  }

  return (
    <div className="mt-4 pt-4 border-t border-dr-border">
      <textarea
        autoFocus
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Paste a raw alert, e.g. suspicious PowerShell execution on HOST-42, user jsmith, 03:14 AM"
        rows={2}
        className="w-full bg-dr-surface text-sm font-mono text-dr-text-dim placeholder:text-dr-text-fainter rounded-lg p-3 outline-none focus:ring-1 focus:ring-dr-accent resize-none"
      />
      <div className="flex justify-end gap-2 mt-2">
        <button
          onClick={() => {
            setOpen(false)
            setValue('')
          }}
          className="text-[11px] text-dr-text-faint px-3 py-1.5"
        >
          Cancel
        </button>
        <button
          onClick={handleSubmit}
          disabled={isSubmitting || !value.trim()}
          className="text-xs font-medium bg-dr-accent text-dr-text px-4 py-1.5 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Develop →
        </button>
      </div>
    </div>
  )
}