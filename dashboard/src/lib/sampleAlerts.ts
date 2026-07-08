// Loads real alert text from your own project data, so the "live feed"
// simulation plays back genuine alerts you already generated in Weeks 1-3,
// rather than made-up placeholder text.
//
// Expects these files to exist (copied from your main project's data folder):
//   public/data/synthetic_alerts.json  (from data/processed/Synthetic/)
//   public/data/cicids_alerts.json     (from data/processed/CIC-IDS2017/)

interface RawAlertRecord {
  alert_text?: string
}

async function loadFile(path: string): Promise<string[]> {
  try {
    const res = await fetch(path)
    if (!res.ok) return []
    const data: RawAlertRecord[] = await res.json()
    return data.map((a) => a.alert_text).filter((t): t is string => Boolean(t))
  } catch {
    return []
  }
}

let cachedPool: string[] | null = null

export async function getSampleAlertPool(): Promise<string[]> {
  if (cachedPool) return cachedPool

  const [synthetic, cicids] = await Promise.all([
    loadFile('/data/synthetic_alerts.json'),
    loadFile('/data/cicids_alerts.json'),
  ])

  const combined = [...synthetic, ...cicids]

  // Fallback so the demo still works even before you've copied your real
  // data files over - a handful of stand-in examples matching the same style.
  if (combined.length === 0) {
    cachedPool = [
      'suspicious PowerShell execution on HOST-42, user jsmith, 03:14 AM',
      'multiple failed login attempts for user admin from unfamiliar IP, 02:07 AM',
      'unusual registry modification on HOST-19, user chenl, 04:02 AM',
    ]
    return cachedPool
  }

  cachedPool = combined
  return cachedPool
}

// Simple shuffle-and-cycle so the feed doesn't repeat the same alert twice
// in a row, without needing to track a full traversal index externally.
export function pickNext(pool: string[], recentlyUsed: Set<string>): string {
  const candidates = pool.filter((a) => !recentlyUsed.has(a))
  const source = candidates.length > 0 ? candidates : pool
  return source[Math.floor(Math.random() * source.length)]
}