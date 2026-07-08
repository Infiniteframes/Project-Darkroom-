import type { TriageResult } from '../types'

// Uses whatever hostname the page itself was loaded from, not a hardcoded
// 127.0.0.1. That matters for testing on a real phone: if you load this
// page via your laptop's LAN IP (e.g. http://192.168.1.23:5173), a
// hardcoded 127.0.0.1 here would point at the phone itself, not your
// laptop, and every request would fail. Falling back to the same hostname
// keeps it working in both cases.
const API_BASE = `http://${window.location.hostname}:8000`

export async function triageAlert(alertText: string): Promise<TriageResult> {
  const res = await fetch(`${API_BASE}/triage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ alert_text: alertText }),
  })

  if (!res.ok) {
    let detail = `Request failed with status ${res.status}`
    try {
      const body = await res.json()
      if (body?.detail) detail = body.detail
    } catch {
      // response wasn't JSON - keep the generic message
    }
    throw new Error(detail)
  }

  return res.json()
}