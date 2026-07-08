// crypto.randomUUID() only works in "secure contexts" (HTTPS or localhost
// specifically) - it silently doesn't exist when a page is loaded over
// plain HTTP via a LAN IP (e.g. testing on a phone at http://192.168.x.x).
// This falls back to a simple manual ID generator in that case, so the
// app works identically on localhost and on a real device on the network.
export function generateId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return `id-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
}