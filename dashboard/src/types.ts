export type Severity = 'Low' | 'Medium' | 'High' | 'Critical'

export interface AttackMatch {
  technique_id: string
  name: string
  tactics: string
  description: string
  distance: number
}

export interface CveMatch {
  cve_id: string
  severity: string
  cvss_score: number | null
  published: string
  description: string
  distance: number
}

export interface TriageResult {
  summary: string
  technique_id: string
  severity: Severity
  recommended_action: string
  attempts_needed: number
  failed?: boolean
  retrieved_context: {
    attack_matches: AttackMatch[]
    cve_matches: CveMatch[]
  }
}

export type FeedStatus = 'analyzing' | 'done' | 'error'

export interface FeedItem {
  id: string
  alertText: string
  status: FeedStatus
  result?: TriageResult
  errorMessage?: string
  receivedAt: number
  durationMs?: number
}