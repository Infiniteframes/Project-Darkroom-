import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import Splash from './components/Splash'
import AboutPanel from './components/AboutPanel'
import StatsBar from './components/StatsBar'
import Filmstrip from './components/Filmstrip'
import AlertRow from './components/AlertRow'
import ManualInput from './components/ManualInput'
import { triageAlert } from './lib/api'
import { getSampleAlertPool, pickNext } from './lib/sampleAlerts'
import { generateId } from './lib/id'
import type { FeedItem } from './types'

const MAX_VISIBLE_ITEMS = 8
const LIVE_FEED_INTERVAL_MS = 6000
const RECENT_MEMORY_SIZE = 5
const MAX_CONSECUTIVE_FAILURES = 3

export default function App() {
  const [revealed, setRevealed] = useState(false)

  const [feed, setFeed] = useState<FeedItem[]>([])
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [isLive, setIsLive] = useState(true)
  const [connectionLost, setConnectionLost] = useState(false)

  const [totalReceived, setTotalReceived] = useState(0)
  const [highCriticalCount, setHighCriticalCount] = useState(0)
  const [durations, setDurations] = useState<number[]>([])

  const samplePoolRef = useRef<string[]>([])
  const recentlyUsedRef = useRef<Set<string>>(new Set())
  const isProcessingRef = useRef(false)
  const consecutiveFailuresRef = useRef(0)

  useEffect(() => {
    getSampleAlertPool().then((pool) => {
      samplePoolRef.current = pool
    })
  }, [])

  async function processAlert(alertText: string) {
    const id = generateId()
    const startedAt = performance.now()

    const newItem: FeedItem = { id, alertText, status: 'analyzing', receivedAt: Date.now() }
    setFeed((prev) => [newItem, ...prev].slice(0, MAX_VISIBLE_ITEMS))
    setTotalReceived((prev) => prev + 1)

    try {
      const result = await triageAlert(alertText)
      const durationMs = performance.now() - startedAt

      setFeed((prev) =>
        prev.map((item) =>
          item.id === id ? { ...item, status: 'done', result, durationMs } : item
        )
      )
      setDurations((prev) => [...prev.slice(-19), durationMs])
      consecutiveFailuresRef.current = 0

      if (result.severity === 'High' || result.severity === 'Critical') {
        setHighCriticalCount((prev) => prev + 1)
      }
    } catch (e) {
      setFeed((prev) =>
        prev.map((item) =>
          item.id === id
            ? { ...item, status: 'error', errorMessage: (e as Error).message }
            : item
        )
      )
      consecutiveFailuresRef.current += 1
      if (consecutiveFailuresRef.current >= MAX_CONSECUTIVE_FAILURES) {
        setIsLive(false)
        setConnectionLost(true)
      }
    }
  }

  useEffect(() => {
    if (!isLive) return

    const interval = setInterval(async () => {
      if (isProcessingRef.current) return
      if (samplePoolRef.current.length === 0) return

      isProcessingRef.current = true
      const next = pickNext(samplePoolRef.current, recentlyUsedRef.current)

      recentlyUsedRef.current.add(next)
      if (recentlyUsedRef.current.size > RECENT_MEMORY_SIZE) {
        const first = recentlyUsedRef.current.values().next().value
        if (first !== undefined) recentlyUsedRef.current.delete(first)
      }

      await processAlert(next)
      isProcessingRef.current = false
    }, LIVE_FEED_INTERVAL_MS)

    return () => clearInterval(interval)
  }, [isLive])

  const avgDurationMs =
    durations.length > 0 ? durations.reduce((a, b) => a + b, 0) / durations.length : null

  function handleToggleLive() {
    consecutiveFailuresRef.current = 0
    setConnectionLost(false)
    setIsLive((v) => !v)
  }

  return (
    <div className="min-h-screen bg-dr-bg text-dr-text font-sans flex items-center justify-center">
      {!revealed && <Splash onComplete={() => setRevealed(true)} />}

      <motion.div
        className="w-full max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-12 py-10 sm:py-14"
        initial={{ opacity: 0, scale: 0.96 }}
        animate={revealed ? { opacity: 1, scale: 1 } : {}}
        transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="text-center mb-10 sm:mb-14">
          <h1 className="font-serif italic font-semibold text-dr-accent text-4xl sm:text-5xl lg:text-6xl">
            Darkroom
          </h1>
          <p
            style={{ fontFamily: "'Instrument Serif', serif" }}
            className="italic text-dr-text-muted text-base sm:text-lg mt-2"
          >
            Alerts, developed.
          </p>
          <button
            onClick={handleToggleLive}
            className="flex items-center justify-center gap-2 mt-4 mx-auto select-none"
            title={isLive ? 'Click to pause the live feed' : 'Click to resume the live feed'}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                isLive ? 'bg-dr-live' : 'bg-dr-text-fainter'
              }`}
            />
            <span className="text-xs font-mono text-dr-live-text">
              {isLive ? 'watching for alerts' : 'paused'}
            </span>
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 lg:gap-0">
          <div className="lg:pr-14 lg:border-r lg:border-dr-border">
            <AboutPanel />
          </div>

          <div className="lg:pl-14">
            <StatsBar
              received={totalReceived}
              highCritical={highCriticalCount}
              avgDurationMs={avgDurationMs}
            />

            {connectionLost && (
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 bg-dr-high-bg border border-dr-high/30 rounded-lg px-4 py-3 mb-4">
                <span className="text-xs text-dr-high">
                  Lost connection to the backend after {MAX_CONSECUTIVE_FAILURES} failed attempts - feed paused.
                </span>
                <button
                  onClick={handleToggleLive}
                  className="text-[11px] font-medium text-dr-text bg-dr-accent px-3 py-1.5 rounded-md shrink-0"
                >
                  Reconnect
                </button>
              </div>
            )}

            <Filmstrip>
              {feed.length === 0 ? (
                <p className="text-xs text-dr-text-faint py-6">
                  Waiting for the first alert to arrive...
                </p>
              ) : (
                feed.map((item) => (
                  <AlertRow
                    key={item.id}
                    item={item}
                    isExpanded={expandedId === item.id}
                    onToggle={() =>
                      setExpandedId((prev) => (prev === item.id ? null : item.id))
                    }
                  />
                ))
              )}
            </Filmstrip>

            <ManualInput onSubmit={processAlert} isSubmitting={false} />
          </div>
        </div>

        <div className="mt-14 pt-8 border-t border-dr-border">
          <div className="text-xs tracking-widest text-dr-text-faint mb-4 uppercase text-center">
            Built with
          </div>
          <div className="flex flex-wrap items-center justify-center gap-2">
            {[
              'Python',
              'FastAPI',
              'ChromaDB',
              'sentence-transformers',
              'Llama 3.1 8B',
              'Ollama',
              'React',
              'TypeScript',
              'Tailwind CSS',
              'Framer Motion',
            ].map((tech) => (
              <span
                key={tech}
                className="font-mono text-[11px] sm:text-xs text-dr-text-muted bg-dr-surface px-3 py-1.5 rounded-full"
              >
                {tech}
              </span>
            ))}
          </div>
        </div>
      </motion.div>
    </div>
  )
}