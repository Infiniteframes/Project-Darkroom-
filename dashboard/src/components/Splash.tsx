import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

interface SplashProps {
  onComplete: () => void
}

type Stage = 'idle' | 'developing'

const ZOOM_DURATION_MS = 600
const BAR_START_DELAY_MS = 500
const BAR_FILL_DURATION_MS = 900
const REVEAL_DELAY_MS = BAR_START_DELAY_MS + BAR_FILL_DURATION_MS + 150

export default function Splash({ onComplete }: SplashProps) {
  const [stage, setStage] = useState<Stage>('idle')

  useEffect(() => {
    if (stage !== 'developing') return
    const timer = setTimeout(onComplete, REVEAL_DELAY_MS)
    return () => clearTimeout(timer)
  }, [stage, onComplete])

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 z-50 flex items-center justify-center bg-dr-bg"
        exit={{ opacity: 0 }}
        transition={{ duration: 0.3 }}
      >
        <button
          onClick={() => stage === 'idle' && setStage('developing')}
          disabled={stage !== 'idle'}
          className="relative flex flex-col items-center justify-center outline-none"
          aria-label="Click to enter Darkroom"
        >
          <motion.div
            className="font-serif italic font-semibold text-dr-accent select-none text-[22vw] leading-none sm:text-[18vw] md:text-[12vw] lg:text-[8rem]"
            animate={{
              scale: stage === 'developing' ? 16 : 1,
              opacity: stage === 'developing' ? 0 : 1,
            }}
            transition={{
              duration: ZOOM_DURATION_MS / 1000,
              ease: [0.6, 0, 0.9, 0.4],
            }}
          >
            PD
          </motion.div>

          <motion.div
            className="absolute -bottom-12 text-xs sm:text-sm text-dr-text-fainter font-mono"
            animate={{ opacity: stage === 'idle' ? 1 : 0 }}
            transition={{ duration: 0.3 }}
          >
            click to develop
          </motion.div>
        </button>

        {stage === 'developing' && (
          <motion.div
            className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none px-6"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: BAR_START_DELAY_MS / 1000, duration: 0.3 }}
          >
            <div className="w-full max-w-[280px] h-0.5 bg-dr-chip rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-dr-accent"
                initial={{ width: '0%' }}
                animate={{ width: '100%' }}
                transition={{
                  delay: BAR_START_DELAY_MS / 1000,
                  duration: BAR_FILL_DURATION_MS / 1000,
                  ease: [0.4, 0, 0.2, 1],
                }}
              />
            </div>
            <motion.div
              className="text-xs sm:text-sm text-dr-text-faint font-mono mt-4 tracking-wide"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: BAR_START_DELAY_MS / 1000, duration: 0.3 }}
            >
              developing…
            </motion.div>
          </motion.div>
        )}
      </motion.div>
    </AnimatePresence>
  )
}