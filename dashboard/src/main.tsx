import { StrictMode, useState, useEffect } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { DebugErrorBoundary, installGlobalErrorDisplay } from './DebugOverlay.tsx'

function Root() {
  const [globalError, setGlobalError] = useState<string | null>(null)

  useEffect(() => {
    installGlobalErrorDisplay(setGlobalError)
  }, [])

  if (globalError) {
    return (
      <div
        style={{
          position: 'fixed',
          inset: 0,
          background: '#1a0e0e',
          color: '#ffb4a8',
          padding: '20px',
          fontFamily: 'monospace',
          fontSize: '13px',
          zIndex: 9999,
          overflow: 'auto',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
        }}
      >
        <div style={{ fontWeight: 'bold', marginBottom: '10px', fontSize: '15px' }}>
          ⚠ Runtime error
        </div>
        {globalError}
      </div>
    )
  }

  return (
    <DebugErrorBoundary>
      <App />
    </DebugErrorBoundary>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
)