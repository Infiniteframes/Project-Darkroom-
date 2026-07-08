import { Component, type ReactNode } from 'react'

// Temporary diagnostic tool - catches both React render errors and
// uncaught runtime/promise errors, displaying them directly on screen.
// Useful for debugging on devices (like a phone) where opening real
// DevTools isn't convenient. Safe to delete once debugging is done.

interface State {
  error: string | null
}

export class DebugErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: unknown): State {
    return { error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) }
  }

  componentDidCatch(error: unknown, info: { componentStack?: string | null }) {
    console.error('Caught by DebugErrorBoundary:', error, info)
  }

  render() {
    if (this.state.error) {
      return <ErrorDisplay title="React render error" message={this.state.error} />
    }
    return this.props.children
  }
}

function ErrorDisplay({ title, message }: { title: string; message: string }) {
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
        ⚠ {title}
      </div>
      {message}
    </div>
  )
}

// Catches errors that happen outside React's render cycle - e.g. in
// promises, event handlers, or async code that isn't already caught
// elsewhere - and reports them the same way.
export function installGlobalErrorDisplay(onError: (message: string) => void) {
  window.addEventListener('error', (event) => {
    onError(`Uncaught error: ${event.message}\nat ${event.filename}:${event.lineno}`)
  })
  window.addEventListener('unhandledrejection', (event) => {
    onError(`Unhandled promise rejection: ${event.reason}`)
  })
}