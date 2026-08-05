'use client';
import { Component, ReactNode } from 'react';

interface Props { children: ReactNode; name?: string; }
interface State { hasError: boolean; error?: Error; isChunkError: boolean; }

// A "chunk load" failure is NOT an application bug — it means this browser tab was
// loaded from a build that no longer exists on the server. Every tab in page.tsx is a
// separate next/dynamic chunk and each deploy renames every chunk, so any tab left
// open across a deploy hits this the moment the user clicks a lazily-loaded tab.
// Before this, the boundary offered a "Retry" that only cleared hasError and
// re-attempted the SAME missing file — it could never succeed, leaving a dead end
// that looked like the feature itself was broken.
const CHUNK_ERROR = /loading chunk|failed to load chunk|chunkloaderror|loading css chunk|dynamically imported module/i;

const isChunkError = (e?: Error) =>
  !!e && (CHUNK_ERROR.test(e.message || '') || e.name === 'ChunkLoadError');

// One reload per cooldown, tracked in sessionStorage. Without a guard, a genuinely
// persistent failure would reload forever; with a plain boolean instead of a time
// window the tab could only self-heal once and the NEXT deploy would strand it again.
const RELOAD_KEY = 'lv-chunk-reload-at';
const RELOAD_COOLDOWN_MS = 15000;

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, isChunkError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, isChunkError: isChunkError(error) };
  }

  componentDidCatch(error: Error) {
    console.error(`[ErrorBoundary:${this.props.name || 'widget'}]`, error);
    if (!isChunkError(error)) return;

    // Only a full reload fetches the new build's chunk manifest.
    try {
      const last = Number(sessionStorage.getItem(RELOAD_KEY) || 0);
      if (Date.now() - last > RELOAD_COOLDOWN_MS) {
        sessionStorage.setItem(RELOAD_KEY, String(Date.now()));
        window.location.reload();
      }
    } catch {
      // sessionStorage throws in some hardened/private modes — fall through to the
      // manual "Reload page" button rather than risk an unguarded reload loop.
    }
  }

  render() {
    if (this.state.hasError) {
      const chunk = this.state.isChunkError;
      return (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius)', padding: '20px 16px', textAlign: 'center' }}>
          <div style={{ fontSize: 'var(--text-xl)', marginBottom: 6 }}>{chunk ? '🔄' : '⚠️'}</div>
          <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
            {chunk ? 'A newer version of LogVault was deployed' : `${this.props.name || 'Widget'} failed to load`}
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 10 }}>
            {chunk
              ? 'This tab is still running an older build. Reloading to pick up the new one…'
              : this.state.error?.message}
          </div>
          <button
            onClick={() => (chunk
              ? window.location.reload()
              : this.setState({ hasError: false, isChunkError: false }))}
            style={{ padding: '4px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
              cursor: 'pointer', fontSize: 'var(--text-xs)', background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
            {chunk ? 'Reload page' : 'Retry'}
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
