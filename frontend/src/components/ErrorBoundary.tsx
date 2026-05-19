'use client';
import { Component, ReactNode } from 'react';

interface Props { children: ReactNode; name?: string; }
interface State { hasError: boolean; error?: Error; }

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error) {
    console.error(`[ErrorBoundary:${this.props.name || 'widget'}]`, error);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 10, padding: '20px 16px', textAlign: 'center' }}>
          <div style={{ fontSize: 20, marginBottom: 6 }}>⚠️</div>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
            {this.props.name || 'Widget'} failed to load
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
            {this.state.error?.message}
          </div>
          <button onClick={() => this.setState({ hasError: false })}
            style={{ padding: '4px 12px', borderRadius: 6, border: '1px solid var(--border)',
              cursor: 'pointer', fontSize: 11, background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
