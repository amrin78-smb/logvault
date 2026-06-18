'use client';
import { useEffect, useRef, useState, useCallback } from 'react';
import { PageHeader, EmptyState } from './ui';

const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#dc2626',
  error: '#ea580c', warning: '#ca8a04', notice: '#2563eb',
  info: '#16a34a', debug: '#9ca3af',
};

const MAX_LINES = 1000;
let persistedLogs: any[] = [];
let persistedCount       = 0;

export default function LiveTail() {
  const [logs, setLogs]             = useState<any[]>(persistedLogs);
  const [paused, setPaused]         = useState(false);
  const [filter, setFilter]         = useState('');
  const [connected, setConn]        = useState(false);
  const [count, setCount]           = useState(persistedCount);
  const [autoScroll, setAutoScroll] = useState(true);
  const containerRef                = useRef<HTMLDivElement>(null);
  const pausedRef                   = useRef(false);
  pausedRef.current = paused;

  useEffect(() => {
    if (autoScroll && containerRef.current)
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
  }, [logs, autoScroll]);

  const handleScroll = useCallback(() => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 60);
  }, []);

  useEffect(() => {
    // Clear persisted logs on mount so we always start fresh
    persistedLogs  = [];
    persistedCount = 0;
    setLogs([]);
    setCount(0);

    let ws: WebSocket | null = null;
    let cancelled = false;

    // The WS connects directly to the API (port 3005), bypassing the auth
    // proxy, so we first fetch a short-lived signed ticket via the proxied
    // /api/ws-ticket (which carries the verified role + sites) and present it on
    // the WS URL. The server scopes the stream to the user's sites from it.
    (async () => {
      let ticket = '';
      try {
        const res = await fetch('/api/ws-ticket');
        if (res.ok) ticket = (await res.json()).ticket || '';
      } catch { /* leave ticket empty → no connection */ }
      if (cancelled || !ticket) { setConn(false); return; }

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${protocol}//${window.location.hostname}:3005/ws/live?ticket=${encodeURIComponent(ticket)}`);
      ws.onopen  = () => setConn(true);
      ws.onclose = () => setConn(false);
      ws.onerror = () => setConn(false);
      ws.onmessage = (evt) => {
        if (pausedRef.current) return;
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'logs' && msg.data?.length) {
            persistedLogs  = [...persistedLogs, ...msg.data].slice(-MAX_LINES);
            persistedCount += msg.data.length;
            setLogs([...persistedLogs]);
            setCount(persistedCount);
          }
        } catch {}
      };
    })();

    return () => { cancelled = true; if (ws) ws.close(); };
  }, []);

  const clearLogs = () => { persistedLogs = []; persistedCount = 0; setLogs([]); setCount(0); };

  const filtered = filter
    ? logs.filter(l => l.message?.toLowerCase().includes(filter.toLowerCase()) ||
        (l.source_host || '').toLowerCase().includes(filter.toLowerCase()) ||
        (l.vendor || '').toLowerCase().includes(filter.toLowerCase()))
    : logs;

  return (
    <>
    <PageHeader title="Live Tail" subtitle="Real-time streaming syslog feed" />
    <div style={{ background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 8, padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 14, fontWeight: 600, color: '#1a202c' }}>Live Tail</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6,
          background: connected ? '#f0fdf4' : '#fef2f2',
          border: `1px solid ${connected ? '#bbf7d0' : '#fecaca'}`,
          borderRadius: 20, padding: '3px 10px' }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%',
            background: connected ? '#22c55e' : '#ef4444',
            boxShadow: connected && !paused ? '0 0 5px #22c55e' : 'none' }} />
          <span style={{ fontSize: 11, color: connected ? '#16a34a' : '#dc2626', fontWeight: 600 }}>
            {connected ? (paused ? 'Paused' : 'Live') : 'Disconnected'}
          </span>
        </div>
        <span style={{ fontSize: 11, color: '#9ca3af' }}>{count.toLocaleString()} total · {filtered.length.toLocaleString()} shown</span>
        {!autoScroll && (
          <button onClick={() => { setAutoScroll(true); if (containerRef.current) containerRef.current.scrollTop = containerRef.current.scrollHeight; }}
            style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #2563eb', cursor: 'pointer', fontSize: 11, background: '#eff6ff', color: '#2563eb', fontWeight: 600 }}>
            ↓ Jump to latest
          </button>
        )}
        <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by host, vendor, message..."
          style={{ marginLeft: 'auto', background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 6,
            padding: '6px 12px', color: '#1a202c', fontSize: 12, outline: 'none', width: 240 }} />
        <button onClick={() => setPaused(p => !p)}
          style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid',
            cursor: 'pointer', fontSize: 12, fontWeight: 500,
            background: paused ? '#eff6ff' : '#f8f9fb',
            borderColor: paused ? '#2563eb' : '#e2e6ea',
            color: paused ? '#2563eb' : '#4a5568' }}>
          {paused ? '▶ Resume' : '⏸ Pause'}
        </button>
        <button onClick={clearLogs}
          style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid #e2e6ea', cursor: 'pointer', fontSize: 12, background: '#f8f9fb', color: '#9ca3af' }}>
          Clear
        </button>
      </div>

      <div ref={containerRef} onScroll={handleScroll}
        style={{ background: '#0d1117', borderRadius: 8, padding: '10px 14px', height: '60vh',
          overflowY: 'auto', fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}>
        {filtered.length === 0 && (
          <EmptyState title="Waiting for logs" message="Live entries will appear here as they arrive." />
        )}
        {filtered.map((log, i) => (
          <div key={`${log.id || i}-${i}`} style={{ display: 'flex', gap: 10, padding: '3px 0',
            borderBottom: '1px solid #161b27', alignItems: 'flex-start' }}>
            <span style={{ color: '#4b5563', whiteSpace: 'nowrap', minWidth: 78, fontSize: 11 }}>
              {new Date(log.received_at).toLocaleTimeString()}
            </span>
            <span style={{ color: '#6b7280', whiteSpace: 'nowrap', minWidth: 115, overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {log.source_host || log.source_ip || '-'}
            </span>
            <span style={{ minWidth: 60, textTransform: 'uppercase', fontSize: 10, fontWeight: 700,
              color: SEV_COLORS[log.severity_label] || '#9ca3af', paddingTop: 1, whiteSpace: 'nowrap' }}>
              {log.severity_label}
            </span>
            <span style={{ color: '#4b5563', minWidth: 65, textTransform: 'capitalize', whiteSpace: 'nowrap', fontSize: 11 }}>
              {log.vendor}
            </span>
            <span style={{ color: '#d1d5db', wordBreak: 'break-word', flex: 1 }}>{log.message}</span>
          </div>
        ))}
      </div>
    </div>
    </>
  );
}
