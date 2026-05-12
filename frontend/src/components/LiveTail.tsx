'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#ef4444',
  error: '#f97316', warning: '#eab308', notice: '#3b82f6',
  info: '#22c55e', debug: '#475569',
};

const MAX_LINES = 1000;

// Persisted outside component so logs survive tab switches
let persistedLogs: any[]  = [];
let persistedCount        = 0;

export default function LiveTail() {
  const [logs, setLogs]              = useState<any[]>(persistedLogs);
  const [paused, setPaused]          = useState(false);
  const [filter, setFilter]          = useState('');
  const [connected, setConn]         = useState(false);
  const [count, setCount]            = useState(persistedCount);
  const [autoScroll, setAutoScroll]  = useState(true);
  const containerRef                 = useRef<HTMLDivElement>(null);
  const pausedRef                    = useRef(false);

  pausedRef.current = paused;

  // Scroll to bottom when new logs arrive and autoScroll is on
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  // Detect manual scroll up — turn off auto-scroll
  const handleScroll = useCallback(() => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const atBottom = scrollHeight - scrollTop - clientHeight < 60;
    setAutoScroll(atBottom);
  }, []);

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host     = window.location.hostname;
    const ws       = new WebSocket(`${protocol}//${host}:3005/ws/live`);

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

    return () => ws.close();
  }, []);

  const clearLogs = () => {
    persistedLogs  = [];
    persistedCount = 0;
    setLogs([]);
    setCount(0);
  };

  const scrollToBottom = () => {
    setAutoScroll(true);
    if (containerRef.current) containerRef.current.scrollTop = containerRef.current.scrollHeight;
  };

  const filtered = filter
    ? logs.filter(l =>
        l.message?.toLowerCase().includes(filter.toLowerCase()) ||
        (l.source_host || '').toLowerCase().includes(filter.toLowerCase()) ||
        (l.vendor      || '').toLowerCase().includes(filter.toLowerCase()))
    : logs;

  return (
    <div style={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20 }}>

      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>Live Tail</span>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%',
            background: connected ? '#22c55e' : '#ef4444',
            boxShadow: connected && !paused ? '0 0 6px #22c55e' : 'none' }} />
          <span style={{ fontSize: 11, color: connected ? '#22c55e' : '#ef4444' }}>
            {connected ? (paused ? 'Paused' : 'Live') : 'Disconnected'}
          </span>
        </div>

        <span style={{ fontSize: 11, color: '#475569' }}>
          {count.toLocaleString()} total · {filtered.length.toLocaleString()} shown
        </span>

        {!autoScroll && (
          <button onClick={scrollToBottom}
            style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #38bdf8',
              cursor: 'pointer', fontSize: 11, background: '#1e3a5f', color: '#38bdf8' }}>
            ↓ Jump to latest
          </button>
        )}

        <input value={filter} onChange={e => setFilter(e.target.value)}
          placeholder="Filter by host, vendor, message..."
          style={{ marginLeft: 'auto', background: '#0f1117', border: '1px solid #1e2d40',
            borderRadius: 6, padding: '6px 12px', color: '#e2e8f0', fontSize: 12,
            outline: 'none', width: 240 }} />

        <button onClick={() => setPaused(p => !p)}
          style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid',
            cursor: 'pointer', fontSize: 12, fontWeight: 500,
            background: paused ? '#1e3a5f' : '#161b27',
            borderColor: paused ? '#38bdf8' : '#1e2d40',
            color: paused ? '#38bdf8' : '#94a3b8' }}>
          {paused ? '▶ Resume' : '⏸ Pause'}
        </button>

        <button onClick={clearLogs}
          style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid #1e2d40',
            cursor: 'pointer', fontSize: 12, background: 'transparent', color: '#64748b' }}>
          Clear
        </button>
      </div>

      {/* Log window */}
      <div ref={containerRef} onScroll={handleScroll}
        style={{ background: '#0a0d13', borderRadius: 6, padding: '8px 12px',
          height: '65vh', overflowY: 'auto', fontFamily: 'Consolas, monospace', fontSize: 12 }}>

        {filtered.length === 0 && (
          <div style={{ color: '#475569', padding: '48px 0', textAlign: 'center' }}>
            {connected
              ? paused ? 'Paused — click Resume to continue' : 'Waiting for log messages...'
              : 'Connecting to log stream...'}
          </div>
        )}

        {filtered.map((log, i) => (
          <div key={`${log.id || i}-${i}`}
            style={{ display: 'flex', gap: 10, padding: '3px 0',
              borderBottom: '1px solid #0d1117', alignItems: 'flex-start' }}>

            <span style={{ color: '#374151', whiteSpace: 'nowrap', minWidth: 78, fontSize: 11 }}>
              {new Date(log.received_at).toLocaleTimeString()}
            </span>

            <span style={{ color: '#6b7280', whiteSpace: 'nowrap', minWidth: 115,
              overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {log.source_host || log.source_ip || '-'}
            </span>

            <span style={{ minWidth: 62, textTransform: 'uppercase', fontSize: 10, fontWeight: 700,
              color: SEV_COLORS[log.severity_label] || '#94a3b8', paddingTop: 1, whiteSpace: 'nowrap' }}>
              {log.severity_label}
            </span>

            <span style={{ color: '#4b5563', minWidth: 65, textTransform: 'capitalize',
              whiteSpace: 'nowrap', fontSize: 11 }}>
              {log.vendor}
            </span>

            <span style={{ color: '#d1d5db', wordBreak: 'break-word', flex: 1 }}>
              {log.message}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
