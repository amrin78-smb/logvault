'use client';

import { useEffect, useRef, useState } from 'react';

const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#ef4444',
  error: '#f97316', warning: '#eab308', notice: '#3b82f6',
  info: '#22c55e', debug: '#475569',
};

const MAX_LINES = 500;

export default function LiveTail() {
  const [logs, setLogs]       = useState<any[]>([]);
  const [paused, setPaused]   = useState(false);
  const [filter, setFilter]   = useState('');
  const [connected, setConn]  = useState(false);
  const [count, setCount]     = useState(0);
  const bottomRef             = useRef<HTMLDivElement>(null);
  const pausedRef             = useRef(false);
  const wsRef                 = useRef<WebSocket | null>(null);

  pausedRef.current = paused;

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/live`);
    wsRef.current = ws;

    ws.onopen  = () => setConn(true);
    ws.onclose = () => setConn(false);
    ws.onerror = () => setConn(false);

    ws.onmessage = (evt) => {
      if (pausedRef.current) return;
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === 'logs' && msg.data?.length) {
          setLogs(prev => [...prev, ...msg.data].slice(-MAX_LINES));
          setCount(c => c + msg.data.length);
        }
      } catch {}
    };

    return () => ws.close();
  }, []);

  useEffect(() => {
    if (!paused) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, paused]);

  const filtered = filter
    ? logs.filter(l => l.message?.toLowerCase().includes(filter.toLowerCase()) ||
        l.source_host?.toLowerCase().includes(filter.toLowerCase()))
    : logs;

  return (
    <div style={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>Live Tail</span>

        <div style={{ width: 8, height: 8, borderRadius: '50%',
          background: connected ? '#22c55e' : '#ef4444',
          boxShadow: connected ? '0 0 6px #22c55e' : 'none',
          animation: connected && !paused ? 'pulse 2s infinite' : 'none' }} />
        <span style={{ fontSize: 11, color: connected ? '#22c55e' : '#ef4444' }}>
          {connected ? (paused ? 'Paused' : 'Streaming') : 'Disconnected'}
        </span>

        <span style={{ fontSize: 11, color: '#475569' }}>{count.toLocaleString()} received</span>

        <input value={filter} onChange={e => setFilter(e.target.value)}
          placeholder="Filter messages..." style={{ marginLeft: 'auto',
            background: '#0f1117', border: '1px solid #1e2d40', borderRadius: 6,
            padding: '6px 12px', color: '#e2e8f0', fontSize: 12, outline: 'none', width: 220 }} />

        <button onClick={() => setPaused(p => !p)}
          style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid',
            cursor: 'pointer', fontSize: 12, fontWeight: 500,
            background: paused ? '#1e3a5f' : '#161b27',
            borderColor: paused ? '#38bdf8' : '#1e2d40',
            color: paused ? '#38bdf8' : '#94a3b8' }}>
          {paused ? '▶ Resume' : '⏸ Pause'}
        </button>

        <button onClick={() => setLogs([])}
          style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid #1e2d40',
            cursor: 'pointer', fontSize: 12, background: 'transparent', color: '#64748b' }}>
          Clear
        </button>
      </div>

      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }`}</style>

      <div style={{ background: '#0a0d13', borderRadius: 6, padding: 12, height: '65vh',
        overflowY: 'auto', fontFamily: 'Consolas, monospace', fontSize: 12 }}>
        {filtered.map((log, i) => (
          <div key={i} style={{ display: 'flex', gap: 12, padding: '2px 0',
            borderBottom: '1px solid #0f1520', alignItems: 'flex-start' }}>
            <span style={{ color: '#475569', whiteSpace: 'nowrap', minWidth: 80 }}>
              {new Date(log.received_at).toLocaleTimeString()}
            </span>
            <span style={{ color: '#94a3b8', whiteSpace: 'nowrap', minWidth: 120 }}>
              {log.source_host || log.source_ip}
            </span>
            <span style={{ minWidth: 56, textTransform: 'uppercase', fontSize: 10, fontWeight: 700,
              color: SEV_COLORS[log.severity_label] || '#94a3b8', paddingTop: 1 }}>
              {log.severity_label}
            </span>
            <span style={{ color: '#475569', minWidth: 70, textTransform: 'capitalize' }}>
              {log.vendor}
            </span>
            <span style={{ color: '#cbd5e1', wordBreak: 'break-all' }}>{log.message}</span>
          </div>
        ))}
        {filtered.length === 0 && (
          <div style={{ color: '#475569', padding: '48px 0', textAlign: 'center' }}>
            {connected ? 'Waiting for log messages...' : 'Connecting to log stream...'}
          </div>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
